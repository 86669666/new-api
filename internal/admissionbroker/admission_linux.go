//go:build linux

// Package admissionbroker implements one fixed-actor admission read. It does not
// reserve quota, authorize sending, issue provenance, or accept SQL operations.
package admissionbroker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	readLimit        = 512
	readTimeout      = 5 * time.Second
	operationTimeout = 2 * time.Second
	writeTimeout     = 2 * time.Second
	drainTimeout     = 8 * time.Second
)

var (
	ErrQualification = errors.New("admission qualification rejected")
	ErrProtocol      = errors.New("admission protocol rejected")
	ErrShutdown      = errors.New("admission shutdown did not drain")
)

// Config is installed by the trusted launcher, never supplied over the service
// socket. Separate root-owned copies are readable by broker and service only.
// Authority is a root peer performing fresh kernel observations, not a static
// receipt. The standalone command refuses to start without that authority.
type Config struct {
	Version                                             int
	Actor                                               int
	Database, Journal, JournalSHA256, Socket, Authority string
	Binding, Capability, ManifestSHA256                 string
	BrokerSHA256, ServiceSHA256                         string
	BrokerUID, ServiceUID                               int
	DatabaseDevice, DatabaseInode                       uint64
}

type OperationResult struct {
	Status     string `json:"status"`
	DriverCode int    `json:"driver_code,omitempty"`
}
type Result struct {
	Version        int             `json:"version"`
	Operation      OperationResult `json:"operation_result"`
	ContextStatus  string          `json:"context_status"`
	AdmissionValid bool            `json:"admission_valid"`
	SendAuthorized bool            `json:"send_authorized"`
}
type TransportResult struct {
	Bytes    int    `json:"bytes"`
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}
type Event struct {
	Kind      string           `json:"event"`
	Result    *Result          `json:"result,omitempty"`
	Transport *TransportResult `json:"transport,omitempty"`
}
type identity struct {
	OK                                                                   bool
	Challenge, Binding, ManifestSHA256                                   string
	PID, UID                                                             int
	StartTime, ExeSHA256, PIDNamespace, MountNamespace, NetworkNamespace string
	SocketInode                                                          string
}

func hashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}

// protectedPath rejects symlinks and writable ancestors. Only the final
// mutable directory/file may grant the distinct broker UID its required access.
func protectedPath(path string, directory bool, broker int, mutable bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrQualification
	}
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return ErrQualification
		}
		var stat unix.Stat_t
		if unix.Lstat(p, &stat) != nil || stat.Uid != 0 {
			return ErrQualification
		}
		leaf := p == path
		if !leaf || directory {
			if !st.IsDir() {
				return ErrQualification
			}
		} else if !st.Mode().IsRegular() {
			return ErrQualification
		}
		permitted := os.FileMode(0)
		if leaf && mutable && int(stat.Gid) == broker {
			permitted = 0020
		}
		if st.Mode().Perm()&(0022&^permitted) != 0 {
			return ErrQualification
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func protectedData(cfg Config) error {
	if protectedPath(filepath.Dir(cfg.Database), true, cfg.BrokerUID, true) != nil {
		return ErrQualification
	}
	// The data parent is the single deliberately broker-writable ancestor.
	st, e := os.Lstat(cfg.Database)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return ErrQualification
	}
	var s unix.Stat_t
	if unix.Lstat(cfg.Database, &s) != nil || s.Uid != 0 || int(s.Gid) != cfg.BrokerUID || s.Mode&0007 != 0 || uint64(s.Dev) != cfg.DatabaseDevice || s.Ino != cfg.DatabaseInode {
		return ErrQualification
	}
	if protectedPath(cfg.Journal, false, 0, false) != nil {
		return ErrQualification
	}
	h, e := hashFile(cfg.Journal)
	if e != nil || h != cfg.JournalSHA256 {
		return ErrQualification
	}
	return nil
}
func loadConfig(path string, broker bool) (Config, error) {
	var cfg Config
	if protectedPath(path, false, 0, false) != nil {
		return cfg, ErrQualification
	}
	f, e := os.Open(path)
	if e != nil {
		return cfg, ErrQualification
	}
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	f.Close()
	if e != nil || len(b) > 8192 || common.Unmarshal(b, &cfg) != nil {
		return cfg, ErrQualification
	}
	if cfg.Version != 1 || cfg.Actor <= 0 || cfg.BrokerUID <= 0 || cfg.ServiceUID <= 0 || cfg.BrokerUID == cfg.ServiceUID || !validHash(cfg.Capability) || !validHash(cfg.Binding) || !validHash(cfg.ManifestSHA256) || !validHash(cfg.BrokerSHA256) || !validHash(cfg.ServiceSHA256) || !validHash(cfg.JournalSHA256) {
		return cfg, ErrQualification
	}
	uid, want := cfg.ServiceUID, cfg.ServiceSHA256
	if broker {
		uid, want = cfg.BrokerUID, cfg.BrokerSHA256
	}
	var configStat unix.Stat_t
	if unix.Lstat(path, &configStat) != nil || int(configStat.Gid) != uid || configStat.Mode&0077 != 0040 {
		return cfg, ErrQualification
	}
	groups, e := os.Getgroups()
	nnp, ne := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if e != nil || ne != nil || os.Geteuid() != uid || os.Getuid() != uid || len(groups) != 0 || nnp != 1 {
		return cfg, ErrQualification
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000") || !strings.Contains(string(status), "CapPrm:\t0000000000000000") || !strings.Contains(string(status), "CapAmb:\t0000000000000000") {
		return cfg, ErrQualification
	}
	h, e := hashFile("/proc/self/exe")
	if e != nil || h != want {
		return cfg, ErrQualification
	}
	if protectedPath(filepath.Dir(cfg.Authority), true, 0, false) != nil || protectedPath(filepath.Dir(cfg.Socket), true, cfg.BrokerUID, true) != nil {
		return cfg, ErrQualification
	}
	if broker && protectedData(cfg) != nil {
		return cfg, ErrQualification
	}
	return cfg, nil
}
func peer(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return nil, e
	}
	var cred *unix.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil {
		return nil, e
	}
	return cred, inner
}
func socketPath(path string, uid int) (os.FileInfo, error) {
	st, e := os.Lstat(path)
	var s unix.Stat_t
	if e != nil || st.Mode()&os.ModeSocket == 0 || st.Mode()&os.ModeSymlink != 0 || unix.Lstat(path, &s) != nil || int(s.Uid) != uid {
		return nil, ErrQualification
	}
	return st, nil
}
func readFrame(conn *net.UnixConn, limit int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(conn, int64(limit+1)))
	if e != nil || len(b) > limit || len(b) == 0 {
		return nil, ErrProtocol
	}
	return b, nil
}
func qualify(cfg Config, role string) (identity, error) {
	var result identity
	before, e := socketPath(cfg.Authority, 0)
	if e != nil {
		return result, e
	}
	rawConn, e := (&net.Dialer{Timeout: writeTimeout}).Dial("unix", cfg.Authority)
	if e != nil {
		return result, ErrQualification
	}
	conn := rawConn.(*net.UnixConn)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(writeTimeout))
	cred, e := peer(conn)
	if e != nil || cred.Uid != 0 {
		return result, ErrQualification
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return result, ErrQualification
	}
	challenge := hex.EncodeToString(nonce)
	b, _ := common.Marshal(map[string]any{"version": 1, "role": role, "binding": cfg.Binding, "challenge": challenge})
	if _, e = conn.Write(b); e != nil {
		return result, ErrQualification
	}
	conn.CloseWrite()
	b, e = readFrame(conn, 4096)
	if e != nil || common.Unmarshal(b, &result) != nil {
		return result, ErrQualification
	}
	after, e := socketPath(cfg.Authority, 0)
	if e != nil || !os.SameFile(before, after) {
		return result, ErrQualification
	}
	uid, want := cfg.BrokerUID, cfg.BrokerSHA256
	if role == "service" {
		uid, want = cfg.ServiceUID, cfg.ServiceSHA256
	}
	if !result.OK || result.Challenge != challenge || result.Binding != cfg.Binding || result.ManifestSHA256 != cfg.ManifestSHA256 || result.PID <= 0 || result.UID != uid || result.StartTime == "" || result.ExeSHA256 != want {
		return result, ErrQualification
	}
	for key, want := range map[string]string{"pid": result.PIDNamespace, "mnt": result.MountNamespace, "net": result.NetworkNamespace} {
		got, e := os.Readlink("/proc/self/ns/" + key)
		if e != nil || got != want {
			return result, ErrQualification
		}
	}
	if role == "broker" && result.SocketInode == "" {
		return result, ErrQualification
	}
	return result, nil
}
func classify(err error) OperationResult {
	result := OperationResult{Status: "STORE_ERROR"}
	switch {
	case err == nil:
		result.Status = "ALLOWED"
	case errors.Is(err, context.Canceled):
		result.Status = "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		result.Status = "DEADLINE"
	case errors.Is(err, model.ErrOAuthTextCharge):
		result.Status = "CHARGE_UNRESOLVED"
	case errors.Is(err, model.ErrTaskObligationConflict):
		result.Status = "TASK_UNRESOLVED"
	case errors.Is(err, gorm.ErrRecordNotFound):
		result.Status = "NOT_FOUND"
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		result.DriverCode = coded.Code()
	}
	return result
}
func finalResult(ctx context.Context, err error) Result {
	result := Result{Version: 1, Operation: classify(err), ContextStatus: "ACTIVE"}
	if ctx.Err() != nil {
		result.ContextStatus = classify(ctx.Err()).Status
	} else if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		result.ContextStatus = "DEADLINE"
	}
	result.AdmissionValid = result.Operation.Status == "ALLOWED" && result.ContextStatus == "ACTIVE"
	return result
}
func emit(w io.Writer, event Event) {
	if w != nil {
		b, _ := common.Marshal(event)
		_, _ = w.Write(append(b, '\n'))
	}
}
func writeTerminal(conn net.Conn, payload []byte) TransportResult {
	result := TransportResult{}
	if e := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); e != nil {
		result.Error = "DEADLINE_SETUP"
		return result
	}
	// At most len(payload) writes, each advancing. All share the same deadline.
	for result.Bytes < len(payload) {
		n, e := conn.Write(payload[result.Bytes:])
		result.Bytes += n
		if e != nil {
			result.Error = "WRITE_ERROR"
			if os.IsTimeout(e) {
				result.Error = "WRITE_TIMEOUT"
			}
			return result
		}
		if n == 0 {
			result.Error = "SHORT_WRITE"
			return result
		}
	}
	result.Complete = true
	return result
}

// monitorSession owns only a duplicate of this accepted socket and its stop
// pipe. Half-close/EOF is framing, not cancellation. Stop joins before fd close.
func monitorSession(conn *net.UnixConn, cancel context.CancelFunc) (func(), error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return nil, e
	}
	fd := -1
	var dupErr error
	e = raw.Control(func(n uintptr) { fd, dupErr = unix.FcntlInt(n, unix.F_DUPFD_CLOEXEC, 0) })
	if e != nil || dupErr != nil {
		return nil, ErrQualification
	}
	r, w, e := os.Pipe()
	if e != nil {
		unix.Close(fd)
		return nil, e
	}
	done := make(chan struct{})
	var mu sync.Mutex
	stopped := false
	go func() {
		defer close(done)
		fds := []unix.PollFd{{Fd: int32(fd)}, {Fd: int32(r.Fd()), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(fds, -1)
			if err == unix.EINTR {
				continue
			}
			mu.Lock()
			if stopped {
				mu.Unlock()
				return
			}
			if err != nil || fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				cancel()
				mu.Unlock()
				return
			}
			mu.Unlock()
			if fds[1].Revents != 0 {
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			stopped = true
			mu.Unlock()
			w.Write([]byte{1})
			<-done
			r.Close()
			w.Close()
			unix.Close(fd)
		})
	}, nil
}

// A process owns one model.DB and one fixed actor. Restart requires a new
// trusted launch; a second Open must never retarget an existing server.
var opened atomic.Bool

type Server struct {
	cfg        Config
	listener   *net.UnixListener
	socketInfo os.FileInfo
	used       atomic.Bool
	audit      io.Writer
}

// Open initializes the real model and validates the permanent birth. InitDB can
// perform startup Option/schema work; only CheckUserBillingAdmission is a read.
func Open(configPath string, audit io.Writer) (server *Server, err error) {
	if !opened.CompareAndSwap(false, true) {
		return nil, ErrQualification
	}
	cfg, e := loadConfig(configPath, true)
	if e != nil {
		return nil, e
	}
	for _, key := range []string{"SQL_DSN", "LOG_SQL_DSN", "PGSERVICE", "PGSERVICEFILE"} {
		if os.Getenv(key) != "" {
			return nil, ErrQualification
		}
	}
	common.SQLitePath = cfg.Database
	common.IsMasterNode = false
	common.DebugEnabled = false
	common.RedisEnabled = false
	os.Setenv("OAUTH_BOOTSTRAP_JOURNAL", cfg.Journal)
	defer func() {
		if server == nil && model.DB != nil {
			if db, e := model.DB.DB(); e == nil {
				db.Close()
			}
		}
	}()
	if e = model.InitDB(); e != nil {
		return nil, ErrQualification
	}
	model.DB.Logger = logger.Default.LogMode(logger.Silent)
	if _, e = os.Lstat(cfg.Socket); !os.IsNotExist(e) {
		return nil, ErrQualification
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	if e != nil {
		return nil, ErrQualification
	}
	listener.SetUnlinkOnClose(false)
	st, e := os.Lstat(cfg.Socket)
	if e != nil {
		listener.Close()
		return nil, ErrQualification
	}
	if e = os.Chmod(cfg.Socket, 0666); e != nil {
		listener.Close()
		if current, e := os.Lstat(cfg.Socket); e == nil && os.SameFile(st, current) {
			os.Remove(cfg.Socket)
		}
		return nil, ErrQualification
	}
	own, e := qualify(cfg, "broker")
	if e != nil || own.PID != os.Getpid() {
		listener.Close()
		if current, e := os.Lstat(cfg.Socket); e == nil && os.SameFile(st, current) {
			os.Remove(cfg.Socket)
		}
		return nil, ErrQualification
	}
	return &Server{cfg: cfg, listener: listener, socketInfo: st, audit: audit}, nil
}
func (s *Server) handle(parent context.Context, conn *net.UnixConn) {
	defer conn.Close()
	rejected := Result{Version: 1, Operation: OperationResult{Status: "REJECTED"}, ContextStatus: "NOT_CALLED"}
	result := rejected
	defer func() {
		b, _ := common.Marshal(result)
		transport := writeTerminal(conn, append(b, '\n'))
		emit(s.audit, Event{Kind: "terminal", Result: &result, Transport: &transport})
	}()
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	cred, e := peer(conn)
	if e != nil || int(cred.Uid) != s.cfg.ServiceUID {
		return
	}
	frame, e := readFrame(conn, readLimit)
	if e != nil {
		return
	}
	if conn.SetDeadline(time.Time{}) != nil {
		return
	}
	fields, e := common.DecodeRawJSONObject(frame)
	if e != nil || len(fields) != 4 {
		return
	}
	var req struct {
		Version    int    `json:"version"`
		Operation  string `json:"operation"`
		Capability string `json:"capability"`
		Binding    string `json:"binding"`
	}
	if common.Unmarshal(frame, &req) != nil {
		return
	}
	for _, k := range []string{"version", "operation", "capability", "binding"} {
		if _, ok := fields[k]; !ok {
			return
		}
	}
	if req.Version != 1 || req.Operation != "CHECK" || req.Binding != s.cfg.Binding || subtle.ConstantTimeCompare([]byte(req.Capability), []byte(s.cfg.Capability)) != 1 {
		return
	}
	qualified, e := qualify(s.cfg, "service")
	if e != nil || qualified.PID != int(cred.Pid) || protectedData(s.cfg) != nil {
		return
	}
	// Qualify our own live listener too: a captured receipt is never sufficient.
	own, e := qualify(s.cfg, "broker")
	if e != nil || own.PID != os.Getpid() {
		return
	}
	if !s.used.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(parent, operationTimeout)
	defer cancel()
	stop, e := monitorSession(conn, cancel)
	if e != nil {
		return
	}
	emit(s.audit, Event{Kind: "model_enter"})
	err := model.CheckUserBillingAdmission(ctx, s.cfg.Actor)
	stop()
	result = finalResult(ctx, err)
	emit(s.audit, Event{Kind: "model_return", Result: &result})
	// Logging/transport may have delayed completion; never turn a late nil result
	// into valid admission. The original business context is never reset.
	result = finalResult(ctx, err)
}

// Serve returns ErrShutdown if cancellation cannot drain the actual operation.
// A process caller must exit nonzero on that error, never detach and report OK.
func (s *Server) Serve(ctx context.Context, ready io.Writer) error {
	if ready != nil {
		fmt.Fprintln(ready, "READY")
	}
	work := make(chan struct{})
	var serveErr error
	go func() {
		defer close(work)
		for {
			conn, e := s.listener.AcceptUnix()
			if e != nil {
				if ctx.Err() == nil {
					serveErr = ErrQualification
				}
				return
			}
			s.handle(ctx, conn)
		}
	}()
	select {
	case <-work:
	case <-ctx.Done():
		s.listener.Close()
		select {
		case <-work:
		case <-time.After(drainTimeout):
			return ErrShutdown
		}
	}
	s.listener.Close()
	if st, e := os.Lstat(s.cfg.Socket); e == nil && os.SameFile(st, s.socketInfo) {
		os.Remove(s.cfg.Socket)
	}
	if model.DB != nil {
		if db, e := model.DB.DB(); e == nil {
			db.Close()
		}
	}
	return serveErr
}

// Check does not fall back to SQL. It returns only a fixed-actor admission read,
// never a reservation, spend receipt or permission to send a request upstream.
func Check(ctx context.Context, configPath string) (Result, error) {
	var result Result
	cfg, e := loadConfig(configPath, false)
	if e != nil {
		return result, e
	}
	before, e := socketPath(cfg.Socket, cfg.BrokerUID)
	if e != nil {
		return result, e
	}
	qualified, e := qualify(cfg, "broker")
	if e != nil {
		return result, e
	}
	dialer := net.Dialer{Timeout: readTimeout}
	raw, e := dialer.DialContext(ctx, "unix", cfg.Socket)
	if e != nil {
		return result, ErrQualification
	}
	conn := raw.(*net.UnixConn)
	defer conn.Close()
	cred, e := peer(conn)
	if e != nil || int(cred.Uid) != cfg.BrokerUID || int(cred.Pid) != qualified.PID {
		return result, ErrQualification
	}
	current, e := qualify(cfg, "broker")
	current.Challenge = qualified.Challenge
	if e != nil || current != qualified {
		return result, ErrQualification
	}
	after, e := socketPath(cfg.Socket, cfg.BrokerUID)
	if e != nil || !os.SameFile(before, after) {
		return result, ErrQualification
	}
	deadline := time.Now().Add(readTimeout + operationTimeout + writeTimeout + drainTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	b, _ := common.Marshal(map[string]any{"version": 1, "operation": "CHECK", "capability": cfg.Capability, "binding": cfg.Binding})
	if _, e = conn.Write(b); e != nil {
		return result, ErrProtocol
	}
	if e = conn.CloseWrite(); e != nil {
		return result, ErrProtocol
	}
	b, e = readFrame(conn, 4096)
	if e != nil {
		return result, e
	}
	fields, e := common.DecodeRawJSONObject(b)
	if e != nil || len(fields) != 5 || common.Unmarshal(b, &result) != nil || result.Version != 1 || result.SendAuthorized {
		return Result{}, ErrProtocol
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	for _, key := range []string{"version", "operation_result", "context_status", "admission_valid", "send_authorized"} {
		if _, ok := fields[key]; !ok {
			return Result{}, ErrProtocol
		}
	}
	if result.AdmissionValid && (result.ContextStatus != "ACTIVE" || result.Operation.Status != "ALLOWED") {
		return Result{}, ErrProtocol
	}
	return result, nil
}
