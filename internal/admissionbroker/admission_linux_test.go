//go:build linux

package admissionbroker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"
)

type partialConn struct {
	net.Conn
	step int
	zero bool
}

func (c partialConn) Write(b []byte) (int, error) {
	if c.zero {
		return 0, nil
	}
	return c.Conn.Write(b[:min(c.step, len(b))])
}

func TestAdmissionUnit(t *testing.T) {
	t.Run("late_nil_is_not_admission", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := finalResult(ctx, nil)
		assert.Equal(t, "ALLOWED", r.Operation.Status)
		assert.Equal(t, "CANCELLED", r.ContextStatus)
		assert.False(t, r.AdmissionValid)
		assert.False(t, r.SendAuthorized)
	})
	t.Run("partial_write", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		got := make(chan []byte, 1)
		go func() {
			v := make([]byte, 7)
			_, e := io.ReadFull(b, v)
			if e != nil {
				got <- nil
			} else {
				got <- v
			}
		}()
		r := writeTerminal(partialConn{Conn: a, step: 2}, []byte("bounded"))
		assert.True(t, r.Complete)
		assert.Equal(t, 7, r.Bytes)
		assert.Equal(t, []byte("bounded"), <-got)
	})
	t.Run("slow_reader_bounded", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		r := writeTerminal(a, []byte("denied"))
		assert.False(t, r.Complete)
		assert.Equal(t, 0, r.Bytes)
		assert.Equal(t, "WRITE_TIMEOUT", r.Error)
	})
	t.Run("zero_progress_stops", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		r := writeTerminal(partialConn{Conn: a, zero: true}, []byte("denied"))
		assert.Equal(t, "SHORT_WRITE", r.Error)
		assert.Zero(t, r.Bytes)
	})
	t.Run("expired_read_does_not_expire_write", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		require.NoError(t, a.SetReadDeadline(time.Unix(1, 0)))
		got := make(chan error, 1)
		go func() { v := make([]byte, 1); _, e := io.ReadFull(b, v); got <- e }()
		r := writeTerminal(a, []byte{1})
		assert.True(t, r.Complete)
		require.NoError(t, <-got)
	})
	t.Run("session_halfclose_fullclose_and_join", func(t *testing.T) {
		fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		require.NoError(t, e)
		f1, f2 := os.NewFile(uintptr(fds[0]), "client"), os.NewFile(uintptr(fds[1]), "server")
		r1, e := net.FileConn(f1)
		require.NoError(t, e)
		require.NoError(t, f1.Close())
		r2, e := net.FileConn(f2)
		require.NoError(t, e)
		require.NoError(t, f2.Close())
		c, s := r1.(*net.UnixConn), r2.(*net.UnixConn)
		defer s.Close()
		defer c.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		beforeFDs, e := os.ReadDir("/proc/self/fd")
		require.NoError(t, e)
		stop, e := monitorSession(s, cancel)
		require.NoError(t, e)
		defer stop()
		require.NoError(t, c.CloseWrite())
		_, e = io.ReadAll(s)
		require.NoError(t, e)
		require.NoError(t, ctx.Err()) // EOF is a completed frame, not cancellation.
		require.NoError(t, c.Close())
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("HUP not observed")
		}
		stop()
		stop() // joined, owned descriptors closed, idempotent stop.
		afterFDs, e := os.ReadDir("/proc/self/fd")
		require.NoError(t, e)
		assert.Len(t, afterFDs, len(beforeFDs))
	})
	t.Run("duplicate_and_trailing_frame", func(t *testing.T) {
		for _, b := range []string{`{"version":1,"version":1}`, `{"version":1} {}`} {
			_, e := common.DecodeRawJSONObject([]byte(b))
			require.Error(t, e)
		}
	})
}

// This test-only control plane is authenticated by the root launcher against the
// frozen test executable and peer PID/UID. It accepts only fixed case/actions.
func fixtureRPC(t *testing.T, action string) []byte {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Getenv("ADMISSION_FIXTURE_SOCKET"), Net: "unix"})
	require.NoError(t, e)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(100*time.Second)))
	cred, e := peer(c)
	require.NoError(t, e)
	require.Zero(t, cred.Uid)
	_, e = c.Write([]byte(action + "\n"))
	require.NoError(t, e)
	require.NoError(t, c.CloseWrite())
	b, e := io.ReadAll(io.LimitReader(c, 8193))
	require.NoError(t, e)
	require.NotEmpty(t, b)
	require.LessOrEqual(t, len(b), 8192)
	return b
}

func rawRequest(t *testing.T, cfg Config, b []byte) (Result, error) {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	if e != nil {
		return Result{}, e
	}
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(12*time.Second)))
	_, e = c.Write(b)
	if e != nil {
		return Result{}, e
	}
	if e = c.CloseWrite(); e != nil {
		return Result{}, e
	}
	v, e := readFrame(c, 4096)
	if e != nil {
		return Result{}, e
	}
	var r Result
	e = common.Unmarshal(v, &r)
	return r, e
}

func TestAdmissionLive(t *testing.T) {
	if os.Getenv("ADMISSION_FIXTURE_SOCKET") == "" {
		t.Skip("explicit trusted admission resource tier not configured")
	}
	cases := []struct {
		name, status string
		code         int
	}{
		{"allowed", "ALLOWED", 0}, {"held", "CHARGE_UNRESOLVED", 0}, {"send_claimed", "CHARGE_UNRESOLVED", 0},
		{"task_held", "TASK_UNRESOLVED", 0}, {"task_send_claimed", "TASK_UNRESOLVED", 0}, {"notfound", "NOT_FOUND", 0},
		{"storeerror", "STORE_ERROR", 1}, {"deadline", "STORE_ERROR", 5}, {"inflight", "STORE_ERROR", 5},
		{"model_first", "ALLOWED", 0}, {"unrelated", "ALLOWED", 0}, {"shutdown", "DRAIN_TIMEOUT", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var born struct {
				Config    string
				BrokerPID int
			}
			require.NoError(t, common.Unmarshal(fixtureRPC(t, "new:"+tc.name), &born))
			cfg, e := loadConfig(born.Config, false)
			require.NoError(t, e)
			// The client never opens the database, its parent, journal, WAL, SHM or the
			// other UID's descriptors. These checks run as the actual no-sudo service.
			for _, p := range []string{cfg.Database, cfg.Database + "-wal", cfg.Database + "-shm", filepath.Dir(cfg.Database), cfg.Journal} {
				f, e := os.OpenFile(p, os.O_RDWR, 0)
				if f != nil {
					f.Close()
				}
				require.Error(t, e, "protected path unexpectedly opened")
			}
			for _, p := range []string{cfg.Database, cfg.Journal} {
				require.Error(t, os.Remove(p))
				require.Error(t, os.Rename(p, p+".replace"))
			}
			_, e = os.ReadDir(filepath.Dir(cfg.Database))
			require.Error(t, e)
			_, e = os.ReadDir("/proc/" + strconv.Itoa(born.BrokerPID) + "/fd")
			require.Error(t, e)
			if tc.name == "allowed" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_, e = Check(ctx, born.Config)
				require.Error(t, e)
				base := map[string]any{"version": 1, "operation": "CHECK", "capability": cfg.Capability, "binding": cfg.Binding}
				good, e := common.Marshal(base)
				require.NoError(t, e)
				badNonce := bytes.Replace(good, []byte(cfg.Capability), []byte(strings.Repeat("0", 64)), 1)
				invalid := [][]byte{badNonce, append(append([]byte{}, good...), []byte(" {}")...), []byte(`{"version":1,"version":1}`), bytes.Repeat([]byte("x"), 513)}
				for _, field := range []string{"actor", "path", "SQL", "amount", "seed"} {
					v := map[string]any{}
					for k, x := range base {
						v[k] = x
					}
					v[field] = "forbidden"
					b, e := common.Marshal(v)
					require.NoError(t, e)
					invalid = append(invalid, b)
				}
				for _, b := range invalid {
					r, e := rawRequest(t, cfg, b)
					if e == nil {
						require.Equal(t, "REJECTED", r.Operation.Status)
						require.False(t, r.AdmissionValid)
					}
				}
				// Kernel qualification failure must not fall back to local SQL.
				copyCfg := cfg
				copyCfg.Authority = filepath.Join(filepath.Dir(cfg.Authority), "missing")
				_, e = qualify(copyCfg, "broker")
				require.Error(t, e)
				copyCfg = cfg
				copyCfg.BrokerSHA256 = strings.Repeat("0", 64)
				_, e = qualify(copyCfg, "broker")
				require.Error(t, e)
			}
			var result Result
			if tc.name == "inflight" || tc.name == "model_first" || tc.name == "unrelated" || tc.name == "shutdown" {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				type answer struct {
					r Result
					e error
				}
				done := make(chan answer, 1)
				go func() { r, e := Check(ctx, born.Config); done <- answer{r, e} }()
				fixtureRPC(t, "entry:"+tc.name)
				if tc.name == "unrelated" {
					// A different connection's complete close has no authority over CHECK.
					c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
					require.NoError(t, e)
					require.NoError(t, c.Close())
					fixtureRPC(t, "release:"+tc.name)
					a := <-done
					require.NoError(t, a.e)
					result = a.r
				} else {
					cancel()
					a := <-done
					require.Error(t, a.e)
					if tc.name == "model_first" {
						fixtureRPC(t, "release:"+tc.name)
					}
				}
			} else {
				result, e = Check(context.Background(), born.Config)
				require.NoError(t, e)
			}
			if tc.name != "inflight" && tc.name != "model_first" && tc.name != "shutdown" {
				assert.Equal(t, tc.status, result.Operation.Status)
				assert.Equal(t, tc.code, result.Operation.DriverCode)
				assert.Equal(t, tc.status == "ALLOWED", result.AdmissionValid)
				assert.False(t, result.SendAuthorized)
				if tc.name == "deadline" {
					assert.Equal(t, "DEADLINE", result.ContextStatus)
				}
			}
			if tc.name == "shutdown" {
				var terminal struct {
					Exit, Calls           int
					Unchanged, NoTerminal bool
				}
				require.NoError(t, common.Unmarshal(fixtureRPC(t, "finish:"+tc.name), &terminal))
				assert.Equal(t, 1, terminal.Exit)
				assert.Equal(t, 1, terminal.Calls)
				assert.True(t, terminal.Unchanged)
				assert.True(t, terminal.NoTerminal)
				return
			}
			// The first call has finished before the replay is attempted, including the
			// SQLite busy-handler's delayed return after a peer disconnect.
			var observed struct {
				Operation OperationResult
				Context   string
				Calls     int
				Unchanged bool
			}
			require.NoError(t, common.Unmarshal(fixtureRPC(t, "result:"+tc.name), &observed))
			assert.Equal(t, tc.status, observed.Operation.Status)
			assert.Equal(t, tc.code, observed.Operation.DriverCode)
			assert.Equal(t, 1, observed.Calls)
			assert.True(t, observed.Unchanged)
			if tc.name == "inflight" {
				assert.Equal(t, "CANCELLED", observed.Context)
			}
			replay, e := Check(context.Background(), born.Config)
			require.NoError(t, e)
			assert.Equal(t, "REJECTED", replay.Operation.Status)
			assert.False(t, replay.AdmissionValid)
			fixtureRPC(t, "finish:"+tc.name)
		})
	}
}

// Root launches the same frozen test executable as a distinct broker UID only
// for deterministic lifecycle barriers. No test mode exists in the command or
// component. The service cannot write or obtain these inherited private pipes.
type workerAudit struct {
	events, ack *os.File
	caseName    string
	mu          sync.Mutex
}

func (w *workerAudit) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, e := os.Stderr.Write(b)
	if e != nil {
		return n, e
	}
	var v Event
	if common.Unmarshal(bytes.TrimSpace(b), &v) == nil {
		if v.Kind == "model_return" && w.caseName == "model_first" {
			fmt.Fprintln(w.events, "MODEL_DONE")
			var one [1]byte
			_, e = io.ReadFull(w.ack, one[:])
		}
		if v.Kind == "terminal" {
			fmt.Fprintln(w.events, "TERMINAL")
		}
	}
	return n, e
}
func TestAdmissionWorker(t *testing.T) {
	path := os.Getenv("ADMISSION_WORKER_CONFIG")
	if path == "" {
		t.Skip("trusted broker worker only")
	}
	eventFD, e := strconv.Atoi(os.Getenv("ADMISSION_EVENT_FD"))
	require.NoError(t, e)
	ackFD, e := strconv.Atoi(os.Getenv("ADMISSION_ACK_FD"))
	require.NoError(t, e)
	events := os.NewFile(uintptr(eventFD), "root-event")
	ack := os.NewFile(uintptr(ackFD), "root-ack")
	defer events.Close()
	defer ack.Close()
	kind := os.Getenv("ADMISSION_WORKER_CASE")
	audit := &workerAudit{events: events, ack: ack, caseName: kind}
	s, e := Open(path, audit)
	require.NoError(t, e)
	var engineVersion string
	require.NoError(t, model.DB.Raw("SELECT sqlite_version()").Scan(&engineVersion).Error)
	fmt.Fprintln(os.Stderr, "ADMISSION_SQLITE_VERSION", engineVersion)
	var once sync.Once
	if kind == "inflight" || kind == "unrelated" || kind == "shutdown" {
		require.NoError(t, model.DB.Callback().Update().Before("gorm:update").Register("admission_test_barrier", func(tx *gorm.DB) {
			once.Do(func() {
				fmt.Fprintln(events, "SQL_ENTRY")
				if kind == "unrelated" || kind == "shutdown" {
					var b [1]byte
					if _, e := io.ReadFull(ack, b[:]); e != nil {
						tx.AddError(e)
					}
				}
			})
		}))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	e = s.Serve(ctx, os.Stdout)
	if kind == "shutdown" && errors.Is(e, ErrShutdown) {
		fmt.Fprintln(os.Stderr, "ADMISSION_SHUTDOWN_TIMEOUT")
		os.Exit(1) // Same fail-closed process policy as the standalone command.
	}
	require.NoError(t, e)
}
