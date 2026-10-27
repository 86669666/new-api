//go:build linux

package model

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func oauthProtectedPath(path string, service bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errOAuthBootstrap
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return errOAuthBootstrap
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return errOAuthBootstrap
		}
		if service && os.Geteuid() == 0 {
			var fs syscall.Statfs_t
			if syscall.Statfs(p, &fs) != nil || fs.Flags&1 == 0 {
				return errOAuthBootstrap
			}
		}
		if p == "/" {
			break
		}
	}
	return nil
}

func readOAuthBirthJournal(path string, service bool) (*oauthBirthJournal, error) {
	if oauthProtectedPath(path, service) != nil {
		return nil, errOAuthBootstrap
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errOAuthBootstrap
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16384 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, errOAuthBootstrap
	}
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(b) > 16384 {
		return nil, errOAuthBootstrap
	}
	var j oauthBirthJournal
	if common.Unmarshal(b, &j) != nil || j.Version != 1 || j.Kind != "fresh" || j.InstallerUID != 0 || j.Contract != oauthBootstrapContract || !oauthDerivedDigest(j.CreationNonce) || !oauthDerivedDigest(j.OperationID) || j.IntentAt <= 0 {
		return nil, errOAuthBootstrap
	}
	digest, e := oauthBirthSchemaDigest()
	if e != nil || j.SchemaDigest != digest || !oauthDerivedDigest(j.Producer) {
		return nil, errOAuthBootstrap
	}
	return &j, nil
}

func oauthSQLiteBinding(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errOAuthBootstrap
	}
	// The DB's parent may grant service write access for WAL; its ancestors must
	// not allow replacing the namespace directory. Journal stays in a separate root.
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return "", errOAuthBootstrap
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return "", errOAuthBootstrap
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok || v.Nlink != 1 {
		return "", errOAuthBootstrap
	}
	return oauthBirthDigest(struct {
		Path          string
		Device, Inode uint64
	}{path, uint64(v.Dev), v.Ino})
}

func oauthSocketEndpoint(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errOAuthBootstrap
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return "", errOAuthBootstrap
	}
	for p := filepath.Dir(path); p != "/"; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return "", errOAuthBootstrap
		}
		// A database daemon may own its socket directory; the service must not.
		if os.Geteuid() != 0 && st.Sys().(*syscall.Stat_t).Uid == uint32(os.Geteuid()) {
			return "", errOAuthBootstrap
		}
	}
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return "", errOAuthBootstrap
	}
	defer conn.Close()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return "", errOAuthBootstrap
	}
	var cred *syscall.Ucred
	var e error
	if raw.Control(func(fd uintptr) { cred, e = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) }) != nil || e != nil || cred == nil {
		return "", errOAuthBootstrap
	}
	st, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return "", errOAuthBootstrap
	}
	v := st.Sys().(*syscall.Stat_t)
	return oauthBirthDigest(struct {
		Path          string
		PeerUID       uint32
		Device, Inode uint64
	}{path, cred.Uid, uint64(v.Dev), v.Ino})
}

func oauthBootstrap(ctx context.Context, mode, engine, target, journal string, out io.Writer) error {
	if os.Getenv("NEWAPI_BOOTSTRAP_BROKER") != "" {
		return oauthBootstrapThroughBroker(mode, engine, target, out)
	}
	if os.Geteuid() != 0 || oauthProtectedPath(filepath.Dir(journal), false) != nil {
		return errOAuthBootstrap
	}
	if engine != "sqlite" && !bootstrapName.MatchString(target) {
		return errOAuthBootstrap
	}
	lock, err := os.OpenFile(journal+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errOAuthBootstrap
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errOAuthBootstrap
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	var j *oauthBirthJournal
	if mode == "fresh" {
		if _, err = os.Lstat(journal); !os.IsNotExist(err) {
			return errOAuthBootstrap
		}
		nonce := make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			return errOAuthBootstrap
		}
		op := make([]byte, 32)
		if _, err = rand.Read(op); err != nil {
			return errOAuthBootstrap
		}
		j = &oauthBirthJournal{Version: 1, Kind: "fresh", OperationID: hex.EncodeToString(op), CreationNonce: hex.EncodeToString(nonce), Engine: engine, Target: target, Contract: oauthBootstrapContract, Producer: common.Version, Phase: "INTENT", IntentAt: time.Now().Unix()}
		j.SchemaDigest, err = oauthBirthSchemaDigest()
		if err != nil {
			return errOAuthBootstrap
		}
		exe, e := os.Executable()
		if e != nil {
			return errOAuthBootstrap
		}
		ef, e := os.Open(exe)
		if e != nil {
			return errOAuthBootstrap
		}
		h := sha256.New()
		_, e = io.Copy(h, ef)
		ef.Close()
		if e != nil {
			return errOAuthBootstrap
		}
		j.Producer = hex.EncodeToString(h.Sum(nil))
	} else {
		j, err = readOAuthBirthJournal(journal, false)
		if err != nil || j.Engine != engine || j.Target != target || j.Phase == "INTENT" {
			return errOAuthBootstrap
		}
	}
	var db *gorm.DB
	var maintenance *sql.DB
	var session *sql.Conn
	var heldFile *os.File
	if engine == "sqlite" {
		if !filepath.IsAbs(target) || filepath.Clean(target) != target || (mode == "fresh" && oauthProtectedPath(filepath.Dir(target), false) != nil) {
			return errOAuthBootstrap
		}
		if mode == "fresh" {
			for _, p := range []string{target, target + "-wal", target + "-shm"} {
				if _, e := os.Lstat(p); !os.IsNotExist(e) {
					return errOAuthBootstrap
				}
			}
			if writeOAuthBirthJournal(journal, j) != nil {
				return errOAuthBootstrap
			}
			heldFile, err = os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
			if err != nil {
				return errOAuthBootstrap
			}
			defer heldFile.Close()
			if heldFile.Sync() != nil {
				return errOAuthBootstrap
			}
			// Preserve an acknowledged exclusive CREATE before DB-open/marker work.
			j.Binding, err = oauthSQLiteBinding(target)
			if err != nil {
				return errOAuthBootstrap
			}
			j.CreatedAt = time.Now().Unix()
		} else {
			if binding, e := oauthSQLiteBinding(target); e != nil || binding != j.Binding {
				return errOAuthBootstrap
			}
		}
		db, err = openOAuthBootstrapDB(engine, target)
	} else {
		admin := os.Getenv("BOOTSTRAP_ADMIN_DSN")
		maintenanceName := ""
		if engine == "postgres" {
			maintenanceName = "postgres"
		}
		dsn, endpoint, e := oauthBootstrapDSN(engine, admin, maintenanceName)
		if e != nil {
			return e
		}
		if mode == "fresh" {
			j.Endpoint = endpoint
		} else if j.Endpoint != endpoint {
			return errOAuthBootstrap
		}
		m, e := openOAuthBootstrapDB(engine, dsn)
		if e != nil {
			return errOAuthBootstrap
		}
		maintenance, e = m.DB()
		if e != nil {
			return errOAuthBootstrap
		}
		defer maintenance.Close()
		session, e = maintenance.Conn(ctx)
		if e != nil {
			return errOAuthBootstrap
		}
		defer session.Close()
		if engine == "mysql" {
			var acquired int
			if session.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", "newapi.birth."+target).Scan(&acquired) != nil || acquired != 1 {
				return errOAuthBootstrap
			}
			defer session.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", "newapi.birth."+target)
		} else {
			var superuser bool
			if session.QueryRowContext(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname=current_user").Scan(&superuser) != nil || !superuser {
				return errOAuthBootstrap
			}
			var acquired bool
			if session.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtext($1))", "newapi.birth."+target).Scan(&acquired) != nil || !acquired {
				return errOAuthBootstrap
			}
			defer session.ExecContext(ctx, "SELECT pg_advisory_unlock(hashtext($1))", "newapi.birth."+target)
		}
		if mode == "fresh" {
			if writeOAuthBirthJournal(journal, j) != nil {
				return errOAuthBootstrap
			}
			statement := "CREATE DATABASE `" + target + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
			if engine == "postgres" {
				statement = "CREATE DATABASE \"" + target + "\" CONNECTION LIMIT 0"
			}
			if _, e = session.ExecContext(ctx, statement); e != nil {
				return errOAuthBootstrap
			}
			if engine == "postgres" {
				if _, e = session.ExecContext(ctx, "REVOKE CONNECT ON DATABASE \""+target+"\" FROM PUBLIC"); e != nil {
					return errOAuthBootstrap
				}
			}
			j.CreatedAt = time.Now().Unix()
		}
		dsn, _, e = oauthBootstrapDSN(engine, admin, target)
		if e != nil {
			return e
		}
		db, err = openOAuthBootstrapDB(engine, dsn)
	}
	if err != nil {
		return errOAuthBootstrap
	}
	sqlDB, err := db.DB()
	if err != nil {
		return errOAuthBootstrap
	}
	defer sqlDB.Close()
	if mode == "fresh" {
		if engine != "sqlite" {
			j.Binding, err = oauthLiveBinding(db, j)
			if err != nil {
				return errOAuthBootstrap
			}
		}
		if db.AutoMigrate(&OAuthDerivedTokenBootstrapIdentity{}) != nil {
			return errOAuthBootstrap
		}
		marker := oauthBirthMarker(j)
		if db.Create(&marker).Error != nil || validateOAuthBirth(db, j, false) != nil {
			return errOAuthBootstrap
		}
		j.Phase = "CREATED_BOUND"
		if writeOAuthBirthJournal(journal, j) != nil {
			return errOAuthBootstrap
		}
	}
	return completeOAuthBirth(db, j, engine, func(j *oauthBirthJournal) error { return writeOAuthBirthJournal(journal, j) }, out)
}

// Both privilege modes use the same migration and seal validation.
func completeOAuthBirth(db *gorm.DB, j *oauthBirthJournal, engine string, persist func(*oauthBirthJournal) error, out io.Writer) error {
	var err error
	if validateOAuthBirth(db, j, false) != nil {
		return errOAuthBootstrap
	}
	if j.Phase == "READY" {
		return validateOAuthBirth(db, j, true)
	}
	if j.Phase != "CREATED_BOUND" && j.Phase != "MIGRATING" && j.Phase != "SEAL_PENDING" {
		return errOAuthBootstrap
	}
	// Check pre-existing business rows before and after resumable formal DDL.
	for _, table := range []string{"tokens", "oauth_derived_token_sources"} {
		if db.Migrator().HasTable(table) {
			var n int64
			if db.Table(table).Count(&n).Error != nil || n != 0 {
				return errOAuthBootstrap
			}
		}
	}
	if j.Phase != "SEAL_PENDING" {
		if db.Migrator().HasTable(&OAuthDerivedTokenHistory{}) {
			var n int64
			if db.Model(&OAuthDerivedTokenHistory{}).Count(&n).Error != nil || n != 0 {
				return errOAuthBootstrap
			}
		}
		j.Phase = "MIGRATING"
		if persist(j) != nil {
			return errOAuthBootstrap
		}
		oldDB := DB
		oldMain, oldLog := common.MainDatabaseType(), common.LogDatabaseType()
		DB = db
		common.SetDatabaseTypes(common.DatabaseType(engine), common.DatabaseType(engine))
		initCol()
		err = migrateDB()
		DB = oldDB
		common.SetDatabaseTypes(oldMain, oldLog)
		initCol()
		if err != nil {
			return errOAuthBootstrap
		}
		// Validate physical source/history schema without inventing a history row.
		if validateOAuthDerivedTokenSchema(db) != nil {
			return errOAuthBootstrap
		}
		for _, table := range []string{"tokens", "oauth_derived_token_sources"} {
			var n int64
			if db.Table(table).Count(&n).Error != nil || n != 0 {
				return errOAuthBootstrap
			}
		}
		j.SealedAt = time.Now().Unix()
		j.HistorySeal, err = j.seal()
		if err != nil {
			return errOAuthBootstrap
		}
		j.Phase = "SEAL_PENDING"
		if persist(j) != nil {
			return errOAuthBootstrap
		}
	}
	if validateOAuthDerivedTokenSchema(db) != nil {
		return errOAuthBootstrap
	}
	expected := OAuthDerivedTokenHistory{ID: 1, SchemaVersion: 1, HistorySeal: j.HistorySeal, SealedAt: j.SealedAt}
	seal, err := j.seal()
	if err != nil || seal != j.HistorySeal {
		return errOAuthBootstrap
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if validateOAuthBirth(tx, j, false) != nil {
			return errOAuthBootstrap
		}
		var rows []OAuthDerivedTokenHistory
		if tx.Limit(2).Find(&rows).Error != nil {
			return errOAuthBootstrap
		}
		if len(rows) == 1 && rows[0] == expected {
			return nil
		}
		if len(rows) != 0 {
			return errOAuthBootstrap
		}
		return tx.Create(&expected).Error
	})
	// Do not infer failure from a lost acknowledgement. Re-read exactly the same
	// identity and expected seal; mismatch remains pending, with no drop/upsert.
	j.Phase = "READY"
	if validateOAuthBirth(db, j, true) != nil {
		return errOAuthBootstrap
	}
	if persist(j) != nil {
		return errOAuthBootstrap
	}
	fmt.Fprintln(out, j.OperationID, "READY")
	return nil
}

// oauthBirthBrokerClient is the unprivileged side of the named birth protocol.
// Selection requires an explicit broker socket and kernel-authenticated root peer.
// The legacy root-only path is unchanged when no broker is configured.
type oauthBirthBrokerClient struct {
	conn     net.Conn
	reader   *bufio.Reader
	sequence int
	target   string
	schema   string
	producer string
	previous *oauthBirthJournal
}

func dialOAuthBirthBroker(path, target, schema, producer string) (*oauthBirthBrokerClient, error) {
	if os.Geteuid() != 997 || os.Getegid() != 990 || oauthProtectedPath(filepath.Dir(path), false) != nil {
		return nil, errOAuthBootstrap
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 || !oauthDerivedDigest(schema) || !oauthDerivedDigest(producer) {
		return nil, errOAuthBootstrap
	}
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, errOAuthBootstrap
	}
	raw, err := conn.(*net.UnixConn).SyscallConn()
	var peer *syscall.Ucred
	var peerErr error
	if err == nil {
		err = raw.Control(func(fd uintptr) {
			peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
	}
	if err != nil || peerErr != nil || peer == nil || peer.Uid != 0 {
		conn.Close()
		return nil, errOAuthBootstrap
	}
	return &oauthBirthBrokerClient{conn: conn, reader: bufio.NewReaderSize(conn, 16385), target: target, schema: schema, producer: producer}, nil
}

func (c *oauthBirthBrokerClient) request(operation string) (result *oauthBirthJournal, err error) {
	defer func() {
		if err != nil {
			c.conn.Close()
		}
	}()
	switch operation {
	case "fresh", "resume", "created", "bound", "migrating", "seal_pending", "ready", "fault_pending", "fault_intent", "fault_restore":
	default:
		return nil, errOAuthBootstrap
	}
	if c.conn.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return nil, errOAuthBootstrap
	}
	message, err := common.Marshal(struct {
		Sequence  int    `json:"sequence"`
		Operation string `json:"operation"`
	}{c.sequence, operation})
	if err != nil {
		return nil, errOAuthBootstrap
	}
	message = append(message, '\n')
	if n, e := c.conn.Write(message); e != nil || n != len(message) {
		return nil, errOAuthBootstrap
	}
	line, err := c.reader.ReadSlice('\n')
	if err != nil || len(line) > 16384 {
		return nil, errOAuthBootstrap
	}
	var reply struct {
		Sequence int               `json:"sequence"`
		Journal  oauthBirthJournal `json:"journal"`
	}
	if common.Unmarshal(line, &reply) != nil || reply.Sequence != c.sequence {
		return nil, errOAuthBootstrap
	}
	j := reply.Journal
	if j.Engine != "sqlite" && j.Engine != "postgres" && j.Engine != "mysql" {
		return nil, errOAuthBootstrap
	}
	phase := map[string]string{"created": "INTENT", "bound": "CREATED_BOUND", "migrating": "MIGRATING", "seal_pending": "SEAL_PENDING", "ready": "READY", "fault_pending": "SEAL_PENDING", "fault_intent": "INTENT", "fault_restore": "READY"}[operation]
	if operation == "fresh" {
		phase = "INTENT"
	}
	if operation == "resume" {
		switch j.Phase {
		case "CREATED_BOUND", "MIGRATING", "SEAL_PENDING", "READY":
			phase = j.Phase
		}
	}
	if j.Phase != phase {
		return nil, errOAuthBootstrap
	}
	if j.Version != 1 || j.Kind != "fresh" || j.InstallerUID != 0 || j.Contract != oauthBootstrapContract ||
		j.Target != c.target || j.SchemaDigest != c.schema || j.Producer != c.producer ||
		!oauthDerivedDigest(j.OperationID) || !oauthDerivedDigest(j.CreationNonce) ||
		!oauthDerivedDigest(j.Binding) || j.IntentAt <= 0 || j.CreatedAt < j.IntentAt {
		return nil, errOAuthBootstrap
	}
	if old := c.previous; old != nil && (j.OperationID != old.OperationID || j.CreationNonce != old.CreationNonce ||
		j.Engine != old.Engine || j.Endpoint != old.Endpoint || j.Binding != old.Binding || j.CreatedAt != old.CreatedAt || j.IntentAt != old.IntentAt) {
		return nil, errOAuthBootstrap
	}
	if j.Phase == "SEAL_PENDING" || j.Phase == "READY" {
		seal, e := j.seal()
		if e != nil || seal != j.HistorySeal || j.SealedAt < j.CreatedAt {
			return nil, errOAuthBootstrap
		}
	}
	c.sequence++
	snapshot := j
	c.previous = &snapshot
	return &j, nil
}

func oauthBootstrapThroughBroker(mode, engine, target string, out io.Writer) error {
	if engine != "sqlite" && !bootstrapName.MatchString(target) {
		return errOAuthBootstrap
	}
	schema, err := oauthBirthSchemaDigest()
	if err != nil {
		return errOAuthBootstrap
	}
	executable, err := os.Executable()
	if err != nil {
		return errOAuthBootstrap
	}
	file, err := os.Open(executable)
	if err != nil {
		return errOAuthBootstrap
	}
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	file.Close()
	if err != nil {
		return errOAuthBootstrap
	}
	client, err := dialOAuthBirthBroker(os.Getenv("NEWAPI_BOOTSTRAP_BROKER"), target, schema, hex.EncodeToString(hash.Sum(nil)))
	if err != nil {
		return errOAuthBootstrap
	}
	defer client.conn.Close()
	j, err := client.request(mode)
	if err != nil || j.Engine != engine {
		return errOAuthBootstrap
	}
	dsn := target
	if engine != "sqlite" {
		var endpoint string
		dsn, endpoint, err = oauthBootstrapDSN(engine, os.Getenv("BOOTSTRAP_OWNED_DSN"), target)
		if err != nil || endpoint != j.Endpoint {
			return errOAuthBootstrap
		}
	}
	db, err := openOAuthBootstrapDB(engine, dsn)
	if err != nil {
		return errOAuthBootstrap
	}
	connection, err := db.DB()
	if err != nil {
		return errOAuthBootstrap
	}
	defer connection.Close()
	persist := func(j *oauthBirthJournal) error {
		operation := map[string]string{"CREATED_BOUND": "bound", "MIGRATING": "migrating", "SEAL_PENDING": "seal_pending", "READY": "ready"}[j.Phase]
		if operation == "" {
			return errOAuthBootstrap
		}
		observed, e := client.request(operation)
		if e != nil {
			return e
		}
		*j = *observed
		return nil
	}
	if mode == "fresh" {
		binding, e := oauthLiveBinding(db, j)
		if e != nil || binding != j.Binding || db.AutoMigrate(&OAuthDerivedTokenBootstrapIdentity{}) != nil {
			return errOAuthBootstrap
		}
		marker := oauthBirthMarker(j)
		if db.Create(&marker).Error != nil || validateOAuthBirth(db, j, false) != nil {
			return errOAuthBootstrap
		}
		j.Phase = "CREATED_BOUND"
		if persist(j) != nil {
			return errOAuthBootstrap
		}
	}
	return completeOAuthBirth(db, j, engine, persist, out)
}
