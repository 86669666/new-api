package model

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	mysqlclient "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// The journal is a provisioning authority, not application-owned configuration.
// This protocol supports protected local SQLite files and local Unix DB sockets.
// Network endpoints, existing namespaces and restore/adoption are not supported.
const oauthBootstrapContract = "newapi.oauth.birth.v1/source-history-identity-v1"

var errOAuthBootstrap = errors.New("database bootstrap identity unavailable or conflicting")
var bootstrapName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

type OAuthDerivedTokenBootstrapIdentity struct {
	ID                   int    `gorm:"primaryKey;autoIncrement:false"`
	Version              int    `gorm:"not null"`
	Kind                 string `gorm:"type:varchar(16);not null"`
	CreationNonce        string `gorm:"type:char(64);not null"`
	NamespaceBindingHash string `gorm:"type:char(64);not null"`
	CreatedAt            int64  `gorm:"not null"`
}

func (OAuthDerivedTokenBootstrapIdentity) TableName() string {
	return "oauth_derived_token_bootstrap_identity"
}

type oauthBirthJournal struct {
	Version       int    `json:"version"`
	Kind          string `json:"kind"`
	OperationID   string `json:"operation_id"`
	CreationNonce string `json:"creation_nonce"`
	InstallerUID  uint32 `json:"installer_uid"`
	Engine        string `json:"engine"`
	Target        string `json:"target"`
	Endpoint      string `json:"endpoint"`
	Binding       string `json:"binding"`
	Contract      string `json:"contract"`
	SchemaDigest  string `json:"schema_digest"`
	Producer      string `json:"producer"`
	Phase         string `json:"phase"`
	IntentAt      int64  `json:"intent_at"`
	CreatedAt     int64  `json:"created_at"`
	SealedAt      int64  `json:"sealed_at"`
	HistorySeal   string `json:"history_seal"`
}

func oauthBirthDigest(value any) (string, error) {
	b, err := common.Marshal(value)
	if err != nil {
		return "", errOAuthBootstrap
	}
	h := sha256.Sum256(append([]byte("newapi.oauth.birth.commitment.v1\x00"), b...))
	return hex.EncodeToString(h[:]), nil
}

func oauthBirthSchemaDigest() (string, error) {
	var fields []string
	for _, value := range []any{&OAuthDerivedTokenSource{}, &OAuthDerivedTokenHistory{}, &OAuthDerivedTokenBootstrapIdentity{}} {
		parsed, err := schema.Parse(value, &sync.Map{}, schema.NamingStrategy{})
		if err != nil {
			return "", errOAuthBootstrap
		}
		for _, f := range parsed.Fields {
			fields = append(fields, fmt.Sprint(parsed.Table, "/", f.DBName, "/", f.FieldType.String(), "/", f.Tag.Get("gorm")))
		}
	}
	return oauthBirthDigest(fields)
}

func (j oauthBirthJournal) seal() (string, error) {
	j.Phase = "SEAL_PENDING"
	j.HistorySeal = ""
	return oauthBirthDigest(j)
}

// Reject symlinks in every existing component and writable ancestors. Root is
// the provisioning principal; the service must have a different UID, or a
// read-only mount. Merely chmod'ing a same-UID file is not a trust boundary.
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

func writeOAuthBirthJournal(path string, j *oauthBirthJournal) error {
	if os.Geteuid() != 0 || oauthProtectedPath(filepath.Dir(path), false) != nil {
		return errOAuthBootstrap
	}
	b, err := common.Marshal(j)
	if err != nil || len(b) > 16384 {
		return errOAuthBootstrap
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".birth-")
	if err != nil {
		return errOAuthBootstrap
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errOAuthBootstrap
	}
	if err = os.Rename(temp, path); err != nil {
		return errOAuthBootstrap
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errOAuthBootstrap
	}
	defer d.Close()
	if d.Sync() != nil {
		return errOAuthBootstrap
	}
	return nil
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

// Endpoint identity is the protected Unix socket namespace and peer UID. No
// DSN (or hash of a DSN containing credentials) is persisted as DB identity.
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

func oauthBootstrapDSN(engine, dsn, target string) (string, string, error) {
	switch engine {
	case "mysql":
		c, e := mysqlclient.ParseDSN(dsn)
		if e != nil || c.Net != "unix" {
			return "", "", errOAuthBootstrap
		}
		endpoint, e := oauthSocketEndpoint(c.Addr)
		if e != nil {
			return "", "", e
		}
		c.DBName = target
		c.ParseTime = true
		return c.FormatDSN(), endpoint, nil
	case "postgres":
		u, e := url.Parse(dsn)
		if e != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" {
			return "", "", errOAuthBootstrap
		}
		q := u.Query()
		host := q.Get("host")
		port := q.Get("port")
		if port == "" {
			port = "5432"
		}
		if _, e = strconv.ParseUint(port, 10, 16); e != nil {
			return "", "", errOAuthBootstrap
		}
		if !filepath.IsAbs(host) || u.Host != "" {
			return "", "", errOAuthBootstrap
		}
		endpoint, e := oauthSocketEndpoint(filepath.Join(host, ".s.PGSQL."+port))
		if e != nil {
			return "", "", e
		}
		u.Path = "/" + target
		return u.String(), endpoint, nil
	}
	return "", "", errOAuthBootstrap
}

type oauthBootstrapLogger struct{ logger.Interface }

func (l oauthBootstrapLogger) LogMode(logger.LogLevel) logger.Interface { return l }

func openOAuthBootstrapDB(engine, dsn string) (*gorm.DB, error) {
	cfg := &gorm.Config{Logger: oauthBootstrapLogger{logger.Default.LogMode(logger.Silent)}}
	switch engine {
	case "sqlite":
		return gorm.Open(sqlite.Open(dsn), cfg)
	case "mysql":
		return gorm.Open(mysqlMigrationDialector{mysql.Dialector{Config: &mysql.Config{DSN: dsn}}}, cfg)
	case "postgres":
		return gorm.Open(postgresMigrationDialector{postgres.Dialector{Config: &postgres.Config{DSN: dsn, PreferSimpleProtocol: true}}}, cfg)
	}
	return nil, errOAuthBootstrap
}

func oauthLiveBinding(db *gorm.DB, j *oauthBirthJournal) (string, error) {
	switch j.Engine {
	case "sqlite":
		var files []struct{ Name, File string }
		if db.Raw("PRAGMA database_list").Scan(&files).Error != nil {
			return "", errOAuthBootstrap
		}
		for _, f := range files {
			if f.Name == "main" && f.File == j.Target {
				return oauthSQLiteBinding(f.File)
			}
		}
	case "mysql":
		var row struct{ Name, Server string }
		if db.Raw("SELECT DATABASE() AS name, @@server_uuid AS server").Scan(&row).Error != nil || row.Name != j.Target || row.Server == "" {
			return "", errOAuthBootstrap
		}
		return oauthBirthDigest(struct{ Endpoint, Database, Server string }{j.Endpoint, row.Name, row.Server})
	case "postgres":
		var row struct {
			Name   string
			OID    int64 `gorm:"column:oid"`
			Schema string
		}
		if db.Raw("SELECT current_database() AS name, oid, current_schema() AS schema FROM pg_database WHERE datname = current_database()").Scan(&row).Error != nil || row.Name != j.Target || row.OID <= 0 || row.Schema != "public" {
			return "", errOAuthBootstrap
		}
		return oauthBirthDigest(struct {
			Endpoint, Database, Schema string
			OID                        int64
		}{j.Endpoint, row.Name, row.Schema, row.OID})
	}
	return "", errOAuthBootstrap
}

func oauthBirthMarker(j *oauthBirthJournal) OAuthDerivedTokenBootstrapIdentity {
	return OAuthDerivedTokenBootstrapIdentity{ID: 1, Version: 1, Kind: "fresh", CreationNonce: j.CreationNonce, NamespaceBindingHash: j.Binding, CreatedAt: j.CreatedAt}
}

func validateOAuthBirth(db *gorm.DB, j *oauthBirthJournal, ready bool) error {
	binding, err := oauthLiveBinding(db, j)
	if err != nil || binding != j.Binding {
		return errOAuthBootstrap
	}
	var markers []OAuthDerivedTokenBootstrapIdentity
	if db.Limit(2).Find(&markers).Error != nil || len(markers) != 1 || markers[0] != oauthBirthMarker(j) {
		return errOAuthBootstrap
	}
	if ready {
		seal, err := j.seal()
		if err != nil || j.Phase != "READY" || seal != j.HistorySeal || j.SealedAt < j.CreatedAt || j.CreatedAt < j.IntentAt || j.SealedAt > time.Now().Unix() {
			return errOAuthBootstrap
		}
		var rows []OAuthDerivedTokenHistory
		if db.Limit(2).Find(&rows).Error != nil || len(rows) != 1 || rows[0] != (OAuthDerivedTokenHistory{ID: 1, SchemaVersion: 1, HistorySeal: seal, SealedAt: j.SealedAt}) {
			return errOAuthBootstrap
		}
	}
	return nil
}

func validateOAuthDerivedTokenAnchor(db *gorm.DB) error {
	j, err := readOAuthBirthJournal(os.Getenv("OAUTH_BOOTSTRAP_JOURNAL"), true)
	if err != nil {
		return ErrOAuthDerivedTokenUnknown
	}
	if j.Engine != db.Dialector.Name() {
		return ErrOAuthDerivedTokenUnknown
	}
	if j.Engine != "sqlite" {
		_, endpoint, err := oauthBootstrapDSN(j.Engine, os.Getenv("SQL_DSN"), j.Target)
		if err != nil || endpoint != j.Endpoint {
			return ErrOAuthDerivedTokenUnknown
		}
	}
	if validateOAuthBirth(db, j, true) != nil {
		return ErrOAuthDerivedTokenUnknown
	}
	return nil
}

// RunOAuthDatabaseBootstrap is an offline producer. It deliberately never loads
// .env, starts HTTP/background work, grants service privileges, or adopts a DB.
func RunOAuthDatabaseBootstrap(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("db-bootstrap", flag.ContinueOnError)
	fs.SetOutput(out)
	engine := fs.String("engine", "", "sqlite|mysql|postgres (local protected sockets only)")
	target := fs.String("target", "", "new absolute SQLite file or new database name")
	journal := fs.String("journal", "", "installer-root-owned absolute journal path")
	if len(args) == 0 {
		fmt.Fprintln(out, "db-bootstrap fresh|resume --engine ... --target ... --journal ...; admin credentials via BOOTSTRAP_ADMIN_DSN only")
		return 2
	}
	mode := args[0]
	if mode == "--help" || mode == "-h" {
		fs.PrintDefaults()
		return 0
	}
	if mode != "fresh" && mode != "resume" {
		return 2
	}
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return 2
	}
	if err := oauthBootstrap(context.Background(), mode, *engine, *target, *journal, out); err != nil {
		fmt.Fprintln(out, "db-bootstrap refused; preserve journal and namespace for diagnosis")
		return 1
	}
	return 0
}

func oauthBootstrap(ctx context.Context, mode, engine, target, journal string, out io.Writer) error {
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
		if writeOAuthBirthJournal(journal, j) != nil {
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
		if writeOAuthBirthJournal(journal, j) != nil {
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
	if writeOAuthBirthJournal(journal, j) != nil {
		return errOAuthBootstrap
	}
	fmt.Fprintln(out, j.OperationID, "READY")
	return nil
}
