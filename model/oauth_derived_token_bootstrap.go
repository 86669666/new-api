package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
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

// Endpoint identity is the protected Unix socket namespace and peer UID. No
// DSN (or hash of a DSN containing credentials) is persisted as DB identity.

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
