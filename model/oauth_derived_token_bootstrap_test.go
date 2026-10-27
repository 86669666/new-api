package model

import (
	"bytes"
	"errors"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Run in an isolated installer container, with /birth owned by root. Ordinary
// developer tests cannot manufacture the required provisioning authority.
func TestOAuthBootstrapProducer(t *testing.T) {
	if runtime.GOOS != "linux" {
		var out bytes.Buffer
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap([]string{"fresh"}, &out))
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap([]string{"resume"}, &out))
		assert.ErrorIs(t, validateOAuthDerivedTokenAnchor(nil), ErrOAuthDerivedTokenUnknown)
		return
	}
	require.Zero(t, os.Geteuid(), "run make test: producer tests need the isolated installer principal")
	root := os.Getenv("NEWAPI_BOOTSTRAP_ROOT_TEST_DIR")
	require.NotEmpty(t, root, "run make test: protected per-run installer test directory is required")
	require.NoError(t, oauthProtectedPath(root, false))
	dir, err := os.MkdirTemp(root, "producer-test-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	target, journal := filepath.Join(dir, "new.db"), filepath.Join(dir, "birth.json")
	args := []string{"fresh", "--engine", "sqlite", "--target", target, "--journal", journal}
	var out bytes.Buffer
	require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
	original, err := readOAuthBirthJournal(journal, false)
	require.NoError(t, err)
	db, err := openOAuthBootstrapDB("sqlite", target)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()
	require.NoError(t, validateOAuthBirth(db, original, true))
	var marker OAuthDerivedTokenBootstrapIdentity
	var history OAuthDerivedTokenHistory
	require.NoError(t, db.First(&marker).Error)
	require.NoError(t, db.First(&history).Error)
	// A second fresh request must preserve the exact existing identity and seal.
	assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
	args[0] = "resume"
	require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
	after, err := readOAuthBirthJournal(journal, false)
	require.NoError(t, err)
	assert.Equal(t, original, after)
	// Lost acknowledgement/external publication: the authoritative SQL row already
	// exists. Resume must only finish that exact pending operation, never reseal.
	pending := *original
	pending.Phase = "SEAL_PENDING"
	require.NoError(t, writeOAuthBirthJournal(journal, &pending))
	require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
	after, err = readOAuthBirthJournal(journal, false)
	require.NoError(t, err)
	assert.Equal(t, original, after)
	var finalHistory OAuthDerivedTokenHistory
	require.NoError(t, db.First(&finalHistory).Error)
	assert.Equal(t, history, finalHistory)
	t.Run("syntactically_valid_forged_history", func(t *testing.T) {
		require.NoError(t, db.Model(&OAuthDerivedTokenHistory{}).Where("id = ?", 1).Update("history_seal", OAuthDerivedTokenKeyRef("untrusted synthetic seal")).Error)
		assert.Error(t, validateOAuthBirth(db, original, true))
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, db.Model(&OAuthDerivedTokenHistory{}).Where("id = ?", 1).Update("history_seal", history.HistorySeal).Error)
	})
	t.Run("wrong_nonce", func(t *testing.T) {
		require.NoError(t, db.Model(&OAuthDerivedTokenBootstrapIdentity{}).Where("id = ?", 1).Update("creation_nonce", OAuthDerivedTokenKeyRef("foreign birth")).Error)
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, db.Model(&OAuthDerivedTokenBootstrapIdentity{}).Where("id = ?", 1).Update("creation_nonce", marker.CreationNonce).Error)
	})
	t.Run("intent_never_adopts", func(t *testing.T) {
		intent := *original
		intent.Phase = "INTENT"
		require.NoError(t, writeOAuthBirthJournal(journal, &intent))
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, writeOAuthBirthJournal(journal, original))
	})
	t.Run("clone_inode", func(t *testing.T) {
		// SQLite backup is not a new birth. Keep all DB data but change file identity.
		backup := filepath.Join(dir, "clone.db")
		require.NoError(t, db.Exec("VACUUM INTO ?", backup).Error)
		clone, err := openOAuthBootstrapDB("sqlite", backup)
		require.NoError(t, err)
		conn, err := clone.DB()
		require.NoError(t, err)
		defer conn.Close()
		assert.Error(t, validateOAuthBirth(clone, original, true))
	})
	t.Run("same_uid_is_not_service_isolation", func(t *testing.T) {
		t.Setenv("OAUTH_BOOTSTRAP_JOURNAL", journal)
		assert.ErrorIs(t, validateOAuthDerivedTokenAnchor(db), ErrOAuthDerivedTokenUnknown)
	})
	t.Run("manual_row_does_not_change_birth", func(t *testing.T) {
		require.NoError(t, db.Create(&Token{UserId: 1, Key: "synthetic-only", Status: common.TokenStatusEnabled}).Error)
		require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, validateOAuthBirth(db, original, true))
	})
}

// oauthBirthFixture obtains a new namespace from an external trusted installer.
// Tests run as the service principal; neither this helper nor the client seals it.
func oauthBirthFixture(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	client := os.Getenv("NEWAPI_BOOTSTRAP_CLIENT")
	require.NotEmpty(t, client, "a separate trusted installer is required for provenance fixtures")
	raw, err := exec.Command(client).Output()
	require.NoError(t, err, "permanent bootstrap fixture producer failed")
	var birth struct{ Engine, DSN, Journal string }
	require.NoError(t, common.Unmarshal(raw, &birth))
	require.NotEmpty(t, birth.Journal)
	t.Setenv("OAUTH_BOOTSTRAP_JOURNAL", birth.Journal)
	t.Setenv("SQL_DSN", birth.DSN)
	var dialect gorm.Dialector
	switch birth.Engine {
	case "sqlite":
		dialect = sqlite.Open(birth.DSN)
	case "mysql":
		dialect = mysql.Open(birth.DSN)
	case "postgres":
		dialect = postgres.Open(birth.DSN)
	default:
		t.Fatalf("unsupported trusted fixture engine %q", birth.Engine)
	}
	db, err := gorm.Open(dialect, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	var rows int64
	require.NoError(t, db.Table("tokens").Count(&rows).Error)
	require.Zero(t, rows, "producer must return a fresh namespace without token writers")
	return db, birth.DSN
}

// Schema-only regression: these empty tables are never treated as a history
// seal or a usable credential store. The permanent producer is tested separately.
func TestOAuthProvenanceSchemaDatabase(t *testing.T) {
	engine := os.Getenv("NEWAPI_SCHEMA_TEST_ENGINE")
	if engine == "" {
		engine = "sqlite"
	}
	var dialect gorm.Dialector
	switch engine {
	case "sqlite":
		dialect = sqlite.Open(filepath.Join(t.TempDir(), "schema.db"))
	case "mysql":
		dialect = mysql.Open(os.Getenv("NEWAPI_SCHEMA_TEST_DSN"))
	case "postgres":
		dialect = postgres.Open(os.Getenv("NEWAPI_SCHEMA_TEST_DSN"))
	default:
		t.Fatal("unsupported explicit schema test engine")
	}
	db, err := gorm.Open(dialect, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	connection, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	connection.SetMaxOpenConns(1)
	var version string
	if engine == "sqlite" {
		require.NoError(t, db.Raw("SELECT sqlite_version()").Scan(&version).Error)
	} else {
		require.NoError(t, db.Raw("SELECT version()").Scan(&version).Error)
	}
	t.Logf("engine=%s version=%s", engine, version)
	models := []any{&OAuthDerivedTokenSource{}, &OAuthDerivedTokenHistory{}, &OAuthDerivedTokenBootstrapIdentity{}}
	require.NoError(t, db.AutoMigrate(models...))
	if engine != "postgres" {
		require.NoError(t, validateOAuthDerivedTokenSchema(db))
		t.Run("missing_unique_index", func(t *testing.T) {
			require.NoError(t, db.Migrator().DropIndex(&OAuthDerivedTokenSource{}, "uq_oauth_derived_key"))
			assert.ErrorIs(t, validateOAuthDerivedTokenSchema(db), ErrOAuthDerivedTokenUnknown)
			require.NoError(t, db.Migrator().CreateIndex(&OAuthDerivedTokenSource{}, "uq_oauth_derived_key"))
		})
		t.Run("missing_table", func(t *testing.T) {
			require.NoError(t, db.Migrator().DropTable(&OAuthDerivedTokenBootstrapIdentity{}))
			assert.ErrorIs(t, validateOAuthDerivedTokenSchema(db), ErrOAuthDerivedTokenUnknown)
		})
		return
	}
	// Only the disposable installer connection owns the fixture DDL. Every
	// validation below executes as a SQL role with SELECT and no table DML.
	require.NoError(t, db.Exec("CREATE ROLE provenance_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE").Error)
	t.Cleanup(func() {
		require.NoError(t, db.Exec("DROP OWNED BY provenance_reader; DROP ROLE provenance_reader").Error)
	})
	require.NoError(t, db.Exec("GRANT USAGE ON SCHEMA public TO provenance_reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO provenance_reader").Error)
	cases := []struct {
		name, ddl string
		pass      bool
	}{
		{"readonly_valid", "", true},
		{"missing_pk", "ALTER TABLE oauth_derived_token_history DROP CONSTRAINT oauth_derived_token_history_pkey", false},
		{"wrong_pk", "ALTER TABLE oauth_derived_token_history DROP CONSTRAINT oauth_derived_token_history_pkey; ALTER TABLE oauth_derived_token_history ADD PRIMARY KEY(schema_version)", false},
		{"composite_pk", "ALTER TABLE oauth_derived_token_history DROP CONSTRAINT oauth_derived_token_history_pkey; ALTER TABLE oauth_derived_token_history ADD PRIMARY KEY(id,schema_version)", false},
		{"pk_order", "ALTER TABLE oauth_derived_token_history DROP CONSTRAINT oauth_derived_token_history_pkey; ALTER TABLE oauth_derived_token_history ADD PRIMARY KEY(schema_version,id)", false},
		{"nonunique", "DROP INDEX uq_oauth_derived_key; CREATE INDEX uq_oauth_derived_key ON oauth_derived_token_sources(key_ref)", false},
		{"partial", "DROP INDEX uq_oauth_derived_key; CREATE UNIQUE INDEX uq_oauth_derived_key ON oauth_derived_token_sources(key_ref) WHERE token_id IS NOT NULL", false},
		{"expression", "DROP INDEX uq_oauth_derived_key; CREATE UNIQUE INDEX uq_oauth_derived_key ON oauth_derived_token_sources(lower(key_ref))", false},
		{"index_order", "DROP INDEX uq_oauth_derived_grant_idem; CREATE UNIQUE INDEX uq_oauth_derived_grant_idem ON oauth_derived_token_sources(idem_hash,grant_ref)", false},
		{"nullable", "ALTER TABLE oauth_derived_token_history ALTER COLUMN history_seal DROP NOT NULL", false},
		{"wrong_type", "ALTER TABLE oauth_derived_token_history ALTER COLUMN history_seal TYPE text", false},
		{"shadow", "CREATE SCHEMA shadow; CREATE TABLE shadow.oauth_derived_token_sources (LIKE public.oauth_derived_token_sources INCLUDING ALL); GRANT USAGE ON SCHEMA shadow TO provenance_reader; GRANT SELECT ON shadow.oauth_derived_token_sources TO provenance_reader; SET LOCAL search_path=shadow,public", false},
		{"temp_shadow", "CREATE TEMP TABLE oauth_derived_token_sources (LIKE public.oauth_derived_token_sources INCLUDING ALL); GRANT SELECT ON pg_temp.oauth_derived_token_sources TO provenance_reader", false},
		{"wrong_schema", "CREATE SCHEMA wrong; ALTER TABLE oauth_derived_token_history SET SCHEMA wrong", false},
		{"same_named_index_other_relation", "CREATE SCHEMA shadow; CREATE TABLE shadow.decoy (key_ref char(64)); CREATE UNIQUE INDEX uq_oauth_derived_key ON shadow.decoy(key_ref); DROP INDEX public.uq_oauth_derived_key", false},
		{"permission", "REVOKE SELECT ON oauth_derived_token_history FROM provenance_reader", false},
		{"query_failure", "SELECT 1/0", false},
	}
	// A failed concurrent unique build leaves a real invalid catalog index.
	// Synthetic source rows exist only in this schema-only disposable database;
	// no history/identity row is created and no store is classified as ready.
	t.Run("invalid_index", func(t *testing.T) {
		require.NoError(t, db.Exec("DROP INDEX uq_oauth_derived_key").Error)
		require.NoError(t, db.Exec(`INSERT INTO oauth_derived_token_sources
			(grant_ref,user_id,schema_version,quota_limit,expires_at,policy_hash,binding_hash,verified_at,proof_expires_at,permit_deadline,verified_method,proof_flow_id,key_ref)
			SELECT repeat(letter,64),1,1,1,1,repeat('0',64),repeat('0',64),0,0,0,'password',number,repeat('c',64)
			FROM (VALUES ('a',1),('b',2)) AS synthetic(letter,number)`).Error)
		require.Error(t, db.Exec("CREATE UNIQUE INDEX CONCURRENTLY uq_oauth_derived_key ON oauth_derived_token_sources(key_ref)").Error)
		var valid bool
		require.NoError(t, db.Raw("SELECT indisvalid FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('public.uq_oauth_derived_key')").Scan(&valid).Error)
		require.False(t, valid)
		rollback := errors.New("rollback readonly invalid-index check")
		err := db.Transaction(func(tx *gorm.DB) error {
			require.NoError(t, tx.Exec("SET LOCAL ROLE provenance_reader").Error)
			assert.ErrorIs(t, validateOAuthDerivedTokenSchema(tx), ErrOAuthDerivedTokenUnknown)
			return rollback
		})
		require.ErrorIs(t, err, rollback)
		require.NoError(t, db.Exec("DROP INDEX uq_oauth_derived_key; DELETE FROM oauth_derived_token_sources; CREATE UNIQUE INDEX uq_oauth_derived_key ON oauth_derived_token_sources(key_ref)").Error)
	})
	rollback := errors.New("rollback schema-only fixture")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := db.Transaction(func(tx *gorm.DB) error {
				if tc.ddl != "" {
					err := tx.Exec(tc.ddl).Error
					if tc.name == "query_failure" {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
				}
				if tc.name != "query_failure" {
					require.NoError(t, tx.Exec("SET LOCAL ROLE provenance_reader").Error)
				}
				validation := validateOAuthDerivedTokenSchema(tx)
				if tc.pass {
					require.NoError(t, validation)
					for _, table := range []string{"oauth_derived_token_sources", "oauth_derived_token_history", "oauth_derived_token_bootstrap_identity"} {
						var dml bool
						require.NoError(t, tx.Raw("SELECT has_table_privilege(current_user, ?, 'INSERT,UPDATE,DELETE,TRUNCATE')", table).Scan(&dml).Error)
						assert.False(t, dml)
					}
				} else {
					assert.ErrorIs(t, validation, ErrOAuthDerivedTokenUnknown)
				}
				return rollback
			})
			require.ErrorIs(t, err, rollback)
		})
	}
}

// The root broker and unprivileged Go producer must commit identical bytes.
// This fixture is generated by the staged broker, not the Go implementation.
func TestOAuthBirthBrokerSealEncoding(t *testing.T) {
	const fixture = `{"version":1,"kind":"fresh","operation_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","creation_nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","installer_uid":0,"engine":"sqlite","target":"/owned/new.db","endpoint":"","binding":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","contract":"newapi.oauth.birth.v1/source-history-identity-v1","schema_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","producer":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","phase":"READY","intent_at":100,"created_at":101,"sealed_at":101,"history_seal":"40abc7355da73156c004295d928bf2c1d2f7ef4b1250af524dbc7576b8cbbc05"}`
	var journal oauthBirthJournal
	require.NoError(t, common.Unmarshal([]byte(fixture), &journal))
	seal, err := journal.seal()
	require.NoError(t, err)
	require.Equal(t, journal.HistorySeal, seal)
	journal.CreationNonce = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	changed, err := journal.seal()
	require.NoError(t, err)
	require.NotEqual(t, seal, changed)
}

// Selecting broker mode never falls back to privileged local provisioning when
// the independently owned endpoint is absent.
func TestOAuthBootstrapBrokerUnavailableFailsClosed(t *testing.T) {
	t.Setenv("NEWAPI_BOOTSTRAP_BROKER", filepath.Join(t.TempDir(), "missing.sock"))
	for _, mode := range []string{"fresh", "resume"} {
		var out bytes.Buffer
		require.Equal(t, 1, RunOAuthDatabaseBootstrap([]string{mode, "--engine", "sqlite", "--target", filepath.Join(t.TempDir(), "new.db"), "--journal", filepath.Join(t.TempDir(), "birth.json")}, &out))
	}
}
