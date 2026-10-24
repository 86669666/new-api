package service

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	mysqlconfig "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Provenance cases require a trusted fresh producer with a distinct service UID.
// Legacy DSN validation remains available for explicitly leased runners.
func TestOAuthDerivedTextRawUsageRejection(t *testing.T) {
	for _, kind := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(kind), func(t *testing.T) {
			if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") != "" {
				require.Equal(t, string(kind), os.Getenv("NEWAPI_BOOTSTRAP_ENGINE"))
				testOAuthDerivedTextRawUsageRejection(t, kind, nil)
				return
			}
			var driver gorm.Dialector
			switch kind {
			case common.DatabaseTypeSQLite:
				driver = sqlite.Open(filepath.Join(t.TempDir(), "charge.sqlite"))
			case common.DatabaseTypeMySQL:
				dsn := os.Getenv("TEST_MYSQL_DSN")
				if dsn == "" {
					require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"), "TEST_MYSQL_DSN is required")
					t.Skip("TEST_MYSQL_DSN is not configured")
				}
				require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
				cfg, err := mysqlconfig.ParseDSN(dsn)
				require.NoError(t, err)
				host, _, err := net.SplitHostPort(cfg.Addr)
				require.NoError(t, err)
				require.Equal(t, "tcp", cfg.Net)
				require.Equal(t, "127.0.0.1", host)
				require.True(t, strings.HasPrefix(cfg.DBName, "newapi_ci_"))
				driver = mysql.Open(dsn)
			case common.DatabaseTypePostgreSQL:
				dsn := os.Getenv("TEST_POSTGRES_DSN")
				if dsn == "" {
					require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"), "TEST_POSTGRES_DSN is required")
					t.Skip("TEST_POSTGRES_DSN is not configured")
				}
				require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
				cfg, err := isolatedOAuthTextPostgresConfig(dsn)
				require.NoError(t, err)
				sqlDB := stdlib.OpenDB(*cfg)
				t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
				driver = postgres.New(postgres.Config{Conn: sqlDB})
			}
			testOAuthDerivedTextRawUsageRejection(t, kind, driver)
		})
	}
}

// Validate the effective driver target, then pass that exact config to OpenDB.
// Requiring explicit URL targets prevents PGHOST/PGDATABASE defaults; service
// files and query overrides cannot redirect this destructive fixture elsewhere.
func isolatedOAuthTextPostgresConfig(dsn string) (*pgx.ConnConfig, error) {
	invalid := errors.New("PostgreSQL fixture requires an explicit loopback newapi_ci_ database without target overrides")
	target, err := url.Parse(dsn)
	if err != nil || (target.Scheme != "postgres" && target.Scheme != "postgresql") || target.Host == "" || target.Path == "" || target.Path == "/" || target.Fragment != "" {
		return nil, invalid
	}
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return nil, invalid
	}
	for key, values := range query {
		if (key != "sslmode" && key != "connect_timeout") || len(values) != 1 {
			return nil, invalid
		}
	}
	if os.Getenv("PGSERVICE") != "" || os.Getenv("PGSERVICEFILE") != "" {
		return nil, invalid
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// Driver parse errors may embed credentials from the DSN.
		return nil, invalid
	}
	if cfg.Host != "127.0.0.1" || !strings.HasPrefix(cfg.Database, "newapi_ci_") {
		return nil, invalid
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback == nil || fallback.Host != "127.0.0.1" {
			return nil, invalid
		}
	}
	return cfg, nil
}

func TestOAuthDerivedTextPostgresConfigIsolation(t *testing.T) {
	// Parsing only: no connector is opened and no database/network is required.
	for _, key := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGSSLCRL", "PGCONNECT_TIMEOUT", "PGTARGETSESSIONATTRS"} {
		t.Setenv(key, "")
	}
	const local = "postgres://unit@127.0.0.1:5432/newapi_ci_safe?sslmode=disable"
	for _, tc := range []struct {
		name, dsn string
		env       map[string]string
		valid     bool
	}{
		{name: "local", dsn: local, valid: true},
		{name: "local_tls_fallback", dsn: "postgresql://unit@127.0.0.1/newapi_ci_safe?sslmode=prefer", valid: true},
		{name: "host_override", dsn: local + "&host=192.0.2.1"},
		{name: "dbname_override", dsn: local + "&dbname=other"},
		{name: "database_override", dsn: local + "&database=other"},
		{name: "encoded_override", dsn: local + "&%68ost=192.0.2.1"},
		{name: "local_override_also_denied", dsn: local + "&host=127.0.0.1"},
		{name: "remote_primary", dsn: "postgres://unit@192.0.2.1/newapi_ci_safe?sslmode=disable"},
		{name: "remote_fallback", dsn: "postgres://unit@127.0.0.1,192.0.2.1/newapi_ci_safe?sslmode=disable"},
		{name: "socket_fallback", dsn: "postgres://unit@127.0.0.1,%2Ftmp/newapi_ci_safe?sslmode=disable"},
		{name: "wrong_database", dsn: "postgres://unit@127.0.0.1/other?sslmode=disable"},
		{name: "empty_host_env", dsn: "postgres:///newapi_ci_safe?sslmode=disable", env: map[string]string{"PGHOST": "192.0.2.1"}},
		{name: "empty_database_env", dsn: "postgres://unit@127.0.0.1/?sslmode=disable", env: map[string]string{"PGDATABASE": "other"}},
		{name: "empty_dsn", env: map[string]string{"PGHOST": "127.0.0.1", "PGDATABASE": "newapi_ci_safe"}},
		{name: "service_query", dsn: local + "&service=remote"},
		{name: "service_env", dsn: local, env: map[string]string{"PGSERVICE": "remote"}},
		{name: "servicefile_env", dsn: local, env: map[string]string{"PGSERVICEFILE": "/unused/service.conf"}},
		{name: "explicit_target_wins_env", dsn: local, env: map[string]string{"PGHOST": "192.0.2.1", "PGDATABASE": "other"}, valid: true},
		{name: "ambiguous_query", dsn: local + "&sslmode=prefer"},
		{name: "invalid_query", dsn: local + "&host=%zz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			cfg, err := isolatedOAuthTextPostgresConfig(tc.dsn)
			if !tc.valid {
				require.Error(t, err)
				assert.Nil(t, cfg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg)
			assert.Equal(t, "127.0.0.1", cfg.Host)
			assert.Equal(t, "newapi_ci_safe", cfg.Database)
			for _, fallback := range cfg.Fallbacks {
				require.NotNil(t, fallback)
				assert.Equal(t, "127.0.0.1", fallback.Host)
			}
			if tc.name == "local_tls_fallback" {
				require.NotEmpty(t, cfg.Fallbacks)
			}
		})
	}
}

func newOAuthDerivedTextBillingFixture(t *testing.T, kind common.DatabaseType, dialect gorm.Dialector) (*gorm.DB, model.OAuthTextFacts) {
	t.Helper()
	db, _ := oauthBirthFixture(t)
	kind = common.DatabaseType(db.Dialector.Name())
	sql, err := db.DB()
	require.NoError(t, err)
	sql.SetMaxOpenConns(1)
	old, oldKind := model.DB, common.MainDatabaseType()
	oldReady, oldRedis := model.OAuthCleanupReady(), common.RedisEnabled
	model.DB = db
	common.SetMainDatabaseType(kind)
	common.RedisEnabled = false
	t.Cleanup(func() {
		model.DB = old
		common.SetMainDatabaseType(oldKind)
		common.RedisEnabled = oldRedis
		assert.NoError(t, model.InitOAuthCleanupStore(oldReady))
		assert.NoError(t, sql.Close())
	})
	tables := []any{&model.User{}, &model.Token{}, &model.UserSession{}, &model.SessionRevocationEvent{}, &model.OAuthGrant{}, &model.OAuthOperation{}, &model.OAuthArtifact{}, &model.OAuthCleanupJob{}, &model.OAuthDerivedTokenSource{}, &model.OAuthDerivedTokenHistory{}, &model.OAuthDerivedTextCharge{}}
	require.NoError(t, db.AutoMigrate(tables...))
	require.NoError(t, model.InitOAuthCleanupStore(true))
	now := time.Now().Unix()
	h := strings.Repeat("a", 64)
	u := model.User{Username: "charge", AffCode: "charge", Quota: 100, Status: common.UserStatusEnabled, AuthVersion: 1}
	require.NoError(t, db.Create(&u).Error)
	token := model.Token{UserId: u.Id, Key: "synthetic-unit-key", Status: common.TokenStatusEnabled, RemainQuota: 100, ExpiredTime: now + 100}
	require.NoError(t, db.Create(&token).Error)
	session := model.UserSession{SID: "unit-session", UserID: u.Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, ExpiresAt: now + 200}
	require.NoError(t, db.Create(&session).Error)
	g := model.OAuthGrant{GrantID: strings.Repeat("g", 43), Issuer: "https://unit.invalid", ClientID: "unit", Subject: strconv.Itoa(u.Id), UserID: u.Id, OriginSID: session.SID, SessionVersion: 1, UserAuthVersion: 1, State: "active", Scopes: `["tokens:write"]`, CreatedAt: now - 15, ExpiresAt: now + 150, ConsentRef: h}
	g.GrantRef = model.OAuthGrantRef(g.Issuer, g.GrantID)
	require.NoError(t, db.Create(&g).Error)
	key := model.OAuthDerivedTokenKeyRef(token.Key)
	created := now - 10
	source := model.OAuthDerivedTokenSource{GrantRef: g.GrantRef, UserID: u.Id, SchemaVersion: 1, QuotaLimit: 100, ExpiresAt: now + 100, PolicyHash: h, BindingHash: h, VerifiedAt: now - 20, ProofExpiresAt: now + 100, PermitDeadline: now + 40, VerifiedMethod: "password", ProofFlowID: 1, TokenID: &token.Id, KeyRef: &key, IdemHash: &h, RequestHash: &h, CreatedAt: &created}
	require.NoError(t, db.Create(&source).Error)
	var birthHistory model.OAuthDerivedTokenHistory
	require.NoError(t, db.First(&birthHistory).Error)
	var version string
	versionQuery := "SELECT version()"
	if kind == common.DatabaseTypeSQLite {
		versionQuery = "SELECT sqlite_version()"
	}
	require.NoError(t, db.Raw(versionQuery).Scan(&version).Error)
	t.Log("database", kind, version)
	return db, model.OAuthTextFacts{GrantRef: g.GrantRef, UserID: u.Id, TokenID: token.Id, Model: "unit-text", ChannelID: 1, RouteHash: h, BodyHash: h, PolicyHash: h, ModelRatio: 1, CompletionRatio: 1, GroupRatio: 1, PromptEstimate: 20, MaxCompletion: 60}
}

func testOAuthDerivedTextRawUsageRejection(t *testing.T, kind common.DatabaseType, driver gorm.Dialector) {
	t.Helper()
	db, f := newOAuthDerivedTextBillingFixture(t, kind, driver)
	f.CacheRatio = .25
	ctx := context.Background()
	ref := strings.Repeat("b", 64)
	_, err := model.ReserveOAuthDerivedText(ctx, ref, f, 80)
	require.NoError(t, err)
	permit, err := model.ClaimOAuthDerivedText(ctx, ref, f, 80)
	require.NoError(t, err)
	require.NotNil(t, permit)
	before, err := model.ReadOAuthDerivedTextCharge(ctx, ref)
	require.NoError(t, err)
	require.Nil(t, before.Actual)
	require.Equal(t, "send_claimed", before.State)
	for _, tc := range []struct{ name, raw string }{
		{"duplicate_prompt", `{"prompt_tokens":100,"prompt_tokens":20,"completion_tokens":40,"total_tokens":60}`},
		{"duplicate_completion", `{"prompt_tokens":20,"completion_tokens":99,"completion_tokens":40,"total_tokens":60}`},
		{"duplicate_total", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":999,"total_tokens":60}`},
		{"prompt_details_hide_audio", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"prompt_tokens_details":{"audio_tokens":1},"prompt_tokens_details":{}}`},
		{"completion_details_hide_reasoning", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"completion_tokens_details":{"reasoning_tokens":1},"completion_tokens_details":{}}`},
		{"duplicate_cached", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"prompt_tokens_details":{"cached_tokens":0,"cached_tokens":20}}`},
		{"escaped_duplicate_scalar", `{"prompt_tokens":100,"prompt\u005ftokens":20,"completion_tokens":40,"total_tokens":60}`},
		{"escaped_duplicate_prompt_details", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"prompt_tokens_details":{"audio_tokens":1},"prompt_tokens\u005fdetails":{}}`},
		{"escaped_duplicate_completion_details", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"completion_tokens_details":{"reasoning_tokens":1},"completion_tokens\u005fdetails":{}}`},
		{"escaped_duplicate_cached", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"prompt_tokens_details":{"cached_tokens":0,"cached\u005ftokens":20}}`},
		{"duplicate_completion_child", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"completion_tokens_details":{"reasoning_tokens":1,"reasoning_tokens":0}}`},
		{"fractional_scalar", `{"prompt_tokens":20.5,"completion_tokens":40,"total_tokens":60}`},
		{"null_cached", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"prompt_tokens_details":{"cached_tokens":null}}`},
		{"unknown_zero", `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60,"prompt_tokens_details":{"audio_tokens":0}}`},
		{"invalid_utf8", "{\"prompt_tokens\":20,\"completion_tokens\":40,\"total_tokens\":60,\"\xff\":0}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := db.Begin()
			require.NoError(t, tx.Error)
			model.DB = tx
			t.Cleanup(func() { model.DB = db; assert.NoError(t, tx.Rollback().Error) })
			q, _, err := CalculateOAuthDerivedTextQuota(f, []byte(tc.raw))
			assert.ErrorIs(t, err, model.ErrOAuthTextCharge)
			assert.Zero(t, q)
			result, err := FinalizeOAuthDerivedText(ctx, ref, []byte(tc.raw))
			assert.ErrorIs(t, err, model.ErrOAuthTextCharge)
			assert.Nil(t, result)
			stored, err := model.ReadOAuthDerivedTextCharge(ctx, ref)
			require.NoError(t, err)
			assert.Equal(t, before, stored, "rejected raw usage must not mutate receipt or Actual")
			var user model.User
			var token model.Token
			require.NoError(t, tx.First(&user, f.UserID).Error)
			require.NoError(t, tx.First(&token, f.TokenID).Error)
			assert.Equal(t, 20, user.Quota)
			assert.Equal(t, 20, token.RemainQuota)
			assert.Equal(t, 80, token.UsedQuota)
		})
	}
	t.Run("valid_and_closed", func(t *testing.T) {
		raw := []byte(`{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60}`)
		q, _, err := CalculateOAuthDerivedTextQuota(f, raw)
		require.NoError(t, err)
		assert.Equal(t, 60, q)
		raw = []byte(`{"prompt\u005ftokens":20,"completion_tokens":40,"total_tokens":60,"prompt_tokens_details":{"cached\u005ftokens":20},"completion_tokens_details":{}}`)
		q, u, err := CalculateOAuthDerivedTextQuota(f, raw)
		require.NoError(t, err)
		assert.Equal(t, 45, q)
		assert.Equal(t, 20, u.Cached)
		settled, err := FinalizeOAuthDerivedText(ctx, ref, raw)
		require.NoError(t, err)
		assert.Equal(t, "settled", settled.State)
		require.NotNil(t, settled.Actual)
		assert.Equal(t, 45, *settled.Actual)
		replay, err := FinalizeOAuthDerivedText(ctx, ref, raw)
		require.NoError(t, err)
		assert.Equal(t, settled, replay)
		var user model.User
		var token model.Token
		require.NoError(t, db.First(&user, f.UserID).Error)
		require.NoError(t, db.First(&token, f.TokenID).Error)
		assert.Equal(t, 55, user.Quota)
		assert.Equal(t, 55, token.RemainQuota)
		assert.Equal(t, 45, token.UsedQuota)
		c, err := ReserveOAuthDerivedText(ctx, ref, f, 80)
		assert.ErrorIs(t, err, ErrOAuthDerivedTextClosed)
		assert.Nil(t, c)
		permit, err := ClaimOAuthDerivedText(ctx, ref, f, 80)
		assert.ErrorIs(t, err, ErrOAuthDerivedTextClosed)
		assert.Nil(t, permit)
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
