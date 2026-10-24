package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
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

// Opt-in, fresh leased databases only. The source/history rows below are test
// provenance fixtures, not a migration, production history seal or issuance.
func newOAuthSelectedHTTPStore(t *testing.T, kind common.DatabaseType) (*gorm.DB, *gorm.DB) {
	t.Helper()
	var pools []*gorm.DB
	if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") != "" {
		db, dsn := oauthBirthFixture(t)
		require.Equal(t, string(kind), db.Dialector.Name())
		var d gorm.Dialector
		switch kind {
		case common.DatabaseTypeSQLite:
			d = sqlite.Open(dsn)
		case common.DatabaseTypeMySQL:
			d = mysql.Open(dsn)
		case common.DatabaseTypePostgreSQL:
			d = postgres.Open(dsn)
		}
		observer, err := gorm.Open(d, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		require.NoError(t, err)
		conn, err := observer.DB()
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, conn.Close()) })
		pools = []*gorm.DB{db, observer}
	} else {
		var lease struct {
			RunID        string
			Database     string
			MySQLPort    int
			PostgresPort int
		}
		raw, err := os.ReadFile(os.Getenv("NEWAPI_W03_SELECTED_LEASE"))
		require.NoError(t, err)
		require.NoError(t, common.Unmarshal(raw, &lease))
		runBytes, err := hex.DecodeString(lease.RunID)
		require.NoError(t, err)
		require.Len(t, runBytes, 12)
		require.Equal(t, os.Getenv("NEWAPI_W03_SELECTED_RUN"), lease.RunID)
		require.Equal(t, "newapi_ci_w03_"+lease.RunID, lease.Database)
		password := os.Getenv("NEWAPI_W03_SELECTED_PASSWORD")
		require.True(t, len(password) >= 32, "private database credential required")
		sqlitePath := filepath.Join(t.TempDir(), "selected.sqlite")
		for range 2 {
			var dialect gorm.Dialector
			switch kind {
			case common.DatabaseTypeSQLite:
				dialect = sqlite.Open(sqlitePath)
			case common.DatabaseTypeMySQL:
				require.Greater(t, lease.MySQLPort, 0)
				require.LessOrEqual(t, lease.MySQLPort, 65535)
				cfg := mysqlconfig.NewConfig()
				cfg.Net, cfg.Addr = "tcp", "127.0.0.1:"+strconv.Itoa(lease.MySQLPort)
				cfg.User, cfg.Passwd, cfg.DBName = "w03", password, lease.Database
				cfg.ParseTime = true
				cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 5*time.Second, 5*time.Second
				dialect = mysql.Open(cfg.FormatDSN())
			case common.DatabaseTypePostgreSQL:
				// No ambient PG service/host/database defaults, query overrides or fallback
				// hosts may redirect this fixture. The runner verifies the port's lease.
				for _, entry := range os.Environ() {
					key, value, _ := strings.Cut(entry, "=")
					require.False(t, strings.HasPrefix(key, "PG") && value != "", "PG environment overrides forbidden")
				}
				require.Greater(t, lease.PostgresPort, 0)
				require.LessOrEqual(t, lease.PostgresPort, 65535)
				cfg, parseErr := pgx.ParseConfig("postgres://w03@127.0.0.1:" + strconv.Itoa(lease.PostgresPort) + "/" + lease.Database + "?sslmode=disable")
				require.True(t, parseErr == nil, "fixed private PostgreSQL configuration must parse")
				require.Equal(t, "127.0.0.1", cfg.Host)
				require.Equal(t, lease.Database, cfg.Database)
				require.Equal(t, "w03", cfg.User)
				require.Equal(t, lease.PostgresPort, int(cfg.Port))
				require.Empty(t, cfg.Fallbacks)
				cfg.Password, cfg.ConnectTimeout = password, 5*time.Second
				sqlDB := stdlib.OpenDB(*cfg)
				t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
				dialect = postgres.New(postgres.Config{Conn: sqlDB})
			default:
				t.Fatal("unsupported selected database")
			}
			db, openErr := gorm.Open(dialect, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			require.True(t, openErr == nil, "private selected database connection failed")
			sqlDB, sqlErr := db.DB()
			require.NoError(t, sqlErr)
			sqlDB.SetMaxOpenConns(1)
			sqlDB.SetMaxIdleConns(1)
			t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
			pools = append(pools, db)
		}
	}
	db, observer := pools[0], pools[1]
	primarySQL, err := db.DB()
	require.NoError(t, err)
	observerSQL, err := observer.DB()
	require.NoError(t, err)
	require.NotSame(t, primarySQL, observerSQL)
	tables, err := db.Migrator().GetTables()
	require.NoError(t, err)
	if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") == "" {
		require.Empty(t, tables, "lease must target a fresh empty database")
	}
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.OAuthDerivedTextCharge{}, &model.OAuthGrant{}, &model.OAuthDerivedTokenSource{}, &model.OAuthDerivedTokenHistory{}, &model.Channel{}, &model.Ability{}, &model.Log{}, &model.UserSession{}, &model.UserAccessToken{}, &model.AuditLog{}))
	var version string
	versionQuery := "SELECT version()"
	if kind == common.DatabaseTypeSQLite {
		versionQuery = "SELECT sqlite_version()"
	}
	require.NoError(t, db.Raw(versionQuery).Scan(&version).Error)
	t.Logf("selected database=%s version=%s", kind, version)
	if kind != common.DatabaseTypeSQLite {
		query := "SELECT CONNECTION_ID()"
		if kind == common.DatabaseTypePostgreSQL {
			query = "SELECT pg_backend_pid()"
		}
		var primaryID, observerID int64
		require.NoError(t, db.Raw(query).Scan(&primaryID).Error)
		require.NoError(t, observer.Raw(query).Scan(&observerID).Error)
		require.NotEqual(t, primaryID, observerID, "observer must use a distinct server connection")
	}
	oldDB, oldKind, oldRedis := model.DB, common.MainDatabaseType(), common.RedisEnabled
	oldLogDB, oldMemory, oldRDB := model.LOG_DB, common.MemoryCacheEnabled, common.RDB
	model.LOG_DB, common.MemoryCacheEnabled = db, false
	oldMaster, oldLogKind := common.IsMasterNode, common.LogDatabaseType()
	// Existing no-DSN, non-master initializer sets dialect column names without
	// opening another connection, migrating, or touching shared resources.
	require.Equal(t, oldKind, oldLogKind, "dedicated process expects matching initial dialects")
	t.Setenv("LOG_SQL_DSN", "")
	common.IsMasterNode = false
	oldReady := model.OAuthCleanupReady()
	model.DB = db
	common.SetMainDatabaseType(kind)
	common.RedisEnabled = false
	require.NoError(t, model.InitLogDB())
	t.Cleanup(func() {
		model.DB = oldDB
		common.SetMainDatabaseType(oldKind)
		require.NoError(t, model.InitLogDB())
		model.LOG_DB, common.MemoryCacheEnabled, common.RDB = oldLogDB, oldMemory, oldRDB
		common.SetLogDatabaseType(oldLogKind)
		common.IsMasterNode = oldMaster
		common.RedisEnabled = oldRedis
		assert.Equal(t, oldReady, model.OAuthCleanupReady(), "selected settlement must not mutate readiness")
	})
	return db, observer
}

func TestOAuthDerivedSelectedHTTP(t *testing.T) {
	if os.Getenv("NEWAPI_W03_SELECTED_LEASE") == "" && os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") == "" {
		t.Skip("requires private three-database lease")
	}
	require.NoError(t, i18n.Init())
	cases := []struct {
		name         string
		manual       bool
		status       int
		reachesRelay bool
	}{
		{"manual_original_validation", true, 400, true},
		{"manual_forged_derived_mark", true, 400, true},
		{"derived_closed", false, 503, true},
		{"derived_forged_manual_mark", false, 503, true},
		{"unknown_corrupt_source", false, 503, false},
		{"history_not_ready", true, 503, false},
		{"source_table_missing", true, 503, false},
		{"missing_credential", true, 401, false},
		{"manual_cache_identity_drift", true, 401, false},
		{"derived_cache_claims_manual", false, 503, true},
		{"unsupported_path", false, 503, false},
		{"unsupported_method", false, 503, false},
		{"unsupported_websocket", false, 503, false},
		{"unsupported_funding", false, 503, false},
		{"selection_key_failure", false, 503, false},
		{"invalid_raw_request", false, 503, false},
		{"unsupported_stream", false, 503, false},
		{"unsupported_encoding", false, 503, false},
		{"missing_selected_channel", false, 503, false},
	}
	for _, kind := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(kind), func(t *testing.T) {
			db, observer := newOAuthSelectedHTTPStore(t, kind)
			now := time.Now().Unix()
			h := strings.Repeat("a", 64)
			var birthHistory model.OAuthDerivedTokenHistory
			require.NoError(t, db.First(&birthHistory).Error)
			// Count attempted writes as well as verifying durable balances. Even a
			// reserve+refund that restored balances would fail this assertion.
			var moneyWrites atomic.Int64
			observeWrite := func(tx *gorm.DB) {
				switch tx.Statement.Table {
				case "users", "tokens", "oauth_derived_text_charges", "logs":
					moneyWrites.Add(1)
				}
			}
			require.NoError(t, db.Callback().Create().Before("gorm:create").Register("w03_money_create", observeWrite))
			require.NoError(t, db.Callback().Update().Before("gorm:update").Register("w03_money_update", observeWrite))
			require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register("w03_money_delete", observeWrite))
			for i, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					common.RedisEnabled = false
					user := model.User{Username: "selected" + strconv.Itoa(i), AffCode: "sel" + strconv.Itoa(i), Status: common.UserStatusEnabled, Group: "default", Quota: 100, AuthVersion: 1, Setting: `{"billing_preference":"wallet_only"}`}
					if tc.name == "unsupported_funding" {
						user.Setting = `{"billing_preference":"subscription_only"}`
					}
					require.NoError(t, db.Create(&user).Error)
					token := model.Token{UserId: user.Id, Key: "selectedfixture" + strconv.Itoa(i), Status: common.TokenStatusEnabled, RemainQuota: 100, ExpiredTime: now + 300}
					require.NoError(t, db.Create(&token).Error)
					if !tc.manual {
						grant := model.OAuthGrant{GrantID: strings.Repeat("g", 40) + strconv.Itoa(i), Issuer: "https://selected.invalid", ClientID: "fixture", Subject: strconv.Itoa(user.Id), UserID: user.Id, OriginSID: "fixture", UserAuthVersion: 1, SessionVersion: 1, State: "active", Scopes: `["tokens:write"]`, CreatedAt: now - 15, ExpiresAt: now + 400, ConsentRef: fmt.Sprintf("%064x", i+1)}
						grant.GrantRef = model.OAuthGrantRef(grant.Issuer, grant.GrantID)
						require.NoError(t, db.Create(&grant).Error)
						keyRef := model.OAuthDerivedTokenKeyRef(token.Key)
						created := now - 10
						source := model.OAuthDerivedTokenSource{GrantRef: grant.GrantRef, UserID: user.Id, SchemaVersion: 1, QuotaLimit: 100, ExpiresAt: now + 300, PolicyHash: h, BindingHash: h, VerifiedAt: now - 20, ProofExpiresAt: now + 400, PermitDeadline: now + 40, VerifiedMethod: "password", ProofFlowID: int64(i + 1), TokenID: &token.Id, KeyRef: &keyRef, IdemHash: &h, RequestHash: &h, CreatedAt: &created}
						require.NoError(t, db.Create(&source).Error)
						if tc.name == "unknown_corrupt_source" {
							require.NoError(t, db.Session(&gorm.Session{SkipHooks: true}).Model(&source).Update("policy_hash", "").Error)
						}
					}
					if tc.name == "history_not_ready" {
						require.NoError(t, db.Delete(&model.OAuthDerivedTokenHistory{}, 1).Error)
						t.Cleanup(func() {
							require.NoError(t, db.Create(&birthHistory).Error)
						})
					}
					if tc.name == "source_table_missing" {
						require.NoError(t, db.Migrator().DropTable(&model.OAuthDerivedTokenSource{}))
						t.Cleanup(func() { require.NoError(t, db.AutoMigrate(&model.OAuthDerivedTokenSource{})) })
					}
					if strings.Contains(tc.name, "cache_") {
						installOAuthSelectedTokenCache(t, token, 100)
						// This is the real cache decoder's identity input, not a fake TokenAuth.
						require.NoError(t, common.RDB.HSet(context.Background(), "token:"+common.GenerateHMAC(token.Key), map[string]any{"Id": token.Id + 100000, "UserId": user.Id + 100000, "Status": common.TokenStatusEnabled, "ExpiredTime": now + 300, "RemainQuota": 100}).Err())
					}
					var wire atomic.Int64
					upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
					upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
						if state == http.StateNew {
							wire.Add(1)
						}
					}
					upstream.StartTLS()
					t.Cleanup(upstream.Close)
					channel := model.Channel{Type: constant.ChannelTypeOpenAI, Key: "privatefixtureupstream", Name: "selected", Status: common.ChannelStatusEnabled, Group: "default", Models: "selected-text", BaseURL: &upstream.URL}
					if tc.name == "selection_key_failure" {
						channel.ChannelInfo = model.ChannelInfo{IsMultiKey: true}
						channel.Key = ""
					}
					require.NoError(t, db.Create(&channel).Error)
					require.NoError(t, db.Create(&model.Ability{Group: "default", Model: "selected-text", ChannelId: channel.Id, Enabled: true, Priority: common.GetPointer(int64(0))}).Error)
					if tc.name == "missing_selected_channel" {
						require.NoError(t, db.Model(&model.Ability{}).Where("channel_id = ?", channel.Id).Update("enabled", false).Error)
					}
					t.Cleanup(func() {
						require.NoError(t, db.Where("channel_id = ?", channel.Id).Delete(&model.Ability{}).Error)
						require.NoError(t, db.Delete(&channel).Error)
					})
					// All test-owned setup precedes the observation interval.
					moneyWrites.Store(0)
					var authReached, relayReached atomic.Int64
					engine := gin.New()
					engine.Use(func(c *gin.Context) {
						defer common.CleanupBodyStorage(c)
						if strings.Contains(tc.name, "forged") {
							c.Set("id", 999999)
							c.Set("token_id", 999999)
							c.Set("oauth_derived", tc.manual)
							if tc.manual {
								c.Set("oauth_token_class", "derived")
							} else {
								c.Set("oauth_token_class", "manual_proven")
							}
						}
						c.Next()
					})
					engine.Use(middleware.TokenAuth())
					engine.Use(func(c *gin.Context) {
						authReached.Add(1)
						class, uid, tid := middleware.OAuthTokenPrincipal(c)
						expected := model.OAuthDerivedTokenBound
						if tc.manual {
							expected = model.OAuthDerivedTokenManualProven
						}
						assert.Equal(t, expected, class)
						assert.Equal(t, user.Id, uid)
						assert.Equal(t, token.Id, tid)
						assert.Equal(t, user.Id, c.GetInt("id"))
						assert.Equal(t, token.Id, c.GetInt("token_id"))
						// Attempt to overwrite classification through arbitrary gin keys after
						// authentication: the private request principal must remain unchanged.
						if strings.Contains(tc.name, "forged") {
							c.Set("oauth_derived", tc.manual)
							if tc.manual {
								c.Set("oauth_token_class", "derived")
							} else {
								c.Set("oauth_token_class", "manual_proven")
							}
						}
						c.Next()
					})
					engine.Use(middleware.Distribute())
					engine.Any("/*path", func(c *gin.Context) { relayReached.Add(1); Relay(c, types.RelayFormatOpenAI) })
					gateway := httptest.NewServer(engine)
					t.Cleanup(gateway.Close)
					body := `{"model":"selected-text","messages":[{"role":"user","content":"hello"}],"max_tokens":1,"stream":false}`
					if tc.manual {
						body = strings.Replace(body, `"max_tokens":1`, `"max_tokens":4294967295`, 1)
					}
					if tc.name == "invalid_raw_request" {
						body = strings.Replace(body, `"max_tokens":1`, `"max_tokens":1,"max_tokens":2`, 1)
					}
					if tc.name == "unsupported_stream" {
						body = strings.Replace(body, `"stream":false`, `"stream":true`, 1)
					}
					method, path := http.MethodPost, "/v1/chat/completions"
					if tc.name == "unsupported_path" {
						path = "/v1/images/generations"
					}
					if tc.name == "unsupported_method" {
						method = http.MethodGet
					}
					req, err := http.NewRequest(method, gateway.URL+path, strings.NewReader(body))
					require.NoError(t, err)
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Accept-Language", "en")
					if tc.name != "missing_credential" {
						req.Header.Set("Authorization", "Bearer sk-"+token.Key)
					}
					if strings.Contains(tc.name, "forged") {
						req.Header.Set("X-OAuth-Token-Class", "manual_proven")
						req.Header.Set("X-User-Id", "999999")
					}
					if tc.name == "unsupported_encoding" {
						req.Header.Set("Content-Encoding", "br")
					}
					if tc.name == "unsupported_websocket" {
						req.Header.Set("Upgrade", "websocket")
						req.Header.Set("Connection", "Upgrade")
					}
					resp, err := gateway.Client().Do(req)
					require.NoError(t, err)
					raw, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					require.NoError(t, resp.Body.Close())
					assert.Equal(t, tc.status, resp.StatusCode, string(raw))
					assert.Equal(t, tc.reachesRelay, relayReached.Load() == 1)
					if tc.reachesRelay {
						assert.Equal(t, int64(1), authReached.Load())
					}
					assert.NotContains(t, string(raw), token.Key)
					if channel.Key != "" {
						assert.NotContains(t, string(raw), channel.Key)
					}
					assert.Zero(t, wire.Load(), "no upstream connection, including failed TLS handshake")
					assert.Zero(t, moneyWrites.Load(), "no attempted legacy debit/refund or charge write")
					var afterUser model.User
					var afterToken model.Token
					require.NoError(t, observer.First(&afterUser, user.Id).Error)
					require.NoError(t, observer.First(&afterToken, token.Id).Error)
					assert.Equal(t, 100, afterUser.Quota)
					assert.Zero(t, afterUser.UsedQuota)
					assert.Equal(t, 100, afterToken.RemainQuota)
					assert.Zero(t, afterToken.UsedQuota)
					assert.Equal(t, common.TokenStatusEnabled, afterToken.Status)
					var charges, logs int64
					require.NoError(t, observer.Model(&model.OAuthDerivedTextCharge{}).Count(&charges).Error)
					require.NoError(t, observer.Model(&model.Log{}).Count(&logs).Error)
					assert.Zero(t, charges)
					assert.Zero(t, logs)
				})
			}
			t.Run("compatibility", func(t *testing.T) { runOAuthSelectedCompatibility(t, db, observer) })
		})
	}
}

// This matrix exercises the two existing billing producers. Browser session
// credentials are signed by the real issuer and consumed by UserAuth, not by
// assigning gin identity fields or promoting the synthetic token to manual.
func runOAuthSelectedCompatibility(t *testing.T, db, observer *gorm.DB) {
	t.Helper()
	oldBatch, oldLogs, oldCount, oldSecret := common.BatchUpdateEnabled, common.LogConsumeEnabled, constant.CountToken, common.SessionSecret
	oldModel, oldCompletion, oldGroup := ratio_setting.ModelRatio2JSONString(), ratio_setting.CompletionRatio2JSONString(), ratio_setting.GroupRatio2JSONString()
	oldTrust := operation_setting.GetQuotaSetting().TrustQuotaUSD
	common.BatchUpdateEnabled, common.LogConsumeEnabled, constant.CountToken = false, false, false
	secret, err := common.GenerateRandomCharsKey(64)
	require.NoError(t, err)
	common.SessionSecret = secret
	operation_setting.GetQuotaSetting().TrustQuotaUSD = 0
	require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(`{"selected-text":1}`))
	require.NoError(t, ratio_setting.UpdateCompletionRatioByJSONString(`{"selected-text":1}`))
	require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(`{"default":1}`))
	t.Cleanup(func() {
		common.BatchUpdateEnabled, common.LogConsumeEnabled, constant.CountToken, common.SessionSecret = oldBatch, oldLogs, oldCount, oldSecret
		operation_setting.GetQuotaSetting().TrustQuotaUSD = oldTrust
		require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(oldModel))
		require.NoError(t, ratio_setting.UpdateCompletionRatioByJSONString(oldCompletion))
		require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(oldGroup))
	})
	now := time.Now().Unix()
	user := model.User{Username: "compatibility", AffCode: "compat", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1, Group: "default", Quota: 10000000, Setting: `{"billing_preference":"wallet_only"}`}
	require.NoError(t, db.Create(&user).Error)
	// SQL state must win even when a cache snapshot claims enabled and funded.
	for i, tc := range []struct {
		name   string
		status int
		expiry int64
		quota  int
		code   string
	}{
		{"disabled", common.TokenStatusDisabled, now + 300, 100, "token_disabled"},
		{"expired_status", common.TokenStatusExpired, now + 300, 100, "token_expired"},
		{"expired_time", common.TokenStatusEnabled, now - 1, 100, "token_expired"},
		{"exhausted_status", common.TokenStatusExhausted, now + 300, 100, "token_exhausted"},
		{"exhausted_quota", common.TokenStatusEnabled, now + 300, 0, "token_exhausted"},
		{"invalid_status", 999, now + 300, 100, "token_invalid"},
	} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("manual_%s_cached_%t", tc.name, cached), func(t *testing.T) {
				token := model.Token{UserId: user.Id, Key: fmt.Sprintf("compatstatus%d%t", i, cached), Status: tc.status, ExpiredTime: tc.expiry, RemainQuota: tc.quota}
				require.NoError(t, db.Create(&token).Error)
				if cached {
					installOAuthSelectedTokenCache(t, token, 100)
				}
				engine := gin.New()
				engine.POST("/v1/chat/completions", middleware.TokenAuth(), func(c *gin.Context) { t.Error("invalid SQL token reached caller"); c.Status(200) })
				response := httptest.NewRecorder()
				request := httptest.NewRequest("POST", "/v1/chat/completions", nil)
				request.Header.Set("Authorization", "Bearer sk-"+token.Key)
				engine.ServeHTTP(response, request)
				assert.Equal(t, 401, response.Code)
				var body struct {
					Error struct {
						Code    string
						Message string
					}
				}
				require.NoError(t, common.Unmarshal(response.Body.Bytes(), &body))
				assert.Equal(t, tc.code, body.Error.Code)
				assert.NotContains(t, body.Error.Message, token.Key)
				var after model.Token
				require.NoError(t, observer.First(&after, token.Id).Error)
				assert.Equal(t, tc.quota, after.RemainQuota)
				assert.Zero(t, after.UsedQuota)
			})
		}
	}
	t.Run("manual_live_quota_cannot_trust_SQL_snapshot", func(t *testing.T) {
		token := model.Token{UserId: user.Id, Key: "compatlivequota", Status: common.TokenStatusEnabled, ExpiredTime: now + 300, RemainQuota: 10000000}
		require.NoError(t, db.Create(&token).Error)
		installOAuthSelectedTokenCache(t, token, 1)
		old := operation_setting.GetQuotaSetting().TrustQuotaUSD
		operation_setting.GetQuotaSetting().TrustQuotaUSD = 1
		t.Cleanup(func() { operation_setting.GetQuotaSetting().TrustQuotaUSD = old })
		engine := gin.New()
		calls := 0
		engine.POST("/v1/chat/completions", middleware.TokenAuth(), func(c *gin.Context) {
			calls++
			info := &relaycommon.RelayInfo{UserId: user.Id, TokenId: token.Id, TokenKey: token.Key}
			info.UserSetting.BillingPreference = "wallet_only"
			session, apiErr := service.NewBillingSession(c, info, 10)
			require.Nil(t, session)
			require.NotNil(t, apiErr)
			assert.Equal(t, types.ErrorCodePreConsumeTokenQuotaFailed, apiErr.GetErrorCode())
			assert.Equal(t, 403, apiErr.StatusCode)
			c.Status(apiErr.StatusCode)
		})
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer sk-"+token.Key)
		engine.ServeHTTP(w, req)
		assert.Equal(t, 1, calls)
		assert.Equal(t, 403, w.Code)
		remain, err := common.RDB.HGet(context.Background(), "token:"+common.GenerateHMAC(token.Key), "RemainQuota").Int()
		require.NoError(t, err)
		assert.Equal(t, 1, remain)
		var stored model.Token
		require.NoError(t, observer.First(&stored, token.Id).Error)
		assert.Equal(t, 10000000, stored.RemainQuota)
		assert.Zero(t, stored.UsedQuota)
		var payer model.User
		require.NoError(t, observer.First(&payer, user.Id).Error)
		assert.Equal(t, 10000000, payer.Quota)
	})
	t.Run("cache_admission_controls", func(t *testing.T) { runOAuthCacheAdmissionControls(t, db, observer) })
	for _, name := range []string{"manual_success", "playground_success", "playground_expired", "playground_revoked", "playground_invalid", "playground_PAT", "playground_spoof", "playground_derived_token", "generic_missing_principal"} {
		t.Run(name, func(t *testing.T) {
			user := model.User{Username: name, AffCode: name, Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1, Group: "default", Quota: 100000, Setting: `{"billing_preference":"wallet_only"}`}
			require.NoError(t, db.Create(&user).Error)
			token := model.Token{UserId: user.Id, Key: strings.ReplaceAll(name, "_", "") + "credential", Status: common.TokenStatusEnabled, ExpiredTime: now + 300, RemainQuota: 100000}
			require.NoError(t, db.Create(&token).Error)
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				assert.Equal(t, "/v1/chat/completions", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, err := io.WriteString(w, `{"id":"fixture","object":"chat.completion","model":"selected-text","choices":[{"index":0,"message":{"role":"assistant","content":"local result"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`)
				assert.NoError(t, err)
			}))
			t.Cleanup(upstream.Close)
			channel := model.Channel{Type: constant.ChannelTypeOpenAI, Key: "localfixtureupstream", Name: name, Status: common.ChannelStatusEnabled, Group: "default", Models: "selected-text", BaseURL: &upstream.URL}
			require.NoError(t, db.Create(&channel).Error)
			require.NoError(t, db.Create(&model.Ability{Group: "default", Model: "selected-text", ChannelId: channel.Id, Enabled: true, Priority: common.GetPointer(int64(0))}).Error)
			t.Cleanup(func() {
				require.NoError(t, db.Where("channel_id = ?", channel.Id).Delete(&model.Ability{}).Error)
				require.NoError(t, db.Delete(&channel).Error)
			})
			path, credential := "/pg/chat/completions", ""
			if name == "manual_success" {
				path = "/v1/chat/completions"
				credential = "sk-" + token.Key
			} else if name == "playground_PAT" {
				credential = "nap_" + strings.Repeat("k", 48)
				pat := model.UserAccessToken{UserId: user.Id, Name: "fixture", TokenHash: model.AccessTokenFingerprint(credential), TokenHint: "fixture", Scopes: `["tokens:read"]`, ExpiresAt: now + 300}
				require.NoError(t, db.Create(&pat).Error)
			} else if name == "playground_derived_token" {
				// Own the complete provenance fixture so this case also runs
				// independently of the selected negative matrix.
				h := strings.Repeat("b", 64)
				grant := model.OAuthGrant{GrantID: "compat-derived-grant", Issuer: "https://compat.invalid", ClientID: "fixture", Subject: strconv.Itoa(user.Id), UserID: user.Id, OriginSID: "fixture", UserAuthVersion: 1, SessionVersion: 1, State: "active", Scopes: `["tokens:write"]`, CreatedAt: now - 15, ExpiresAt: now + 400, ConsentRef: h}
				grant.GrantRef = model.OAuthGrantRef(grant.Issuer, grant.GrantID)
				require.NoError(t, db.Create(&grant).Error)
				keyRef, created := model.OAuthDerivedTokenKeyRef(token.Key), now-10
				source := model.OAuthDerivedTokenSource{GrantRef: grant.GrantRef, UserID: user.Id, SchemaVersion: 1, QuotaLimit: int64(token.RemainQuota), ExpiresAt: token.ExpiredTime, PolicyHash: h, BindingHash: h, VerifiedAt: now - 20, ProofExpiresAt: now + 400, PermitDeadline: now + 40, VerifiedMethod: "password", ProofFlowID: int64(token.Id) + 100000, TokenID: &token.Id, KeyRef: &keyRef, IdemHash: &h, RequestHash: &h, CreatedAt: &created}
				require.NoError(t, db.Create(&source).Error)
				class, err := model.ClassifyOAuthDerivedToken(context.Background(), token.Id)
				require.NoError(t, err)
				require.Equal(t, model.OAuthDerivedTokenBound, class)
				credential = "sk-" + token.Key
			} else if name == "playground_invalid" {
				credential = "invalid.dashboard.credential"
			} else if name != "playground_spoof" && name != "generic_missing_principal" {
				session := model.UserSession{SID: name, UserID: user.Id, UserAuthVersion: 1, Version: 1, Status: model.UserSessionStatusActive, RefreshHash: "test-only", ExpiresAt: now + 300}
				if name == "playground_expired" {
					session.ExpiresAt = now - 1
				}
				if name == "playground_revoked" {
					session.Status = model.UserSessionStatusRevoked
					session.RevokedAt = now - 1
				}
				require.NoError(t, db.Create(&session).Error)
				var err error
				credential, _, err = service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1})
				require.NoError(t, err)
			}
			engine := gin.New()
			engine.Use(middleware.DecompressRequestMiddleware())
			engine.Use(func(c *gin.Context) {
				defer common.CleanupBodyStorage(c)
				if strings.Contains(name, "spoof") || name == "generic_missing_principal" {
					c.Set("id", user.Id)
					c.Set("is_playground", true)
					c.Set("use_access_token", false)
					c.Set("session_id", "pretend")
				}
				c.Next()
			})
			done := make(chan struct{})
			if name == "manual_success" {
				engine.POST(path, middleware.TokenAuth(), middleware.Distribute(), func(c *gin.Context) { defer close(done); Relay(c, types.RelayFormatOpenAI) })
			} else if name == "generic_missing_principal" {
				engine.POST(path, func(c *gin.Context) { Relay(c, types.RelayFormatOpenAI) })
			} else {
				engine.POST(path, middleware.UserAuth(), middleware.Distribute(), func(c *gin.Context) { defer close(done); Playground(c) })
			}
			gateway := httptest.NewServer(engine)
			t.Cleanup(gateway.Close)
			req, err := http.NewRequest("POST", gateway.URL+path, strings.NewReader(`{"model":"selected-text","messages":[{"role":"user","content":"hello"}],"max_tokens":1,"stream":false}`))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Language", "en")
			if credential != "" {
				req.Header.Set("Authorization", "Bearer "+credential)
			}
			resp, err := gateway.Client().Do(req)
			require.NoError(t, err)
			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			success := name == "manual_success" || name == "playground_success"
			if success {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("relay did not finish")
				}
				assert.Equal(t, 200, resp.StatusCode, string(raw))
				assert.Contains(t, string(raw), "local result")
				assert.Equal(t, int64(1), calls.Load())
			} else {
				expectedStatus := 401
				if name == "playground_PAT" {
					expectedStatus = 403
				}
				if name == "generic_missing_principal" {
					expectedStatus = 503
				}
				assert.Equal(t, expectedStatus, resp.StatusCode, string(raw))
				assert.Zero(t, calls.Load())
			}
			assert.NotContains(t, string(raw), "localfixtureupstream")
			if credential != "" {
				assert.NotContains(t, string(raw), credential)
			}
			var payer model.User
			var stored model.Token
			require.NoError(t, observer.First(&payer, user.Id).Error)
			require.NoError(t, observer.First(&stored, token.Id).Error)
			cost := 0
			if success {
				cost = 12
			}
			assert.Equal(t, 100000-cost, payer.Quota)
			assert.Equal(t, cost, payer.UsedQuota)
			tokenCost := 0
			if name == "manual_success" {
				tokenCost = 12
			}
			assert.Equal(t, 100000-tokenCost, stored.RemainQuota)
			assert.Equal(t, tokenCost, stored.UsedQuota)
			var charges int64
			require.NoError(t, observer.Model(&model.OAuthDerivedTextCharge{}).Count(&charges).Error)
			assert.Zero(t, charges)
		})
	}
}

func installOAuthSelectedTokenCache(t *testing.T, token model.Token, remain int) {
	t.Helper()
	addr := os.Getenv("NEWAPI_TEST_REDIS_ADDR")
	if addr == "" {
		addr = miniredis.RunT(t).Addr()
	} else {
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		host, _, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", host)
	}
	oldRDB, oldEnabled := common.RDB, common.RedisEnabled
	common.RDB = redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
	common.RedisEnabled = true
	client := common.RDB
	require.NoError(t, client.Ping(t.Context()).Err())
	t.Cleanup(func() {
		require.NoError(t, client.Del(context.Background(), "token:"+common.GenerateHMAC(token.Key), "token:fence:"+common.GenerateHMAC(token.Key)).Err())
		require.NoError(t, client.Close())
		common.RDB, common.RedisEnabled = oldRDB, oldEnabled
	})
	require.NoError(t, common.RDB.HSet(context.Background(), "token:"+common.GenerateHMAC(token.Key), map[string]any{"Id": token.Id, "UserId": token.UserId, "Status": common.TokenStatusEnabled, "ExpiredTime": time.Now().Unix() + 300, "RemainQuota": remain, "UsedQuota": 0}).Err())
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

// Exercise the formal TokenAuth -> BillingSession boundary with independent
// SQL money and Redis observations, including actual miss/transport failures.
func runOAuthCacheAdmissionControls(t *testing.T, db, observer *gorm.DB) {
	for _, tc := range []struct {
		name                                                 string
		sqlQuota, cacheQuota, requestQuota, status, reserved int
		unlimited                                            bool
	}{
		{"owner_conflict", 1000, 1000, 10, 401, 0, false},
		{"key_id_conflict", 1000, 1000, 10, 401, 0, false},
		{"key_member_conflict", 1000, 1000, 10, 401, 0, false},
		{"deleted_sql", 1000, 1000, 10, 401, 0, false},
		{"miss", 1000, 1000, 10, 200, 0, false},
		{"unreachable", 1000, 1000, 10, 200, 0, false},
		{"trust_only", 1000, 50, 10, 200, 10, false},
		{"below_admission", 1000, 1, 10, 403, 0, false},
		{"high_cache_low_sql", 5, 1000000, 10, 403, 0, false},
		{"fake_unlimited", 5, 1000000, 10, 403, 0, false},
		{"sql_unlimited", 0, 1, 10, 200, 0, true},
		// Strict authentication rejects exhausted observations even for a free request.
		{"zero", 1000, 0, 0, 401, 0, false},
		{"zero_unexhausted", 1000, 1, 0, 200, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := model.User{Username: "cachepolicy_" + tc.name, AffCode: "cp_" + tc.name, Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1, Group: "default", Quota: 1000, Setting: `{"billing_preference":"wallet_only"}`}
			require.NoError(t, db.Create(&user).Error)
			token := model.Token{UserId: user.Id, Key: "cachepolicy" + tc.name, Status: common.TokenStatusEnabled, ExpiredTime: time.Now().Unix() + 300, RemainQuota: tc.sqlQuota, UnlimitedQuota: tc.unlimited}
			require.NoError(t, db.Create(&token).Error)
			installOAuthSelectedTokenCache(t, token, tc.cacheQuota)
			realCache := common.RDB
			key := "token:" + common.GenerateHMAC(token.Key)
			require.NoError(t, realCache.HSet(t.Context(), key, "UsedQuota", 777).Err())
			switch tc.name {
			case "owner_conflict":
				require.NoError(t, realCache.HSet(t.Context(), key, "UserId", user.Id+10000).Err())
			case "key_id_conflict":
				other := model.Token{UserId: user.Id, Key: "different_request_key", Status: common.TokenStatusEnabled, ExpiredTime: -1, RemainQuota: 1000}
				require.NoError(t, db.Create(&other).Error)
				require.NoError(t, realCache.HSet(t.Context(), key, "Id", other.Id).Err())
			case "key_member_conflict":
				require.NoError(t, realCache.HSet(t.Context(), key, "Key", "other_key").Err())
			case "deleted_sql":
				require.NoError(t, db.Delete(&token).Error)
			case "fake_unlimited":
				require.NoError(t, realCache.HSet(t.Context(), key, "UnlimitedQuota", true).Err())
			case "miss":
				require.NoError(t, realCache.Del(t.Context(), key).Err())
			case "unreachable":
				unreachable := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0", MaxRetries: -1, DialTimeout: time.Second})
				common.RDB = unreachable
				t.Cleanup(func() { require.NoError(t, unreachable.Close()); common.RDB = realCache })
			}
			oldTrust := operation_setting.GetQuotaSetting().TrustQuotaUSD
			operation_setting.GetQuotaSetting().TrustQuotaUSD = 100 / common.QuotaPerUnit
			t.Cleanup(func() { operation_setting.GetQuotaSetting().TrustQuotaUSD = oldTrust })
			var moneyAttempts atomic.Int64
			callback := "cache_admission_" + tc.name
			require.NoError(t, db.Callback().Update().Before("gorm:update").Register(callback, func(tx *gorm.DB) {
				if tx.Statement.Table == "tokens" || tx.Statement.Table == "users" {
					// SQLite admission takes its existing user lock through an
					// auth_version no-op. Count monetary updates, not that lock.
					if fields, ok := tx.Statement.Dest.(map[string]any); ok {
						for _, name := range []string{"quota", "remain_quota", "used_quota"} {
							if _, money := fields[name]; money {
								moneyAttempts.Add(1)
								break
							}
						}
					}
				}
			}))
			t.Cleanup(func() { require.NoError(t, db.Callback().Update().Remove(callback)) })
			calls := 0
			engine := gin.New()
			engine.POST("/v1/chat/completions", middleware.TokenAuth(), func(c *gin.Context) {
				calls++
				general, err := model.GetTokenByKey(token.Key, false)
				require.NoError(t, err)
				assert.Equal(t, tc.sqlQuota, general.RemainQuota)
				assert.Zero(t, general.UsedQuota)
				assert.Equal(t, tc.unlimited, general.UnlimitedQuota)
				observation, err := model.ReadTokenCacheAdmissionObservation(token.Id, token.Key)
				require.NoError(t, err)
				if tc.name == "below_admission" {
					assert.True(t, observation.Rejects(10))
				}
				info := &relaycommon.RelayInfo{UserId: user.Id, TokenId: token.Id, TokenKey: token.Key, TokenUnlimited: c.GetBool("token_unlimited_quota")}
				info.UserSetting.BillingPreference = "wallet_only"
				session, apiErr := service.NewBillingSession(c, info, tc.requestQuota)
				if tc.status == 403 {
					require.Nil(t, session)
					require.NotNil(t, apiErr)
					assert.Equal(t, types.ErrorCodePreConsumeTokenQuotaFailed, apiErr.GetErrorCode())
					assert.Equal(t, 403, apiErr.StatusCode)
					c.Status(apiErr.StatusCode)
					return
				}
				require.Nil(t, apiErr)
				require.NotNil(t, session)
				assert.Equal(t, tc.reserved, session.GetPreConsumedQuota())
				var current model.Token
				require.NoError(t, observer.First(&current, token.Id).Error)
				assert.Equal(t, tc.sqlQuota-tc.reserved, current.RemainQuota)
				if tc.name == "trust_only" {
					// The low observation may veto only NEW admission, never historical settle.
					require.NoError(t, realCache.HSet(t.Context(), key, "Id", token.Id, "UserId", user.Id, "RemainQuota", 0).Err())
					require.NoError(t, session.Settle(20))
					require.NoError(t, session.Settle(20))
				}
				c.Status(200)
			})
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			req.Header.Set("Authorization", "Bearer sk-"+token.Key)
			engine.ServeHTTP(w, req)
			assert.Equal(t, tc.status, w.Code, w.Body.String())
			if tc.status == 401 {
				assert.Zero(t, calls)
				if tc.name == "zero" {
					assert.Contains(t, w.Body.String(), "token_exhausted")
				} else {
					assert.Contains(t, w.Body.String(), "token_invalid")
				}
			} else {
				assert.Equal(t, 1, calls)
			}
			spent := tc.reserved
			if tc.name == "trust_only" {
				spent = 20
			}
			var stored model.Token
			require.NoError(t, observer.Unscoped().First(&stored, token.Id).Error)
			assert.Equal(t, tc.sqlQuota-spent, stored.RemainQuota)
			assert.Equal(t, spent, stored.UsedQuota)
			var payer model.User
			require.NoError(t, observer.First(&payer, user.Id).Error)
			assert.Equal(t, 1000-spent, payer.Quota)
			assert.Equal(t, user.AuthVersion, payer.AuthVersion)
			if tc.name == "below_admission" || tc.status == 401 || tc.requestQuota == 0 {
				assert.Zero(t, moneyAttempts.Load(), "veto must precede any attempted money update")
			}
			if tc.status != 200 {
				remaining, err := realCache.HGet(t.Context(), key, "RemainQuota").Int()
				require.NoError(t, err)
				assert.Equal(t, tc.cacheQuota, remaining)
			}
		})
	}
}
