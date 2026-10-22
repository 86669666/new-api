package router

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestOAuthSessionRevocation(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	require.NoError(t, model.MigrateOAuthRevocationJobsIfEnabled(f.db))
	require.False(t, f.db.Migrator().HasTable(&model.OAuthRevocationJob{}))
	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(f.db))
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(f.db))
	require.NoError(t, model.MigrateOAuthRevocationJobsIfEnabled(f.db))
	require.NoError(t, model.MigrateOAuthRevocationJobsIfEnabled(f.db))

	const boxoCanary = "fixture-oauth-revoke-boxo"
	const otherCanary = "fixture-oauth-revoke-other"
	user := oauthRevocationUser(t, f.db, "revoke-pw", "old-password-1")
	require.NoError(t, f.db.Create(&model.UserSession{
		SID: "revoke-pw-sid", UserID: user.Id, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("a", 64),
		LoginMethod: "password", LastActiveAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 3600,
	}).Error)
	_, first, err := model.IssueOAuthClientToken(user.Id, "oc_boxo", 3, 2)
	require.NoError(t, err)
	require.True(t, first)
	_, first, err = model.IssueOAuthClientToken(user.Id, "oc_other", 3, 2)
	require.NoError(t, err)
	require.True(t, first)
	require.NoError(t, f.db.Create(&model.Token{
		UserId: user.Id, Key: "manual-revoke-key", Name: "manual", Status: common.TokenStatusEnabled, ExpiredTime: -1,
	}).Error)
	require.NoError(t, model.SaveOAuthAuthorization(user.Id, "oc_boxo", "Boxo", "openid profile"))
	require.NoError(t, model.SaveOAuthAuthorization(user.Id, "oc_other", "Other", "openid profile"))

	var passwordUser atomic.Int64
	passwordUser.Store(int64(user.Id))
	var issuerURL atomic.Value
	issuerURL.Store("")
	var mu sync.Mutex
	var hits []string
	revokedAll := map[string]bool{}
	revokedClient := map[string]bool{}
	mode := "ok"
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 4096))
		if readErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mu.Lock()
		hits = append(hits, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		current := mode
		mu.Unlock()
		if r.Method == http.MethodDelete {
			if strings.Contains(r.URL.RawQuery, boxoCanary) || strings.Contains(r.URL.RawQuery, otherCanary) || strings.Contains(string(body), boxoCanary) || strings.Contains(string(body), otherCanary) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if current == "fail" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if current == "status200" {
				w.WriteHeader(http.StatusOK)
				return
			}
			q := r.URL.Query()
			mu.Lock()
			if strings.HasSuffix(r.URL.Path, "/sessions/consent") && q.Get("all") == "true" {
				revokedAll[q.Get("subject")] = true
			}
			if client := q.Get("client"); client != "" {
				revokedClient[q.Get("subject")+"/"+client] = true
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/admin/oauth2/introspect" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := r.Form.Get("token")
		clientID := "oc_boxo"
		if token == otherCanary {
			clientID = "oc_other"
		}
		subject := strconv.FormatInt(passwordUser.Load(), 10)
		var version int64
		_ = model.DB.Raw("SELECT auth_version FROM users WHERE id = ?", passwordUser.Load()).Scan(&version)
		mu.Lock()
		active := (token == boxoCanary || token == otherCanary) && !revokedAll[subject] && !revokedClient[subject+"/"+clientID]
		mu.Unlock()
		issuer, _ := issuerURL.Load().(string)
		if !active {
			_, _ = w.Write([]byte(`{"active":false}`))
			return
		}
		payload, err := common.Marshal(map[string]any{
			"active": true, "token_use": "access_token", "token_type": "Bearer",
			"iss": issuer + "/", "aud": []string{"newapi-userinfo"},
			"client_id": clientID, "sub": subject, "exp": time.Now().Unix() + 3600,
			"scope": "openid profile balance:read", "ext": map[string]any{"newapi_auth_version": strconv.FormatInt(version, 10)},
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(payload)
	}))
	t.Cleanup(admin.Close)
	issuerURL.Store(admin.URL)
	pool := x509.NewCertPool()
	pool.AddCert(admin.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: admin.URL + "/",
		Audience: "newapi-userinfo", ClientIDs: []string{"oc_boxo", "oc_other"},
	}, pool)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{
		Enabled: true, RevocationEnabled: true, AdminBaseURL: admin.URL, AuthorizationURL: admin.URL + "/oauth2/auth",
	}, resource)
	require.NoError(t, err)
	previous := service.UseOAuthProviderBridge(bridge)
	t.Cleanup(func() { service.UseOAuthProviderBridge(previous) })
	SetOAuthResourceRouter(f.engine, resource)
	previousUnit := common.QuotaPerUnit
	t.Cleanup(func() { common.QuotaPerUnit = previousUnit })
	common.QuotaPerUnit = 500000

	balance := func(credential string) (int, map[string]any) {
		t.Helper()
		status, _, payload := f.request(t, http.MethodGet, "/api/v1/oauth/balance", credential, "", nil)
		return status, payload
	}
	status, payload := balance(boxoCanary)
	require.Equal(t, http.StatusOK, status, payload)
	status, payload = balance(otherCanary)
	require.Equal(t, http.StatusOK, status, payload)

	mu.Lock()
	beforeRevoke := len(hits)
	mu.Unlock()
	require.NoError(t, model.RevokeOAuthAuthorization(user.Id, "oc_boxo"))
	service.FlushOAuthSessionRevocations(t.Context())
	assert.Equal(t, common.TokenStatusDisabled, oauthRevocationTokenStatus(t, f.db, user.Id, "oauth-oc_boxo"))
	assert.Equal(t, common.TokenStatusEnabled, oauthRevocationTokenStatus(t, f.db, user.Id, "oauth-oc_other"))
	assert.Equal(t, common.TokenStatusEnabled, oauthRevocationTokenStatus(t, f.db, user.Id, "manual"))
	mu.Lock()
	perApp := append([]string(nil), hits[beforeRevoke:]...)
	mu.Unlock()
	require.Len(t, perApp, 1)
	assert.Contains(t, perApp[0], "DELETE /admin/oauth2/auth/sessions/consent?")
	assert.Contains(t, perApp[0], "client=oc_boxo")
	assert.NotContains(t, perApp[0], "sessions/login")
	assert.NotContains(t, perApp[0], boxoCanary)
	status, payload = balance(boxoCanary)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_token", payload["error"])
	status, _ = balance(otherCanary)
	assert.Equal(t, http.StatusOK, status)

	require.NoError(t, model.ChangeUserPassword(model.AuthSessionIdentity{
		UserID: user.Id, SessionID: "revoke-pw-sid", UserAuthVersion: 1, SessionVersion: 1,
	}, &model.User{Id: user.Id, Password: "new-password-2", OriginalPassword: "old-password-1"}, false))
	assert.Equal(t, common.TokenStatusDisabled, oauthRevocationTokenStatus(t, f.db, user.Id, "oauth-oc_other"))
	assert.Equal(t, common.TokenStatusEnabled, oauthRevocationTokenStatus(t, f.db, user.Id, "manual"))
	var session model.UserSession
	_, err = model.RevokeAllUserSessions(user.Id, "password_changed")
	require.NoError(t, err)
	require.NoError(t, f.db.First(&session, "sid = ?", "revoke-pw-sid").Error)
	assert.Equal(t, model.UserSessionStatusRevoked, session.Status)
	status, _ = balance(otherCanary)
	assert.Equal(t, http.StatusOK, status, "local auth version does not make Hydra introspection inactive")

	mu.Lock()
	mode = "fail"
	mu.Unlock()
	service.FlushOAuthSessionRevocations(t.Context())
	var job model.OAuthRevocationJob
	require.NoError(t, f.db.Where("user_id = ? AND client_id = ?", user.Id, "").First(&job).Error)
	assert.GreaterOrEqual(t, job.Attempts, 1)
	assert.Contains(t, f.logs.snapshot(), common.LogText("oauth session revocation failed for user %d", user.Id))
	assert.NotContains(t, f.logs.snapshot(), boxoCanary)
	assert.NotContains(t, f.logs.snapshot(), otherCanary)

	mu.Lock()
	mode = "status200"
	mu.Unlock()
	require.NoError(t, f.db.Model(&job).Update("next_at", 0).Error)
	service.FlushOAuthSessionRevocations(t.Context())
	require.NoError(t, f.db.First(&job, job.ID).Error)
	status, _ = balance(otherCanary)
	assert.Equal(t, http.StatusOK, status)

	mu.Lock()
	mode = "ok"
	mu.Unlock()
	require.NoError(t, f.db.Model(&job).Update("next_at", 0).Error)
	service.FlushOAuthSessionRevocations(t.Context())
	assert.ErrorIs(t, f.db.First(&model.OAuthRevocationJob{}, job.ID).Error, gorm.ErrRecordNotFound)
	mu.Lock()
	full := append([]string(nil), hits...)
	mu.Unlock()
	joined := strings.Join(full, "\n")
	assert.Contains(t, joined, "DELETE /admin/oauth2/auth/sessions/login?")
	assert.Contains(t, joined, "subject="+strconv.Itoa(user.Id))
	assert.Contains(t, joined, "all=true")
	assert.NotContains(t, joined, boxoCanary)
	assert.NotContains(t, joined, otherCanary)
	status, payload = balance(otherCanary)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_token", payload["error"])

	disabled := oauthRevocationUser(t, f.db, "revoke-off", "old-password-1")
	_, _, err = model.IssueOAuthClientToken(disabled.Id, "oc_boxo", 1, 1)
	require.NoError(t, err)
	var loaded model.User
	require.NoError(t, f.db.First(&loaded, disabled.Id).Error)
	loaded.Status = common.UserStatusDisabled
	require.NoError(t, loaded.Update(false))
	assert.Equal(t, common.TokenStatusDisabled, oauthRevocationTokenStatus(t, f.db, disabled.Id, "oauth-oc_boxo"))
	service.FlushOAuthSessionRevocations(t.Context())
	assert.Equal(t, int64(0), oauthRevocationJobCount(t, f.db, disabled.Id))

	deleted := oauthRevocationUser(t, f.db, "revoke-del", "old-password-1")
	_, _, err = model.IssueOAuthClientToken(deleted.Id, "oc_other", 1, 1)
	require.NoError(t, err)
	_, err = deleted.Delete()
	require.NoError(t, err)
	assert.Equal(t, common.TokenStatusDisabled, oauthRevocationTokenStatus(t, f.db, deleted.Id, "oauth-oc_other"))
	service.FlushOAuthSessionRevocations(t.Context())
	assert.Equal(t, int64(0), oauthRevocationJobCount(t, f.db, deleted.Id))

	bulk := oauthRevocationUser(t, f.db, "revoke-all", "old-password-1")
	require.NoError(t, f.db.Create(&model.UserSession{
		SID: "revoke-all-sid", UserID: bulk.Id, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("b", 64),
		LoginMethod: "password", LastActiveAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 3600,
	}).Error)
	_, _, err = model.IssueOAuthClientToken(bulk.Id, "oc_boxo", 1, 1)
	require.NoError(t, err)
	_, err = model.RevokeAllUserSessions(bulk.Id, "user_revoked_others")
	require.NoError(t, err)
	assert.Equal(t, common.TokenStatusDisabled, oauthRevocationTokenStatus(t, f.db, bulk.Id, "oauth-oc_boxo"))
	var bulkSession model.UserSession
	require.NoError(t, f.db.Where("sid = ?", "revoke-all-sid").First(&bulkSession).Error)
	assert.Equal(t, model.UserSessionStatusRevoked, bulkSession.Status)

	rollback := oauthRevocationUser(t, f.db, "revoke-rollback", "old-password-1")
	require.NoError(t, f.db.Create(&model.UserSession{
		SID: "revoke-rollback-sid", UserID: rollback.Id, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("c", 64),
		LoginMethod: "password", LastActiveAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 3600,
	}).Error)
	_, _, err = model.IssueOAuthClientToken(rollback.Id, "oc_boxo", 1, 1)
	require.NoError(t, err)
	require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("oauth-revoke-fail", func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}
		if _, ok := tx.Statement.Dest.(*model.OAuthRevocationJob); ok {
			_ = tx.AddError(assert.AnError)
		}
	}))
	t.Cleanup(func() { f.db.Callback().Create().Remove("oauth-revoke-fail") })
	err = model.ChangeUserPassword(model.AuthSessionIdentity{
		UserID: rollback.Id, SessionID: "revoke-rollback-sid", UserAuthVersion: 1, SessionVersion: 1,
	}, &model.User{Id: rollback.Id, Password: "new-password-2", OriginalPassword: "old-password-1"}, false)
	require.Error(t, err)
	var unchanged model.User
	require.NoError(t, f.db.First(&unchanged, rollback.Id).Error)
	assert.Equal(t, int64(1), unchanged.AuthVersion)
	assert.Equal(t, common.TokenStatusEnabled, oauthRevocationTokenStatus(t, f.db, rollback.Id, "oauth-oc_boxo"))
	assert.Equal(t, int64(0), oauthRevocationJobCount(t, f.db, rollback.Id))
}

func TestOAuthRevocationMySQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN is not configured")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	var version string
	require.NoError(t, db.Raw("SELECT VERSION()").Scan(&version).Error)
	t.Logf("mysql version=%s", version)
	exerciseOAuthRevocationDialect(t, db, common.DatabaseTypeMySQL)
}

func TestOAuthRevocationPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not configured")
	}
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true}), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	var version string
	require.NoError(t, db.Raw("SELECT version()").Scan(&version).Error)
	t.Logf("postgres version=%s", version)
	exerciseOAuthRevocationDialect(t, db, common.DatabaseTypePostgreSQL)
}

func exerciseOAuthRevocationDialect(t *testing.T, db *gorm.DB, kind common.DatabaseType) {
	t.Helper()
	previousDB := model.DB
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	previousRedis := common.RedisEnabled
	t.Cleanup(func() {
		model.DB = previousDB
		common.SetDatabaseTypes(previousMain, previousLog)
		common.RedisEnabled = previousRedis
		_ = db.Migrator().DropTable(&model.OAuthRevocationJob{}, &model.OAuthIssuedToken{}, &model.Token{})
	})
	model.DB = db
	common.SetDatabaseTypes(kind, kind)
	common.RedisEnabled = false
	require.NoError(t, db.Migrator().DropTable(&model.OAuthRevocationJob{}, &model.OAuthIssuedToken{}, &model.Token{}))
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	require.NoError(t, model.MigrateOAuthRevocationJobsIfEnabled(db))
	require.False(t, db.Migrator().HasTable(&model.OAuthRevocationJob{}))
	require.NoError(t, db.AutoMigrate(&model.Token{}))
	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(db))
	require.NoError(t, model.MigrateOAuthRevocationJobsIfEnabled(db))
	require.NoError(t, model.MigrateOAuthRevocationJobsIfEnabled(db))

	_, _, err := model.IssueOAuthClientToken(7, "oc_dialect", 1, 1)
	require.NoError(t, err)
	_, _, err = model.IssueOAuthClientToken(7, "oc_other", 1, 1)
	require.NoError(t, err)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		return model.ScheduleOAuthRevocation(tx, 7, "oc_dialect")
	}))
	assert.Equal(t, common.TokenStatusDisabled, oauthRevocationTokenStatus(t, db, 7, "oauth-oc_dialect"))
	assert.Equal(t, common.TokenStatusEnabled, oauthRevocationTokenStatus(t, db, 7, "oauth-oc_other"))
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		return model.ScheduleOAuthRevocation(tx, 7, "oc_dialect")
	}))
	assert.Equal(t, int64(1), oauthRevocationJobCount(t, db, 7))
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		return model.ScheduleOAuthRevocation(tx, 7, "")
	}))
	assert.Equal(t, common.TokenStatusDisabled, oauthRevocationTokenStatus(t, db, 7, "oauth-oc_other"))
	assert.Equal(t, int64(2), oauthRevocationJobCount(t, db, 7))
}

func oauthRevocationUser(t *testing.T, db *gorm.DB, name, password string) *model.User {
	t.Helper()
	hash, err := common.HashAccountPassword(password)
	require.NoError(t, err)
	user := &model.User{
		Username: name, Password: hash, DisplayName: name, Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: name, Quota: 100,
	}
	require.NoError(t, db.Create(user).Error)
	return user
}

func oauthRevocationTokenStatus(t *testing.T, db *gorm.DB, userID int, name string) int {
	t.Helper()
	var token model.Token
	require.NoError(t, db.Where("user_id = ? AND name = ?", userID, name).First(&token).Error)
	return token.Status
}

func oauthRevocationJobCount(t *testing.T, db *gorm.DB, userID int) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(&model.OAuthRevocationJob{}).Where("user_id = ?", userID).Count(&count).Error)
	return count
}
