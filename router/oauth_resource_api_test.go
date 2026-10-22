package router

import (
	"crypto/x509"
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

func TestOAuthResourceAPIHTTP(t *testing.T) {
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	t.Setenv("OAUTH_ISSUED_TOKEN_QUOTA", "")
	t.Setenv("OAUTH_ISSUED_TOKEN_EXPIRE_DAYS", "")
	require.NoError(t, service.InitOAuthUserInfoResource())
	t.Cleanup(func() {
		require.NoError(t, os.Setenv("OAUTH_USERINFO_ENABLED", "false"))
		require.NoError(t, service.InitOAuthUserInfoResource())
	})
	f := newOrganizationHTTPFixture(t)
	user := f.users["owner"]
	require.False(t, f.db.Migrator().HasTable(&model.OAuthIssuedToken{}))
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(f.db))
	require.False(t, f.db.Migrator().HasTable(&model.OAuthIssuedToken{}))
	for _, path := range []string{"/api/v1/oauth/balance", "/api/v1/oauth/usage", "/api/v1/oauth/tokens"} {
		status, _, _ := f.request(t, http.MethodGet, path, "", "", nil)
		assert.Equal(t, http.StatusNotFound, status, path)
	}
	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(f.db))
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(f.db))
	require.True(t, f.db.Migrator().HasTable(&model.OAuthIssuedToken{}))

	const credential = "fixture-oauth-resource-canary"
	const otherCredential = "fixture-oauth-other-client-canary"
	previousUnit := common.QuotaPerUnit
	t.Cleanup(func() { common.QuotaPerUnit = previousUnit })
	common.QuotaPerUnit = 250000
	require.NoError(t, f.db.Model(user).Updates(map[string]any{"quota": 1000000, "used_quota": 25}).Error)
	manualKey := "manualcanarymanualcanarymanualcanarymanual00"
	require.NoError(t, f.db.Create(&model.Token{
		UserId: user.Id, Key: manualKey, Name: "manual-key", Status: common.TokenStatusEnabled,
		UnlimitedQuota: true, ExpiredTime: -1, RemainQuota: 0,
	}).Error)

	var mu sync.Mutex
	scope := "profile balance:read usage:read tokens:read tokens:write"
	tokenUse := "access_token"
	clientID := "cherry-studio"
	subject := strconv.Itoa(user.Id)
	var failSecond atomic.Bool
	var calls atomic.Int64
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Cookie"))
		if !assert.NoError(t, r.ParseForm()) || len(r.PostForm["token"]) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := calls.Add(1)
		token := r.PostForm.Get("token")
		active := token == credential || token == otherCredential
		mu.Lock()
		body := map[string]any{
			"active": active, "token_use": tokenUse, "token_type": "Bearer",
			"iss": "https://issuer.example/", "aud": []string{"newapi-userinfo"},
			"client_id": clientID, "sub": subject, "exp": time.Now().Unix() + 3600,
			"scope": scope, "ext": map[string]any{"newapi_auth_version": "1"},
		}
		if token == otherCredential {
			body["client_id"] = "other-client"
		}
		if failSecond.Load() && n%2 == 0 {
			body = map[string]any{"active": false}
		}
		mu.Unlock()
		data, err := common.Marshal(body)
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(issuer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: issuer.URL + "/admin/oauth2/introspect",
		Issuer: "https://issuer.example/", Audience: "newapi-userinfo",
		ClientIDs: []string{"cherry-studio", "other-client"},
	}, roots)
	require.NoError(t, err)
	require.Equal(t, 0, resource.IssuedTokenQuota())
	require.Equal(t, 30, resource.IssuedTokenExpireDays())
	t.Cleanup(resource.CloseIdleConnections)
	SetOAuthResourceRouter(f.engine, resource)

	call := func(method, path, actor string) (int, http.Header, map[string]any) {
		t.Helper()
		return f.request(t, method, path, actor, "", nil)
	}
	setScope := func(value string) {
		mu.Lock()
		scope = value
		tokenUse = "access_token"
		mu.Unlock()
	}

	t.Run("balance", func(t *testing.T) {
		setScope("profile balance:read")
		status, header, body := call(http.MethodGet, "/api/v1/oauth/balance", credential)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "private, no-store", header.Get("Cache-Control"))
		require.Equal(t, true, body["success"])
		data := body["data"].(map[string]any)
		assert.Equal(t, 1000000.0, data["quota"])
		assert.Equal(t, 25.0, data["used_quota"])
		assert.Equal(t, 250000.0, data["quota_per_unit"])
		assert.Equal(t, 4.0, data["display_amount"])

		setScope("profile")
		status, header, body = call(http.MethodGet, "/api/v1/oauth/balance", credential)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, map[string]any{"error": "insufficient_scope"}, body)
		assert.Equal(t, `Bearer error="insufficient_scope", scope="balance:read"`, header.Get("WWW-Authenticate"))

		mu.Lock()
		tokenUse = "refresh_token"
		scope = "profile balance:read"
		mu.Unlock()
		status, header, body = call(http.MethodGet, "/api/v1/oauth/balance", credential)
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Equal(t, map[string]any{"error": "invalid_token"}, body)
		assert.Equal(t, `Bearer error="invalid_token"`, header.Get("WWW-Authenticate"))
		setScope("profile balance:read")

		calls.Store(0)
		failSecond.Store(true)
		status, _, body = call(http.MethodGet, "/api/v1/oauth/balance", credential)
		failSecond.Store(false)
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Equal(t, "invalid_token", body["error"])

		common.QuotaPerUnit = 0
		status, _, body = call(http.MethodGet, "/api/v1/oauth/balance", credential)
		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, "temporarily_unavailable", body["error"])
		common.QuotaPerUnit = 250000

		status, _, _ = call(http.MethodGet, "/api/v1/oauth/balance/", credential)
		assert.Equal(t, http.StatusUnauthorized, status)

		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.Id).Update("status", common.UserStatusDisabled).Error)
		status, _, body = call(http.MethodGet, "/api/v1/oauth/balance", credential)
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Equal(t, "invalid_token", body["error"])
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.Id).Update("status", common.UserStatusEnabled).Error)
	})

	t.Run("usage", func(t *testing.T) {
		require.NoError(t, model.LOG_DB.Create(&model.Log{
			UserId: user.Id, CreatedAt: common.GetTimestamp(), Type: model.LogTypeConsume,
			ModelName: "oauth-usage-fixture", Quota: 3, TokenName: "oauth-usage",
		}).Error)
		setScope("profile usage:read")
		status, _, body := call(http.MethodGet, "/api/v1/oauth/usage", credential)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, true, body["success"])
		data := body["data"].(map[string]any)
		assert.GreaterOrEqual(t, data["total"], 1.0)
		assert.Equal(t, 1.0, data["page"])
		assert.NotEmpty(t, data["items"])

		status, _, body = call(http.MethodGet, "/api/v1/oauth/usage?page=2", credential)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, 2.0, body["data"].(map[string]any)["page"])
		status, _, body = call(http.MethodGet, "/api/v1/oauth/usage?p=3&page=1", credential)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, 3.0, body["data"].(map[string]any)["page"])

		for _, path := range []string{"?p=0", "?p=abc", "?page=0", "?page_size=0", "?page_size=101", "?ps=0", "?size=nope", "?start_timestamp=1"} {
			status, _, body = call(http.MethodGet, "/api/v1/oauth/usage"+path, credential)
			assert.Equal(t, http.StatusBadRequest, status, path)
			assert.Equal(t, map[string]any{"error": "invalid_request"}, body, path)
		}
		setScope("profile")
		status, header, body := call(http.MethodGet, "/api/v1/oauth/usage", credential)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, `Bearer error="insufficient_scope", scope="usage:read"`, header.Get("WWW-Authenticate"))
	})

	t.Run("tokens", func(t *testing.T) {
		var before int64
		require.NoError(t, f.db.Model(&model.Token{}).Where("user_id = ?", user.Id).Count(&before).Error)
		setScope("profile tokens:read tokens:write")
		status, _, body := call(http.MethodGet, "/api/v1/oauth/tokens", credential)
		require.Equal(t, http.StatusOK, status)
		assert.Empty(t, body["data"])
		var afterGet int64
		require.NoError(t, f.db.Model(&model.Token{}).Where("user_id = ?", user.Id).Count(&afterGet).Error)
		assert.Equal(t, before, afterGet)

		setScope("profile tokens:read")
		status, header, body := call(http.MethodPost, "/api/v1/oauth/tokens", credential)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, `Bearer error="insufficient_scope", scope="tokens:write"`, header.Get("WWW-Authenticate"))

		setScope("profile tokens:read tokens:write")
		status, _, body = call(http.MethodPost, "/api/v1/oauth/tokens", credential)
		require.Equal(t, http.StatusOK, status)
		created := body["data"].([]any)
		require.Len(t, created, 1)
		key := created[0].(map[string]any)["key"].(string)
		assert.Regexp(t, `^sk-[A-Za-z0-9]{48}$`, key)
		var afterPost int64
		require.NoError(t, f.db.Model(&model.Token{}).Where("user_id = ?", user.Id).Count(&afterPost).Error)
		assert.Equal(t, before+1, afterPost)

		status, _, body = call(http.MethodPost, "/api/v1/oauth/tokens", credential)
		require.Equal(t, http.StatusOK, status)
		again := body["data"].([]any)
		require.Len(t, again, 1)
		_, revealed := again[0].(map[string]any)["key"]
		assert.False(t, revealed)
		encoded, err := common.Marshal(body)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), key)

		status, _, body = call(http.MethodGet, "/api/v1/oauth/tokens", credential)
		require.Equal(t, http.StatusOK, status)
		listed := body["data"].([]any)
		require.Len(t, listed, 1)
		item := listed[0].(map[string]any)
		assert.Equal(t, "oauth-cherry-studio", item["name"])
		assert.Equal(t, float64(common.TokenStatusEnabled), item["status"])
		assert.Equal(t, 0.0, item["remain_quota"])
		assert.Equal(t, false, item["unlimited_quota"])
		assert.Greater(t, item["expired_time"], float64(common.GetTimestamp()))
		_, hasKey := item["key"]
		assert.False(t, hasKey)
		encoded, err = common.Marshal(body)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), key)
		assert.NotContains(t, string(encoded), manualKey)
		assert.NotContains(t, f.logs.snapshot(), key)

		status, _, body = call(http.MethodGet, "/api/v1/oauth/tokens", otherCredential)
		require.Equal(t, http.StatusOK, status)
		assert.Empty(t, body["data"])
		status, _, body = call(http.MethodPost, "/api/v1/oauth/tokens", otherCredential)
		require.Equal(t, http.StatusOK, status)
		otherKey := body["data"].([]any)[0].(map[string]any)["key"].(string)
		assert.NotEqual(t, key, otherKey)

		require.NoError(t, model.DisableOAuthIssuedTokens(user.Id, "cherry-studio"))
		var cherry, other model.OAuthIssuedToken
		require.NoError(t, f.db.Where("user_id = ? AND client_id = ?", user.Id, "cherry-studio").First(&cherry).Error)
		require.NoError(t, f.db.Where("user_id = ? AND client_id = ?", user.Id, "other-client").First(&other).Error)
		var cherryToken, otherToken, manual model.Token
		require.NoError(t, f.db.First(&cherryToken, cherry.TokenID).Error)
		require.NoError(t, f.db.First(&otherToken, other.TokenID).Error)
		require.NoError(t, f.db.Where("key = ?", manualKey).First(&manual).Error)
		assert.Equal(t, common.TokenStatusDisabled, cherryToken.Status)
		assert.Equal(t, common.TokenStatusEnabled, otherToken.Status)
		assert.Equal(t, common.TokenStatusEnabled, manual.Status)

		status, _, _ = call(http.MethodPost, "/api/user/auth/logout", "owner")
		require.Equal(t, http.StatusOK, status)
		require.NoError(t, f.db.First(&otherToken, other.TokenID).Error)
		require.NoError(t, f.db.Where("key = ?", manualKey).First(&manual).Error)
		assert.Equal(t, common.TokenStatusDisabled, otherToken.Status)
		assert.Equal(t, common.TokenStatusEnabled, manual.Status)

		plain, first, err := model.IssueOAuthClientToken(user.Id, "quota-client", 7, 2)
		require.NoError(t, err)
		assert.True(t, first)
		assert.Regexp(t, `^sk-[A-Za-z0-9]{48}$`, plain)
		status, _, _ = call(http.MethodGet, "/v1/models", plain)
		assert.Equal(t, http.StatusOK, status)
		require.NoError(t, model.DisableOAuthIssuedTokens(user.Id, "quota-client"))
		status, _, body = call(http.MethodGet, "/v1/models", plain)
		assert.Equal(t, http.StatusUnauthorized, status)
		second, first, err := model.IssueOAuthClientToken(user.Id, "quota-client", 7, 2)
		require.NoError(t, err)
		assert.False(t, first)
		assert.Empty(t, second)
		var capped model.Token
		require.NoError(t, f.db.Where("user_id = ? AND name = ?", user.Id, "oauth-quota-client").First(&capped).Error)
		assert.Equal(t, 7, capped.RemainQuota)
		assert.False(t, capped.UnlimitedQuota)
		assert.Greater(t, capped.ExpiredTime, common.GetTimestamp())
		assert.LessOrEqual(t, capped.ExpiredTime, common.GetTimestamp()+2*86400+2)
		_, _, err = model.IssueOAuthClientToken(0, "quota-client", 7, 2)
		assert.Error(t, err)
	})

	t.Run("policy", func(t *testing.T) {
		_, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
			Enabled: true, IntrospectionURL: issuer.URL + "/admin/oauth2/introspect",
			Issuer: "https://issuer.example/", Audience: "newapi-userinfo",
			ClientIDs: []string{"cherry-studio"}, IssuedTokenQuota: -1,
		}, roots)
		assert.ErrorIs(t, err, service.ErrOAuthResourceConfiguration)
		days, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
			Enabled: true, IntrospectionURL: issuer.URL + "/admin/oauth2/introspect",
			Issuer: "https://issuer.example/", Audience: "newapi-userinfo",
			ClientIDs: []string{"cherry-studio"}, IssuedTokenExpireDays: 0,
		}, roots)
		require.NoError(t, err)
		t.Cleanup(days.CloseIdleConnections)
		assert.Equal(t, 30, days.IssuedTokenExpireDays())
		assert.Equal(t, 0, days.IssuedTokenQuota())

		t.Setenv("OAUTH_USERINFO_ENABLED", "true")
		for _, daysText := range []string{"0", "3651", "nope"} {
			t.Setenv("OAUTH_ISSUED_TOKEN_EXPIRE_DAYS", daysText)
			assert.ErrorIs(t, service.InitOAuthUserInfoResource(), service.ErrOAuthResourceConfiguration, daysText)
		}
		t.Setenv("OAUTH_ISSUED_TOKEN_EXPIRE_DAYS", "30")
		t.Setenv("OAUTH_ISSUED_TOKEN_QUOTA", "-5")
		assert.ErrorIs(t, service.InitOAuthUserInfoResource(), service.ErrOAuthResourceConfiguration)
		t.Setenv("OAUTH_USERINFO_ENABLED", "false")
		t.Setenv("OAUTH_ISSUED_TOKEN_EXPIRE_DAYS", "nope")
		assert.NoError(t, service.InitOAuthUserInfoResource())
	})
}

func TestOAuthIssuedTokenMySQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN is not configured")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	exerciseOAuthIssuedTokenDialect(t, db, common.DatabaseTypeMySQL)
}

func TestOAuthIssuedTokenPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not configured")
	}
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true}), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	exerciseOAuthIssuedTokenDialect(t, db, common.DatabaseTypePostgreSQL)
}

// exerciseOAuthIssuedTokenDialect checks the association table on one live
// engine: disabled startup leaves the schema alone, enabling it adds the table
// beside an existing relay key, and issue/list/disable honor that binding.
func exerciseOAuthIssuedTokenDialect(t *testing.T, db *gorm.DB, kind common.DatabaseType) {
	t.Helper()
	previousDB := model.DB
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	previousRedis := common.RedisEnabled
	t.Cleanup(func() {
		model.DB = previousDB
		common.SetDatabaseTypes(previousMain, previousLog)
		common.RedisEnabled = previousRedis
		_ = db.Migrator().DropTable(&model.OAuthIssuedToken{}, &model.Token{})
	})
	model.DB = db
	common.SetDatabaseTypes(kind, kind)
	common.RedisEnabled = false
	require.NoError(t, db.Migrator().DropTable(&model.OAuthIssuedToken{}, &model.Token{}))

	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(db))
	require.False(t, db.Migrator().HasTable(&model.OAuthIssuedToken{}))
	require.NoError(t, model.DisableOAuthIssuedTokensForUser(1))

	require.NoError(t, db.AutoMigrate(&model.Token{}))
	manual := &model.Token{UserId: 1, Key: "manual-upgrade-key", Name: "manual", Status: common.TokenStatusEnabled, UnlimitedQuota: true, ExpiredTime: -1}
	require.NoError(t, db.Create(manual).Error)
	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(db))
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(db))

	var still model.Token
	require.NoError(t, db.First(&still, manual.Id).Error)
	assert.Equal(t, "manual-upgrade-key", still.Key)
	assert.True(t, still.UnlimitedQuota)
	assert.Equal(t, int64(-1), still.ExpiredTime)

	plain, first, err := model.IssueOAuthClientToken(1, "boxo", 9, 3)
	require.NoError(t, err)
	assert.True(t, first)
	assert.Regexp(t, `^sk-[A-Za-z0-9]{48}$`, plain)
	again, first, err := model.IssueOAuthClientToken(1, "boxo", 9, 3)
	require.NoError(t, err)
	assert.False(t, first)
	assert.Empty(t, again)

	listed, err := model.ListOAuthIssuedTokens(1, "boxo")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Empty(t, listed[0].Key)
	assert.Equal(t, 9, listed[0].RemainQuota)
	assert.False(t, listed[0].UnlimitedQuota)
	assert.Greater(t, listed[0].ExpiredTime, common.GetTimestamp())
	other, err := model.ListOAuthIssuedTokens(1, "other")
	require.NoError(t, err)
	assert.Empty(t, other)

	require.NoError(t, model.DisableOAuthIssuedTokens(1, "boxo"))
	var stored model.Token
	require.NoError(t, db.First(&stored, listed[0].Id).Error)
	assert.Equal(t, common.TokenStatusDisabled, stored.Status)
	require.NoError(t, db.First(&still, manual.Id).Error)
	assert.Equal(t, common.TokenStatusEnabled, still.Status)

	_, first, err = model.IssueOAuthClientToken(1, "other", 1, 1)
	require.NoError(t, err)
	assert.True(t, first)
	require.NoError(t, model.DisableOAuthIssuedTokensForUser(1))
	var second model.Token
	require.NoError(t, db.Where("user_id = ? AND name = ?", 1, "oauth-other").First(&second).Error)
	assert.Equal(t, common.TokenStatusDisabled, second.Status)
	require.NoError(t, db.First(&still, manual.Id).Error)
	assert.Equal(t, common.TokenStatusEnabled, still.Status)
}
