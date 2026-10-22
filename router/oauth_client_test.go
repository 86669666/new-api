package router

import (
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

func TestOAuthClientHTTP(t *testing.T) {
	previousPassword := common.PasswordLoginEnabled
	common.PasswordLoginEnabled = true
	t.Cleanup(func() { common.PasswordLoginEnabled = previousPassword })
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	t.Setenv("OAUTH_ISSUED_TOKEN_QUOTA", "")
	t.Setenv("OAUTH_ISSUED_TOKEN_EXPIRE_DAYS", "")
	require.NoError(t, service.InitOAuthUserInfoResource())
	t.Cleanup(func() {
		require.NoError(t, os.Setenv("OAUTH_USERINFO_ENABLED", "false"))
		require.NoError(t, service.InitOAuthUserInfoResource())
		service.UseOAuthProviderBridge(nil)
	})

	f := newOrganizationHTTPFixture(t)
	require.False(t, f.db.Migrator().HasTable(&model.OAuthClient{}))
	require.False(t, f.db.Migrator().HasTable(&model.OAuthAuthorization{}))
	status, payload := oauthClientCall(t, f, http.MethodGet, "/api/oauth/clients", "", "", "")
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "not_found", payload["error"])

	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	t.Setenv("OAUTH_USERINFO_INTROSPECTION_URL", "https://issuer.example/admin/oauth2/introspect")
	t.Setenv("OAUTH_USERINFO_ISSUER", "https://issuer.example/")
	t.Setenv("OAUTH_USERINFO_AUDIENCE", "newapi-userinfo")
	t.Setenv("OAUTH_USERINFO_CLIENT_IDS", "env-client")
	t.Setenv("OAUTH_ISSUED_TOKEN_QUOTA", "0")
	t.Setenv("OAUTH_ISSUED_TOKEN_EXPIRE_DAYS", "30")
	require.NoError(t, service.InitOAuthUserInfoResource())
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(f.db))
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(f.db))
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(f.db))
	require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}, &model.TwoFA{}, &model.PasskeyCredential{}))

	status, payload = oauthClientCall(t, f, http.MethodGet, "/api/oauth/clients", "", "", "")
	assert.Equal(t, http.StatusUnauthorized, status)
	status, _ = oauthClientCall(t, f, http.MethodGet, "/api/oauth/clients", "member", "", "")
	assert.Equal(t, http.StatusForbidden, status)
	_, err := service.GetVerificationRequirements(oauthClientIdentity(t, f.bearer["member"]), service.VerificationScopeOAuthClientManage)
	assert.ErrorIs(t, err, service.ErrVerificationForbidden)

	status, payload = oauthClientCall(t, f, http.MethodGet, "/api/oauth/clients", "root", "", "")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, payload["success"])
	assert.Empty(t, payload["data"])

	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", `{"name":"Boxo","preset":"boxo"}`, "")
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "SECURITY_PROOF_REQUIRED", payload["code"])
	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", `{"name":"Bad","redirects":["javascript:alert(1)"],"scopes":["profile"]}`, "")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, payload["success"])
	assert.Equal(t, "Invalid parameters", payload["message"])
	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", `{"name":"Bad","redirects":["http://evil.example/oauth/callback"],"scopes":["profile"]}`, "")
	assert.Equal(t, false, payload["success"])
	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", `{"name":"Bad","client_secret":"super-secret","preset":"boxo"}`, "")
	assert.Equal(t, false, payload["success"])
	assert.NotContains(t, f.logs.snapshot(), "super-secret")

	boxoName, boxoRedirects, boxoScopes, err := service.NormalizeOAuthClientRegistration("Boxo", "boxo", nil, nil)
	require.NoError(t, err)
	boxoProof := oauthClientProof(t, f.bearer["root"], service.OAuthClientManageContext{
		Action: "create", Name: boxoName, Redirects: boxoRedirects, Scopes: boxoScopes,
	})
	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", `{"name":"Boxo","preset":"boxo"}`, boxoProof)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, payload["success"])
	boxo := payload["data"].(map[string]any)
	boxoID := boxo["client_id"].(string)
	assert.Regexp(t, `^oc_[0-9a-f]{32}$`, boxoID)
	assert.Equal(t, "Boxo", boxo["name"])
	assert.Equal(t, []any{"http://127.0.0.1/oauth/callback"}, boxo["redirects"])
	assert.NotContains(t, boxo, "client_secret")
	assert.True(t, service.OAuthRedirectRegistered("http://127.0.0.1:54321/oauth/callback"))
	assert.False(t, service.OAuthRedirectRegistered("http://127.0.0.1:54321/oauth/other"))
	assert.False(t, service.OAuthRedirectRegistered("http://10.1.2.3:54321/oauth/callback"))
	assert.True(t, service.CurrentOAuthUserInfoResource().AllowsClient("env-client"))
	assert.True(t, service.CurrentOAuthUserInfoResource().AllowsClient(boxoID))

	var audit model.AuditLog
	require.NoError(t, model.LOG_DB.Where("action = ?", "oauth.client.create").Take(&audit).Error)
	assert.Contains(t, audit.Content, boxoID)
	assert.NotContains(t, audit.Content, "secret")

	customName, customRedirects, customScopes, err := service.NormalizeOAuthClientRegistration("App", "", []string{"boxo://oauth/callback", "https://app.example/oauth/callback"}, []string{"profile", "openid"})
	require.NoError(t, err)
	customProof := oauthClientProof(t, f.bearer["root"], service.OAuthClientManageContext{
		Action: "create", Name: customName, Redirects: customRedirects, Scopes: customScopes,
	})
	customBody, err := common.Marshal(map[string]any{"name": "App", "redirects": []string{"https://app.example/oauth/callback", "boxo://oauth/callback"}, "scopes": []string{"openid", "profile"}})
	require.NoError(t, err)
	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", string(customBody), customProof)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, payload["success"])
	custom := payload["data"].(map[string]any)
	customClientID := custom["client_id"].(string)
	assert.NotEqual(t, boxoID, customClientID)
	assert.True(t, service.OAuthRedirectRegistered("https://app.example/oauth/callback"))
	assert.False(t, service.OAuthRedirectRegistered("https://app.example/other"))
	assert.True(t, service.OAuthRedirectRegistered("boxo://oauth/callback"))
	assert.False(t, service.OAuthRedirectRegistered("boxo://oauth/other"))

	for _, slug := range []string{"login", "consent", "logout", "admin", "provider"} {
		err = model.CreateCustomOAuthProvider(&model.CustomOAuthProvider{
			Name: "Reserved", Slug: slug, ClientId: "cid", AuthorizationEndpoint: "https://example.com/auth",
			TokenEndpoint: "https://example.com/token", UserInfoEndpoint: "https://example.com/userinfo",
		})
		assert.EqualError(t, err, "this provider slug is reserved")
	}
	err = model.CreateCustomOAuthProvider(&model.CustomOAuthProvider{
		Name: "Telegram", Slug: "telegram", ClientId: "cid", AuthorizationEndpoint: "https://example.com/auth",
		TokenEndpoint: "https://example.com/token", UserInfoEndpoint: "https://example.com/userinfo",
	})
	assert.EqualError(t, err, "the telegram slug is reserved for built-in Telegram OAuth; rename this custom provider")

	rowID := int(boxo["id"].(float64))
	updatedName, updatedRedirects, updatedScopes, err := service.NormalizeOAuthClientRegistration("Boxo desktop", "boxo", nil, []string{"profile", "offline_access"})
	require.NoError(t, err)
	updateProof := oauthClientProof(t, f.bearer["root"], service.OAuthClientManageContext{
		Action: "update", ClientRowID: rowID, Name: updatedName, Redirects: updatedRedirects, Scopes: updatedScopes,
	})
	updateBody, err := common.Marshal(map[string]any{"name": "Boxo desktop", "preset": "boxo", "scopes": []string{"offline_access", "profile"}, "enabled": true})
	require.NoError(t, err)
	status, payload = oauthClientCall(t, f, http.MethodPut, "/api/oauth/clients/"+strconv.Itoa(rowID), "root", string(updateBody), updateProof)
	require.Equal(t, http.StatusOK, status, payload)
	require.Equal(t, true, payload["success"], payload)
	assert.Equal(t, "Boxo desktop", payload["data"].(map[string]any)["name"])

	plain, first, err := model.IssueOAuthClientToken(f.users["owner"].Id, boxoID, 3, 2)
	require.NoError(t, err)
	require.True(t, first)
	require.NotEmpty(t, plain)
	otherPlain, first, err := model.IssueOAuthClientToken(f.users["owner"].Id, customClientID, 3, 2)
	require.NoError(t, err)
	require.True(t, first)
	require.NoError(t, model.SaveOAuthAuthorization(f.users["owner"].Id, boxoID, "Boxo desktop", "profile offline_access"))
	require.NoError(t, model.SaveOAuthAuthorization(f.users["owner"].Id, customClientID, "App", "openid profile"))
	status, payload = oauthClientCall(t, f, http.MethodGet, "/api/oauth/authorizations", "owner", "", "")
	require.Equal(t, http.StatusOK, status)
	listed := payload["data"].([]any)
	assert.Len(t, listed, 2)
	status, payload = oauthClientCall(t, f, http.MethodDelete, "/api/oauth/authorizations/"+boxoID, "owner", "", "")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, payload["success"])
	var disabledIssued model.OAuthIssuedToken
	require.NoError(t, f.db.Where("user_id = ? AND client_id = ?", f.users["owner"].Id, boxoID).First(&disabledIssued).Error)
	var disabled model.Token
	require.NoError(t, f.db.First(&disabled, disabledIssued.TokenID).Error)
	assert.Equal(t, common.TokenStatusDisabled, disabled.Status)
	var keptIssued model.OAuthIssuedToken
	require.NoError(t, f.db.Where("user_id = ? AND client_id = ?", f.users["owner"].Id, customClientID).First(&keptIssued).Error)
	var kept model.Token
	require.NoError(t, f.db.First(&kept, keptIssued.TokenID).Error)
	assert.Equal(t, common.TokenStatusEnabled, kept.Status)
	assert.NotContains(t, f.logs.snapshot(), plain)
	assert.NotContains(t, f.logs.snapshot(), otherPlain)
	status, payload = oauthClientCall(t, f, http.MethodGet, "/api/oauth/authorizations", "owner", "", "")
	require.Equal(t, true, payload["success"])
	assert.Len(t, payload["data"].([]any), 1)
	status, payload = oauthClientCall(t, f, http.MethodDelete, "/api/oauth/authorizations/"+boxoID, "owner", "", "")
	assert.Equal(t, false, payload["success"])
	assert.Equal(t, "OAuth authorization not found", payload["message"])

	var created atomic.Int32
	var failed atomic.Bool
	var deleted atomic.Int32
	var mu sync.Mutex
	var synced map[string]any
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if readErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodDelete {
			deleted.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if failed.Load() && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var decoded map[string]any
		if common.Unmarshal(body, &decoded) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		synced = decoded
		mu.Unlock()
		created.Add(1)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(admin.Close)
	pool := x509.NewCertPool()
	pool.AddCert(admin.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: "https://issuer.example/",
		Audience: "newapi-userinfo", ClientIDs: []string{"env-client"}, IssuedTokenExpireDays: 30,
	}, pool)
	require.NoError(t, err)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{
		Enabled: true, AdminBaseURL: admin.URL, AuthorizationURL: "https://issuer.example/oauth2/auth",
	}, resource)
	require.NoError(t, err)
	previous := service.UseOAuthProviderBridge(bridge)
	t.Cleanup(func() { service.UseOAuthProviderBridge(previous) })

	hydraName, hydraRedirects, hydraScopes, err := service.NormalizeOAuthClientRegistration("Hydra", "cherry_studio", nil, nil)
	require.NoError(t, err)
	hydraProof := oauthClientProof(t, f.bearer["root"], service.OAuthClientManageContext{
		Action: "create", Name: hydraName, Redirects: hydraRedirects, Scopes: hydraScopes,
	})
	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", `{"name":"Hydra","preset":"cherry_studio"}`, hydraProof)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, payload["success"], payload)
	hydraView := payload["data"].(map[string]any)
	hydraRowID := int(hydraView["id"].(float64))
	hydraClientID := hydraView["client_id"].(string)
	mu.Lock()
	syncedCopy := synced
	mu.Unlock()
	require.NotNil(t, syncedCopy)
	_, hasSecret := syncedCopy["client_secret"]
	assert.False(t, hasSecret)
	assert.Equal(t, false, syncedCopy["skip_consent"])
	assert.Equal(t, "none", syncedCopy["token_endpoint_auth_method"])
	assert.Equal(t, []any{"authorization_code", "refresh_token"}, syncedCopy["grant_types"])
	assert.Equal(t, []any{"code"}, syncedCopy["response_types"])
	assert.Equal(t, []any{"http://127.0.0.1:29873/oauth/callback"}, syncedCopy["redirect_uris"])
	assert.NotContains(t, f.logs.snapshot(), "client_secret")

	assert.Equal(t, int32(1), created.Load())
	failed.Store(true)
	var before int64
	require.NoError(t, f.db.Model(&model.OAuthClient{}).Count(&before).Error)
	rollbackProof := oauthClientProof(t, f.bearer["root"], service.OAuthClientManageContext{
		Action: "create", Name: hydraName, Redirects: hydraRedirects, Scopes: hydraScopes,
	})
	status, payload = oauthClientCall(t, f, http.MethodPost, "/api/oauth/clients", "root", `{"name":"Hydra","preset":"cherry_studio"}`, rollbackProof)
	assert.Equal(t, false, payload["success"])
	var after int64
	require.NoError(t, f.db.Model(&model.OAuthClient{}).Count(&after).Error)
	assert.Equal(t, before, after)

	deleteProof := oauthClientProof(t, f.bearer["root"], service.OAuthClientManageContext{Action: "delete", ClientRowID: hydraRowID})
	status, payload = oauthClientCall(t, f, http.MethodDelete, "/api/oauth/clients/"+strconv.Itoa(hydraRowID), "root", "", deleteProof)
	require.Equal(t, http.StatusOK, status, payload)
	require.Equal(t, true, payload["success"], payload)
	assert.Equal(t, int32(1), deleted.Load())
	assert.True(t, service.CurrentOAuthUserInfoResource().AllowsClient("env-client"))
	assert.False(t, service.CurrentOAuthUserInfoResource().AllowsClient(hydraClientID))
}

func oauthClientCall(t *testing.T, f *organizationHTTPFixture, method, path, actor, body, proof string) (int, map[string]any) {
	t.Helper()
	headers := http.Header{}
	if body != "" {
		headers.Set("Content-Type", "application/json")
	}
	if proof != "" {
		headers.Set("X-Security-Proof", proof)
	}
	status, _, payload := f.request(t, method, path, actor, body, headers)
	return status, payload
}

func oauthClientIdentity(t *testing.T, token string) service.AuthIdentity {
	t.Helper()
	identity, err := service.ParseAccessToken(token)
	require.NoError(t, err)
	return identity
}

func oauthClientProof(t *testing.T, token string, operation service.OAuthClientManageContext) string {
	t.Helper()
	encoded, err := common.Marshal(operation)
	require.NoError(t, err)
	binding, err := service.BindVerificationOperation(service.VerificationOperation{
		Scope: service.VerificationScopeOAuthClientManage, Context: encoded,
	})
	require.NoError(t, err)
	proof, _, err := service.IssueSecurityProof(oauthClientIdentity(t, token), service.VerificationMethodPassword, binding)
	require.NoError(t, err)
	return proof
}

func TestOAuthClientMySQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN is not configured")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	exerciseOAuthClientDialect(t, db, common.DatabaseTypeMySQL)
}

func TestOAuthClientPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not configured")
	}
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true}), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	exerciseOAuthClientDialect(t, db, common.DatabaseTypePostgreSQL)
}

func exerciseOAuthClientDialect(t *testing.T, db *gorm.DB, kind common.DatabaseType) {
	t.Helper()
	previousDB := model.DB
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	previousRedis := common.RedisEnabled
	t.Cleanup(func() {
		model.DB = previousDB
		common.SetDatabaseTypes(previousMain, previousLog)
		common.RedisEnabled = previousRedis
		_ = db.Migrator().DropTable(&model.OAuthClient{}, &model.OAuthAuthorization{}, &model.OAuthIssuedToken{}, &model.Token{})
	})
	model.DB = db
	common.SetDatabaseTypes(kind, kind)
	common.RedisEnabled = false
	require.NoError(t, db.Migrator().DropTable(&model.OAuthClient{}, &model.OAuthAuthorization{}, &model.OAuthIssuedToken{}, &model.Token{}))
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(db))
	require.False(t, db.Migrator().HasTable(&model.OAuthClient{}))
	require.False(t, db.Migrator().HasTable(&model.OAuthAuthorization{}))
	require.NoError(t, db.AutoMigrate(&model.Token{}))
	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(db))
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(db))
	require.NoError(t, model.MigrateOAuthIssuedTokensIfEnabled(db))

	encoded, err := common.Marshal([]string{"http://127.0.0.1/oauth/callback"})
	require.NoError(t, err)
	row := &model.OAuthClient{ClientID: "oc_dialect", Name: "Boxo", RedirectURIs: string(encoded), Scopes: "openid profile", Enabled: true, CreatedAt: 1, UpdatedAt: 1}
	require.NoError(t, model.CreateOAuthClient(row))
	assert.True(t, model.OAuthClientEnabled("oc_dialect"))
	row.Enabled = false
	row.UpdatedAt = 2
	require.NoError(t, model.UpdateOAuthClient(row))
	var stored model.OAuthClient
	require.NoError(t, db.First(&stored, row.ID).Error)
	assert.False(t, stored.Enabled)
	assert.False(t, model.OAuthClientEnabled("oc_dialect"))
	row.Enabled = true
	require.NoError(t, model.UpdateOAuthClient(row))
	assert.True(t, service.OAuthRedirectRegistered("http://127.0.0.1:4242/oauth/callback"))
	assert.False(t, service.OAuthRedirectRegistered("http://127.0.0.1:4242/other"))

	_, first, err := model.IssueOAuthClientToken(7, "oc_dialect", 1, 1)
	require.NoError(t, err)
	assert.True(t, first)
	_, first, err = model.IssueOAuthClientToken(7, "oc_other", 1, 1)
	require.NoError(t, err)
	assert.True(t, first)
	require.NoError(t, model.SaveOAuthAuthorization(7, "oc_dialect", "Boxo", "openid profile"))
	require.NoError(t, model.RevokeOAuthAuthorization(7, "oc_dialect"))
	var dialectToken model.Token
	require.NoError(t, db.Where("user_id = ? AND name = ?", 7, "oauth-oc_dialect").First(&dialectToken).Error)
	assert.Equal(t, common.TokenStatusDisabled, dialectToken.Status)
	var otherToken model.Token
	require.NoError(t, db.Where("user_id = ? AND name = ?", 7, "oauth-oc_other").First(&otherToken).Error)
	assert.Equal(t, common.TokenStatusEnabled, otherToken.Status)
	listed, err := model.ListOAuthAuthorizations(7)
	require.NoError(t, err)
	assert.Empty(t, listed)
}
