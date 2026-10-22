package service

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestOAuthScopeGrantAndMapping(t *testing.T) {
	requested := []string{"openid", "profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write", "admin"}
	registered := []string{"profile", "email", "tokens:read", "tokens:write", "balance:read", "usage:read", "openid"}
	allowed, err := oauthProviderAllowedScopes(requested, registered)
	require.NoError(t, err)
	assert.Equal(t, []string{"openid", "profile", "email", "balance:read", "usage:read", "tokens:read", "tokens:write"}, allowed)

	_, err = oauthProviderAllowedScopes([]string{"email", "openid"}, registered)
	assert.ErrorIs(t, err, ErrOAuthProviderDenied)

	require.NoError(t, oauthProviderGrantScopes([]string{"profile", "tokens:read"}, allowed))
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"email"}, allowed), ErrOAuthProviderDenied)
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"profile", "offline_access"}, allowed), ErrOAuthProviderDenied)
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"profile", "profile"}, allowed), ErrOAuthProviderDenied)
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"profile", "api_key:reveal"}, allowed), ErrOAuthProviderDenied)

	mapped := OAuthAccessTokenScopes([]string{"openid", "profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write"})
	assert.Equal(t, []string{"profile:read", "wallet:read", "usage:read", "api_key:read", "api_key:write"}, mapped)
	assert.NotContains(t, mapped, "api_key:reveal")
	assert.Empty(t, OAuthAccessTokenScopes([]string{"openid", "offline_access"}))

	assert.NoError(t, OAuthResourceRequireScope([]string{"profile", "tokens:read"}, "profile"))
	assert.NoError(t, OAuthResourceRequireScope([]string{"profile", "tokens:read"}, "tokens:read"))
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"openid"}, "profile"), ErrOAuthInsufficientScope)
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"profile", "balance:read"}, "usage:read"), ErrOAuthInsufficientScope)
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"profile", "tokens:read"}, "api_key:read"), ErrOAuthInsufficientScope)
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"profile"}, "api_key:reveal"), ErrOAuthInsufficientScope)

	assert.False(t, oauthScopeGrantsOfflineAccess("openid profile email"))
	assert.False(t, oauthScopeGrantsOfflineAccess("openid offline_access_extra"))
	assert.True(t, oauthScopeGrantsOfflineAccess("openid offline_access email"))
	assert.Equal(t, []string{"openid", "profile"}, filterOAuthScopeNames([]string{"openid", "profile", "admin", "bad scope"}))
}

func TestOAuthClientRedirectRules(t *testing.T) {
	assert.False(t, ValidOAuthClientRedirect("javascript:alert(1)"))
	assert.False(t, ValidOAuthClientRedirect("data:text/html,hi"))
	assert.False(t, ValidOAuthClientRedirect("file:///tmp/x"))
	assert.False(t, ValidOAuthClientRedirect("http://evil.example/oauth/callback"))
	assert.False(t, ValidOAuthClientRedirect("https://app.example"))
	assert.False(t, ValidOAuthClientRedirect("https://app.example/oauth/callback?code=1"))
	assert.True(t, ValidOAuthClientRedirect("http://127.0.0.1/oauth/callback"))
	assert.True(t, ValidOAuthClientRedirect("http://127.0.0.1:29873/oauth/callback"))
	assert.True(t, ValidOAuthClientRedirect("http://[::1]/oauth/callback"))
	assert.True(t, ValidOAuthClientRedirect("https://app.example/oauth/callback"))
	assert.True(t, ValidOAuthClientRedirect("boxo://oauth/callback"))
	assert.True(t, ValidOAuthClientRedirect("cherrystudio://oauth/callback"))
	assert.False(t, ValidOAuthClientRedirect("boxo://oauth/callback?next=1"))

	redirects, scopes, ok := OAuthClientPreset("boxo")
	require.True(t, ok)
	assert.Equal(t, []string{"http://127.0.0.1/oauth/callback"}, redirects)
	assert.Equal(t, oauthProviderKnownScopes, scopes)
	redirects, _, ok = OAuthClientPreset("cherry_studio")
	require.True(t, ok)
	assert.Equal(t, []string{"http://127.0.0.1:29873/oauth/callback"}, redirects)
	_, _, ok = OAuthClientPreset("other")
	assert.False(t, ok)

	assert.True(t, validOAuthProviderRedirect("http://127.0.0.1:4242/oauth/callback", "http://127.0.0.1/oauth/callback"))
	assert.False(t, validOAuthProviderRedirect("http://127.0.0.1:4242/oauth/other", "http://127.0.0.1/oauth/callback"))
	assert.False(t, validOAuthProviderRedirect("http://10.1.2.3:4242/oauth/callback", "http://127.0.0.1/oauth/callback"))
	assert.True(t, validOAuthProviderRedirect("https://app.example/oauth/callback", "https://app.example/oauth/callback"))
	assert.False(t, validOAuthProviderRedirect("https://app.example/oauth/callback", "https://other.example/oauth/callback"))
	assert.True(t, validOAuthProviderRedirect("boxo://oauth/callback", "boxo://oauth/callback"))
	assert.False(t, validOAuthProviderRedirect("javascript://oauth/callback", "javascript://oauth/callback"))
	assert.True(t, validOAuthProviderRedirect("cherrystudio://oauth/callback", "cherrystudio://oauth/callback"))
}

func TestOAuthRegisteredRedirectIsNotHostRewritten(t *testing.T) {
	previousDB := model.DB
	previousAddress := system_setting.ServerAddress
	t.Cleanup(func() {
		model.DB = previousDB
		system_setting.ServerAddress = previousAddress
	})
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "oauth-clients.db")), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	model.DB = db
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(db))
	require.False(t, db.Migrator().HasTable(&model.OAuthClient{}))
	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(db))
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(db))
	encoded, err := common.Marshal([]string{"https://app.example/oauth/callback", "http://127.0.0.1/oauth/callback"})
	require.NoError(t, err)
	require.NoError(t, model.CreateOAuthClient(&model.OAuthClient{
		ClientID: "oc_test", Name: "Boxo", RedirectURIs: string(encoded), Scopes: "openid profile", Enabled: true,
	}))
	system_setting.ServerAddress = "https://auth.example"
	bridge := &OAuthProviderBridge{upstream: "https://hydra.example:4444", resource: &OAuthUserInfoResource{issuer: "https://auth.example/"}}

	got, err := bridge.rewriteLocation("https://app.example/oauth/callback", []string{"app.example"})
	require.NoError(t, err)
	assert.Equal(t, "https://app.example/oauth/callback", got)
	got, err = bridge.rewriteLocation("http://127.0.0.1:4242/oauth/callback", []string{"127.0.0.1"})
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:4242/oauth/callback", got)
	_, err = bridge.rewriteLocation("https://evil.example/oauth/callback", []string{"evil.example"})
	assert.ErrorIs(t, err, ErrOAuthResourceUnavailable)
	_, err = bridge.rewriteLocation("https://app.example/other", nil)
	assert.ErrorIs(t, err, ErrOAuthResourceUnavailable)

	require.NoError(t, db.Model(&model.OAuthClient{}).Where("client_id = ?", "oc_test").Update("enabled", false).Error)
	_, err = bridge.rewriteLocation("https://app.example/oauth/callback", nil)
	assert.ErrorIs(t, err, ErrOAuthResourceUnavailable)
}

func TestDesktopOAuthStatus(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	resource, err := NewOAuthUserInfoResource(OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: server.URL + "/admin/oauth2/introspect",
		Issuer: "https://auth.example/", Audience: "newapi-userinfo", ClientIDs: []string{"env-client"},
	}, pool)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := NewOAuthProviderBridge(OAuthProviderConfig{
		Enabled: true, RevocationEnabled: true, PublicProxy: true,
		AdminBaseURL: server.URL, AuthorizationURL: "https://auth.example/oauth2/auth",
		UpstreamURL: "https://hydra.example:4444",
	}, resource)
	require.NoError(t, err)
	previous := UseOAuthProviderBridge(nil)
	t.Cleanup(func() { UseOAuthProviderBridge(previous) })

	disabled, feature := DesktopOAuthStatus(context.Background())
	assert.Equal(t, map[string]any{"enabled": false}, disabled)
	assert.False(t, feature)
	assert.Equal(t, int32(0), hits.Load())

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "oauth-status.db")), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	previousDB := model.DB
	t.Cleanup(func() { model.DB = previousDB })
	model.DB = db
	t.Setenv("OAUTH_USERINFO_ENABLED", "true")
	require.NoError(t, model.MigrateOAuthClientsIfEnabled(db))
	boxoID := "oc_" + strings.Repeat("a", 32)
	cherryID := "oc_" + strings.Repeat("b", 32)
	require.NoError(t, model.CreateOAuthClient(&model.OAuthClient{
		ClientID: boxoID, Name: "Boxo", RedirectURIs: `["http://127.0.0.1/oauth/callback"]`, Scopes: "openid profile", Enabled: true,
	}))

	UseOAuthProviderBridge(bridge)
	status, feature := DesktopOAuthStatus(context.Background())
	assert.True(t, feature)
	assert.Equal(t, true, status["enabled"])
	assert.Equal(t, "https://auth.example/", status["issuer"])
	assert.Equal(t, boxoID, status["desktop_client_id"])
	assert.Equal(t, map[string]string{"boxo": boxoID}, status["desktop_clients"])
	assert.Equal(t, int32(1), hits.Load())
	encoded, err := common.Marshal(status)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), server.URL)
	assert.NotContains(t, string(encoded), "client_secret")
	assert.NotContains(t, string(encoded), "env-client")

	status, feature = DesktopOAuthStatus(context.Background())
	assert.True(t, feature)
	assert.Equal(t, int32(1), hits.Load())

	require.NoError(t, model.CreateOAuthClient(&model.OAuthClient{
		ClientID: cherryID, Name: "Cherry", RedirectURIs: `["http://127.0.0.1:29873/oauth/callback"]`, Scopes: "openid profile", Enabled: true,
	}))
	status, _ = DesktopOAuthStatus(context.Background())
	assert.Equal(t, boxoID, status["desktop_client_id"])
	assert.Equal(t, map[string]string{"boxo": boxoID, "cherry_studio": cherryID}, status["desktop_clients"])
	assert.Equal(t, int32(1), hits.Load())

	bridge.readyUntil = time.Time{}
	fail.Store(true)
	status, feature = DesktopOAuthStatus(context.Background())
	assert.False(t, feature)
	assert.Equal(t, map[string]any{"enabled": false}, status)
	assert.Equal(t, int32(2), hits.Load())
	status, feature = DesktopOAuthStatus(context.Background())
	assert.False(t, feature)
	assert.Equal(t, int32(2), hits.Load())

	local, err := NewOAuthProviderBridge(OAuthProviderConfig{
		Enabled: true, AdminBaseURL: server.URL, AuthorizationURL: "https://auth.example/oauth2/auth",
	}, resource)
	require.NoError(t, err)
	UseOAuthProviderBridge(local)
	status, feature = DesktopOAuthStatus(context.Background())
	assert.False(t, feature)
	assert.Equal(t, map[string]any{"enabled": false}, status)
	assert.Equal(t, int32(2), hits.Load())
}
