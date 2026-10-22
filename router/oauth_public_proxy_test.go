package router

import (
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthPublicProxyHTTP(t *testing.T) {
	oldAPI, oldNum, oldDuration := common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration
	oldCritical, oldRedis, oldMaster := common.CriticalRateLimitEnable, common.RedisEnabled, common.IsMasterNode
	oldAddress := system_setting.ServerAddress
	oldWriter, oldMode := gin.DefaultWriter, gin.Mode()
	common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable, common.RedisEnabled = false, false, false
	common.IsMasterNode = false
	system_setting.ServerAddress = "https://gateway.example"
	gin.SetMode(gin.TestMode)
	logs := &organizationLogBuffer{}
	gin.DefaultWriter = logs
	t.Cleanup(func() {
		common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = oldAPI, oldNum, oldDuration
		common.CriticalRateLimitEnable, common.RedisEnabled, common.IsMasterNode = oldCritical, oldRedis, oldMaster
		system_setting.ServerAddress = oldAddress
		gin.DefaultWriter = oldWriter
		gin.SetMode(oldMode)
	})
	t.Setenv("TRUSTED_PROXIES", "none")
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_BRIDGE_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_REVOCATION_ENABLED", "false")
	t.Setenv("OAUTH_PUBLIC_PROXY_ENABLED", "false")
	require.NoError(t, service.InitOAuthUserInfoResource())
	require.NoError(t, service.InitOAuthProviderBridge())

	const canary = "oauth-proxy-canary"
	const issuer = "https://gateway.example/"
	const publicAuth = "https://gateway.example/oauth2/auth"
	var pkce [32]byte
	for i := range pkce {
		pkce[i] = byte(i + 1)
	}
	challenge := base64.RawURLEncoding.EncodeToString(pkce[:])
	loopback := "http://127.0.0.1:54321/oauth/callback"
	authQuery := url.Values{
		"client_id": {"boxo"}, "response_type": {"code"}, "redirect_uri": {loopback},
		"scope": {"openid profile email"}, "state": {"state-" + canary},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	t.Run("startup_rejects_partial_config", func(t *testing.T) {
		for _, value := range []string{"TRUE", "1", " ", "yes"} {
			t.Setenv("OAUTH_PUBLIC_PROXY_ENABLED", value)
			assert.ErrorIs(t, service.InitOAuthProviderBridge(), service.ErrOAuthProviderConfiguration)
		}
		t.Setenv("OAUTH_PUBLIC_PROXY_ENABLED", "true")
		assert.ErrorIs(t, service.InitOAuthProviderBridge(), service.ErrOAuthProviderConfiguration)
		t.Setenv("OAUTH_PUBLIC_PROXY_ENABLED", "false")
		t.Setenv("OAUTH_PROVIDER_UPSTREAM_URL", "http://not-used.example")
		require.NoError(t, service.InitOAuthProviderBridge())
		assert.Nil(t, service.CurrentOAuthProviderBridge())
	})

	t.Run("disabled_snapshot", func(t *testing.T) {
		dbBefore := model.DB
		for _, split := range []bool{false, true} {
			frontend := ""
			if split {
				frontend = "https://frontend.invalid"
			}
			t.Setenv("FRONTEND_BASE_URL", frontend)
			e := gin.New()
			middleware.SetUpLogger(e)
			SetRouter(e, WebAssets{IndexPage: []byte("owned-SPA-fallback")})
			for _, path := range []string{"/oauth2/auth?" + authQuery, "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/oauth2/token"} {
				w := httptest.NewRecorder()
				e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				if split {
					assert.Equal(t, http.StatusMovedPermanently, w.Code)
					assert.Equal(t, frontend+path, w.Header().Get("Location"))
				} else if path == "/oauth2/token" {
					assert.Equal(t, "owned-SPA-fallback", w.Body.String())
				} else {
					assert.Equal(t, http.StatusOK, w.Code)
					assert.Equal(t, "owned-SPA-fallback", w.Body.String())
				}
				assert.NotContains(t, w.Body.String(), "private, no-store")
			}
			w := httptest.NewRecorder()
			e.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/oauth2/revoke?token="+canary, strings.NewReader("token="+canary)))
			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.JSONEq(t, `{"error":"not_found"}`, w.Body.String())
			assert.Empty(t, w.Header().Get("Location"))
		}
		assert.Equal(t, dbBefore, model.DB)
		t.Setenv("FRONTEND_BASE_URL", "")
	})

	var adminCalls atomic.Int64
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminCalls.Add(1)
		http.Error(w, canary, http.StatusInternalServerError)
	}))
	t.Cleanup(admin.Close)
	var mu sync.Mutex
	var calls int
	var lastHost, lastForwardedHost, lastQuery, lastBody, lastPath string
	var forbiddenSeen []string
	replyStatus := http.StatusOK
	replyLocation := ""
	replyBody := ""
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		lastHost, lastPath, lastQuery = r.Host, r.URL.Path, r.URL.RawQuery
		lastForwardedHost = r.Header.Get("X-Forwarded-Host")
		data, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		lastBody = string(data)
		for _, name := range []string{"Cookie", "Authorization", "Forwarded", "X-Forwarded-For"} {
			if r.Header.Get(name) != "" {
				forbiddenSeen = append(forbiddenSeen, name+"="+r.Header.Get(name))
			}
		}
		if replyLocation != "" {
			w.Header().Set("Location", replyLocation)
		}
		w.WriteHeader(replyStatus)
		_, _ = io.WriteString(w, replyBody)
	}))
	t.Cleanup(upstream.Close)
	setReply := func(status int, location, body string) {
		mu.Lock()
		defer mu.Unlock()
		replyStatus, replyLocation, replyBody = status, location, body
	}
	roots := x509.NewCertPool()
	roots.AddCert(admin.Certificate())
	roots.AddCert(upstream.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: issuer,
		Audience: "newapi-userinfo", ClientIDs: []string{"boxo"},
	}, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	baseConfig := service.OAuthProviderConfig{
		Enabled: true, RevocationEnabled: true, PublicProxy: true, AdminBaseURL: admin.URL + "/",
		AuthorizationURL: publicAuth, UpstreamURL: upstream.URL,
	}
	bridge, err := service.NewOAuthProviderBridge(baseConfig, resource)
	require.NoError(t, err)
	require.True(t, bridge.PublicProxyEnabled())

	t.Run("constructor_rejects_open_proxy", func(t *testing.T) {
		for _, upstreamURL := range []string{"https://gateway.example", "https://gateway.example:443", admin.URL, "http://upstream.example", "https://upstream.example/hydra", ""} {
			cfg := baseConfig
			cfg.UpstreamURL = upstreamURL
			_, err := service.NewOAuthProviderBridge(cfg, resource)
			assert.ErrorIs(t, err, service.ErrOAuthProviderConfiguration)
		}
		cfg := baseConfig
		cfg.PublicProxy = false
		cfg.RevocationEnabled = false
		cfg.UpstreamURL = "http://not-used.example"
		plain, err := service.NewOAuthProviderBridge(cfg, resource)
		require.NoError(t, err)
		assert.False(t, plain.PublicProxyEnabled())
		prefixed, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
			Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: "https://gateway.example/tenant/",
			Audience: "newapi-userinfo", ClientIDs: []string{"boxo"},
		}, roots)
		require.NoError(t, err)
		t.Cleanup(prefixed.CloseIdleConnections)
		cfg = baseConfig
		cfg.AuthorizationURL = "https://gateway.example/tenant/oauth2/auth"
		_, err = service.NewOAuthProviderBridge(cfg, prefixed)
		assert.ErrorIs(t, err, service.ErrOAuthProviderConfiguration)
		cfg.PublicProxy = false
		cfg.UpstreamURL = ""
		legacy, err := service.NewOAuthProviderBridge(cfg, prefixed)
		require.NoError(t, err)
		assert.False(t, legacy.PublicProxyEnabled())
	})

	e := gin.New()
	middleware.SetUpLogger(e)
	SetOAuthProviderRouter(e, bridge)
	e.NoRoute(func(c *gin.Context) {
		c.String(http.StatusOK, "owned-SPA-fallback")
	})
	call := func(method, path, body string, headers http.Header) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.40:43210"
		r.Host = "forged.example"
		r.Header.Set("X-Forwarded-Host", "also-forged.example")
		r.Header.Set("Forwarded", `for=198.51.100.8;host="third-forged.example";proto=http`)
		r.Header.Set("X-Forwarded-For", "198.51.100.8")
		r.Header.Set("Cookie", "session="+canary)
		for name, values := range headers {
			r.Header[name] = values
		}
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	before := func() int {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
	idToken := oauthTestIDToken(t, issuer)
	badIDToken := oauthTestIDToken(t, "https://id-token-canary.example/")

	t.Run("whitelist_and_redirect_rewrite", func(t *testing.T) {
		setReply(http.StatusFound, upstream.URL+"/oauth2/auth?login_challenge=abc", canary)
		w := call(http.MethodGet, "/oauth2/auth?"+authQuery, "", nil)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://gateway.example/oauth2/auth?login_challenge=abc", w.Header().Get("Location"))
		assert.NotContains(t, w.Body.String(), canary)
		assert.NotContains(t, w.Header().Get("Location"), "forged.example")
		assert.NotContains(t, w.Header().Get("Location"), upstream.URL)
		assert.Equal(t, "private, no-store", w.Header().Get("Cache-Control"))
		mu.Lock()
		assert.Equal(t, upstream.Listener.Addr().String(), lastHost)
		assert.Equal(t, "gateway.example", lastForwardedHost)
		assert.Empty(t, forbiddenSeen)
		assert.NotContains(t, lastQuery, "forged.example")
		assert.Contains(t, lastQuery, "code_challenge="+challenge)
		mu.Unlock()

		setReply(http.StatusFound, "http://127.0.0.1:54321/oauth/callback?code=one-time", "")
		w = call(http.MethodGet, "/oauth2/auth?"+authQuery, "", http.Header{"X-Forwarded-Host": {"127.0.0.1"}})
		assert.Equal(t, "http://127.0.0.1:54321/oauth/callback?code=one-time", w.Header().Get("Location"))
		setReply(http.StatusFound, "http://[::1]:54321/oauth/callback?code=one-time", "")
		w = call(http.MethodGet, "/oauth2/auth?"+authQuery, "", nil)
		assert.Equal(t, "http://[::1]:54321/oauth/callback?code=one-time", w.Header().Get("Location"))
		setReply(http.StatusFound, "cherrystudio://oauth/callback?code=one-time", "")
		w = call(http.MethodGet, "/oauth2/auth?"+authQuery, "", nil)
		assert.Equal(t, "cherrystudio://oauth/callback?code=one-time", w.Header().Get("Location"))
		setReply(http.StatusFound, "/oauth/provider/login?login_challenge=abc", "")
		w = call(http.MethodGet, "/oauth2/auth?"+authQuery, "", nil)
		assert.Equal(t, "https://gateway.example/oauth/provider/login?login_challenge=abc", w.Header().Get("Location"))

		for _, location := range []string{"https://forged.example/steal?code=" + canary, "//forged.example/steal", "https://gateway.example.evil/steal", "http://localhost/oauth/callback"} {
			setReply(http.StatusFound, location, canary)
			w = call(http.MethodGet, "/oauth2/auth?"+authQuery, "", nil)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, location)
			assert.Empty(t, w.Header().Get("Location"))
			assert.NotContains(t, w.Body.String(), canary)
			assert.NotContains(t, w.Body.String(), "forged.example")
		}
		assert.NotContains(t, logs.String(), canary)
		assert.NotContains(t, logs.String(), challenge)
	})

	t.Run("token_refresh_and_fixed_errors", func(t *testing.T) {
		tokenBody := `{"access_token":"access-token-canary","token_type":"bearer","expires_in":3600,"refresh_token":"refresh-token-canary","scope":"openid profile email","ext":{"leak":"` + canary + `"},"id_token":"` + idToken + `"}`
		setReply(http.StatusOK, "", tokenBody)
		form := url.Values{"grant_type": {"authorization_code"}, "code": {"auth-code"}, "redirect_uri": {loopback}, "client_id": {"boxo"}, "code_verifier": {strings.Repeat("a", 43)}}
		w := call(http.MethodPost, "/oauth2/token", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"access_token":"access-token-canary","token_type":"Bearer","expires_in":3600,"scope":"openid profile email","id_token":"`+idToken+`"}`, w.Body.String())
		assert.NotContains(t, w.Body.String(), "refresh-token-canary")
		assert.NotContains(t, w.Body.String(), canary)
		offlineBody := `{"access_token":"access-token-canary","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-offline","scope":"openid profile email offline_access","id_token":"` + idToken + `"}`
		setReply(http.StatusOK, "", offlineBody)
		w = call(http.MethodPost, "/oauth2/token", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"access_token":"access-token-canary","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-offline","scope":"openid profile email offline_access","id_token":"`+idToken+`"}`, w.Body.String())
		mu.Lock()
		assert.NotContains(t, lastBody, "client_secret")
		assert.Contains(t, lastBody, "code=auth-code")
		mu.Unlock()

		setReply(http.StatusOK, "", `{"access_token":"next-access","token_type":"Bearer","expires_in":1800,"refresh_token":"next-refresh","scope":"openid profile"}`)
		refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"refresh-token-canary"}, "client_id": {"boxo"}}
		w = call(http.MethodPost, "/oauth2/token", refresh.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"access_token":"next-access","token_type":"Bearer","expires_in":1800,"scope":"openid profile"}`, w.Body.String())
		setReply(http.StatusOK, "", `{"access_token":"next-access","token_type":"Bearer","expires_in":1800,"refresh_token":"next-refresh","scope":"openid offline_access"}`)
		w = call(http.MethodPost, "/oauth2/token", refresh.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"access_token":"next-access","token_type":"Bearer","expires_in":1800,"refresh_token":"next-refresh","scope":"openid offline_access"}`, w.Body.String())

		setReply(http.StatusBadRequest, "", `{"error":"invalid_grant","error_description":"`+canary+`","cause":"`+canary+`"}`)
		w = call(http.MethodPost, "/oauth2/token", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.JSONEq(t, `{"error":"invalid_grant","error_description":"The authorization grant is invalid."}`, w.Body.String())

		setReply(http.StatusOK, "", `<html>`+canary+`</html>`)
		w = call(http.MethodPost, "/oauth2/token", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{"error":"temporarily_unavailable"}`, w.Body.String())
		setReply(http.StatusOK, "", `{"access_token":"access-token-canary","token_type":"Bearer","expires_in":3600,"id_token":"`+badIDToken+`"}`)
		w = call(http.MethodPost, "/oauth2/token", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.NotContains(t, w.Body.String(), "id-token-canary")

		skipped := before()
		for _, tc := range []struct {
			path, body string
			headers    http.Header
		}{
			{"/oauth2/token", url.Values{"grant_type": {"password"}, "client_id": {"boxo"}}.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}},
			{"/oauth2/token", form.Encode() + "&client_secret=secret", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}},
			{"/oauth2/token?code=" + canary, form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}},
			{"/oauth2/token", form.Encode(), http.Header{"Content-Type": {"application/json"}}},
			{"/oauth2/token", form.Encode(), http.Header{"Authorization": {"Bearer " + canary}, "Content-Type": {"application/x-www-form-urlencoded"}}},
		} {
			w = call(http.MethodPost, tc.path, tc.body, tc.headers)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.NotContains(t, w.Body.String(), canary)
		}
		w = call(http.MethodPost, "/oauth2/token", url.Values{"grant_type": {"password"}, "client_id": {"boxo"}}.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.JSONEq(t, `{"error":"unsupported_grant_type","error_description":"The grant type is unsupported."}`, w.Body.String())
		assert.Equal(t, skipped, before())
		assert.NotContains(t, logs.String(), "access-token-canary")
		assert.NotContains(t, logs.String(), "refresh-token-canary")
	})

	t.Run("discovery_jwks_and_revoke", func(t *testing.T) {
		setReply(http.StatusOK, "", `{"issuer":"`+issuer+`","authorization_endpoint":"`+upstream.URL+`/oauth2/auth","token_endpoint":"`+upstream.URL+`/oauth2/token","scopes_supported":["openid","profile","email","bad scope"],"code_challenge_methods_supported":["plain","S256"],"grant_types_supported":["authorization_code","refresh_token","password"],"canary":"`+canary+`"}`)
		for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
			w := call(http.MethodGet, path, "", nil)
			assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), canary)
			assert.NotContains(t, w.Body.String(), upstream.URL)
			assert.NotContains(t, w.Body.String(), "forged.example")
			assert.NotContains(t, w.Body.String(), "password")
			assert.NotContains(t, w.Body.String(), "bad scope")
			var got map[string]any
			require.NoError(t, common.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, issuer, got["issuer"])
			assert.Equal(t, publicAuth, got["authorization_endpoint"])
			assert.Equal(t, "https://gateway.example/oauth2/token", got["token_endpoint"])
			assert.Equal(t, "https://gateway.example/api/v1/oauth/userinfo", got["userinfo_endpoint"])
			assert.Equal(t, []any{"openid", "profile", "email"}, got["scopes_supported"])
		}
		setReply(http.StatusOK, "", `{"issuer":"https://issuer-canary.example/","scopes_supported":["openid"],"code_challenge_methods_supported":["S256"],"grant_types_supported":["authorization_code","refresh_token"]}`)
		w := call(http.MethodGet, "/.well-known/openid-configuration", "", nil)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.NotContains(t, w.Body.String(), "issuer-canary")

		setReply(http.StatusOK, "", `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"public-material"}],"canary":"`+canary+`"}`)
		w = call(http.MethodGet, "/.well-known/jwks.json", "", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"keys":[{"crv":"Ed25519","kty":"OKP","x":"public-material"}]}`, w.Body.String())
		setReply(http.StatusOK, "", `{"keys":[{"kty":"RSA","d":"jwks-private-canary"}]}`)
		w = call(http.MethodGet, "/.well-known/jwks.json", "", nil)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.NotContains(t, w.Body.String(), "jwks-private-canary")

		setReply(http.StatusOK, "", "")
		adminBefore := adminCalls.Load()
		w = call(http.MethodPost, "/oauth2/revoke", url.Values{"token": {"owned-token"}, "client_id": {"boxo"}}.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Body.String())
		mu.Lock()
		assert.Equal(t, "/oauth2/revoke", lastPath)
		assert.Contains(t, lastBody, "token=owned-token")
		assert.NotEqual(t, "forged.example", lastHost)
		assert.Empty(t, forbiddenSeen)
		mu.Unlock()
		assert.Equal(t, adminBefore, adminCalls.Load())
	})

	t.Run("off_whitelist_is_local", func(t *testing.T) {
		skipped := before()
		for _, tc := range []struct {
			method, path string
			status       int
		}{
			{http.MethodPost, "/oauth2/auth", http.StatusMethodNotAllowed},
			{http.MethodGet, "/oauth2/token", http.StatusMethodNotAllowed},
			{http.MethodGet, "/oauth2/clients", http.StatusNotFound},
			{http.MethodGet, "/.well-known/webfinger", http.StatusNotFound},
			{http.MethodGet, "/oauth2/%61uth", http.StatusBadRequest},
		} {
			w := call(tc.method, tc.path, "", nil)
			assert.Equal(t, tc.status, w.Code, tc.path)
			assert.Empty(t, w.Header().Get("Location"))
			assert.NotContains(t, w.Body.String(), "owned-SPA-fallback")
			assert.NotContains(t, w.Body.String(), "forged.example")
		}
		for _, path := range []string{"/oauth2evil", "/.well-known-evil"} {
			w := call(http.MethodGet, path, "", nil)
			assert.Equal(t, "owned-SPA-fallback", w.Body.String())
		}
		system_setting.ServerAddress = "https://wrong.example"
		w := call(http.MethodGet, "/oauth2/auth?"+authQuery, "", nil)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		system_setting.ServerAddress = "http://gateway.example"
		w = call(http.MethodGet, "/oauth2/auth?"+authQuery, "", nil)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		system_setting.ServerAddress = "https://gateway.example"
		assert.Equal(t, skipped, before())
		w = call(http.MethodGet, "/oauth2/auth?client_id=boxo&client_id=other&response_type=code&redirect_uri="+url.QueryEscape(loopback)+"&code_challenge="+challenge+"&code_challenge_method=S256", "", nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, skipped, before())
	})

	t.Run("login_resume_uses_public_origin", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}))
		adminBefore := adminCalls.Load()
		query := url.Values{
			"audience": {"newapi-userinfo"}, "client_id": {"boxo"}, "code_challenge": {challenge},
			"code_challenge_method": {"S256"}, "redirect_uri": {loopback}, "response_type": {"code"},
			"scope": {"profile email"}, "state": {"fixture-state-login"},
		}
		requestURL := "https://upstream.example/oauth2/auth?" + query.Encode()
		resumeQuery := url.Values{}
		for key, values := range query {
			resumeQuery[key] = values
		}
		resumeQuery.Set("login_verifier", "loginverifier")
		resume := "https://upstream.example/oauth2/auth?" + resumeQuery.Encode()
		document := map[string]any{
			"challenge": "login-challenge", "subject": "", "skip": false, "request_url": requestURL,
			"requested_scope": []string{"profile", "email"}, "requested_access_token_audience": []string{"newapi-userinfo"},
			"client": map[string]any{
				"client_id": "boxo", "client_name": "Boxo", "token_endpoint_auth_method": "none",
				"scope": "profile email", "audience": []string{"newapi-userinfo"},
				"redirect_uris": []string{"http://127.0.0.1:29873/oauth/callback"},
				"grant_types":   []string{"authorization_code"}, "response_types": []string{"code"}, "skip_consent": false,
			},
		}
		var putBody map[string]any
		loginAdmin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin/oauth2/auth/requests/login":
				encoded, err := common.Marshal(document)
				if !assert.NoError(t, err) {
					return
				}
				_, _ = w.Write(encoded)
			case "/admin/oauth2/auth/requests/login/accept":
				raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
				assert.NoError(t, common.Unmarshal(raw, &putBody))
				encoded, err := common.Marshal(map[string]any{"redirect_to": resume})
				if !assert.NoError(t, err) {
					return
				}
				_, _ = w.Write(encoded)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(loginAdmin.Close)
		loginRoots := x509.NewCertPool()
		loginRoots.AddCert(loginAdmin.Certificate())
		loginResource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
			Enabled: true, IntrospectionURL: loginAdmin.URL + "/admin/oauth2/introspect", Issuer: issuer,
			Audience: "newapi-userinfo", ClientIDs: []string{"boxo"},
		}, loginRoots)
		require.NoError(t, err)
		t.Cleanup(loginResource.CloseIdleConnections)
		loginBridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{
			Enabled: true, RevocationEnabled: true, PublicProxy: true, AdminBaseURL: loginAdmin.URL + "/",
			AuthorizationURL: publicAuth, UpstreamURL: "https://upstream.example",
		}, loginResource)
		require.NoError(t, err)
		engine := gin.New()
		SetOAuthProviderRouter(engine, loginBridge)
		post := func(path, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			r.Host = "forged.example"
			r.Header.Set("X-Forwarded-Host", "also-forged.example")
			r.Header.Set("Authorization", "Bearer "+f.bearer["owner"])
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, r)
			return w
		}
		previewBody, err := common.Marshal(map[string]any{"challenge": "login-challenge"})
		require.NoError(t, err)
		w := post("/api/oauth/provider/login/preview", string(previewBody))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var preview map[string]any
		require.NoError(t, common.Unmarshal(w.Body.Bytes(), &preview))
		token, _ := preview["preview_token"].(string)
		require.Len(t, token, 43)
		decision, err := common.Marshal(map[string]any{"challenge": "login-challenge", "preview_token": token, "decision": "continue"})
		require.NoError(t, err)
		w = post("/api/oauth/provider/login", string(decision))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var decided map[string]any
		require.NoError(t, common.Unmarshal(w.Body.Bytes(), &decided))
		redirect, _ := decided["redirect_to"].(string)
		parsed, err := url.Parse(redirect)
		require.NoError(t, err)
		assert.Equal(t, "https", parsed.Scheme)
		assert.Equal(t, "gateway.example", parsed.Host)
		assert.Equal(t, "/oauth2/auth", parsed.Path)
		assert.Equal(t, "loginverifier", parsed.Query().Get("login_verifier"))
		assert.Equal(t, loopback, parsed.Query().Get("redirect_uri"))
		assert.NotContains(t, redirect, "upstream.example")
		assert.NotContains(t, redirect, "forged.example")
		assert.Equal(t, false, putBody["remember"])
		assert.Equal(t, strconv.Itoa(f.users["owner"].Id), putBody["subject"])
		assert.Equal(t, adminBefore, adminCalls.Load())

		document["challenge"] = "forged-challenge"
		document["request_url"] = "https://forged.example/oauth2/auth?" + query.Encode()
		previewBody, err = common.Marshal(map[string]any{"challenge": "forged-challenge"})
		require.NoError(t, err)
		w = post("/api/oauth/provider/login/preview", string(previewBody))
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.NotContains(t, w.Body.String(), "forged.example")
	})
}

func oauthTestIDToken(t *testing.T, iss string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := common.Marshal(map[string]string{"iss": iss})
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}
