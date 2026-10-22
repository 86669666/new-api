package router

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	sqlmysql "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestOAuthPublicHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	var logs bytes.Buffer
	old := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() { gin.DefaultWriter = old })
	middleware.SetUpLogger(engine)
	SetOAuthProviderRouter(engine, nil)
	engine.NoRoute(func(c *gin.Context) { c.String(200, "frontend") })
	for _, path := range []string{"/oauth2/auth?state=SECRET", "/oauth2/token?code=SECRET", "/oauth2/unknown?token=SECRET", "//oauth2/auth?state=SECRET", "/oauth2/auth/?state=SECRET", "/%6fauth2/auth?state=SECRET", "/.well-known/openid-configuration?code=SECRET"} {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		assert.GreaterOrEqual(t, w.Code, 400, path)
		assert.Empty(t, w.Header().Get("Location"), path)
		assert.Contains(t, w.Header().Get("Cache-Control"), "no-store", path)
	}
	assert.NotContains(t, logs.String(), "SECRET")
}

type oauthHydraInput struct {
	Admin, Public, Issuer, CA, Certificate, Key, Runtime string
	Port                                                 int
}
type oauthHydraGrant struct{ Code, Verifier, Access, Refresh, ID, Nonce string }
type oauthHydraClient struct {
	t        *testing.T
	input    oauthHydraInput
	fixture  *organizationHTTPFixture
	http     *http.Client
	clientID string
	secrets  []string
}

func (c *oauthHydraClient) request(method, path, contentType, body, bearer string) (int, http.Header, []byte) {
	c.t.Helper()
	req, err := http.NewRequest(method, path, strings.NewReader(body))
	require.NoError(c.t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Origin", strings.TrimSuffix(c.input.Issuer, "/"))
	}
	response, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal("synthetic HTTP request failed; credential details withheld")
	}
	defer response.Body.Close()
	if strings.HasPrefix(path, c.input.Issuer+"oauth2/") {
		for _, cookie := range response.Cookies() {
			assert.Regexp(c.t, `^__Host-newapi_oauth_(login|consent)_csrf_[0-9]{1,10}$`, cookie.Name)
			assert.True(c.t, cookie.Secure && cookie.HttpOnly)
			assert.Empty(c.t, cookie.Domain)
			assert.Equal(c.t, "/", cookie.Path)
			assert.Equal(c.t, http.SameSiteLaxMode, cookie.SameSite)
		}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	require.NoError(c.t, err)
	require.LessOrEqual(c.t, len(data), 65536)
	return response.StatusCode, response.Header, data
}
func (c *oauthHydraClient) decision(phase, challenge string, scopes []string) string {
	c.t.Helper()
	body, err := common.Marshal(map[string]any{"challenge": challenge})
	require.NoError(c.t, err)
	status, _, data := c.request("POST", c.input.Issuer+"api/oauth/provider/"+phase+"/preview", "application/json", string(body), c.fixture.bearer["owner"])
	require.Equal(c.t, 200, status, "real Hydra preview rejected")
	var preview service.OAuthProviderPreview
	require.NoError(c.t, common.Unmarshal(data, &preview))
	c.secrets = append(c.secrets, challenge, preview.PreviewToken)
	action := "continue"
	input := map[string]any{"challenge": challenge, "preview_token": preview.PreviewToken}
	if phase == "consent" {
		action = "approve"
		input["selected_scopes"] = scopes
	}
	input["decision"] = action
	body, err = common.Marshal(input)
	require.NoError(c.t, err)
	status, _, data = c.request("POST", c.input.Issuer+"api/oauth/provider/"+phase, "application/json", string(body), c.fixture.bearer["owner"])
	require.Equal(c.t, 200, status, "real Hydra decision rejected")
	var result service.OAuthProviderRedirect
	require.NoError(c.t, common.Unmarshal(data, &result))
	return result.RedirectTo
}
func (c *oauthHydraClient) consent(scopes string) (string, oauthHydraGrant, string) {
	c.t.Helper()
	random := make([]byte, 32)
	_, err := rand.Read(random)
	require.NoError(c.t, err)
	verifier := base64.RawURLEncoding.EncodeToString(random)
	challenge := sha256.Sum256([]byte(verifier))
	_, err = rand.Read(random)
	require.NoError(c.t, err)
	state := base64.RawURLEncoding.EncodeToString(random)
	_, err = rand.Read(random)
	require.NoError(c.t, err)
	nonce := base64.RawURLEncoding.EncodeToString(random)
	q := url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:29873/oauth/callback"}, "scope": {scopes}, "state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	status, headers, _ := c.request("GET", c.input.Issuer+"oauth2/auth?"+q.Encode(), "", "", "")
	require.Equal(c.t, 302, status, "real authorize did not issue login challenge")
	login, err := url.Parse(headers.Get("Location"))
	require.NoError(c.t, err)
	c.t.Logf("real encrypted login challenge length=%d", len(login.Query().Get("login_challenge")))
	resumed := c.decision("login", login.Query().Get("login_challenge"), nil)
	status, headers, _ = c.request("GET", resumed, "", "", "")
	require.Equal(c.t, 302, status, "real login verifier failed")
	consent, err := url.Parse(headers.Get("Location"))
	require.NoError(c.t, err)
	c.t.Logf("real encrypted consent challenge length=%d", len(consent.Query().Get("consent_challenge")))
	c.secrets = append(c.secrets, verifier, state, nonce)
	return consent.Query().Get("consent_challenge"), oauthHydraGrant{Verifier: verifier, Nonce: nonce}, state
}

func (c *oauthHydraClient) code(scopes string, selected ...string) oauthHydraGrant {
	c.t.Helper()
	challenge, grant, state := c.consent(scopes)
	if len(selected) == 0 {
		selected = strings.Split(scopes, " ")
	}
	resumed := c.decision("consent", challenge, selected)
	status, headers, _ := c.request("GET", resumed, "", "", "")
	require.Equal(c.t, http.StatusSeeOther, status, "real consent verifier failed")
	callback, err := url.Parse(headers.Get("Location"))
	require.NoError(c.t, err)
	require.Equal(c.t, "http", callback.Scheme)
	require.Equal(c.t, "127.0.0.1:29873", callback.Host)
	require.Equal(c.t, "/oauth/callback", callback.Path)
	require.True(c.t, state == callback.Query().Get("state"), "callback state must match this transaction")
	require.Equal(c.t, c.input.Issuer, callback.Query().Get("iss"))
	require.True(c.t, callback.Query().Get("code") != "", "missing authorization code")
	c.secrets = append(c.secrets, callback.Query().Get("code"))
	grant.Code = callback.Query().Get("code")
	return grant
}
func (c *oauthHydraClient) exchange(grant oauthHydraGrant) (int, oauthHydraGrant) {
	c.t.Helper()
	form := url.Values{"client_id": {c.clientID}, "grant_type": {"authorization_code"}, "code": {grant.Code}, "redirect_uri": {"http://127.0.0.1:29873/oauth/callback"}, "code_verifier": {grant.Verifier}}
	status, _, data := c.request("POST", c.input.Issuer+"oauth2/token", "application/x-www-form-urlencoded", form.Encode(), "")
	var value struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		ID      string `json:"id_token"`
	}
	require.NoError(c.t, common.Unmarshal(data, &value))
	c.secrets = append(c.secrets, value.Access, value.Refresh, value.ID)
	grant.Access, grant.Refresh, grant.ID = value.Access, value.Refresh, value.ID
	return status, grant
}
func (c *oauthHydraClient) grant(scopes string) oauthHydraGrant {
	c.t.Helper()
	status, grant := c.exchange(c.code(scopes))
	require.Equal(c.t, 200, status, "real code exchange failed")
	require.True(c.t, grant.Access != "")
	return grant
}
func (c *oauthHydraClient) refresh(grant oauthHydraGrant) (int, oauthHydraGrant) {
	c.t.Helper()
	form := url.Values{"client_id": {c.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {grant.Refresh}}
	status, _, data := c.request("POST", c.input.Issuer+"oauth2/token", "application/x-www-form-urlencoded", form.Encode(), "")
	var value struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		ID      string `json:"id_token"`
	}
	require.NoError(c.t, common.Unmarshal(data, &value))
	c.secrets = append(c.secrets, value.Access, value.Refresh, value.ID)
	return status, oauthHydraGrant{Access: value.Access, Refresh: value.Refresh, ID: value.ID}
}
func (c *oauthHydraClient) active(token string) bool {
	c.t.Helper()
	status, _, data := c.request("POST", c.input.Admin+"/admin/oauth2/introspect", "application/x-www-form-urlencoded", url.Values{"token": {token}}.Encode(), "")
	require.Equal(c.t, 200, status)
	var result struct {
		Active bool `json:"active"`
	}
	require.NoError(c.t, common.Unmarshal(data, &result))
	return result.Active
}
func (c *oauthHydraClient) userinfo(token string) int {
	status, _, _ := c.request("GET", c.input.Issuer+"api/v1/oauth/userinfo", "", "", token)
	return status
}

func TestOAuthPublicHydraHTTP(t *testing.T) {
	inputPath := os.Getenv("NEWAPI_W01_HYDRA_INPUT")
	if inputPath == "" {
		t.Skip("requires isolated real Hydra runtime; local HTTP checks run separately")
	}
	var input oauthHydraInput
	data, err := os.ReadFile(inputPath)
	require.NoError(t, err)
	require.NoError(t, common.Unmarshal(data, &input))
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_BRIDGE_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_PUBLIC_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_REVOCATION_ENABLED", "false")
	require.NoError(t, service.InitOAuthUserInfoResource())
	require.NoError(t, service.InitOAuthProviderBridge())
	f := newOrganizationHTTPFixture(t)
	oauthPublicDatabase(t, f)
	require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}))
	oldAddress, oldCritical := system_setting.ServerAddress, common.CriticalRateLimitEnable
	system_setting.ServerAddress = input.Issuer
	common.CriticalRateLimitEnable = false
	t.Cleanup(func() {
		system_setting.ServerAddress = oldAddress
		common.CriticalRateLimitEnable = oldCritical
		t.Setenv("OAUTH_USERINFO_ENABLED", "false")
		t.Setenv("OAUTH_PROVIDER_BRIDGE_ENABLED", "false")
		t.Setenv("OAUTH_PROVIDER_PUBLIC_ENABLED", "false")
		t.Setenv("OAUTH_PROVIDER_REVOCATION_ENABLED", "false")
		require.NoError(t, service.InitOAuthUserInfoResource())
		require.NoError(t, service.InitOAuthProviderBridge())
	})
	// A transparent, certificate-verified proxy lets the test commit local
	// revocation after a real issuer response and before the final local gate.
	ca, err := os.ReadFile(input.CA)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca))
	cert, err := tls.LoadX509KeyPair(input.Certificate, input.Key)
	require.NoError(t, err)
	issuerHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}, Timeout: 5 * time.Second}
	t.Cleanup(issuerHTTP.CloseIdleConnections)
	var introspections atomic.Int64
	var changeAt atomic.Int64
	var consentFault atomic.Int32
	var consentPuts atomic.Int64
	var trustedConsentIDs sync.Map
	mutations := make(chan func() error, 1)
	adminProxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, input.Admin+r.URL.RequestURI(), r.Body)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		req.Header = r.Header.Clone()
		req.GetBody = nil
		response, err := issuerHTTP.Do(req)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/admin/oauth2/introspect" && introspections.Add(1) == changeAt.Load() {
			if err := (<-mutations)(); err != nil {
				w.WriteHeader(503)
				return
			}
		}
		if r.URL.Path == "/admin/oauth2/auth/requests/consent" && r.Method == "GET" {
			var trusted struct {
				Consent string `json:"consent_request_id"`
				Login   string `json:"login_session_id"`
			}
			if common.Unmarshal(data, &trusted) == nil && trusted.Consent != "" {
				trustedConsentIDs.Store(trusted.Consent, trusted.Login)
			}
			if fault := consentFault.Load(); fault == 1 || fault == 2 {
				var fields map[string]common.RawMessage
				if common.Unmarshal(data, &fields) != nil {
					w.WriteHeader(503)
					return
				}
				if fault == 1 {
					delete(fields, "consent_request_id")
				} else {
					fields["consent_request_id"] = common.RawMessage(`"different-trusted-id"`)
				}
				data, err = common.Marshal(fields)
				if err != nil {
					w.WriteHeader(503)
					return
				}
				response.Header.Del("Content-Length")
			}
		}
		if r.URL.Path == "/admin/oauth2/auth/requests/consent/accept" && r.Method == "PUT" {
			consentPuts.Add(1)
			switch consentFault.Load() {
			case 3:
				w.WriteHeader(503)
				return // genuine issuer acceptance, response lost
			case 4:
				if err := f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["owner"]).UpdateColumn("revoked_at", time.Now().Unix()).Error; err != nil {
					w.WriteHeader(503)
					return
				}
			}
		}
		for key, values := range response.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(data)
	}))
	adminProxy.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	adminProxy.StartTLS()
	t.Cleanup(adminProxy.Close)
	for key, value := range map[string]string{"OAUTH_USERINFO_ENABLED": "true", "OAUTH_USERINFO_ISSUER": input.Issuer, "OAUTH_USERINFO_INTROSPECTION_URL": adminProxy.URL + "/admin/oauth2/introspect", "OAUTH_USERINFO_AUDIENCE": "newapi-userinfo", "OAUTH_USERINFO_CLIENT_IDS": "newapi-w01-desktop,newapi-w01-independent", "OAUTH_PROVIDER_BRIDGE_ENABLED": "true", "OAUTH_PROVIDER_REVOCATION_ENABLED": "true", "OAUTH_PROVIDER_ADMIN_BASE_URL": adminProxy.URL, "OAUTH_PROVIDER_AUTHORIZATION_URL": input.Issuer + "oauth2/auth", "OAUTH_PROVIDER_PUBLIC_ENABLED": "true", "OAUTH_PROVIDER_PUBLIC_BASE_URL": input.Public} {
		t.Setenv(key, value)
	}
	require.NoError(t, service.InitOAuthUserInfoResource())
	require.NoError(t, service.InitOAuthProviderBridge())
	common.IsMasterNode = true
	require.NoError(t, service.InitOAuthGrantStore())
	common.IsMasterNode = false
	require.NoError(t, service.ValidateOAuthPublicTopology(t.Context()))
	engine := gin.New()
	middleware.SetUpLogger(engine)
	root, err := os.Getwd()
	require.NoError(t, err)
	root = filepath.Dir(root)
	index, _ := os.ReadFile(filepath.Join(root, "web/dist/index.html"))
	SetRouter(engine, WebAssets{IndexPage: index})
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(input.Port))
	require.NoError(t, err)
	server := &http.Server{Handler: engine, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}, Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	c := &oauthHydraClient{t: t, input: input, fixture: f, http: client, clientID: "newapi-w01-desktop"}
	t.Cleanup(func() {
		for _, secret := range c.secrets {
			assert.True(t, secret == "" || !strings.Contains(f.logs.String(), secret), "gateway logs must exclude protocol secrets")
		}
		if input.Runtime != "" {
			encoded, err := common.Marshal(c.secrets)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(input.Runtime, "log-secrets-"+f.db.Dialector.Name()+".json"), encoded, 0600))
		}
	})
	t.Run("enabled_protocol_rejections", func(t *testing.T) {
		c.t = t
		cases := []struct {
			method, path, body string
			status             int
		}{
			{"GET", "oauth2/token", "", 405},
			{"POST", "oauth2/token", "grant_type=client_credentials&client_id=newapi-w01-desktop", 400},
			{"POST", "oauth2/token", "grant_type=refresh_token&client_id=newapi-w01-desktop&refresh_token=canary&scope=profile", 400},
			{"POST", "oauth2/token", "grant_type=refresh_token&client_id=newapi-w01-desktop&refresh_token=a&refresh_token=b", 400},
			{"GET", "oauth2/unknown?code=SECRET", "", 404},
			{"GET", ".well-known/openid-configuration?code=SECRET", "", 400},
		}
		for _, tc := range cases {
			status, headers, data := c.request(tc.method, input.Issuer+tc.path, "application/x-www-form-urlencoded", tc.body, "")
			assert.Equal(t, tc.status, status, tc.path)
			assert.Empty(t, headers.Get("Location"))
			assert.Contains(t, headers.Get("Cache-Control"), "no-store")
			assert.NotContains(t, string(data), "SECRET")
			var failure map[string]any
			require.NoError(t, common.Unmarshal(data, &failure))
			assert.NotEmpty(t, failure["error"])
		}
	})
	t.Run("code_id_token_and_resource", func(t *testing.T) {
		c.t = t
		grant := c.grant("openid profile email offline_access")
		require.Equal(t, 200, c.userinfo(grant.Access))
		_, _, profileData := c.request("GET", input.Issuer+"api/v1/oauth/userinfo", "", "", grant.Access)
		var profile struct {
			Sub string `json:"sub"`
		}
		require.NoError(t, common.Unmarshal(profileData, &profile))
		assert.Equal(t, strconv.Itoa(f.users["owner"].Id), profile.Sub)
		require.Equal(t, 401, c.userinfo(grant.Refresh))
		require.Equal(t, 401, c.userinfo(grant.ID))
		status, _, data := c.request("POST", input.Admin+"/admin/oauth2/introspect", "application/x-www-form-urlencoded", url.Values{"token": {grant.Access}}.Encode(), "")
		require.Equal(t, 200, status)
		var introspection map[string]common.RawMessage
		require.NoError(t, common.Unmarshal(data, &introspection))
		var use, kind, issuer string
		require.NoError(t, common.Unmarshal(introspection["token_use"], &use))
		require.NoError(t, common.Unmarshal(introspection["token_type"], &kind))
		require.NoError(t, common.Unmarshal(introspection["iss"], &issuer))
		require.Equal(t, "access_token", use)
		require.Equal(t, "Bearer", kind)
		require.Equal(t, input.Issuer, issuer)
		status, _, data = c.request("GET", input.Issuer+".well-known/jwks.json", "", "", "")
		require.Equal(t, 200, status)
		var jwks struct{ Keys []struct{ N, E, Kid string } }
		require.NoError(t, common.Unmarshal(data, &jwks))
		require.NotEmpty(t, jwks.Keys)
		token, err := jwt.Parse(grant.ID, func(token *jwt.Token) (any, error) {
			for _, key := range jwks.Keys {
				if key.Kid == token.Header["kid"] {
					n, err := base64.RawURLEncoding.DecodeString(key.N)
					if err != nil {
						return nil, err
					}
					e, err := base64.RawURLEncoding.DecodeString(key.E)
					if err != nil {
						return nil, err
					}
					return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
				}
			}
			return nil, service.ErrOAuthInvalidToken
		}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(input.Issuer), jwt.WithAudience("newapi-w01-desktop"), jwt.WithExpirationRequired())
		require.True(t, err == nil && token != nil && token.Valid, "real ID token verification failed")
		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)
		require.Equal(t, strconv.Itoa(f.users["owner"].Id), claims["sub"])
		require.True(t, grant.Nonce == claims["nonce"], "ID token nonce must match this transaction")
	})
	t.Run("scopes_control_issuance", func(t *testing.T) {
		c.t = t
		grant := c.grant("profile")
		assert.Empty(t, grant.ID)
		assert.Empty(t, grant.Refresh)
		status, withoutOffline := c.exchange(c.code("openid profile offline_access", "openid", "profile"))
		require.Equal(t, 200, status)
		assert.NotEmpty(t, withoutOffline.ID)
		assert.Empty(t, withoutOffline.Refresh)
	})
	t.Run("wrong_pkce", func(t *testing.T) {
		c.t = t
		grant := c.code("openid profile offline_access")
		grant.Verifier = strings.Repeat("X", 43)
		status, _ := c.exchange(grant)
		assert.Equal(t, 400, status)
	})
	t.Run("code_reuse_revokes_family", func(t *testing.T) {
		c.t = t
		grant := c.grant("openid profile offline_access")
		status, _ := c.exchange(grant)
		assert.Equal(t, 400, status)
		assert.False(t, c.active(grant.Access))
		assert.False(t, c.active(grant.Refresh))
	})
	t.Run("refresh_rotation_and_replay", func(t *testing.T) {
		c.t = t
		grant := c.grant("openid profile offline_access")
		status, next := c.refresh(grant)
		require.Equal(t, 200, status)
		assert.True(t, next.Refresh != "" && next.Refresh != grant.Refresh)
		assert.Equal(t, 200, c.userinfo(next.Access))
		status, _ = c.refresh(grant)
		assert.Equal(t, 400, status)
		assert.False(t, c.active(next.Access))
		assert.False(t, c.active(next.Refresh))
	})
	t.Run("different_client_cannot_refresh_or_revoke", func(t *testing.T) {
		c.t = t
		a := c.grant("openid profile offline_access")
		c.clientID = "newapi-w01-independent"
		defer func() { c.clientID = "newapi-w01-desktop" }()
		b := c.grant("openid profile offline_access")
		status, _ := c.refresh(a)
		assert.Equal(t, 400, status)
		status, _, _ = c.request("POST", input.Issuer+"oauth2/revoke", "application/x-www-form-urlencoded", url.Values{"token": {a.Access}, "client_id": {c.clientID}}.Encode(), "")
		// Hydra masks a wrong-client revocation as 200; our inactive postcondition rejects it.
		assert.Equal(t, 503, status)
		assert.True(t, c.active(a.Access))
		assert.True(t, c.active(a.Refresh))
		status, _, _ = c.request("POST", input.Issuer+"oauth2/revoke", "application/x-www-form-urlencoded", url.Values{"token": {b.Refresh}, "client_id": {c.clientID}}.Encode(), "")
		require.Equal(t, 200, status)
		assert.False(t, c.active(b.Access))
		assert.False(t, c.active(b.Refresh))
		assert.Equal(t, 200, c.userinfo(a.Access))
	})
	t.Run("revocation_storage_failure_is_not_success", func(t *testing.T) {
		c.t = t
		source := os.Getenv("NEWAPI_W01_HYDRA_FAULT_DSN")
		if source == "" {
			t.Skip("requires explicitly owned Hydra database for mutation fault")
		}
		parsed, err := url.Parse(source)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", parsed.Hostname())
		require.Equal(t, "/hydra_w01", parsed.Path)
		database, err := gorm.Open(postgres.New(postgres.Config{DSN: source, PreferSimpleProtocol: true}), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
		require.NoError(t, err)
		connection, err := database.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, connection.Close()) })
		grant := c.grant("openid profile offline_access")
		require.NoError(t, database.Exec(`CREATE FUNCTION newapi_cherry_w01_revoke_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'W01 synthetic revocation write failure'; END $$`).Error)
		t.Cleanup(func() {
			require.NoError(t, database.Exec("DROP FUNCTION newapi_cherry_w01_revoke_fault() CASCADE").Error)
		})
		for _, table := range []string{"hydra_oauth2_access", "hydra_oauth2_refresh"} {
			require.NoError(t, database.Exec("CREATE TRIGGER newapi_cherry_w01_revoke_fault BEFORE UPDATE OR DELETE ON "+table+" FOR EACH ROW EXECUTE FUNCTION newapi_cherry_w01_revoke_fault()").Error)
		}
		form := url.Values{"token": {grant.Access}, "client_id": {"newapi-w01-desktop"}}.Encode()
		upstream, _, _ := c.request("POST", input.Public+"/oauth2/revoke", "application/x-www-form-urlencoded", form, "")
		t.Logf("real Hydra revocation under write fault status=%d", upstream)
		require.True(t, c.active(grant.Access), "fault must preserve token so a success status cannot prove revocation")
		status, _, data := c.request("POST", input.Issuer+"oauth2/revoke", "application/x-www-form-urlencoded", form, "")
		assert.Equal(t, 503, status)
		assert.JSONEq(t, `{"error":"temporarily_unavailable"}`, string(data))
		assert.True(t, c.active(grant.Access))
	})
	t.Run("persistent_grants_and_final_local_gate", func(t *testing.T) {
		c.t = t
		a := c.grant("openid profile offline_access")
		b := c.grant("openid profile offline_access")
		var rows []model.OAuthGrant
		require.NoError(t, f.db.Where("user_id = ? AND state = ?", f.users["owner"].Id, "active").Order("created_at, grant_ref").Find(&rows).Error)
		require.GreaterOrEqual(t, len(rows), 2)
		for _, row := range rows {
			require.NotEmpty(t, row.ConsentRequestID)
			require.NotEmpty(t, row.HydraLoginSessionID)
			login, ok := trustedConsentIDs.Load(row.ConsentRequestID)
			require.True(t, ok, "consent ID must come from real Admin metadata")
			assert.Equal(t, login, row.HydraLoginSessionID)
			require.Equal(t, f.sids["owner"], row.OriginSID)
			require.Equal(t, int64(1), row.SessionVersion)
			require.Equal(t, int64(1), row.UserAuthVersion)
		}
		// Resolve A's binding through real introspection, then revoke precisely A.
		status, _, data := c.request("POST", input.Admin+"/admin/oauth2/introspect", "application/x-www-form-urlencoded", url.Values{"token": {a.Access}}.Encode(), "")
		require.Equal(t, 200, status)
		var value struct {
			Ext map[string]string `json:"ext"`
		}
		require.NoError(t, common.Unmarshal(data, &value))
		ref := model.OAuthGrantRef(input.Issuer, value.Ext["newapi_grant_id"])
		require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", ref).UpdateColumn("state", "revoked").Error)
		require.Equal(t, 401, c.userinfo(a.Access))
		require.Equal(t, 200, c.userinfo(b.Access))
		status, _ = c.refresh(a)
		require.Equal(t, 400, status)
		status, _ = c.refresh(b)
		require.Equal(t, 200, status)
		for _, column := range []string{"revoked_at", "version", "user_auth_version", "expires_at"} {
			t.Run("source_session_"+column, func(t *testing.T) {
				c.t = t
				token := c.grant("openid profile offline_access")
				var before model.UserSession
				require.NoError(t, f.db.Where("sid = ?", f.sids["owner"]).First(&before).Error)
				var changed any = int64(2)
				if column == "expires_at" {
					changed = time.Now().Unix() - 1
				}
				mutations <- func() error {
					return f.db.Model(&model.UserSession{}).Where("sid = ?", before.SID).UpdateColumn(column, changed).Error
				}
				changeAt.Store(introspections.Load() + 3) // refresh input, issued access, issued refresh
				status, _ := c.refresh(token)
				assert.Equal(t, 400, status)
				require.NoError(t, f.db.Save(&before).Error)
			})
		}
		t.Run("auth_version_during_code_exchange", func(t *testing.T) {
			c.t = t
			code := c.code("openid profile offline_access")
			mutations <- func() error {
				return f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).UpdateColumn("auth_version", 2).Error
			}
			changeAt.Store(introspections.Load() + 2)
			status, _ := c.exchange(code)
			assert.Equal(t, 400, status)
			require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).UpdateColumn("auth_version", 1).Error)
		})
		t.Run("database_unavailable_at_publication", func(t *testing.T) {
			c.t = t
			code := c.code("openid profile offline_access")
			mutations <- func() error { return f.db.Migrator().RenameTable("oauth_grants", "oauth_grants_unavailable") }
			changeAt.Store(introspections.Load() + 2)
			status, _ := c.exchange(code)
			require.NoError(t, f.db.Migrator().RenameTable("oauth_grants_unavailable", "oauth_grants"))
			assert.Equal(t, 503, status)
		})

		t.Run("prepared_cannot_activate", func(t *testing.T) {
			c.t = t
			code := c.code("openid profile offline_access")
			// All preceding grants are active/revoked or failed approved. Match the
			// current pending consent via the latest approved row created by this flow.
			var approved []model.OAuthGrant
			require.NoError(t, f.db.Where("state = ?", "approved").Find(&approved).Error)
			for _, row := range approved {
				require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", row.GrantRef).UpdateColumn("state", "prepared").Error)
			}
			status, _ := c.exchange(code)
			assert.Equal(t, 400, status)
		})
		c.t = t
	})

	t.Run("approval_binding_and_unknown_accept", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			fault    int32
			expected int
			prepared bool
		}{
			{"missing_trusted_id", 1, 403, false}, {"changed_trusted_id", 2, 403, false},
			{"accepted_response_lost", 3, 503, true}, {"logout_during_accept", 4, 401, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c.t = t
				consentFault.Store(0)
				challenge, _, _ := c.consent("profile")
				body, err := common.Marshal(map[string]any{"challenge": challenge})
				require.NoError(t, err)
				status, _, data := c.request("POST", input.Issuer+"api/oauth/provider/consent/preview", "application/json", string(body), f.bearer["owner"])
				require.Equal(t, 200, status)
				var preview service.OAuthProviderPreview
				require.NoError(t, common.Unmarshal(data, &preview))
				c.secrets = append(c.secrets, challenge, preview.PreviewToken)
				var before int64
				require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("state = ?", "prepared").Count(&before).Error)
				consentFault.Store(tc.fault)
				body, err = common.Marshal(service.OAuthProviderDecision{Challenge: challenge, PreviewToken: preview.PreviewToken, Decision: "approve", SelectedScopes: []string{"profile"}})
				require.NoError(t, err)
				status, _, _ = c.request("POST", input.Issuer+"api/oauth/provider/consent", "application/json", string(body), f.bearer["owner"])
				assert.Equal(t, tc.expected, status)
				consentFault.Store(0)
				require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["owner"]).UpdateColumn("revoked_at", 0).Error)
				var after int64
				require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("state = ?", "prepared").Count(&after).Error)
				if tc.prepared {
					assert.Equal(t, before+1, after)
					puts := consentPuts.Load()
					status, _, _ = c.request("POST", input.Issuer+"api/oauth/provider/consent", "application/json", string(body), f.bearer["owner"])
					assert.NotEqual(t, 200, status)
					assert.Equal(t, puts, consentPuts.Load(), "unknown accept must not be replayed")
				} else {
					assert.Equal(t, before, after)
				}
			})
		}
		c.t = t
	})

	for _, kind := range []string{"access", "refresh"} {
		t.Run("revoke_"+kind+"_preserves_independent_authorization", func(t *testing.T) {
			c.t = t
			a := c.grant("openid profile offline_access")
			b := c.grant("openid profile offline_access")
			status, rotated := c.refresh(a)
			require.Equal(t, 200, status)
			require.False(t, c.active(a.Access), "Hydra rotation invalidates the preceding access token")
			target := rotated.Access
			if kind == "refresh" {
				target = rotated.Refresh
			}
			status, _, _ = c.request("POST", input.Issuer+"oauth2/revoke", "application/x-www-form-urlencoded", url.Values{"token": {target}, "client_id": {"newapi-w01-desktop"}}.Encode(), "")
			require.Equal(t, 200, status)
			assert.False(t, c.active(a.Access))
			assert.False(t, c.active(a.Refresh))
			assert.False(t, c.active(rotated.Access))
			assert.False(t, c.active(rotated.Refresh))
			assert.Equal(t, 401, c.userinfo(a.Access))
			status, _ = c.refresh(a)
			assert.Equal(t, 400, status)
			assert.Equal(t, 200, c.userinfo(b.Access))
			status, _ = c.refresh(b)
			assert.Equal(t, 200, status)
		})
	}
}

// Reuse signed-session fixtures, but keep external databases in this suite's
// explicitly owned namespace. Never migrate a supplied administrative database.
func oauthPublicDatabase(t *testing.T, f *organizationHTTPFixture) {
	t.Helper()
	kind := os.Getenv("NEWAPI_W01_MAIN_KIND")
	if kind == "" || kind == "sqlite" {
		return
	}
	require.Contains(t, []string{"mysql", "postgres"}, kind)
	source := os.Getenv("NEWAPI_W01_MAIN_DSN")
	require.NoError(t, organizationFixtureDSN(kind, source, os.Getenv("NEWAPI_W01_MAIN_PORT")))
	random := make([]byte, 12)
	_, err := rand.Read(random)
	require.NoError(t, err)
	name := "newapi_cherry_w01_" + fmt.Sprintf("%x", random)
	var adminDial, testDial gorm.Dialector
	if kind == "mysql" {
		config, err := sqlmysql.ParseDSN(source)
		require.NoError(t, err)
		adminDial = mysql.Open(source)
		config.DBName = name
		testDial = mysql.Open(config.FormatDSN())
	} else {
		parsed, err := url.Parse(source)
		require.NoError(t, err)
		adminDial = postgres.New(postgres.Config{DSN: source, PreferSimpleProtocol: true})
		parsed.Path = "/" + name
		testDial = postgres.New(postgres.Config{DSN: parsed.String(), PreferSimpleProtocol: true})
	}
	config := &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)}
	admin, err := gorm.Open(adminDial, config)
	require.NoError(t, err)
	connection, err := admin.DB()
	require.NoError(t, err)
	adminConnection := connection
	t.Cleanup(func() { require.NoError(t, adminConnection.Close()) })
	require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)
	t.Cleanup(func() { require.NoError(t, admin.Exec("DROP DATABASE "+name).Error) })
	db, err := gorm.Open(testDial, config)
	require.NoError(t, err)
	connection, err = db.DB()
	require.NoError(t, err)
	owned := connection
	t.Cleanup(func() { require.NoError(t, owned.Close()) })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.AuthFlow{}))
	var users []model.User
	var sessions []model.UserSession
	require.NoError(t, f.db.Find(&users).Error)
	require.NoError(t, f.db.Find(&sessions).Error)
	require.NotEmpty(t, users)
	require.NotEmpty(t, sessions)
	require.NoError(t, db.Create(&users).Error)
	require.NoError(t, db.Create(&sessions).Error)
	f.db, model.DB = db, db
	common.SetDatabaseTypes(common.DatabaseType(kind), common.DatabaseType("sqlite"))
	var version string
	require.NoError(t, db.Raw("SELECT version()").Scan(&version).Error)
	t.Logf("OAuth primary database=%s engine=%s version=%s", name, kind, version)
}

func TestOAuthPublicRateLimitHTTP(t *testing.T) {
	oldEnable, oldNum, oldRedis := common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.RedisEnabled
	common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.RedisEnabled = true, 1, false
	t.Cleanup(func() {
		common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.RedisEnabled = oldEnable, oldNum, oldRedis
	})
	engine := gin.New()
	require.NoError(t, engine.SetTrustedProxies(nil))
	engine.POST("/oauth2/token", middleware.OAuthPublicRateFailure, middleware.CriticalRateLimit(), func(c *gin.Context) { middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest) })
	for _, want := range []int{400, 429} {
		request := httptest.NewRequest("POST", "/oauth2/token", nil)
		request.RemoteAddr = "192.0.2.237:18000"
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		require.Equal(t, want, response.Code)
		assert.Contains(t, response.Header().Get("Cache-Control"), "no-store")
		if want == 429 {
			assert.JSONEq(t, `{"error":"temporarily_unavailable"}`, response.Body.String())
			assert.NotEmpty(t, response.Header().Get("Retry-After"))
		}
	}
}

func TestOAuthPublicAuthorizationBoundary(t *testing.T) {
	const issuer = "https://gateway.example/"
	const callback = "https://client.example/cb"
	diagnostics := []string{"error_description", "error_hint", "error_debug"}
	redirects := []string{callback}
	for _, key := range diagnostics {
		redirects = append(redirects, callback+"?"+key+"=registered-context")
	}
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/clients/boundary-client" {
			w.WriteHeader(404)
			return
		}
		data, err := common.Marshal(map[string]any{
			"client_id": "boundary-client", "token_endpoint_auth_method": "none", "subject_type": "public",
			"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
			"scope": "openid profile email offline_access", "audience": []string{"boundary-userinfo"},
			"redirect_uris": redirects, "skip_consent": false,
		})
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(admin.Close)
	var authCalls atomic.Int64
	forwarded := make(chan http.Header, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			data, err := common.Marshal(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "oauth2/auth", "token_endpoint": issuer + "oauth2/token", "revocation_endpoint": issuer + "oauth2/revoke", "jwks_uri": issuer + ".well-known/jwks.json", "id_token_signing_alg_values_supported": []string{"RS256"}})
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
			return
		}
		if r.URL.Path != "/oauth2/auth" {
			w.WriteHeader(404)
			return
		}
		authCalls.Add(1)
		forwarded <- r.Header.Clone()
		query := r.URL.Query()
		target, err := url.Parse(query.Get("redirect_uri"))
		if err != nil {
			w.WriteHeader(500)
			return
		}
		result := target.Query()
		for _, key := range diagnostics {
			switch query.Get("state") {
			case "append-diagnostic":
				result.Add(key, "UPSTREAM-PRIVATE-DIAGNOSTIC")
			case "replace-diagnostic":
				result.Set(key, "UPSTREAM-PRIVATE-DIAGNOSTIC")
			}
		}
		result.Set("state", query.Get("state"))
		result.Set("code", "synthetic-code")
		target.RawQuery = result.Encode()
		w.Header().Set("Location", target.String())
		w.WriteHeader(http.StatusSeeOther)
	}))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: admin.TLS.Certificates}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	roots := x509.NewCertPool()
	roots.AddCert(admin.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: issuer, Audience: "boundary-userinfo", ClientIDs: []string{"boundary-client"}}, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{Enabled: true, RevocationEnabled: true, AdminBaseURL: admin.URL, AuthorizationURL: issuer + "oauth2/auth"}, resource)
	require.NoError(t, err)
	public, err := service.NewOAuthPublic(service.OAuthPublicConfig{Enabled: true, BaseURL: upstream.URL}, bridge)
	require.NoError(t, err)
	oldAddress, oldGlobal, oldCritical := system_setting.ServerAddress, common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable
	system_setting.ServerAddress, common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable = issuer, false, false
	t.Setenv("FRONTEND_BASE_URL", "")
	t.Cleanup(func() {
		system_setting.ServerAddress, common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable = oldAddress, oldGlobal, oldCritical
	})
	require.NoError(t, public.ValidateTopology(t.Context()))
	engine := gin.New()
	SetOAuthProviderRouter(engine, bridge)
	serve := func(t *testing.T, redirect, state string, headers http.Header) *httptest.ResponseRecorder {
		t.Helper()
		pkce := sha256.Sum256([]byte(strings.Repeat("v", 43)))
		query := url.Values{"client_id": {"boundary-client"}, "response_type": {"code"}, "redirect_uri": {redirect}, "scope": {"profile"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(pkce[:])}, "code_challenge_method": {"S256"}}
		request := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+query.Encode(), nil)
		request.Header = headers
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		assert.Contains(t, response.Header().Get("Cache-Control"), "no-store")
		assert.NotContains(t, response.Body.String(), "UPSTREAM-PRIVATE-DIAGNOSTIC")
		return response
	}
	t.Run("cookie_headers", func(t *testing.T) {
		allowed := "__Host-newapi_oauth_login_csrf_1=login"
		second := "__Host-newapi_oauth_consent_csrf_2=consent"
		big := []string{}
		for i := range 5 {
			big = append(big, fmt.Sprintf("__Host-newapi_oauth_login_csrf_%d=%s", i+1, strings.Repeat("x", 3500)))
		}
		for _, tc := range []struct {
			name    string
			headers http.Header
			want    int
			cookies int
		}{
			{"normal isolation", http.Header{"Cookie": {allowed + "; dashboard_refresh=PRIVATE-DASHBOARD; hydra_session=PRIVATE-SESSION; " + second}}, 303, 2},
			{"multiple values", http.Header{"Cookie": {allowed, second}}, 303, 2},
			{"case insensitive names", http.Header{"cOoKiE": {allowed}, "COOKIE": {second}}, 303, 2},
			{"exact combined limit", http.Header{"Cookie": {allowed, "ignored=" + strings.Repeat("x", 16384-len(allowed)-2-len("ignored="))}}, 303, 1},
			{"combined limit plus one", http.Header{"Cookie": {allowed, "ignored=" + strings.Repeat("x", 16385-len(allowed)-2-len("ignored="))}}, 400, 0},
			{"allowlisted multiple header overflow", http.Header{"Cookie": big}, 400, 0},
			{"mixed case overflow", http.Header{"Cookie": {allowed}, "cookie": {strings.Repeat("z", 16384)}}, 400, 0},
			{"unallowed overflow", http.Header{"Cookie": {allowed, "ignored=" + strings.Repeat("x", 16384)}}, 400, 0},
			{"merged overflow", http.Header{"Cookie": {strings.Join(big, "; ")}}, 400, 0},
			{"excess empty fields", http.Header{"Cookie": make([]string, 8194)}, 400, 0},
			{"repeated name", http.Header{"Cookie": {allowed, allowed}}, 400, 0},
			{"repeated name across header casing", http.Header{"Cookie": {allowed}, "cOOkie": {allowed}}, 400, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := authCalls.Load()
				response := serve(t, callback, "cookie-check", tc.headers)
				assert.Equal(t, tc.want, response.Code)
				if authCalls.Load() == before {
					assert.Equal(t, 400, tc.want)
					assert.Empty(t, response.Header().Get("Location"))
					return
				}
				headers := <-forwarded
				require.Equal(t, 1, int(authCalls.Load()-before))
				assert.Equal(t, 303, tc.want, "rejected input must not reach the issuer authorization endpoint")
				cookies := (&http.Request{Header: headers}).Cookies()
				assert.Len(t, cookies, tc.cookies)
				for _, cookie := range cookies {
					assert.Contains(t, []string{"__Host-newapi_oauth_login_csrf_1", "__Host-newapi_oauth_consent_csrf_2"}, cookie.Name)
				}
				assert.NotContains(t, headers.Get("Cookie"), "PRIVATE-DASHBOARD")
				assert.NotContains(t, headers.Get("Cookie"), "PRIVATE-SESSION")
			})
		}
	})
	t.Run("callback_queries", func(t *testing.T) {
		for _, key := range diagnostics {
			for _, state := range []string{"registered-context", "append-diagnostic", "replace-diagnostic"} {
				t.Run(key+"/"+state, func(t *testing.T) {
					response := serve(t, callback+"?"+key+"=registered-context", state, nil)
					<-forwarded
					if state != "registered-context" {
						assert.Equal(t, 503, response.Code)
						assert.Empty(t, response.Header().Get("Location"))
						return
					}
					require.Equal(t, 303, response.Code)
					target, err := url.Parse(response.Header().Get("Location"))
					require.NoError(t, err)
					assert.Equal(t, []string{"registered-context"}, target.Query()[key])
					assert.Equal(t, "synthetic-code", target.Query().Get("code"))
					assert.Equal(t, state, target.Query().Get("state"))
					assert.Equal(t, issuer, target.Query().Get("iss"))
				})
			}
		}
		t.Run("strip unregistered diagnostics", func(t *testing.T) {
			response := serve(t, callback, "append-diagnostic", nil)
			<-forwarded
			require.Equal(t, 303, response.Code)
			target, err := url.Parse(response.Header().Get("Location"))
			require.NoError(t, err)
			for _, key := range diagnostics {
				assert.NotContains(t, target.Query(), key)
			}
			assert.NotContains(t, response.Header().Get("Location"), "UPSTREAM-PRIVATE-DIAGNOSTIC")
		})
	})
}

func TestOAuthGrantStore(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oauthPublicDatabase(t, f)
	require.NoError(t, model.InitOAuthGrantStore(false))
	require.False(t, f.db.Migrator().HasTable(&model.OAuthGrant{}))
	require.Error(t, model.InitOAuthGrantStore(true), "non-master must fail on missing schema")
	common.IsMasterNode = true
	require.NoError(t, model.InitOAuthGrantStore(true))
	require.NoError(t, model.InitOAuthGrantStore(true))
	grant := &model.OAuthGrant{GrantID: strings.Repeat("a", 43), Issuer: "https://issuer.example/", ClientID: "desktop", Subject: strconv.Itoa(f.users["owner"].Id), UserID: f.users["owner"].Id,
		ConsentRequestID: "trusted-consent", HydraLoginSessionID: "trusted-login", OriginSID: f.sids["owner"], SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("b", 64)}
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
	var session model.UserSession
	require.NoError(t, f.db.Where("sid = ?", grant.OriginSID).First(&session).Error)
	require.Equal(t, session.ExpiresAt, grant.ExpiresAt, "absolute lifetime is capped by source session")
	require.NoError(t, model.InitOAuthGrantStore(true))
	require.NoError(t, model.InitOAuthGrantStore(false))
	var retained model.OAuthGrant
	require.NoError(t, f.db.First(&retained, "grant_ref = ?", grant.GrantRef).Error)
	assert.Equal(t, *grant, retained)
	duplicate := *grant
	duplicate.GrantRef = strings.Repeat("c", 64)
	duplicate.GrantID = strings.Repeat("d", 43)
	require.Error(t, f.db.Create(&duplicate).Error, "same trusted consent cannot create another grant")
	duplicate = *grant
	duplicate.ConsentRef = strings.Repeat("e", 64)
	require.Error(t, f.db.Create(&duplicate).Error, "grant identity is unique")
	// Digest identity preserves case distinctions even under MySQL's default
	// case-insensitive text collation, and long-lived sessions cannot extend 7d.
	require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", grant.OriginSID).UpdateColumn("expires_at", time.Now().Unix()+8*24*60*60).Error)
	for i, id := range []string{"case-sensitive-consent", "CASE-SENSITIVE-CONSENT"} {
		other := *grant
		other.GrantID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 32))
		other.ConsentRequestID = id
		require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, &other) }))
		assert.Equal(t, other.CreatedAt+7*24*60*60, other.ExpiresAt)
	}

	common.IsMasterNode = false
	require.NoError(t, model.InitOAuthGrantStore(true))
	require.NoError(t, f.db.Migrator().DropIndex(&model.OAuthGrant{}, "idx_oauth_grants_consent"))
	require.Error(t, model.InitOAuthGrantStore(true), "missing uniqueness must fail closed")
}

func TestOAuthGrantUserInfo(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oauthPublicDatabase(t, f)
	common.IsMasterNode = true
	require.NoError(t, model.InitOAuthGrantStore(true))
	common.IsMasterNode = false
	const issuer = "https://gateway.example/"
	const clientID = "grant-client"
	grantBytes := make([]byte, 32)
	_, err := rand.Read(grantBytes)
	require.NoError(t, err)
	grant := &model.OAuthGrant{GrantID: base64.RawURLEncoding.EncodeToString(grantBytes), Issuer: issuer, ClientID: clientID, Subject: strconv.Itoa(f.users["owner"].Id), UserID: f.users["owner"].Id,
		ConsentRequestID: "trusted-consent", HydraLoginSessionID: "trusted-login", OriginSID: f.sids["owner"], SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("a", 64)}
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
	var payload atomic.Pointer[map[string]any]
	mutation := make(chan func() error, 1)
	calls := atomic.Int64{}
	mutateAt := atomic.Int64{}
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == mutateAt.Load() {
			change := <-mutation
			if err := change(); err != nil {
				w.WriteHeader(500)
				return
			}
		}
		data, err := common.Marshal(*payload.Load())
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(admin.Close)
	roots := x509.NewCertPool()
	roots.AddCert(admin.Certificate())
	makeResource := func(public bool) *service.OAuthUserInfoResource {
		resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: issuer, Audience: "userinfo", ClientIDs: []string{clientID, "other-client"}}, roots)
		require.NoError(t, err)
		t.Cleanup(resource.CloseIdleConnections)
		if public {
			bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{Enabled: true, RevocationEnabled: true, AdminBaseURL: admin.URL, AuthorizationURL: issuer + "oauth2/auth"}, resource)
			require.NoError(t, err)
			_, err = service.NewOAuthPublic(service.OAuthPublicConfig{Enabled: true, BaseURL: "https://hydra-private.example"}, bridge)
			require.NoError(t, err)
		}
		return resource
	}
	public, legacy := gin.New(), gin.New()
	SetOAuthResourceRouter(public, makeResource(true))
	SetOAuthResourceRouter(legacy, makeResource(false))
	setClaims := func(extra map[string]any) {
		value := map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": issuer, "aud": []string{"userinfo"}, "client_id": clientID, "sub": grant.Subject, "exp": time.Now().Unix() + 600, "scope": "profile", "ext": extra}
		payload.Store(&value)
	}
	extras := func() map[string]any {
		return map[string]any{"newapi_auth_version": "1", "newapi_grant_id": grant.GrantID, "newapi_grant_expires_at": strconv.FormatInt(grant.ExpiresAt, 10)}
	}
	serve := func(engine *gin.Engine) int {
		req := httptest.NewRequest("GET", "/api/v1/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer synthetic-opaque-token")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
		return w.Code
	}
	setClaims(extras())
	assert.Equal(t, 401, serve(public), "prepared cannot authorize userinfo")
	require.NoError(t, model.ApproveOAuthGrant(t.Context(), grant))
	assert.Equal(t, 401, serve(public), "approved cannot authorize userinfo")
	claims := model.OAuthGrantAuthorization{Issuer: issuer, GrantID: grant.GrantID, ClientID: clientID, Subject: grant.Subject, UserID: grant.UserID, AuthVersion: 1, GrantExpiresAt: grant.ExpiresAt, TokenExpiresAt: time.Now().Unix() + 600, Scopes: []string{"profile"}, Activate: true}
	_, err = model.AuthorizeOAuthGrant(t.Context(), claims)
	require.NoError(t, err)
	require.Equal(t, 200, serve(public))
	assert.Equal(t, 401, serve(legacy), "public-off must reject the same valid issuer/client token")
	for _, key := range []string{"newapi_grant_id", "newapi_grant_expires_at"} {
		for _, value := range []any{"", nil, 42, []any{}, map[string]any{}, false} {
			t.Run(key+"/"+fmt.Sprintf("%T", value), func(t *testing.T) {
				setClaims(map[string]any{"newapi_auth_version": "1", key: value})
				expected := 401
				// The existing strict envelope rejects JSON null before typed claims.
				if value == nil {
					expected = 503
				}
				assert.Equal(t, expected, serve(legacy))
				assert.Equal(t, expected, serve(public))
			})
		}
	}
	setClaims(map[string]any{"newapi_auth_version": "1"})
	require.Equal(t, 200, serve(legacy), "pure legacy remains compatible")
	require.Equal(t, 401, serve(public))
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unknown_grant", func(e map[string]any) { e["newapi_grant_id"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }},
		{"expiry_mismatch", func(e map[string]any) { e["newapi_grant_expires_at"] = strconv.FormatInt(grant.ExpiresAt-1, 10) }},
	} {
		t.Run(tc.name, func(t *testing.T) { e := extras(); tc.change(e); setClaims(e); assert.Equal(t, 401, serve(public)) })
	}
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"foreign_user", "sub", strconv.Itoa(f.users["foreign"].Id)},
		{"foreign_client", "client_id", "other-client"},
		{"wider_scope", "scope", "profile email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setClaims(extras())
			value := *payload.Load()
			value[tc.key] = tc.value
			payload.Store(&value)
			assert.Equal(t, 401, serve(public))
		})
	}

	setClaims(extras())
	for _, tc := range []struct {
		name    string
		table   any
		where   string
		value   any
		column  string
		restore any
	}{
		{"sid_logout", &model.UserSession{}, "sid = ?", grant.OriginSID, "revoked_at", int64(0)},
		{"sid_version", &model.UserSession{}, "sid = ?", grant.OriginSID, "version", int64(1)},
		{"auth_version", &model.User{}, "id = ?", grant.UserID, "auth_version", int64(1)},
		{"user_disabled", &model.User{}, "id = ?", grant.UserID, "status", common.UserStatusEnabled},
		{"grant_revoked", &model.OAuthGrant{}, "grant_ref = ?", grant.GrantRef, "state", "active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var invalid any = int64(2)
			if tc.column == "state" {
				invalid = "revoked"
			}
			// The second issuer check is the final userinfo projection. Commit the
			// revocation before returning that response, without timing sleeps.
			mutation <- func() error {
				return f.db.Model(tc.table).Where(tc.where, tc.value).UpdateColumn(tc.column, invalid).Error
			}
			mutateAt.Store(calls.Load() + 2)
			assert.Equal(t, 401, serve(public))
			assert.Equal(t, 401, serve(legacy))
			require.NoError(t, f.db.Model(tc.table).Where(tc.where, tc.value).UpdateColumn(tc.column, tc.restore).Error)
			require.Equal(t, 200, serve(public))
		})
	}
	// A schema/connection failure is unavailable, never interpreted as missing
	// authorization or used to fall back to legacy authorization.
	require.NoError(t, f.db.Migrator().DropTable(&model.OAuthGrant{}))
	require.Equal(t, 503, serve(public))
	require.Equal(t, 401, serve(legacy))
}
