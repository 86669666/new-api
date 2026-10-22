package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
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
	engine.Use(middleware.OAuthBalanceBoundary)
	SetOAuthProviderRouter(engine, nil)
	engine.NoRoute(func(c *gin.Context) { c.String(200, "frontend") })
	for _, path := range []string{"/oauth2/auth?state=SECRET", "/oauth2/token?code=SECRET", "/oauth2/unknown?token=SECRET", "//oauth2/auth?state=SECRET", "/oauth2/auth/?state=SECRET", "/%6fauth2/auth?state=SECRET", "/.well-known/openid-configuration?code=SECRET"} {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		assert.GreaterOrEqual(t, w.Code, 400, path)
		assert.Empty(t, w.Header().Get("Location"), path)
		assert.Contains(t, w.Header().Get("Cache-Control"), "no-store", path)
	}
	for _, path := range []string{"/api/v1/oauth/balance", "/api/v1/oauth/balance?access_token=SECRET", "/api/v1/oauth/balance/"} {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		want := 400
		if path == "/api/v1/oauth/balance" {
			want = 401
		}
		assert.Equal(t, want, w.Code)
		assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
		assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
		assert.NotContains(t, w.Body.String(), "frontend")
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

// usage uses the formal HTTP resource with a credential returned by the real
// issuer. Exact successful payloads are compared at the call site; this shared
// assertion protects the privacy/error envelope on both success and rejection.
func (c *oauthHydraClient) usage(path, token string, want int) map[string]any {
	c.t.Helper()
	status, headers, raw := c.request(http.MethodGet, c.input.Issuer+path, "", "", token)
	require.Equal(c.t, want, status, "real Hydra usage resource status")
	assert.Contains(c.t, headers.Get("Cache-Control"), "no-store")
	assert.Equal(c.t, "no-referrer", headers.Get("Referrer-Policy"))
	assert.Empty(c.t, headers.Get("Location"))
	var body map[string]any
	require.NoError(c.t, common.Unmarshal(raw, &body))
	if want != http.StatusOK {
		assert.NotContains(c.t, body, "data")
		if want == http.StatusForbidden {
			assert.Equal(c.t, "insufficient_scope", body["error"])
			assert.Equal(c.t, `Bearer error="insufficient_scope", scope="usage:read"`, headers.Get("WWW-Authenticate"))
		} else if want == http.StatusUnauthorized {
			assert.Equal(c.t, "invalid_token", body["error"])
		}
		return body
	}
	keys := []string{"success", "message", "data", "data_complete", "quota_per_unit"}
	if strings.Contains(path, "/stat?") {
		keys = append(keys, "granularity")
	}
	assert.ElementsMatch(c.t, keys, slices.Collect(maps.Keys(body)))
	assert.Equal(c.t, true, body["success"])
	assert.Equal(c.t, "", body["message"])
	assert.Equal(c.t, false, body["data_complete"], "persisted history never promises complete accounting")
	assert.Equal(c.t, float64(500000), body["quota_per_unit"])
	return body
}

// The signed-session fixture may start in SQLite even when oauthPublicDatabase
// moves the current primary to MySQL/PostgreSQL. Allocate a second private DB of
// that actual primary kind, never use the initial fixture's LOG_DB or alias main.
// organizationTestDB validates the existing owned loopback receipt, logs its
// exact generated name, and registers close -> DROP -> admin-close cleanup (or
// a real SQLite TempDir file). No shared infrastructure or DSN is written/logged.
func oauthPublicUsageDatabase(t *testing.T, f *organizationHTTPFixture) {
	t.Helper()
	kind := f.db.Dialector.Name()
	require.Contains(t, []string{"sqlite", "mysql", "postgres"}, kind)
	if selected := os.Getenv("NEWAPI_W01_MAIN_KIND"); selected != "" {
		require.Equal(t, selected, kind)
	}
	t.Setenv("NEWAPI_S2_MAIN", kind)
	t.Setenv("NEWAPI_S2_LOG", kind)
	if kind != "sqlite" {
		t.Setenv("NEWAPI_S2_"+strings.ToUpper(kind)+"_PORT", os.Getenv("NEWAPI_W01_MAIN_PORT"))
	}
	logDB, _ := organizationTestDB(t, kind, os.Getenv("NEWAPI_W01_MAIN_DSN"))
	require.NotSame(t, f.db, logDB)
	require.NoError(t, f.db.AutoMigrate(&model.Token{}, &model.Log{}, &model.QuotaData{}))
	require.NoError(t, logDB.AutoMigrate(&model.Log{}, &model.AuditLog{}))
	previousLog := model.LOG_DB
	previousMain, previousLogKind := common.MainDatabaseType(), common.LogDatabaseType()
	model.LOG_DB = logDB
	common.SetDatabaseTypes(common.DatabaseType(kind), common.DatabaseType(kind))
	t.Cleanup(func() {
		model.LOG_DB = previousLog
		common.SetDatabaseTypes(previousMain, previousLogKind)
	})
	query := "SELECT version()"
	if kind == "sqlite" {
		query = "SELECT sqlite_version()"
	}
	var mainVersion, logVersion string
	require.NoError(t, f.db.Raw(query).Scan(&mainVersion).Error)
	require.NoError(t, logDB.Raw(query).Scan(&logVersion).Error)
	t.Logf("OAuth usage stores: main_engine=%s main_version=%s log_engine=%s log_version=%s independent_log=true cleanup=registered", kind, mainVersion, logDB.Dialector.Name(), logVersion)
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

	t.Run("explicit_usage_scope_and_old_grant_refresh", func(t *testing.T) {
		c.t = t
		oauthPublicUsageDatabase(t, f)
		oldConsume, oldExport, oldUnit := common.LogConsumeEnabled, common.DataExportEnabled, common.QuotaPerUnit
		oldRange := operation_setting.GetLogSetting().MaxRangeDays
		common.LogConsumeEnabled, common.DataExportEnabled, common.QuotaPerUnit = true, true, 500000
		operation_setting.GetLogSetting().MaxRangeDays = 2
		t.Cleanup(func() {
			common.LogConsumeEnabled, common.DataExportEnabled, common.QuotaPerUnit = oldConsume, oldExport, oldUnit
			operation_setting.GetLogSetting().MaxRangeDays = oldRange
		})
		base := time.Now().UTC().Truncate(24 * time.Hour).Add(-48 * time.Hour).Unix()
		start, end := base+23*3600+1, base+25*3600+20
		window := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", start, end)
		const largeQuota = 1<<40 + 3 // JS-safe, above int32; not an overflow matrix.
		var usageTokens []model.Token
		for _, name := range []string{"hydra-usage-live", "hydra-usage-deleted"} {
			key, err := common.GenerateKey()
			require.NoError(t, err)
			c.secrets = append(c.secrets, key)
			token := model.Token{UserId: f.users["owner"].Id, Key: key, Name: name, Status: common.TokenStatusEnabled, ExpiredTime: -1}
			require.NoError(t, f.db.Create(&token).Error)
			usageTokens = append(usageTokens, token)
		}
		require.NoError(t, f.db.Delete(&usageTokens[1]).Error)
		var activeDeleted int64
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", usageTokens[1].Id).Count(&activeDeleted).Error)
		require.Zero(t, activeDeleted, "deleted-token history must not rely on a live token row")
		logs := []model.Log{
			{UserId: f.users["owner"].Id, TokenId: usageTokens[0].Id, CreatedAt: start, Type: model.LogTypeConsume, ModelName: "live", Quota: 11, PromptTokens: 2, CompletionTokens: 3, UseTime: 4, IsStream: true, Group: "default"},
			{UserId: f.users["owner"].Id, TokenId: 0, CreatedAt: base + 24*3600, Type: model.LogTypeConsume, ModelName: "zero", Quota: 17},
			{UserId: f.users["owner"].Id, TokenId: usageTokens[1].Id, CreatedAt: end, Type: model.LogTypeConsume, ModelName: "deleted", Quota: largeQuota},
			{UserId: f.users["foreign"].Id, TokenId: 0, CreatedAt: start, Type: model.LogTypeConsume, ModelName: "subject-B", Quota: 9000},
		}
		for i := range logs {
			logs[i].Ip, logs[i].ChannelId, logs[i].Other = "203.0.113.88", 99, `{"private":"usage-canary"}`
			logs[i].RequestId = fmt.Sprintf("hydra-usage-private-%d", i)
			require.NoError(t, model.LOG_DB.Create(&logs[i]).Error)
		}
		// If the reader accidentally uses main rather than LOG_DB, this row
		// appears instead of the exact three account-attributed history rows.
		require.NoError(t, f.db.Create(&model.Log{UserId: f.users["owner"].Id, CreatedAt: start, Type: model.LogTypeConsume, ModelName: "wrong-main-database", Quota: 777}).Error)
		require.NoError(t, f.db.Create(&[]model.QuotaData{
			{UserID: f.users["owner"].Id, TokenID: usageTokens[0].Id, CreatedAt: base + 23*3600, Quota: 11, Count: 1, TokenUsed: 5},
			{UserID: f.users["owner"].Id, TokenID: 0, CreatedAt: base + 24*3600, Quota: 17, Count: 2, TokenUsed: 7},
			{UserID: f.users["owner"].Id, TokenID: usageTokens[1].Id, CreatedAt: base + 25*3600, Quota: largeQuota, Count: 3, TokenUsed: 11},
			{UserID: f.users["foreign"].Id, CreatedAt: base + 23*3600, Quota: 9000, Count: 9, TokenUsed: 90},
		}).Error)
		usageCases := []struct{ path, data string }{
			{"api/v1/oauth/usage/logs?" + window + "&page_size=10", fmt.Sprintf(`{"items":[{"created_at":%d,"model_name":"deleted","prompt_tokens":0,"completion_tokens":0,"quota":%d,"use_time":0,"is_stream":false,"group":""},{"created_at":%d,"model_name":"zero","prompt_tokens":0,"completion_tokens":0,"quota":17,"use_time":0,"is_stream":false,"group":""},{"created_at":%d,"model_name":"live","prompt_tokens":2,"completion_tokens":3,"quota":11,"use_time":4,"is_stream":true,"group":"default"}],"total":3,"page":1,"page_size":10}`, end, largeQuota, base+24*3600, start)},
			{"api/v1/oauth/usage/stat?" + window + "&granularity=hour", fmt.Sprintf(`[{"ts":%d,"quota":11,"requests":1,"tokens":5},{"ts":%d,"quota":17,"requests":2,"tokens":7},{"ts":%d,"quota":%d,"requests":3,"tokens":11}]`, base+23*3600, base+24*3600, base+25*3600, largeQuota)},
			{"api/v1/oauth/usage/stat?" + window + "&granularity=day", fmt.Sprintf(`[{"ts":%d,"quota":11,"requests":1,"tokens":5},{"ts":%d,"quota":%d,"requests":5,"tokens":18}]`, base, base+86400, largeQuota+17)},
		}
		var selectedGrant oauthHydraGrant
		var selectedGrantRef string
		freshNarrow := c.grant("openid profile offline_access balance:read")
		clientURL := input.Admin + "/admin/clients/" + url.PathEscape(c.clientID)
		status, _, raw := c.request("GET", clientURL, "", "", "")
		require.Equal(t, 200, status)
		var registration map[string]any
		require.NoError(t, common.Unmarshal(raw, &registration))
		original, err := common.Marshal(registration)
		require.NoError(t, err)
		defer func() {
			status, _, _ = c.request("PUT", clientURL, "application/json", string(original), "")
			require.Equal(t, 200, status)
		}()
		registered := strings.Fields(registration["scope"].(string))
		withoutUsage := make([]string, 0, len(registered))
		for _, scope := range registered {
			if scope != "usage:read" {
				withoutUsage = append(withoutUsage, scope)
			}
		}
		registration["scope"] = strings.Join(withoutUsage, " ")
		encoded, err := common.Marshal(registration)
		require.NoError(t, err)
		status, _, _ = c.request("PUT", clientURL, "application/json", string(encoded), "")
		require.Equal(t, 200, status)
		pkce := sha256.Sum256([]byte(strings.Repeat("a", 43)))
		query := url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:29873/oauth/callback"}, "scope": {"openid profile offline_access usage:read"}, "nonce": {"scope-registration-nonce"}, "state": {"scope-registration-boundary"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(pkce[:])}, "code_challenge_method": {"S256"}}
		status, _, _ = c.request("GET", input.Issuer+"oauth2/auth?"+query.Encode(), "", "", "")
		assert.Equal(t, 400, status, "unregistered usage scope must be rejected before consent")
		registration["scope"] = strings.Join(append(withoutUsage, "usage:read"), " ")
		encoded, err = common.Marshal(registration)
		require.NoError(t, err)
		status, _, _ = c.request("PUT", clientURL, "application/json", string(encoded), "")
		require.Equal(t, 200, status)
		status, _, raw = c.request("GET", input.Issuer+".well-known/openid-configuration", "", "", "")
		require.Equal(t, 200, status)
		var discovery struct {
			Scopes []string `json:"scopes_supported"`
		}
		require.NoError(t, common.Unmarshal(raw, &discovery))
		assert.Contains(t, discovery.Scopes, "usage:read")
		introspect := func(token string) map[string]any {
			status, _, raw := c.request("POST", input.Admin+"/admin/oauth2/introspect", "application/x-www-form-urlencoded", url.Values{"token": {token}}.Encode(), "")
			require.Equal(t, 200, status)
			var claims map[string]any
			require.NoError(t, common.Unmarshal(raw, &claims))
			require.Equal(t, true, claims["active"])
			return claims
		}
		for _, choice := range []bool{false, true} {
			selected := []string{"openid", "profile", "offline_access"}
			if choice {
				selected = append(selected, "usage:read")
			}
			status, grant := c.exchange(c.code("openid profile offline_access usage:read", selected...))
			require.Equal(t, 200, status)
			claims := introspect(grant.Access)
			scopes := strings.Fields(claims["scope"].(string))
			assert.Equal(t, choice, slices.Contains(scopes, "usage:read"))
			ext := claims["ext"].(map[string]any)
			var stored model.OAuthGrant
			require.NoError(t, f.db.Where("grant_id = ?", ext["newapi_grant_id"]).First(&stored).Error)
			var persisted []string
			require.NoError(t, common.UnmarshalJsonStr(stored.Scopes, &persisted))
			assert.Equal(t, choice, slices.Contains(persisted, "usage:read"))
			before := stored.Scopes
			refreshed := grant
			for _, refreshBeforeRead := range []bool{false, true} {
				token := grant.Access
				if refreshBeforeRead {
					status, refreshed = c.refresh(grant)
					require.Equal(t, 200, status)
					assert.Equal(t, choice, slices.Contains(strings.Fields(introspect(refreshed.Access)["scope"].(string)), "usage:read"))
					token = refreshed.Access
				}
				for _, tc := range usageCases {
					if !choice {
						c.usage(tc.path, token, http.StatusForbidden)
						continue
					}
					body := c.usage(tc.path, token, http.StatusOK)
					encoded, err := common.Marshal(body["data"])
					require.NoError(t, err)
					assert.JSONEq(t, tc.data, string(encoded), "real issued/refreshed token must consume exact subject usage")
					if strings.Contains(tc.path, "granularity=") {
						assert.Equal(t, strings.Split(tc.path, "granularity=")[1], body["granularity"])
					} else {
						items := body["data"].(map[string]any)["items"].([]any)
						actual := items[0].(map[string]any)["quota"].(float64)
						assert.Equal(t, float64(largeQuota), actual)
						assert.Equal(t, math.Trunc(actual), actual)
						assert.LessOrEqual(t, actual, float64(model.OAuthUsageMaxInteger))
					}
				}
			}
			require.NoError(t, f.db.Where("grant_ref = ?", stored.GrantRef).First(&stored).Error)
			assert.Equal(t, before, stored.Scopes, "refresh must not alter stored consent")
			for _, tc := range usageCases[:2] {
				c.usage(tc.path, grant.Access, http.StatusUnauthorized)
			}
			if choice {
				selectedGrant, selectedGrantRef = refreshed, stored.GrantRef
				for _, tc := range usageCases[:2] {
					c.usage(tc.path, refreshed.Refresh, http.StatusUnauthorized)
				}
			}
		}
		status, refreshed := c.refresh(freshNarrow)
		require.Equal(t, 200, status)
		assert.NotContains(t, strings.Fields(introspect(refreshed.Access)["scope"].(string)), "usage:read")
		for _, tc := range usageCases[:2] {
			c.usage(tc.path, refreshed.Access, http.StatusForbidden)
		}
		form := url.Values{"client_id": {c.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {refreshed.Refresh}, "scope": {"usage:read"}}
		status, _, _ = c.request("POST", input.Issuer+"oauth2/token", "application/x-www-form-urlencoded", form.Encode(), "")
		assert.Equal(t, 400, status)
		// Simulate a persisted preview bound to the prior public-v2 policy. The
		// current policy must reject it even with the same actor/challenge/token.
		challenge, _, _ := c.consent("openid profile offline_access balance:read")
		data, err := common.Marshal(map[string]any{"challenge": challenge})
		require.NoError(t, err)
		status, _, raw = c.request("POST", input.Issuer+"api/oauth/provider/consent/preview", "application/json", string(data), f.bearer["owner"])
		require.Equal(t, 200, status)
		var preview service.OAuthProviderPreview
		require.NoError(t, common.Unmarshal(raw, &preview))
		c.secrets = append(c.secrets, challenge, preview.PreviewToken)
		var flow model.AuthFlow
		require.NoError(t, f.db.Where("purpose = ? AND user_id = ? AND intent = ?", model.AuthFlowPurposeOAuthProviderPreview, f.users["owner"].Id, "consent").Order("id DESC").First(&flow).Error)
		var binding map[string]any
		require.NoError(t, common.UnmarshalJsonStr(flow.Payload, &binding))
		policy := binding["policy_hash"].(string)
		require.Contains(t, policy, ":public-v3:")
		legacyPolicy := strings.Split(policy, ":public-v3:")[0] + ":public-v2:openid-profile-email-offline-balance:7d"
		legacyPolicyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(legacyPolicy)))

		// Reconstructed pre-upgrade local fixture: real Hydra issued this
		// refresh chain, then the test replaces only its persisted policy hash
		// with the exact v2 hash for the same bridge configuration. This is not
		// evidence of running an old gateway deployment or a historical dump.
		// No production policy switch or compatibility bypass is introduced.
		legacyChain := c.grant("openid profile offline_access balance:read")
		legacyClaims := introspect(legacyChain.Access)
		legacyID := legacyClaims["ext"].(map[string]any)["newapi_grant_id"].(string)
		var legacyStored model.OAuthGrant
		require.NoError(t, f.db.Where("grant_ref = ?", model.OAuthGrantRef(input.Issuer, legacyID)).First(&legacyStored).Error)
		require.NotEqual(t, legacyPolicyHash, legacyStored.PolicyHash)
		require.NoError(t, f.db.Model(&legacyStored).UpdateColumn("policy_hash", legacyPolicyHash).Error)
		require.NoError(t, f.db.Where("grant_ref = ?", legacyStored.GrantRef).First(&legacyStored).Error)
		require.Equal(t, legacyPolicyHash, legacyStored.PolicyHash)
		var legacyScopes []string
		require.NoError(t, common.UnmarshalJsonStr(legacyStored.Scopes, &legacyScopes))
		require.ElementsMatch(t, []string{"openid", "profile", "offline_access", "balance:read"}, legacyScopes)
		legacyBefore := legacyStored
		status, legacyRefreshed := c.refresh(legacyChain)
		require.Equal(t, 200, status, "reconstructed v2-policy grant must remain refreshable")
		actualScopes := strings.Fields(introspect(legacyRefreshed.Access)["scope"].(string))
		assert.ElementsMatch(t, legacyScopes, actualScopes)
		assert.NotContains(t, actualScopes, "usage:read")
		require.NoError(t, f.db.Where("grant_ref = ?", legacyBefore.GrantRef).First(&legacyStored).Error)
		assert.Equal(t, legacyBefore.Scopes, legacyStored.Scopes, "refresh cannot rewrite consented scopes")
		assert.Equal(t, legacyBefore.PolicyHash, legacyStored.PolicyHash, "refresh cannot upgrade the persisted v2 policy")
		assert.Equal(t, legacyBefore.ExpiresAt, legacyStored.ExpiresAt, "refresh cannot extend consent expiry")
		assert.Equal(t, legacyBefore.Revision, legacyStored.Revision, "refresh cannot revise consent")
		assert.Equal(t, legacyBefore.ConsentRef, legacyStored.ConsentRef)
		assert.Equal(t, legacyBefore.ConsentRequestID, legacyStored.ConsentRequestID)
		assert.Equal(t, legacyBefore.OriginSID, legacyStored.OriginSID)
		assert.Equal(t, legacyBefore.SessionVersion, legacyStored.SessionVersion)
		assert.Equal(t, legacyBefore.UserAuthVersion, legacyStored.UserAuthVersion)
		assert.Equal(t, legacyBefore.GrantID, legacyStored.GrantID)
		assert.Equal(t, legacyBefore.State, legacyStored.State)
		for _, tc := range usageCases[:2] {
			c.usage(tc.path, legacyRefreshed.Access, http.StatusForbidden)
		}

		for _, tc := range usageCases[:2] {
			for _, selector := range []string{"&user_id=" + strconv.Itoa(f.users["foreign"].Id), "&org_id=0"} {
				c.usage(tc.path+selector, selectedGrant.Access, http.StatusBadRequest)
			}
			req, err := http.NewRequest(http.MethodGet, input.Issuer+tc.path, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+selectedGrant.Access)
			req.Header.Set("X-Organization-Id", "0")
			response, err := c.http.Do(req)
			if err != nil {
				t.Fatal("usage organization selector request failed; credential details withheld")
			}
			raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
			require.NoError(t, response.Body.Close())
			require.NoError(t, readErr)
			require.LessOrEqual(t, len(raw), 65536)
			assert.Equal(t, http.StatusBadRequest, response.StatusCode)
			assert.Contains(t, response.Header.Get("Cache-Control"), "no-store")
			assert.Equal(t, "no-referrer", response.Header.Get("Referrer-Policy"))
			assert.Empty(t, response.Header.Get("Location"))
			assert.JSONEq(t, `{"error":"invalid_request"}`, string(raw))
		}

		// Grant revocation uses the real local lifecycle, without claiming that
		// the issuer has completed remote cleanup or single-token RFC7009.
		require.NotEmpty(t, selectedGrantRef)
		require.NoError(t, model.RevokeOAuth(t.Context(), f.users["owner"].Id, "grant", selectedGrantRef))
		for _, tc := range usageCases[:2] {
			c.usage(tc.path, selectedGrant.Access, http.StatusUnauthorized)
		}

		// The other existing dashboard actor obtains an actual Hydra grant.
		// No issuer/introspection is fabricated and no OAuth token is signed here.
		ownerBearer := f.bearer["owner"]
		f.bearer["owner"] = f.bearer["foreign"]
		t.Cleanup(func() { f.bearer["owner"] = ownerBearer })
		foreignGrant := c.grant("openid profile usage:read")
		f.bearer["owner"] = ownerBearer
		foreignBody := c.usage(usageCases[0].path, foreignGrant.Access, http.StatusOK)
		foreignData := foreignBody["data"].(map[string]any)
		assert.Equal(t, float64(1), foreignData["total"])
		require.Len(t, foreignData["items"], 1)
		assert.Equal(t, "subject-B", foreignData["items"].([]any)[0].(map[string]any)["model_name"])
		revoked, err := model.RevokeUserSession(f.users["foreign"].Id, f.sids["foreign"], "logout")
		require.NoError(t, err)
		require.True(t, revoked)
		for _, tc := range usageCases[:2] {
			c.usage(tc.path, foreignGrant.Access, http.StatusUnauthorized)
		}
		t.Log("Combined real Hydra chain exercised issued/refreshed access -> independent log DB and primary hourly/day usage; withheld scope and local revocation reject resource reads")

		binding["policy_hash"] = legacyPolicy
		data, err = common.Marshal(binding)
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&flow).UpdateColumn("payload", string(data)).Error)
		data, err = common.Marshal(map[string]any{"challenge": challenge, "preview_token": preview.PreviewToken, "decision": "approve", "selected_scopes": []string{"openid", "profile", "offline_access"}})
		require.NoError(t, err)
		status, _, _ = c.request("POST", input.Issuer+"api/oauth/provider/consent", "application/json", string(data), f.bearer["owner"])
		assert.Equal(t, 403, status)
	})
	t.Run("balance_explicit_consent_and_refresh", func(t *testing.T) {
		c.t = t
		grant := c.grant("openid profile email offline_access balance:read")
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Updates(map[string]any{"quota": -1, "used_quota": 123}).Error)
		status, headers, data := c.request("GET", input.Issuer+"api/v1/oauth/balance", "", "", grant.Access)
		require.Equal(t, 200, status)
		assert.Equal(t, "no-referrer", headers.Get("Referrer-Policy"))
		assert.Contains(t, headers.Get("Cache-Control"), "no-store")
		balance := oauthBalanceResponseData(t, data)
		assert.Equal(t, float64(-1), balance["quota"])
		assert.Equal(t, float64(123), balance["used_quota"])
		status, next := c.refresh(grant)
		require.Equal(t, 200, status)
		status, _, data = c.request("GET", input.Issuer+"api/v1/oauth/balance", "", "", next.Access)
		require.Equal(t, 200, status)
		balance = oauthBalanceResponseData(t, data)
		assert.Equal(t, float64(-1), balance["quota"])
		assert.Equal(t, float64(123), balance["used_quota"])
		for _, token := range []string{next.Refresh, grant.ID, f.bearer["owner"]} {
			status, _, _ = c.request("GET", input.Issuer+"api/v1/oauth/balance", "", "", token)
			assert.Equal(t, 401, status)
		}
		status, declined := c.exchange(c.code("openid profile offline_access balance:read", "openid", "profile", "offline_access"))
		require.Equal(t, 200, status)
		status, headers, _ = c.request("GET", input.Issuer+"api/v1/oauth/balance", "", "", declined.Access)
		assert.Equal(t, 403, status)
		assert.Equal(t, `Bearer error="insufficient_scope", scope="balance:read"`, headers.Get("WWW-Authenticate"))
		status, refreshed := c.refresh(declined)
		require.Equal(t, 200, status)
		status, _, _ = c.request("GET", input.Issuer+"api/v1/oauth/balance", "", "", refreshed.Access)
		assert.Equal(t, 403, status)
		independent := c.grant("profile balance:read")
		mutations <- func() error {
			return f.db.Model(&model.OAuthGrant{}).Where("user_id = ?", f.users["owner"].Id).UpdateColumn("state", "revoked").Error
		}
		changeAt.Store(introspections.Load() + 2)
		status, _, _ = c.request("GET", input.Issuer+"api/v1/oauth/balance", "", "", independent.Access)
		assert.Equal(t, 401, status)
	})
	t.Run("balance_root_privacy", func(t *testing.T) {
		c.t = t
		c.secrets = append(c.secrets, "BALANCE_QUERY_CANARY")
		for _, path := range []string{"api/v1/oauth/balance?", "api/v1/oauth/balance?org_id=0", "api/v1/oauth/balance?org_id=&org_id=1", "api/v1/oauth/balance?ORG_ID=0", "api/v1/oauth/balance?x=%ZZ", "api/v1/oauth/balance?access_token=BALANCE_QUERY_CANARY", "api/v1/oauth/balance/", "api/v1/oauth/%62alance", "api/v1/oauth/%2562alance", "api//v1/oauth/balance", "API/V1/OAUTH/BALANCE"} {
			status, headers, _ := c.request("GET", input.Issuer+path, "", "", "")
			assert.Equal(t, 400, status, path)
			assert.Contains(t, headers.Get("Cache-Control"), "no-store", path)
			assert.Equal(t, "no-referrer", headers.Get("Referrer-Policy"), path)
			assert.Empty(t, headers.Get("Location"), path)
		}
		for _, method := range []string{"POST", "HEAD", "OPTIONS", "PUT"} {
			status, headers, _ := c.request(method, input.Issuer+"api/v1/oauth/balance", "", "", "")
			assert.Equal(t, 400, status)
			assert.Equal(t, "no-referrer", headers.Get("Referrer-Policy"))
		}
		for _, values := range [][]string{{""}, {"0"}, {"1", "2"}} {
			req, err := http.NewRequest("GET", input.Issuer+"api/v1/oauth/balance", nil)
			require.NoError(t, err)
			req.Header["X-Organization-Id"] = values
			res, err := c.http.Do(req)
			require.NoError(t, err)
			res.Body.Close()
			assert.Equal(t, 400, res.StatusCode)
			assert.Contains(t, res.Header.Get("Cache-Control"), "no-store")
			assert.Equal(t, "no-referrer", res.Header.Get("Referrer-Policy"))
		}
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

	for _, scope := range []string{"grant", "client", "sid", "others", "user"} {
		t.Run("durable_cleanup_"+scope, func(t *testing.T) {
			c.t = t
			c.clientID = "newapi-w01-desktop"
			a := c.grant("openid profile offline_access")
			status, rotated := c.refresh(a)
			require.Equal(t, 200, status)
			b := c.grant("openid profile offline_access")
			c.clientID = "newapi-w01-independent"
			otherClient := c.grant("openid profile offline_access")
			c.clientID = "newapi-w01-desktop"
			originalSID, originalBearer := f.sids["owner"], f.bearer["owner"]
			var source model.UserSession
			require.NoError(t, f.db.Where("sid = ?", originalSID).First(&source).Error)
			source.SID = "g3-other-" + scope
			require.NoError(t, model.CreateUserSession(&source))
			bearer, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: source.UserID, SessionID: source.SID, UserAuthVersion: 1, SessionVersion: 1})
			require.NoError(t, err)
			f.sids["owner"], f.bearer["owner"] = source.SID, bearer
			otherSID := c.grant("openid profile offline_access")
			f.sids["owner"], f.bearer["owner"] = originalSID, originalBearer
			_, origin, err := model.FindOAuthArtifact(t.Context(), input.Issuer, "access_token", rotated.Access)
			require.NoError(t, err)
			value := ""
			switch scope {
			case "grant":
				value = origin.GrantRef
			case "client":
				value = "newapi-w01-desktop"
			case "sid", "others":
				value = originalSID
			}
			require.NoError(t, model.RevokeOAuth(t.Context(), source.UserID, scope, value))
			for _, tc := range []struct {
				token   oauthHydraGrant
				revoked bool
			}{
				{rotated, scope != "others"},
				{b, scope == "client" || scope == "sid" || scope == "user"},
				{otherClient, scope == "sid" || scope == "user"},
				{otherSID, scope == "client" || scope == "others" || scope == "user"},
			} {
				want := 200
				if tc.revoked {
					want = 401
				}
				assert.Equal(t, want, c.userinfo(tc.token.Access), "local denial precedes remote cleanup")
			}
			for range 5 {
				processed, err := service.RunOAuthCleanup(t.Context(), service.CurrentOAuthProviderBridge(), "g3-real-worker")
				require.NoError(t, err)
				if processed == 0 {
					break
				}
			}
			for _, tc := range []struct {
				token   oauthHydraGrant
				revoked bool
			}{
				{rotated, scope != "others"},
				{b, scope == "client" || scope == "sid" || scope == "user"},
				{otherClient, scope == "sid" || scope == "user"},
				{otherSID, scope == "client" || scope == "others" || scope == "user"},
			} {
				assert.Equal(t, !tc.revoked, c.active(tc.token.Access), "issuer access state follows exact cleanup scope")
				assert.Equal(t, !tc.revoked, c.active(tc.token.Refresh), "issuer refresh state follows exact cleanup scope")
			}
			if scope != "others" {
				assert.False(t, c.active(a.Access))
				assert.False(t, c.active(a.Refresh))
			}
		})
	}

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
				require.NoError(t, f.db.Model(&model.OAuthGrant{}).Count(&before).Error)
				consentFault.Store(tc.fault)
				body, err = common.Marshal(service.OAuthProviderDecision{Challenge: challenge, PreviewToken: preview.PreviewToken, Decision: "approve", SelectedScopes: []string{"profile"}})
				require.NoError(t, err)
				status, _, _ = c.request("POST", input.Issuer+"api/oauth/provider/consent", "application/json", string(body), f.bearer["owner"])
				assert.Equal(t, tc.expected, status)
				consentFault.Store(0)
				require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["owner"]).UpdateColumn("revoked_at", 0).Error)
				var after int64
				require.NoError(t, f.db.Model(&model.OAuthGrant{}).Count(&after).Error)
				if tc.prepared {
					assert.Equal(t, before+1, after)
					var revoked int64
					require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("state = ? AND revoked_reason = ?", "revoked", "issuer_unknown").Count(&revoked).Error)
					assert.Positive(t, revoked)
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
	t.Run("unknown_hold_and_issuer_late_insert_constraint", func(t *testing.T) {
		c.t = t
		source := os.Getenv("NEWAPI_W01_HYDRA_FAULT_DSN")
		require.NotEmpty(t, source, "owned real Hydra storage required")
		parsed, err := url.Parse(source)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", parsed.Hostname())
		require.Equal(t, "/hydra_w01", parsed.Path)
		database, err := gorm.Open(postgres.New(postgres.Config{DSN: source, PreferSimpleProtocol: true}), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
		require.NoError(t, err)
		pool, err := database.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, pool.Close()) })
		token := c.grant("openid profile offline_access")
		_, origin, err := model.FindOAuthArtifact(t.Context(), input.Issuer, "access_token", token.Access)
		require.NoError(t, err)
		var grant model.OAuthGrant
		require.NoError(t, f.db.Where("grant_ref = ?", origin.GrantRef).First(&grant).Error)
		op := &model.OAuthOperation{Issuer: grant.Issuer, UserID: grant.UserID, ClientID: grant.ClientID, OriginSID: grant.OriginSID, GrantRef: grant.GrantRef, AuthVersion: 1, SessionVersion: 1, Kind: "refresh_token_exchange"}
		require.NoError(t, model.ReserveOAuthOperation(t.Context(), op))
		require.NoError(t, model.SendOAuthOperation(t.Context(), op))
		require.NoError(t, model.RevokeOAuth(t.Context(), grant.UserID, "grant", grant.GrantRef))
		_, err = service.RunOAuthCleanup(t.Context(), service.CurrentOAuthProviderBridge(), "unknown-worker")
		require.NoError(t, err)
		var job model.OAuthCleanupJob
		require.NoError(t, f.db.Where("value = ? AND scope = ?", grant.GrantRef, "grant").First(&job).Error)
		require.Equal(t, "blocked", job.State)
		require.True(t, c.active(token.Access), "unknown hold must not delete the issuer flow")
		// Inject the precise storage interleaving into an owned Hydra database:
		// a request's already-produced token row arrives after flow deletion.
		// Observe actual FK behavior rather than presuming that the insert succeeds.
		// This does not prove every issuer operation has terminated.
		for _, kind := range []string{"access", "refresh"} {
			table := "newapi_cherry_w01_late_" + kind
			require.NoError(t, database.Exec("CREATE TABLE "+table+" AS SELECT * FROM hydra_oauth2_"+kind+" WHERE request_id = ?", grant.ConsentRequestID).Error)
			t.Cleanup(func() { require.NoError(t, database.Exec("DROP TABLE "+table).Error) })
			var count int64
			require.NoError(t, database.Table(table).Count(&count).Error)
			require.Positive(t, count)
		}
		endpoint := input.Admin + "/admin/oauth2/auth/sessions/consent?" + url.Values{"consent_request_id": {grant.ConsentRequestID}}.Encode()
		status, _, _ := c.request(http.MethodDelete, endpoint, "", "", "")
		require.Equal(t, 204, status)
		require.False(t, c.active(token.Access))
		for _, kind := range []string{"access", "refresh"} {
			err := database.Exec("INSERT INTO hydra_oauth2_" + kind + " SELECT * FROM newapi_cherry_w01_late_" + kind).Error
			require.Error(t, err, "pinned Hydra PostgreSQL schema rejects the late insert")
			assert.Contains(t, err.Error(), "23503")
		}
		status, _, _ = c.request(http.MethodDelete, endpoint, "", "", "")
		require.Equal(t, 204, status)
		assert.False(t, c.active(token.Access))
		assert.False(t, c.active(token.Refresh))
		t.Log("Hydra26.2/PostgreSQL foreign keys reject late access/refresh INSERT after flow deletion; this bounded storage result does not establish a general unknown-operation recovery protocol")
		require.NoError(t, f.db.Model(&job).Update("next_attempt_at", time.Now().Unix()).Error)
		_, err = service.RunOAuthCleanup(t.Context(), service.CurrentOAuthProviderBridge(), "replacement-worker")
		require.NoError(t, err)
		require.NoError(t, f.db.First(&job, "job_ref = ?", job.JobRef).Error)
		assert.Equal(t, "blocked", job.State)
		assert.Equal(t, 401, c.userinfo(token.Access), "local revocation never republishes a late issuer credential")
	})

}

// Reuse signed-session fixtures, but keep external databases in this suite's
// explicitly owned namespace. Never migrate a supplied administrative database.
func oauthPublicDatabase(t *testing.T, f *organizationHTTPFixture) {
	t.Helper()
	kind := os.Getenv("NEWAPI_W01_MAIN_KIND")
	if kind == "" || kind == "sqlite" {
		var version string
		require.NoError(t, f.db.Raw("SELECT sqlite_version()").Scan(&version).Error)
		t.Logf("OAuth primary database=sqlite version=%s", version)
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

	// Keep pending batch deltas and Redis observations in a random fixture identity.
	randomID := make([]byte, 4)
	_, randomErr := rand.Read(randomID)
	require.NoError(t, randomErr)
	ownerID := 1000000000 + int(new(big.Int).SetBytes(randomID).Int64()%1000000000)
	previousID := f.users["owner"].Id
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", previousID).UpdateColumn("id", ownerID).Error)
	require.NoError(t, f.db.Model(&model.UserSession{}).Where("user_id = ?", previousID).UpdateColumn("user_id", ownerID).Error)
	f.users["owner"].Id = ownerID
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
	public.Use(middleware.OAuthBalanceBoundary)
	legacy.Use(middleware.OAuthBalanceBoundary)
	SetOAuthResourceRouter(public, makeResource(true))
	SetOAuthResourceRouter(legacy, makeResource(false))
	scope := "profile"
	setClaims := func(extra map[string]any) {
		value := map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": issuer, "aud": []string{"userinfo"}, "client_id": clientID, "sub": grant.Subject, "exp": time.Now().Unix() + 600, "scope": scope, "ext": extra}
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
	t.Run("balance", func(t *testing.T) {
		oldUnit, oldConfig, oldRate := common.QuotaPerUnit, *operation_setting.GetGeneralSetting(), operation_setting.USDExchangeRate
		oldBatch, oldRedis, oldRDB := common.BatchUpdateEnabled, common.RedisEnabled, common.RDB
		t.Cleanup(func() {
			common.QuotaPerUnit = oldUnit
			*operation_setting.GetGeneralSetting() = oldConfig
			operation_setting.USDExchangeRate = oldRate
			common.BatchUpdateEnabled, common.RedisEnabled, common.RDB = oldBatch, oldRedis, oldRDB
		})
		common.QuotaPerUnit = 500000
		operation_setting.GetGeneralSetting().QuotaDisplayType = "USD"
		balance := func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/api/v1/oauth/balance", nil)
			req.Header.Set("Authorization", "Bearer synthetic-opaque-token")
			public.ServeHTTP(w, req)
			assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
			if w.Code != http.StatusOK {
				var failure map[string]any
				require.NoError(t, common.Unmarshal(w.Body.Bytes(), &failure))
				require.Len(t, failure, 1)
				require.Contains(t, failure, "error")
				assert.NotContains(t, failure, "success")
				assert.NotContains(t, failure, "data")
			}
			return w
		}
		setClaims(extras())
		w := balance()
		require.Equal(t, 403, w.Code)
		assert.Equal(t, `Bearer error="insufficient_scope", scope="balance:read"`, w.Header().Get("WWW-Authenticate"))
		scope = "profile balance:read"
		require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("scopes", `["profile","balance:read"]`).Error)
		setClaims(extras())
		for _, tc := range []struct {
			quota, used int
			status      int
			display     string
		}{
			{0, 0, 200, "$0"}, {-1, -7, 200, "-$0.0001"}, {9007199254740991, 9007199254740991, 200, "$18,014,398,509.48"},
			{-9007199254740991, -9007199254740991, 200, "-$18,014,398,509.48"},
			{9007199254740992, 0, 503, ""}, {-9007199254740992, 0, 503, ""}, {0, 9007199254740992, 503, ""}, {0, -9007199254740992, 503, ""},
		} {
			t.Run(fmt.Sprintf("numbers_%d_%d", tc.quota, tc.used), func(t *testing.T) {
				require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", grant.UserID).Updates(map[string]any{"quota": tc.quota, "used_quota": tc.used}).Error)
				w := balance()
				require.Equal(t, tc.status, w.Code)
				var data map[string]any
				require.NoError(t, common.Unmarshal(w.Body.Bytes(), &data))
				if tc.status == 200 {
					data = oauthBalanceResponseData(t, w.Body.Bytes())
					assert.Len(t, data, 5)
					assert.Equal(t, float64(tc.quota), data["quota"])
					assert.Equal(t, float64(tc.used), data["used_quota"])
					assert.Equal(t, float64(500000), data["quota_per_unit"])
					assert.Equal(t, tc.display, data["display_amount"])
					assert.Equal(t, "en-US", data["display_locale"])
				} else {
					assert.Equal(t, map[string]any{"error": "temporarily_unavailable"}, data)
				}
			})
		}
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", grant.UserID).Updates(map[string]any{"quota": 100, "used_quota": 17}).Error)
		for _, unit := range []float64{0, -1, math.NaN(), math.Inf(1)} {
			common.QuotaPerUnit = unit
			require.Equal(t, 503, balance().Code)
		}
		common.QuotaPerUnit = 500000
		t.Run("optional_display", func(t *testing.T) {
			for _, tc := range []struct {
				mode, symbol, want string
				rate               float64
			}{
				{"USD", "", "$0.0002", 1}, {"CNY", "", "¥0.0014", 7}, {"CUSTOM", " ", "¤ 0.0004", 2}, {"TOKENS", "", "100", 1}, {"CUSTOM", "x\ny", "", 1}, {"CNY", "", "", math.NaN()},
			} {
				cfg := operation_setting.GetGeneralSetting()
				cfg.QuotaDisplayType = tc.mode
				cfg.CustomCurrencySymbol = tc.symbol
				cfg.CustomCurrencyExchangeRate = tc.rate
				operation_setting.USDExchangeRate = tc.rate
				w := balance()
				require.Equal(t, 200, w.Code)
				data := oauthBalanceResponseData(t, w.Body.Bytes())
				if tc.want == "" {
					assert.NotContains(t, data, "display_amount")
				} else {
					assert.Equal(t, tc.want, data["display_amount"])
				}
			}
			operation_setting.GetGeneralSetting().QuotaDisplayType = "USD"
		})
		t.Run("same_row_and_captured_config", func(t *testing.T) {
			var reads atomic.Int32
			name := "oauth_balance_config_capture"
			require.NoError(t, f.db.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table == "users" && reads.Add(1) == 2 {
					common.QuotaPerUnit = 1
					operation_setting.GetGeneralSetting().QuotaDisplayType = "TOKENS"
				}
			}))
			w := balance()
			require.NoError(t, f.db.Callback().Query().Remove(name))
			common.QuotaPerUnit = 500000
			operation_setting.GetGeneralSetting().QuotaDisplayType = "USD"
			require.Equal(t, 200, w.Code)
			assert.Equal(t, int32(2), reads.Load())
			assert.JSONEq(t, `{"success":true,"message":"","data":{"quota":100,"used_quota":17,"quota_per_unit":500000,"display_amount":"$0.0002","display_locale":"en-US"}}`, w.Body.String())
		})
		t.Run("final_gate_changes", func(t *testing.T) {
			for _, tc := range []struct {
				name             string
				table            any
				where            string
				value            any
				column           string
				invalid, restore any
			}{
				{"revision", &model.OAuthGrant{}, "grant_ref = ?", grant.GrantRef, "revision", 4, 3},
				{"grant_revoke", &model.OAuthGrant{}, "grant_ref = ?", grant.GrantRef, "state", "revoked", "active"},
				{"sid_logout", &model.UserSession{}, "sid = ?", grant.OriginSID, "revoked_at", 1, 0},
				{"sid_version", &model.UserSession{}, "sid = ?", grant.OriginSID, "version", 2, 1},
				{"auth_version", &model.User{}, "id = ?", grant.UserID, "auth_version", 2, 1},
				{"disabled", &model.User{}, "id = ?", grant.UserID, "status", 2, common.UserStatusEnabled},
				{"deleted", &model.User{}, "id = ?", grant.UserID, "deleted_at", time.Now(), nil},
			} {
				t.Run(tc.name, func(t *testing.T) {
					mutations := func() error {
						return f.db.Model(tc.table).Where(tc.where, tc.value).UpdateColumn(tc.column, tc.invalid).Error
					}
					mutation <- mutations
					mutateAt.Store(calls.Load() + 2)
					assert.Equal(t, 401, balance().Code)
					require.NoError(t, f.db.Unscoped().Model(tc.table).Where(tc.where, tc.value).UpdateColumn(tc.column, tc.restore).Error)
					require.Equal(t, 200, balance().Code)
				})
			}
		})
		t.Run("final_row_fault_is_not_zero", func(t *testing.T) {
			var reads atomic.Int32
			name := "oauth_balance_read_fault"
			require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table == "users" && reads.Add(1) == 2 {
					tx.AddError(errors.New("private database diagnostic"))
				}
			}))
			w := balance()
			require.NoError(t, f.db.Callback().Query().Remove(name))
			require.Equal(t, 503, w.Code)
			assert.NotContains(t, w.Body.String(), "diagnostic")
		})
		t.Run("account_binding", func(t *testing.T) {
			value := *payload.Load()
			value["sub"] = strconv.Itoa(f.users["foreign"].Id)
			payload.Store(&value)
			assert.Equal(t, 401, balance().Code)
			setClaims(extras())
		})

		t.Run("valid_other_account_and_independent_grant", func(t *testing.T) {
			other := &model.OAuthGrant{Issuer: issuer, ClientID: clientID, Subject: strconv.Itoa(f.users["foreign"].Id), UserID: f.users["foreign"].Id, ConsentRequestID: "balance-foreign", HydraLoginSessionID: "balance-foreign-login", OriginSID: f.sids["foreign"], SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile","balance:read"]`, PolicyHash: strings.Repeat("a", 64)}
			bytes := make([]byte, 32)
			_, err := rand.Read(bytes)
			require.NoError(t, err)
			other.GrantID = base64.RawURLEncoding.EncodeToString(bytes)
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, other) }))
			require.NoError(t, model.ApproveOAuthGrant(t.Context(), other))
			_, err = model.AuthorizeOAuthGrant(t.Context(), model.OAuthGrantAuthorization{Issuer: issuer, GrantID: other.GrantID, ClientID: clientID, Subject: other.Subject, UserID: other.UserID, AuthVersion: 1, GrantExpiresAt: other.ExpiresAt, TokenExpiresAt: time.Now().Unix() + 600, Scopes: []string{"profile", "balance:read"}, Activate: true})
			require.NoError(t, err)
			require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", other.UserID).Updates(map[string]any{"quota": 456, "used_quota": 789}).Error)
			value := *payload.Load()
			value["sub"] = other.Subject
			value["ext"] = map[string]any{"newapi_auth_version": "1", "newapi_grant_id": other.GrantID, "newapi_grant_expires_at": strconv.FormatInt(other.ExpiresAt, 10)}
			payload.Store(&value)
			w := balance()
			require.Equal(t, 200, w.Code)
			data := oauthBalanceResponseData(t, w.Body.Bytes())
			assert.Equal(t, float64(456), data["quota"])
			assert.Equal(t, float64(789), data["used_quota"])
			require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", other.GrantRef).UpdateColumn("state", "revoked").Error)
			assert.Equal(t, 401, balance().Code)
			setClaims(extras())
			w = balance()
			require.Equal(t, 200, w.Code)
			data = oauthBalanceResponseData(t, w.Body.Bytes())
			assert.Equal(t, float64(100), data["quota"])
			assert.Equal(t, float64(17), data["used_quota"])
		})
		t.Run("batch_and_redis_are_not_balance_sources", func(t *testing.T) {
			endpoint := os.Getenv("NEWAPI_W01_REDIS_ADDR")
			require.NotEmpty(t, endpoint, "real Redis endpoint required for balance matrix")
			rdb := redis.NewClient(&redis.Options{Addr: endpoint, DB: 15})
			require.NoError(t, rdb.Ping(t.Context()).Err())
			defer rdb.Close()
			// UUID-prefixed DB fixtures use random user IDs, and this key is leased only
			// after verifying it does not exist. GET neither fetches nor populates it.
			key := fmt.Sprintf("user:%d", grant.UserID)
			count, err := rdb.Exists(t.Context(), key).Result()
			require.NoError(t, err)
			require.Zero(t, count)
			defer rdb.Del(context.Background(), key)
			common.RDB = rdb
			for _, batch := range []bool{false, true} {
				for _, redisOn := range []bool{false, true} {
					common.BatchUpdateEnabled, common.RedisEnabled = batch, redisOn
					require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", grant.UserID).Updates(map[string]any{"quota": 100, "used_quota": 17}).Error)
					model.UpdateUserUsedQuota(grant.UserID, 9)
					expected := 26
					if batch {
						expected = 17
					}
					for _, cache := range []string{"miss", "stale", "wrong_type"} {
						require.NoError(t, rdb.Del(t.Context(), key).Err())
						if cache == "stale" {
							require.NoError(t, rdb.HSet(t.Context(), key, "Quota", 999999).Err())
						}
						if cache == "wrong_type" {
							require.NoError(t, rdb.Set(t.Context(), key, "invalid", 0).Err())
						}
						w := balance()
						require.Equal(t, 200, w.Code)
						data := oauthBalanceResponseData(t, w.Body.Bytes())
						assert.Equal(t, float64(100), data["quota"])
						assert.Equal(t, float64(expected), data["used_quota"])
					}
					if batch {
						model.UpdateUserUsedQuota(grant.UserID, -9)
					} // cancel this fixture's queued delta; never flush GET
				}
			}
			common.BatchUpdateEnabled, common.RedisEnabled, common.RDB = oldBatch, oldRedis, oldRDB
		})
		t.Run("commit_deadline", func(t *testing.T) {
			var savedSession model.UserSession
			require.NoError(t, f.db.Where("sid = ?", grant.OriginSID).First(&savedSession).Error)
			var savedGrant model.OAuthGrant
			require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).First(&savedGrant).Error)
			sqlDB, err := f.db.DB()
			require.NoError(t, err)
			for _, deadline := range []string{"token", "grant", "session"} {
				t.Run(deadline, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						now := time.Now().Unix()
						tokenExpiry, grantExpiry, sessionExpiry := now+60, now+60, now+60
						switch deadline {
						case "token":
							tokenExpiry = now + 1
						case "grant":
							grantExpiry = now + 1
						case "session":
							sessionExpiry = now + 1
							grantExpiry = sessionExpiry
						}
						require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", grant.OriginSID).UpdateColumn("expires_at", sessionExpiry).Error)
						require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("expires_at", grantExpiry).Error)
						db := f.db.Session(&gorm.Session{NewDB: true}).WithContext(context.Background())
						db.Statement.ConnPool = &oauthCommitDelayPool{DB: sqlDB}
						model.DB = db
						require.NoError(t, model.InitOAuthCleanupStore(true))
						_, err := model.AuthorizeOAuthGrant(context.Background(), model.OAuthGrantAuthorization{Issuer: issuer, GrantID: grant.GrantID, ClientID: clientID, Subject: grant.Subject, UserID: grant.UserID, AuthVersion: 1, GrantExpiresAt: grantExpiry, TokenExpiresAt: tokenExpiry, Scopes: []string{"profile", "balance:read"}})
						model.DB = f.db
						require.NoError(t, model.InitOAuthCleanupStore(true))
						require.ErrorIs(t, err, model.ErrOAuthGrantInvalid)
					})
				})
			}
			require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", grant.OriginSID).UpdateColumn("expires_at", savedSession.ExpiresAt).Error)
			require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("expires_at", savedGrant.ExpiresAt).Error)
		})
	})
	// A schema/connection failure is unavailable, never interpreted as missing
	// authorization or used to fall back to legacy authorization.
	require.NoError(t, f.db.Migrator().DropTable(&model.OAuthGrant{}))
	require.Equal(t, 503, serve(public))
	require.Equal(t, 401, serve(legacy))
}

// The virtual delay represents COMMIT acknowledgment after successful DB work.
// synctest advances time deterministically; no wall-clock sleep or fake DB.
type oauthCommitDelayPool struct{ *sql.DB }

func (p *oauthCommitDelayPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := p.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &oauthCommitDelayTx{Tx: tx}, nil
}

type oauthCommitDelayTx struct{ *sql.Tx }

func (t *oauthCommitDelayTx) Commit() error {
	err := t.Tx.Commit()
	if err == nil {
		time.Sleep(2 * time.Second)
	}
	return err
}

// oauthBalanceResponseData validates the public success envelope and field
// allowlist for both synthetic issuer and real Hydra HTTP responses.
func oauthBalanceResponseData(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var response map[string]any
	require.NoError(t, common.Unmarshal(body, &response))
	require.Len(t, response, 3)
	require.Equal(t, true, response["success"])
	require.Equal(t, "", response["message"])
	data, ok := response["data"].(map[string]any)
	require.True(t, ok, "balance data must be an object")
	for _, key := range []string{"quota", "used_quota", "quota_per_unit"} {
		require.Contains(t, data, key)
		require.IsType(t, float64(0), data[key])
	}
	require.Equal(t, "en-US", data["display_locale"])
	for key := range data {
		require.Contains(t, []string{"quota", "used_quota", "quota_per_unit", "display_locale", "display_amount"}, key)
	}
	if display, exists := data["display_amount"]; exists {
		require.IsType(t, "", display)
		require.NotEmpty(t, display)
	}
	return data
}

// These cases use the production transaction and operation APIs. The paused
// send boundary is the durable reserved/sent transition, before any issuer IO.
func TestOAuthCleanupJournal(t *testing.T) {
	for _, scenario := range []string{"reserved", "sent", "rollback", "lease", "hard_deleted", "cookie_logout", "sid_logout", "other_sessions", "all_sessions", "auth_version"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			oauthPublicDatabase(t, f)
			common.IsMasterNode = true
			require.NoError(t, model.InitOAuthGrantStore(true))
			common.IsMasterNode = false
			userID := f.users["owner"].Id
			grant := &model.OAuthGrant{GrantID: strings.Repeat("a", 43), Issuer: "https://cleanup.example/", ClientID: "desktop", Subject: strconv.Itoa(userID), UserID: userID, ConsentRequestID: "cleanup-consent", HydraLoginSessionID: "cleanup-login", OriginSID: f.sids["owner"], SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("b", 64)}
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
			op := &model.OAuthOperation{Issuer: grant.Issuer, UserID: userID, ClientID: grant.ClientID, OriginSID: grant.OriginSID, AuthVersion: 1, SessionVersion: 1, GrantRef: grant.GrantRef, Kind: "code_exchange"}
			require.NoError(t, model.ReserveOAuthOperation(t.Context(), op))
			if scenario == "sent" || scenario == "hard_deleted" {
				require.NoError(t, model.SendOAuthOperation(t.Context(), op))
				// The fresh admission gate rejects a sent row even before a crash
				// recovery has had the opportunity to create an outbox job.
				require.ErrorIs(t, model.ValidateOAuthOperationPublication(t.Context(), op), model.ErrOAuthCleanupHeld)
			}
			switch scenario {
			case "rollback":
				rollback := errors.New("intentional rollback")
				err := f.db.Transaction(func(tx *gorm.DB) error {
					if err := model.LockOAuthUser(tx, userID); err != nil {
						return err
					}
					if err := model.RevokeOAuthWithTx(tx, userID, "user", "", "security_changed"); err != nil {
						return err
					}
					return rollback
				})
				require.ErrorIs(t, err, rollback)
				var count int64
				require.NoError(t, f.db.Model(&model.OAuthCleanupJob{}).Count(&count).Error)
				assert.Zero(t, count)
				require.NoError(t, model.SendOAuthOperation(t.Context(), op))
				return
			case "cookie_logout":
				var source model.UserSession
				require.NoError(t, f.db.Where("sid = ?", grant.OriginSID).First(&source).Error)
				ok, err := model.RevokeUserSessionByRefreshHash(source.SID, "unrecognized", "logout")
				require.NoError(t, err)
				require.False(t, ok)
				var count int64
				require.NoError(t, f.db.Model(&model.OAuthCleanupJob{}).Count(&count).Error)
				assert.Zero(t, count)
				ok, err = model.RevokeUserSessionByRefreshHash(source.SID, source.RefreshHash, "logout")
				require.NoError(t, err)
				require.True(t, ok)
			case "sid_logout":
				ok, err := model.RevokeUserSession(userID, grant.OriginSID, "logout")
				require.NoError(t, err)
				require.True(t, ok)
			case "other_sessions":
				_, err := model.RevokeOtherUserSessions(userID, grant.OriginSID, "logout_others")
				require.NoError(t, err)
				require.NoError(t, model.SendOAuthOperation(t.Context(), op), "excluded current SID remains usable")
				return
			case "all_sessions":
				_, err := model.RevokeAllUserSessions(userID, "logout_all")
				require.NoError(t, err)
			case "auth_version":
				_, err := model.BumpUserAuthVersion(userID)
				require.NoError(t, err)
			default:
				require.NoError(t, model.RevokeOAuth(t.Context(), userID, "grant", grant.GrantRef))
			}
			var jobs []model.OAuthCleanupJob
			require.NoError(t, f.db.Find(&jobs).Error)
			require.NotEmpty(t, jobs)
			var revoked model.OAuthGrant
			require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).First(&revoked).Error)
			assert.NotZero(t, revoked.RevokedAt)
			require.Error(t, model.SendOAuthOperation(t.Context(), op), "revocation wins after reservation")
			job := jobs[0]
			if scenario == "hard_deleted" {
				// The worker must not depend on the source rows surviving. The
				// actual HardDelete entry point is covered by the security matrix.
				require.NoError(t, f.db.Where("user_id = ?", userID).Delete(&model.UserSession{}).Error)
				require.NoError(t, f.db.Unscoped().Delete(&model.User{}, userID).Error)
			}
			now := time.Now().Unix()
			claimed, err := model.ClaimOAuthCleanup(t.Context(), job.JobRef, "worker-a", now)
			require.NoError(t, err)
			if scenario == "sent" || scenario == "hard_deleted" {
				require.Nil(t, claimed)
				require.NoError(t, f.db.Where("job_ref = ?", job.JobRef).First(&job).Error)
				assert.Equal(t, "blocked", job.State)
				assert.Equal(t, "issuer_unknown", job.ErrorCode)
				claimed, err = model.ClaimOAuthCleanup(t.Context(), job.JobRef, "worker-b", now+86400)
				require.NoError(t, err)
				require.Nil(t, claimed, "time cannot prove remote quiescence")
				require.NoError(t, model.ObserveOAuthOperation(t.Context(), op, nil), "late response can be reconciled without a user")
				require.Error(t, model.ValidateOAuthOperationPublication(t.Context(), op), "late response never republishes")
				require.NoError(t, f.db.Model(&job).Update("next_attempt_at", now).Error)
				claimed, err = model.ClaimOAuthCleanup(t.Context(), job.JobRef, "worker-b", now)
				require.NoError(t, err)
			}
			require.NotNil(t, claimed)
			if scenario == "lease" {
				other, err := model.ClaimOAuthCleanup(t.Context(), job.JobRef, "worker-b", now)
				require.NoError(t, err)
				require.Nil(t, other)
				require.NoError(t, f.db.Model(&job).Update("lease_until", now-1).Error)
				other, err = model.ClaimOAuthCleanup(t.Context(), job.JobRef, "worker-b", now)
				require.NoError(t, err)
				require.NotNil(t, other)
				require.ErrorIs(t, model.FinishOAuthCleanup(t.Context(), claimed, "", 0), model.ErrOAuthCleanupHeld)
				claimed = other
			}
			require.NoError(t, model.FinishOAuthCleanup(t.Context(), claimed, "", 0))
			require.Error(t, model.SendOAuthOperation(t.Context(), op), "completion cannot revive an old reservation")
		})
	}
}

func TestOAuthCleanupSecurityEvents(t *testing.T) {
	for _, event := range []string{"password_change", "password_reset", "disable_enable", "soft_delete", "hard_delete", "http_sid", "http_logout", "expiry"} {
		t.Run(event, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			oauthPublicDatabase(t, f)
			require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}, &model.Organization{}, &model.OrganizationMember{}, &model.UserAccessToken{}, &model.ExternalIdentityClaim{}, &model.TwoFABackupCode{}, &model.TwoFA{}, &model.PasskeyCredential{}, &model.Token{}, &model.UserOAuthBinding{}))
			common.IsMasterNode = true
			require.NoError(t, model.InitOAuthGrantStore(true))
			common.IsMasterNode = false
			user := *f.users["empty"]
			sid := f.sids["empty"]
			grant := &model.OAuthGrant{GrantID: strings.Repeat("s", 43), Issuer: "https://security.example/", ClientID: "desktop", Subject: strconv.Itoa(user.Id), UserID: user.Id, ConsentRequestID: "security-consent", HydraLoginSessionID: "security-login", OriginSID: sid, SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("b", 64)}
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
			switch event {
			case "password_change":
				hash, err := common.HashAccountPassword("Old-password-123!")
				require.NoError(t, err)
				require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.Id).UpdateColumn("password", hash).Error)
				update := model.User{Password: "New-password-123!", OriginalPassword: "Old-password-123!"}
				require.NoError(t, model.ChangeUserPassword(model.AuthSessionIdentity{UserID: user.Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1}, &update, false))
			case "password_reset":
				email := fmt.Sprintf("g3-%d@example.test", user.Id)
				require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.Id).UpdateColumn("email", email).Error)
				require.NoError(t, model.ResetUserPasswordByEmail(email, "Reset-password-123!"))
			case "disable_enable":
				user.Status = common.UserStatusDisabled
				require.NoError(t, user.Update(false))
				user.Status = common.UserStatusEnabled
				require.NoError(t, user.Update(false))
			case "soft_delete":
				_, err := user.Delete()
				require.NoError(t, err)
			case "hard_delete":
				_, err := user.HardDelete()
				require.NoError(t, err)
			case "http_sid", "http_logout":
				method, path := http.MethodDelete, "/api/user/sessions/"+sid
				if event == "http_logout" {
					method, path = http.MethodPost, "/api/user/auth/logout"
				}
				status, _, body := f.request(t, method, path, "empty", "", nil)
				require.Equal(t, 200, status)
				require.Equal(t, true, body["success"])
			case "expiry":
				require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", sid).Updates(map[string]any{"expires_at": time.Now().Unix() - 1, "created_at": time.Now().Unix() - 86400}).Error)
				require.NoError(t, model.DeleteExpiredUserSessions(time.Now().Unix()))
			}
			var current model.OAuthGrant
			require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).First(&current).Error)
			require.NotZero(t, current.RevokedAt)
			var jobs []model.OAuthCleanupJob
			require.NoError(t, f.db.Where("user_id = ?", user.Id).Find(&jobs).Error)
			require.NotEmpty(t, jobs)
			for _, job := range jobs {
				assert.Equal(t, strconv.Itoa(user.Id), job.Subject)
				assert.Contains(t, job.Targets, "security-consent")
			}
			if event == "hard_delete" {
				claimed, err := model.ClaimOAuthCleanup(t.Context(), jobs[0].JobRef, "after-delete", time.Now().Unix())
				require.NoError(t, err)
				require.NotNil(t, claimed)
			}
		})
	}
}

func TestOAuthCleanupRetry(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oauthPublicDatabase(t, f)
	common.IsMasterNode = true
	require.NoError(t, model.InitOAuthGrantStore(true))
	common.IsMasterNode = false
	var status atomic.Int64
	status.Store(429)
	var calls atomic.Int64
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Cookie"))
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(int(status.Load()))
	}))
	defer admin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(admin.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{Enabled: true, Issuer: "https://retry.example/", IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Audience: "newapi-userinfo", ClientIDs: []string{"desktop"}}, roots)
	require.NoError(t, err)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{Enabled: true, AdminBaseURL: admin.URL, AuthorizationURL: "https://retry.example/oauth2/auth"}, resource)
	require.NoError(t, err)
	job := model.OAuthCleanupJob{JobRef: strings.Repeat("f", 64), Issuer: "https://retry.example/", UserID: f.users["owner"].Id, Subject: strconv.Itoa(f.users["owner"].Id), Scope: "user", Targets: "[]", State: "pending", NextAttemptAt: time.Now().Unix()}
	require.NoError(t, f.db.Create(&job).Error)
	for _, tc := range []struct {
		status      int64
		state, code string
	}{{429, "pending", "rate_limited"}, {503, "pending", "unavailable"}, {403, "blocked", "configuration"}, {204, "complete", ""}} {
		status.Store(tc.status)
		require.NoError(t, f.db.Model(&job).Update("next_attempt_at", time.Now().Unix()).Error)
		count, err := service.RunOAuthCleanup(t.Context(), bridge, "retry-worker")
		require.NoError(t, err)
		assert.Equal(t, 1, count)
		require.NoError(t, f.db.First(&job, "job_ref = ?", job.JobRef).Error)
		assert.Equal(t, tc.state, job.State)
		assert.Equal(t, tc.code, job.ErrorCode)
		if tc.status == 429 {
			assert.GreaterOrEqual(t, job.NextAttemptAt, time.Now().Unix()+119)
		}
		before := calls.Load()
		_, err = service.RunOAuthCleanup(t.Context(), bridge, "other-worker")
		require.NoError(t, err)
		assert.Equal(t, before, calls.Load(), "persisted backoff/completion survives another runner")
	}
	job.JobRef = strings.Repeat("e", 64)
	job.State = "pending"
	job.NextAttemptAt = time.Now().Unix()
	job.CompletedAt = 0
	require.NoError(t, f.db.Create(&job).Error)
	_, err = service.RunOAuthCleanup(t.Context(), nil, "bridge-disabled")
	require.NoError(t, err)
	require.NoError(t, f.db.First(&job, "job_ref = ?", job.JobRef).Error)
	assert.Equal(t, "blocked", job.State)
	assert.Equal(t, "configuration", job.ErrorCode, "disabled issuer never discards durable cleanup")
}

func TestOAuthCleanupFlowDeletionOrder(t *testing.T) {
	for _, purpose := range []string{model.AuthFlowPurposeOAuthProviderPreview, model.AuthFlowPurposePasskeyRegister, model.AuthFlowPurposeSecurityProof} {
		t.Run(purpose, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			oauthPublicDatabase(t, f)
			require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}, &model.Organization{}, &model.OrganizationMember{}, &model.UserAccessToken{}, &model.ExternalIdentityClaim{}, &model.TwoFABackupCode{}, &model.TwoFA{}, &model.PasskeyCredential{}, &model.Token{}, &model.UserOAuthBinding{}))
			user := *f.users["empty"]
			token, _, err := model.CreateAuthFlow(model.AuthFlowCreate{Purpose: purpose, UserId: user.Id, SessionId: f.sids["empty"], ExpiresAt: time.Now().Add(time.Minute)})
			require.NoError(t, err)
			locked, release := make(chan struct{}), make(chan struct{})
			attempt := make(chan string, 1)
			var holding atomic.Bool
			require.NoError(t, f.db.Callback().Update().After("gorm:update").Register("g3:delete-user-held", func(tx *gorm.DB) {
				if tx.Statement.Table == "users" && holding.CompareAndSwap(false, true) {
					close(locked)
					<-release
				}
			}))
			t.Cleanup(func() { _ = f.db.Callback().Update().Remove("g3:delete-user-held") })
			probe := func(tx *gorm.DB) {
				if !holding.Load() {
					return
				}
				kind := ""
				if tx.Statement.Table == "users" {
					kind = "user"
				}
				if tx.Statement.Table == "auth_flows" {
					kind = "flow"
				}
				if kind != "" {
					select {
					case attempt <- kind:
					default:
					}
				}
			}
			require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("g3:consume-attempt", probe))
			require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("g3:consume-attempt", probe))
			t.Cleanup(func() {
				_ = f.db.Callback().Update().Remove("g3:consume-attempt")
				_ = f.db.Callback().Query().Remove("g3:consume-attempt")
			})
			deleted := make(chan error, 1)
			go func() { _, err := user.HardDelete(); deleted <- err }()
			select {
			case <-locked:
			case err := <-deleted:
				require.NoError(t, err)
				t.Fatal("deletion did not reach locked boundary")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			consumed := make(chan error, 1)
			go func() {
				_, err := model.ConsumeAuthFlowWithActionWithContext(ctx, token, model.AuthFlowMatch{Purpose: purpose, UserId: user.Id, SessionId: f.sids["empty"]}, func(tx *gorm.DB, _ *model.AuthFlow) error {
					return model.ValidateAuthSessionWithTx(tx, model.AuthSessionIdentity{UserID: user.Id, SessionID: f.sids["empty"], UserAuthVersion: 1, SessionVersion: 1})
				})
				consumed <- err
			}()
			select {
			case first := <-attempt:
				assert.Equal(t, "user", first, "consumer must wait on user before writing the flow")
			case <-ctx.Done():
				t.Error("consumer did not reach lock boundary")
			}
			close(release)
			require.NoError(t, <-deleted)
			require.ErrorIs(t, <-consumed, model.ErrAuthFlowInvalid, "hard deletion wins without a lock cycle")
		})
	}
}

func TestOAuthCleanupFailureFences(t *testing.T) {
	for _, fault := range []string{"outbox_write", "redis_fence", "bulk_interruption", "orphan_sent"} {
		t.Run(fault, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			oauthPublicDatabase(t, f)
			common.IsMasterNode = true
			require.NoError(t, model.InitOAuthGrantStore(true))
			common.IsMasterNode = false
			userID, sid := f.users["empty"].Id, f.sids["empty"]
			grant := &model.OAuthGrant{GrantID: strings.Repeat("x", 43), Issuer: "https://failure.example/", ClientID: "desktop", Subject: strconv.Itoa(userID), UserID: userID, ConsentRequestID: "failure-consent", HydraLoginSessionID: "failure-login", OriginSID: sid, SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("b", 64)}
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
			switch fault {
			case "outbox_write":
				forced := errors.New("synthetic outbox failure")
				require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("g3:fail-outbox", func(tx *gorm.DB) {
					if _, ok := tx.Statement.Dest.(*model.OAuthCleanupJob); ok {
						tx.AddError(forced)
					}
				}))
				t.Cleanup(func() { _ = f.db.Callback().Create().Remove("g3:fail-outbox") })
				_, err := model.RevokeUserSession(userID, sid, "logout")
				require.ErrorIs(t, err, forced)
				var session model.UserSession
				require.NoError(t, f.db.Where("sid = ?", sid).First(&session).Error)
				assert.Equal(t, model.UserSessionStatusActive, session.Status)
				var current model.OAuthGrant
				require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).First(&current).Error)
				assert.Zero(t, current.RevokedAt)
			case "redis_fence":
				oldEnabled, oldClient := common.RedisEnabled, common.RDB
				client := redis.NewClient(&redis.Options{Addr: os.Getenv("NEWAPI_W01_REDIS_ADDR")})
				require.NoError(t, client.Close())
				common.RedisEnabled, common.RDB = true, client
				_, err := model.BumpUserAuthVersion(userID)
				common.RedisEnabled, common.RDB = oldEnabled, oldClient
				require.Error(t, err)
				var user model.User
				require.NoError(t, f.db.First(&user, userID).Error)
				assert.Equal(t, int64(1), user.AuthVersion)
				var count int64
				require.NoError(t, f.db.Model(&model.OAuthCleanupJob{}).Count(&count).Error)
				assert.Zero(t, count)
			case "bulk_interruption":
				// The starting range fence is durable even if the process stops
				// before its first session batch. An ordinary retry finishes it.
				require.NoError(t, model.BeginOAuthSessionRevocation(userID, ""))
				newGrant := *grant
				newGrant.GrantID = strings.Repeat("y", 43)
				newGrant.ConsentRequestID = "new-consent"
				require.ErrorIs(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, &newGrant) }), model.ErrOAuthCleanupHeld)
				var job model.OAuthCleanupJob
				require.NoError(t, f.db.First(&job).Error)
				claimed, err := model.ClaimOAuthCleanup(t.Context(), job.JobRef, "after-restart", time.Now().Unix())
				require.NoError(t, err)
				require.Nil(t, claimed)
				_, err = model.RevokeAllUserSessions(userID, "retry")
				require.NoError(t, err)
				var remaining int64
				require.NoError(t, f.db.Model(&model.OAuthOperation{}).Where("state = ?", "local_pending").Count(&remaining).Error)
				assert.Zero(t, remaining)
			case "orphan_sent":
				op := &model.OAuthOperation{Issuer: grant.Issuer, UserID: userID, ClientID: grant.ClientID, OriginSID: sid, GrantRef: grant.GrantRef, AuthVersion: 1, SessionVersion: 1, Kind: "code_exchange"}
				require.NoError(t, model.ReserveOAuthOperation(t.Context(), op))
				require.NoError(t, model.SendOAuthOperation(t.Context(), op))
				require.NoError(t, f.db.Model(op).Update("created_at", time.Now().Unix()-120).Error)
				_, err := service.RunOAuthCleanup(t.Context(), nil, "restart")
				require.NoError(t, err)
				var job model.OAuthCleanupJob
				require.NoError(t, f.db.First(&job).Error)
				assert.Equal(t, "blocked", job.State)
				assert.Equal(t, "issuer_unknown", job.ErrorCode)
				require.NoError(t, f.db.Where("operation_ref = ?", op.OperationRef).First(op).Error)
				assert.Equal(t, "unknown", op.State)
			}
		})
	}
}
