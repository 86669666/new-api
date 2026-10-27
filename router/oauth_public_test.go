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
	"github.com/glebarez/sqlite"
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
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	sqlmysql "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
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

func TestOAuthDeployDocsOmitSecrets(t *testing.T) {
	root := ".."
	files := []string{"deploy/oauth/README.md", "deploy/oauth/docker-compose.example.yml", "deploy/oauth/check-discovery.sh"}
	forbidden := regexp.MustCompile(`(?i)(?:\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b|123456|InsecureSkipVerify|--dev\b|boxnai-desktop|dev-api\.grok\.fan|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY)`)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err, name)
		assert.NotRegexp(t, forbidden, string(data), name)
	}
	script, err := os.ReadFile(filepath.Join(root, "deploy/oauth/check-discovery.sh"))
	require.NoError(t, err)
	text := string(script)
	assert.Contains(t, text, "curl")
	assert.NotContains(t, text, "--head")
	assert.NotContains(t, text, "-I")
	assert.NotContains(t, text, "HEAD")
	compose, err := os.ReadFile(filepath.Join(root, "deploy/oauth/docker-compose.example.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(compose), "oryd/hydra:v26.2.0")
	assert.Contains(t, string(compose), "STRATEGIES_ACCESS_TOKEN: opaque")
	assert.Contains(t, string(compose), "OAUTH2_PKCE_ENFORCED_FOR_PUBLIC_CLIENTS: \"true\"")
	assert.NotContains(t, string(compose), "ports:")
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
	redirect string
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
	q := url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "redirect_uri": {c.redirect}, "scope": {scopes}, "state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
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
	registered, err := url.Parse(c.redirect)
	require.NoError(c.t, err)
	require.Equal(c.t, registered.Scheme, callback.Scheme)
	require.Equal(c.t, registered.Host, callback.Host)
	require.Equal(c.t, registered.EscapedPath(), callback.EscapedPath())
	require.True(c.t, state == callback.Query().Get("state"), "callback state must match this transaction")
	require.Equal(c.t, c.input.Issuer, callback.Query().Get("iss"))
	require.True(c.t, callback.Query().Get("code") != "", "missing authorization code")
	c.secrets = append(c.secrets, callback.Query().Get("code"))
	grant.Code = callback.Query().Get("code")
	return grant
}
func (c *oauthHydraClient) exchange(grant oauthHydraGrant) (int, oauthHydraGrant) {
	c.t.Helper()
	form := url.Values{"client_id": {c.clientID}, "grant_type": {"authorization_code"}, "code": {grant.Code}, "redirect_uri": {c.redirect}, "code_verifier": {grant.Verifier}}
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
	combinedFixtureDatabase(t, "main", f.db)
	combinedFixtureDatabase(t, "log", logDB)
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
	c := &oauthHydraClient{t: t, input: input, fixture: f, http: client, clientID: "newapi-w01-desktop", redirect: "http://127.0.0.1:29873/oauth/callback"}
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
	t.Run("personal_callback_rejections", func(t *testing.T) {
		c.t = t
		pkce := sha256.Sum256([]byte(strings.Repeat("v", 43)))
		for _, redirect := range []string{
			"boxnai://oauth/other", "boxnai://other/callback", "boxnai://oauth/callback?x=1",
			"boxnai://oauth:123/callback", "boxnai://oauth/callback#", "other://oauth/callback",
			"http://localhost:39874/oauth/callback", "http://127.0.0.1:39874/other",
		} {
			q := url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "redirect_uri": {redirect}, "scope": {"profile"}, "state": {"personal-callback-negative"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(pkce[:])}, "code_challenge_method": {"S256"}}
			status, headers, _ := c.request("GET", input.Issuer+"oauth2/auth?"+q.Encode(), "", "", "")
			assert.Equal(t, 400, status, redirect)
			assert.Empty(t, headers.Get("Location"))
			assert.Contains(t, headers.Get("Cache-Control"), "no-store")
		}
		// A fixed scheme is not sufficient: this other allowed public client
		// has only a loopback redirect registered with the real issuer.
		q := url.Values{"client_id": {"newapi-w01-independent"}, "response_type": {"code"}, "redirect_uri": {"boxnai://oauth/callback"}, "scope": {"profile"}, "state": {"personal-callback-unregistered"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(pkce[:])}, "code_challenge_method": {"S256"}}
		status, headers, _ := c.request("GET", input.Issuer+"oauth2/auth?"+q.Encode(), "", "", "")
		assert.Equal(t, 400, status)
		assert.Empty(t, headers.Get("Location"))
	})

	t.Run("personal_registered_callbacks", func(t *testing.T) {
		original := c.redirect
		t.Cleanup(func() { c.redirect = original })
		for _, tc := range []struct{ name, redirect string }{
			{"dynamic_loopback", "http://127.0.0.1:39874/oauth/callback"},
			{"boxnai", "boxnai://oauth/callback"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c.t, c.redirect = t, tc.redirect
				grant := c.grant("openid profile offline_access")
				require.Equal(t, 200, c.userinfo(grant.Access))
				status, next := c.refresh(grant)
				require.Equal(t, 200, status)
				require.True(t, next.Refresh != "" && next.Refresh != grant.Refresh, "refresh must rotate")
				require.Equal(t, 200, c.userinfo(next.Access))
				// OAuth identity is not a dashboard/organization credential.
				status, _, _ = c.request("GET", input.Issuer+"api/organizations", "", "", next.Access)
				assert.Equal(t, 401, status)
				status, _, _ = c.request("POST", input.Issuer+"oauth2/revoke", "application/x-www-form-urlencoded", url.Values{"token": {next.Refresh}, "client_id": {c.clientID}}.Encode(), "")
				require.Equal(t, 200, status)
				assert.False(t, c.active(next.Access))
				assert.False(t, c.active(next.Refresh))
				assert.Equal(t, 401, c.userinfo(next.Access))

				code := c.code("profile")
				c.redirect = original // Another registered URI cannot redeem this code.
				status, _ = c.exchange(code)
				assert.Equal(t, 400, status)
				c.redirect = tc.redirect
			})
		}
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

	t.Run("explicit_tokens_read_empty_and_refresh", func(t *testing.T) {
		c.t = t
		// The permanent CLI must have born this very database. The test never adopts
		// a copied actor database or writes a source/history to manufacture metadata.
		require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
		clientURL := input.Admin + "/admin/clients/" + url.PathEscape(c.clientID)
		status, _, raw := c.request("GET", clientURL, "", "", "")
		require.Equal(t, 200, status)
		var registration map[string]any
		require.NoError(t, common.Unmarshal(raw, &registration))
		original, e := common.Marshal(registration)
		require.NoError(t, e)
		defer func() {
			status, _, _ = c.request("PUT", clientURL, "application/json", string(original), "")
			require.Equal(t, 200, status)
		}()
		registered := strings.Fields(registration["scope"].(string))
		if !slices.Contains(registered, "tokens:read") {
			registered = append(registered, "tokens:read")
		}
		registration["scope"] = strings.Join(registered, " ")
		updated, e := common.Marshal(registration)
		require.NoError(t, e)
		status, _, _ = c.request("PUT", clientURL, "application/json", string(updated), "")
		require.Equal(t, 200, status)
		c.tokenMetadata("", 401)
		challenge := sha256.Sum256([]byte(strings.Repeat("a", 43)))
		writeRequest := url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:29873/oauth/callback"}, "scope": {"profile tokens:write"}, "state": {strings.Repeat("b", 43)}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
		status, writeHeaders, _ := c.request("GET", input.Issuer+"oauth2/auth?"+writeRequest.Encode(), "", "", "")
		assert.Equal(t, 400, status, "tokens:write has no public producer")
		assert.Empty(t, writeHeaders.Get("Location"))
		journal, e := os.ReadFile(os.Getenv("OAUTH_BOOTSTRAP_JOURNAL"))
		require.NoError(t, e)
		for _, selected := range []bool{false, true} {
			t.Run(strconv.FormatBool(selected), func(t *testing.T) {
				c.t = t
				scopes := []string{"openid", "profile", "offline_access"}
				if selected {
					scopes = append(scopes, "tokens:read")
				}
				status, grant := c.exchange(c.code("openid profile offline_access tokens:read", scopes...))
				require.Equal(t, 200, status)
				for _, refresh := range []bool{false, true} {
					if refresh {
						var next oauthHydraGrant
						status, next = c.refresh(grant)
						require.Equal(t, 200, status)
						grant = next
					}
					want := 403
					if selected {
						want = 200
					}
					body := c.tokenMetadata(grant.Access, want)
					if selected {
						assert.Equal(t, []any{}, body["data"])
					}
					c.tokenMetadata(grant.Refresh, 401)
				}
				if selected {
					// The credential is issued and introspected by real Hydra. Mutate
					// only this synthetic local grant to test its binding, then restore.
					status, _, raw := c.request("POST", input.Admin+"/admin/oauth2/introspect", "application/x-www-form-urlencoded", url.Values{"token": {grant.Access}}.Encode(), "")
					require.Equal(t, 200, status)
					var introspection struct {
						Active bool `json:"active"`
						Ext    struct {
							GrantID string `json:"newapi_grant_id"`
						} `json:"ext"`
					}
					require.NoError(t, common.Unmarshal(raw, &introspection))
					require.True(t, introspection.Active)
					require.NotEmpty(t, introspection.Ext.GrantID)
					var local model.OAuthGrant
					require.NoError(t, f.db.Where("grant_id = ?", introspection.Ext.GrantID).First(&local).Error)
					for _, mismatch := range []struct {
						label, field    string
						value, original any
					}{
						{"actor", "user_id", f.users["foreign"].Id, local.UserID},
						{"client", "client_id", "newapi-w01-independent", local.ClientID},
						{"grant", "grant_id", strings.Repeat("x", 43), local.GrantID},
					} {
						t.Run("binding_"+mismatch.label, func(t *testing.T) {
							c.t = t
							t.Cleanup(func() {
								require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", local.GrantRef).UpdateColumn(mismatch.field, mismatch.original).Error)
							})
							require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", local.GrantRef).UpdateColumn(mismatch.field, mismatch.value).Error)
							c.tokenMetadata(grant.Access, 401)
						})
					}
					c.t = t
					c.tokenMetadata(grant.Access, 200)
				}
				// Supplying a scope on refresh never upgrades an omitted permission.
				form := url.Values{"client_id": {c.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {grant.Refresh}, "scope": {"tokens:read"}}
				status, _, _ = c.request("POST", input.Issuer+"oauth2/token", "application/x-www-form-urlencoded", form.Encode(), "")
				assert.Equal(t, 400, status)
			})
		}
		c.t = t
		var sources int64
		require.NoError(t, f.db.Model(&model.OAuthDerivedTokenSource{}).Count(&sources).Error)
		assert.Zero(t, sources)
		after, e := os.ReadFile(os.Getenv("OAUTH_BOOTSTRAP_JOURNAL"))
		require.NoError(t, e)
		assert.Equal(t, journal, after)
		status, _, raw = c.request("GET", input.Issuer+".well-known/openid-configuration", "", "", "")
		require.Equal(t, 200, status)
		var metadata struct {
			Scopes []string `json:"scopes_supported"`
		}
		require.NoError(t, common.Unmarshal(raw, &metadata))
		assert.Contains(t, metadata.Scopes, "tokens:read")
		assert.NotContains(t, metadata.Scopes, "tokens:write")
		status, headers, _ := c.request("POST", input.Issuer+"api/v1/oauth/tokens", "application/json", "{}", "")
		assert.Equal(t, 400, status)
		assert.Empty(t, headers.Get("Location"))
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
		require.Contains(t, policy, ":public-v4:")
		legacyPolicy := strings.Split(policy, ":public-v4:")[0] + ":public-v2:openid-profile-email-offline-balance:7d"
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
	if tier := os.Getenv("NEWAPI_BOOTSTRAP_TIER"); tier == "postgres" || tier == "postgres-redis" {
		require.Equal(t, "postgres", kind)
		require.Equal(t, "postgres", f.db.Dialector.Name())
		require.Equal(t, os.Getenv("SQL_DSN"), f.mainDSN)
		require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
		combinedFixtureDatabase(t, "main", f.db)
		return // The born DB already contains these actors; never copy to another DB.
	}
	if kind == "" || kind == "sqlite" {
		var version string
		require.NoError(t, f.db.Raw("SELECT sqlite_version()").Scan(&version).Error)
		t.Logf("OAuth primary database=sqlite version=%s", version)
		combinedFixtureDatabase(t, "main", f.db)
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
	t.Logf("W01-03 owned database=%s engine=%s", name, kind)
	t.Cleanup(func() {
		err := admin.Exec("DROP DATABASE " + name).Error
		require.NoError(t, err)
		if err == nil {
			if combinedFixtureBound(t) {
				query := "SELECT count(*) FROM information_schema.schemata WHERE schema_name = ?"
				if kind == "postgres" {
					query = "SELECT count(*) FROM pg_database WHERE datname = ?"
				}
				var remaining int64
				require.NoError(t, admin.Raw(query, name).Scan(&remaining).Error)
				require.Zero(t, remaining, "exact OAuth fixture database must be absent after DROP")
				combinedFixtureEvent(t, "removed", map[string]any{"kind": "database", "identity": name})
			}
			t.Logf("W01-03 removed database=%s engine=%s", name, kind)
		}
	})
	combinedFixtureEvent(t, "created", map[string]any{"kind": "database", "identity": name})
	db, err := gorm.Open(testDial, config)
	require.NoError(t, err)
	connection, err = db.DB()
	require.NoError(t, err)
	owned := connection
	t.Cleanup(func() { require.NoError(t, owned.Close()) })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.SessionRevocationEvent{}, &model.AuthFlow{}))
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
	combinedFixtureDatabase(t, "main", db)
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
	redirects := []string{callback, "http://127.0.0.1:29873/oauth/callback", "cherrystudio://oauth/callback"}
	for _, key := range diagnostics {
		redirects = append(redirects, callback+"?"+key+"=registered-context")
	}
	var introspection atomic.Pointer[map[string]any]
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/oauth2/introspect" {
			payload := introspection.Load()
			if payload == nil || r.ParseForm() != nil || r.PostForm.Get("token") != "synthetic-access-token" {
				w.WriteHeader(400)
				return
			}
			data, err := common.Marshal(*payload)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
			return
		}
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
	var tokenCalls atomic.Int64
	var wrongState atomic.Bool
	forwarded := make(chan struct {
		headers http.Header
		query   url.Values
	}, 1)
	tokenForms := make(chan url.Values, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if r.ParseForm() != nil {
				w.WriteHeader(400)
				return
			}
			tokenForms <- r.PostForm
			w.Header().Set("Content-Type", "application/json")
			if tokenCalls.Add(1) > 1 {
				// The stub supplies issuer replay rejection; this verifies its
				// propagation, not Hydra's single-use enforcement.
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"synthetic-access-token","token_type":"bearer","expires_in":600,"scope":"profile"}`)
			return
		}
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
		query := r.URL.Query()
		forwarded <- struct {
			headers http.Header
			query   url.Values
		}{r.Header.Clone(), query}
		switch query.Get("state") {
		case "issuer-login-page":
			w.Header().Set("Location", issuer+"oauth/provider/login?login_challenge=login-challenge-value")
			w.WriteHeader(http.StatusSeeOther)
			return
		case "upstream-uses-attacker-host":
			w.Header().Set("Location", "https://attacker.example/oauth/provider/login?login_challenge=login-challenge-value")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
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
		if wrongState.Load() {
			result.Set("state", "other-transaction-state")
		}
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
	serve := func(t *testing.T, redirect, state string, headers http.Header, params url.Values) *httptest.ResponseRecorder {
		t.Helper()
		pkce := sha256.Sum256([]byte(strings.Repeat("v", 43)))
		query := url.Values{"client_id": {"boundary-client"}, "response_type": {"code"}, "redirect_uri": {redirect}, "scope": {"profile"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(pkce[:])}, "code_challenge_method": {"S256"}}
		maps.Copy(query, params)
		request := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+query.Encode(), nil)
		request.Header = headers
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		assert.Contains(t, response.Header().Get("Cache-Control"), "no-store")
		assert.Equal(t, "no-referrer", response.Header().Get("Referrer-Policy"))
		assert.NotContains(t, response.Body.String(), "UPSTREAM-PRIVATE-DIAGNOSTIC")
		return response
	}
	t.Run("loopback_redirect_contract", func(t *testing.T) {
		for _, tc := range []struct {
			name, redirect string
			accepted       bool
		}{
			{"different_port", "http://127.0.0.1:39874/oauth/callback", true},
			{"minimum_port", "http://127.0.0.1:1/oauth/callback", true},
			{"maximum_port", "http://127.0.0.1:65535/oauth/callback", true},
			{"legacy_registered_scheme", "cherrystudio://oauth/callback", true},
			{"localhost", "http://localhost:39874/oauth/callback", false},
			{"host_suffix", "http://127.0.0.1.evil:39874/oauth/callback", false},
			{"numeric_host", "http://2130706433:39874/oauth/callback", false},
			{"https", "https://127.0.0.1:39874/oauth/callback", false},
			{"path", "http://127.0.0.1:39874/other", false},
			{"encoded_path", "http://127.0.0.1:39874/oauth/%63allback", false},
			{"query", "http://127.0.0.1:39874/oauth/callback?x=1", false},
			{"empty_query", "http://127.0.0.1:39874/oauth/callback?", false},
			{"userinfo", "http://user@127.0.0.1:39874/oauth/callback", false},
			{"fragment", "http://127.0.0.1:39874/oauth/callback#x", false},
			{"empty_fragment", "http://127.0.0.1:39874/oauth/callback#", false},
			{"missing_port", "http://127.0.0.1/oauth/callback", false},
			{"zero_port", "http://127.0.0.1:0/oauth/callback", false},
			{"over_port", "http://127.0.0.1:65536/oauth/callback", false},
			{"nonnumeric_port", "http://127.0.0.1:x/oauth/callback", false},
			{"ipv6_unregistered", "http://[::1]:39874/oauth/callback", false},
			{"ipv6_zone", "http://[::1%25lo]:39874/oauth/callback", false},
			{"unregistered_custom_scheme", "boxnai://oauth/callback", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := authCalls.Load()
				response := serve(t, tc.redirect, "loopback-contract-state", nil, nil)
				forwardedCount := authCalls.Load() - before
				if forwardedCount > 0 {
					<-forwarded
				}
				if !tc.accepted {
					assert.Equal(t, http.StatusBadRequest, response.Code)
					assert.Zero(t, forwardedCount, "invalid redirect must not reach issuer")
					assert.Empty(t, response.Header().Get("Location"))
					return
				}
				require.Equal(t, http.StatusSeeOther, response.Code)
				assert.EqualValues(t, 1, forwardedCount)
				target, err := url.Parse(response.Header().Get("Location"))
				require.NoError(t, err)
				requested, err := url.Parse(tc.redirect)
				require.NoError(t, err)
				assert.Equal(t, requested.Host, target.Host)
				assert.Equal(t, requested.Path, target.Path)
				assert.Equal(t, requested.Scheme, target.Scheme)
				assert.Equal(t, "loopback-contract-state", target.Query().Get("state"))
				assert.Equal(t, issuer, target.Query().Get("iss"))
			})
		}
	})
	t.Run("pkce_authorization_contract", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			params url.Values
		}{
			{"missing_challenge", url.Values{"code_challenge": nil}},
			{"plain_method", url.Values{"code_challenge_method": {"plain"}}},
			{"missing_method", url.Values{"code_challenge_method": nil}},
			{"short_challenge", url.Values{"code_challenge": {"short"}}},
			{"padded_challenge", url.Values{"code_challenge": {base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}}},
			{"missing_state", url.Values{"state": nil}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := authCalls.Load()
				response := serve(t, "http://127.0.0.1:39874/oauth/callback", "pkce-contract-state", nil, tc.params)
				if authCalls.Load() > before {
					<-forwarded
				}
				assert.Equal(t, http.StatusBadRequest, response.Code)
				assert.Equal(t, before, authCalls.Load(), "invalid PKCE/state must not reach issuer")
				assert.Empty(t, response.Header().Get("Location"))
			})
		}
	})
	t.Run("callback_state_mismatch", func(t *testing.T) {
		wrongState.Store(true)
		defer wrongState.Store(false)
		response := serve(t, callback, "expected-transaction-state", nil, nil)
		<-forwarded
		assert.Equal(t, http.StatusServiceUnavailable, response.Code)
		assert.Empty(t, response.Header().Get("Location"))
		assert.NotContains(t, response.Body.String(), "synthetic-code")
	})
	t.Run("loopback_code_exchange_contract", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		common.IsMasterNode = true
		require.NoError(t, model.InitOAuthGrantStore(true))
		common.IsMasterNode = false
		const actualRedirect = "http://127.0.0.1:39874/oauth/callback"
		const registeredRedirect = "http://127.0.0.1:29873/oauth/callback"
		verifier := strings.Repeat("v", 43)
		pkce := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(pkce[:])
		grant := &model.OAuthGrant{GrantID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Issuer: issuer, ClientID: "boundary-client", Subject: strconv.Itoa(f.users["owner"].Id), UserID: f.users["owner"].Id,
			ConsentRequestID: "loopback-consent", HydraLoginSessionID: "loopback-login", OriginSID: f.sids["owner"], SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("a", 64)}
		require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
		require.NoError(t, model.ApproveOAuthGrant(t.Context(), grant))
		// Seed only the completed consent boundary. The formal authorization
		// route must create the code artifact with the actual redirect and PKCE.
		op := &model.OAuthOperation{Issuer: issuer, UserID: grant.UserID, ClientID: grant.ClientID, OriginSID: grant.OriginSID, AuthVersion: 1, SessionVersion: 1, GrantRef: grant.GrantRef, Kind: "consent_accept"}
		require.NoError(t, model.ReserveOAuthOperation(t.Context(), op))
		require.NoError(t, model.SendOAuthOperation(t.Context(), op))
		require.NoError(t, model.ObserveOAuthOperation(t.Context(), op, []model.OAuthArtifact{{ArtifactRef: model.OAuthArtifactRef(issuer, "consent_verifier", "synthetic-consent-verifier"), Kind: "consent_verifier", PKCE: challenge, RedirectHash: model.OAuthArtifactRef(issuer, "redirect", actualRedirect), ExpiresAt: time.Now().Add(time.Minute).Unix()}}))
		claims := map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": issuer, "aud": []string{"boundary-userinfo"}, "client_id": grant.ClientID, "sub": grant.Subject, "exp": time.Now().Unix() + 600, "scope": "profile",
			"ext": map[string]any{"newapi_auth_version": "1", "newapi_grant_id": grant.GrantID, "newapi_grant_expires_at": strconv.FormatInt(grant.ExpiresAt, 10)}}
		introspection.Store(&claims)
		before := authCalls.Load()
		response := serve(t, actualRedirect, "loopback-exchange-state", nil, url.Values{"consent_verifier": {"synthetic-consent-verifier"}})
		require.Equal(t, before+1, authCalls.Load(), "authorization must reach issuer")
		request := <-forwarded
		require.Equal(t, http.StatusSeeOther, response.Code)
		assert.Equal(t, actualRedirect, request.query.Get("redirect_uri"))
		assert.Equal(t, challenge, request.query.Get("code_challenge"))
		assert.Equal(t, "S256", request.query.Get("code_challenge_method"))
		target, err := url.Parse(response.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1:39874", target.Host)
		assert.Equal(t, "/oauth/callback", target.Path)
		assert.Equal(t, "loopback-exchange-state", target.Query().Get("state"))
		assert.Equal(t, issuer, target.Query().Get("iss"))
		require.Equal(t, "synthetic-code", target.Query().Get("code"))
		for _, tc := range []struct {
			name, redirect, verifier, failure string
			status                            int
			forwarded                         bool
		}{
			{"registered_port_is_not_authorized_port", registeredRedirect, verifier, "invalid_grant", 400, false},
			{"wrong_verifier", actualRedirect, strings.Repeat("x", 43), "invalid_grant", 400, false},
			{"missing_verifier", actualRedirect, "", "invalid_request", 400, false},
			{"short_verifier", actualRedirect, strings.Repeat("v", 42), "invalid_request", 400, false},
			{"invalid_verifier_alphabet", actualRedirect, strings.Repeat("v", 42) + "+", "invalid_request", 400, false},
			{"actual_port_and_verifier", actualRedirect, verifier, "", 200, true},
			{"issuer_rejects_code_reuse", actualRedirect, verifier, "invalid_grant", 400, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				form := url.Values{"client_id": {grant.ClientID}, "grant_type": {"authorization_code"}, "code": {target.Query().Get("code")}, "redirect_uri": {tc.redirect}, "code_verifier": {tc.verifier}}
				before := tokenCalls.Load()
				request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				response := httptest.NewRecorder()
				engine.ServeHTTP(response, request)
				calls := tokenCalls.Load() - before
				if calls > 0 {
					assert.Equal(t, form, <-tokenForms, "exchange parameters must be preserved exactly")
				}
				assert.Equal(t, tc.forwarded, calls == 1, "invalid local binding must not reach issuer")
				require.Equal(t, tc.status, response.Code)
				assert.Contains(t, response.Header().Get("Cache-Control"), "no-store")
				assert.Equal(t, "no-referrer", response.Header().Get("Referrer-Policy"))
				assert.Empty(t, response.Header().Get("Location"))
				var body map[string]any
				require.NoError(t, common.Unmarshal(response.Body.Bytes(), &body))
				if tc.failure != "" {
					assert.Equal(t, map[string]any{"error": tc.failure}, body)
				} else {
					assert.Equal(t, "synthetic-access-token", body["access_token"])
					assert.Equal(t, "bearer", body["token_type"])
					assert.Equal(t, "profile", body["scope"])
				}
			})
		}
	})
	t.Run("forwarded_host_does_not_select_redirect", func(t *testing.T) {
		spoofed := http.Header{"Host": {"attacker.example"}, "X-Forwarded-Host": {"attacker.example"}, "Forwarded": {"host=attacker.example;proto=https"}}
		response := serve(t, callback, "issuer-login-page", spoofed, nil)
		request := <-forwarded
		require.Equal(t, http.StatusSeeOther, response.Code)
		assert.Equal(t, issuer+"oauth/provider/login?login_challenge=login-challenge-value", response.Header().Get("Location"))
		assert.NotContains(t, response.Header().Get("Location"), "attacker.example")
		assert.Empty(t, request.headers.Get("X-Forwarded-Host"))
		assert.Empty(t, request.headers.Get("Forwarded"))
		assert.NotContains(t, request.headers.Get("Host"), "attacker.example")
		response = serve(t, callback, "keep-callback-host", spoofed, nil)
		<-forwarded
		require.Equal(t, http.StatusSeeOther, response.Code)
		target, err := url.Parse(response.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "client.example", target.Host)
		assert.Equal(t, issuer, target.Query().Get("iss"))
		assert.NotContains(t, response.Header().Get("Location"), "attacker.example")
		response = serve(t, callback, "upstream-uses-attacker-host", spoofed, nil)
		<-forwarded
		assert.Equal(t, http.StatusServiceUnavailable, response.Code)
		assert.Empty(t, response.Header().Get("Location"))
		assert.NotContains(t, response.Body.String(), "attacker.example")
		assert.Contains(t, response.Body.String(), "temporarily_unavailable")
		for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodOptions} {
			discovery := httptest.NewRequest(method, "/.well-known/openid-configuration", nil)
			discovery.Host = "attacker.example"
			discovery.Header.Set("X-Forwarded-Host", "attacker.example")
			recorded := httptest.NewRecorder()
			engine.ServeHTTP(recorded, discovery)
			assert.Equal(t, http.StatusMethodNotAllowed, recorded.Code, method)
			assert.Contains(t, recorded.Body.String(), "invalid_request")
			assert.NotContains(t, recorded.Body.String(), "attacker.example")
		}
		for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
			discovery := httptest.NewRequest(http.MethodGet, path, nil)
			discovery.Host = "attacker.example"
			discovery.Header.Set("X-Forwarded-Host", "attacker.example")
			recorded := httptest.NewRecorder()
			engine.ServeHTTP(recorded, discovery)
			require.Equal(t, http.StatusOK, recorded.Code, path)
			var document map[string]any
			require.NoError(t, common.Unmarshal(recorded.Body.Bytes(), &document))
			assert.Equal(t, issuer, document["issuer"])
			assert.Equal(t, issuer+"oauth2/auth", document["authorization_endpoint"])
			assert.Equal(t, issuer+"oauth2/token", document["token_endpoint"])
			assert.NotContains(t, recorded.Body.String(), "attacker.example")
			assert.NotContains(t, recorded.Body.String(), "tokens:write")
		}
		unknown := httptest.NewRecorder()
		engine.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/oauth2/not-whitelisted", nil))
		assert.Equal(t, http.StatusNotFound, unknown.Code)
		assert.Contains(t, unknown.Body.String(), "not_found")
	})
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
				response := serve(t, callback, "cookie-check", tc.headers, nil)
				assert.Equal(t, tc.want, response.Code)
				if authCalls.Load() == before {
					assert.Equal(t, 400, tc.want)
					assert.Empty(t, response.Header().Get("Location"))
					return
				}
				headers := (<-forwarded).headers
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
					response := serve(t, callback+"?"+key+"=registered-context", state, nil, nil)
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
			response := serve(t, callback, "append-diagnostic", nil, nil)
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
				legacy := &model.OAuthOperation{OperationRef: strings.Repeat("e", 64), UserID: userID, Kind: "sessions_all", State: "local_pending", CreatedAt: time.Now().Unix()}
				require.NoError(t, f.db.Create(legacy).Error)
				_, err := model.RevokeAllUserSessions(userID, "session_revoked")
				require.NoError(t, err)
				require.ErrorIs(t, model.CompleteOAuthSessionRevocation(userID, ""), model.ErrOAuthCleanupHeld)
				require.NoError(t, f.db.Where("operation_ref = ?", legacy.OperationRef).First(legacy).Error)
				assert.Equal(t, "local_pending", legacy.State)
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

// seedSessionRevocationSessions is a bounded, deterministic batch-boundary fixture.
// It intentionally inserts old valid sessions directly; creation limits are tested
// separately through the production creator after the first batch frees capacity.
func seedSessionRevocationSessions(t *testing.T, f *organizationHTTPFixture, count int) {
	t.Helper()
	now := time.Now().Unix()
	rows := make([]model.UserSession, count)
	for i := range rows {
		rows[i] = model.UserSession{SID: fmt.Sprintf("s1-z-%04d-%d", i, f.users["owner"].Id), UserID: f.users["owner"].Id,
			Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("a", 64),
			LoginMethod: "password", CreatedAt: now, LastActiveAt: now, ExpiresAt: now + 3600}
	}
	require.NoError(t, f.db.CreateInBatches(&rows, 100).Error)
}

// Proposed for the root's exact A+B+C three-engine fixture run. This package
// compiles these cases but does not launch the fixture servers/databases here.
func TestSessionRevocationS1(t *testing.T) {
	for _, scenario := range []string{"dynamic_and_stale", "overlapping_others", "credential_intent_rollback", "sid_outbox_rollback", "http_pending", "hard_delete_capacity", "claim_pending", "unknown_version", "missing_store", "lost_historical_store"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			oauthPublicDatabase(t, f)
			common.IsMasterNode = true
			require.NoError(t, model.InitOAuthGrantStore(true))
			common.IsMasterNode = false
			require.NoError(t, model.ValidateSessionRevocationStore())
			userID, sid := f.users["owner"].Id, f.sids["owner"]
			var source model.UserSession
			require.NoError(t, f.db.Where("sid = ?", sid).First(&source).Error)
			if scenario == "lost_historical_store" {
				var event *model.SessionRevocationEvent
				require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
					var err error
					event, err = model.StartSessionRevocationWithTx(tx, userID, "", "session_revoked")
					return err
				}))
				require.True(t, event.OAuthAttributionRequired)
				require.NoError(t, model.InitOAuthCleanupStore(false))
				require.NoError(t, f.db.Migrator().DropTable(&model.OAuthArtifact{}, &model.OAuthCleanupJob{}, &model.OAuthOperation{}, &model.OAuthGrant{}))
				require.ErrorIs(t, model.ValidateSessionOAuthHistoryBeforeMigration(), model.ErrSessionRevocationStore)
				require.ErrorIs(t, model.ValidateSessionRevocationStore(), model.ErrSessionRevocationStore)
				_, err := model.RunSessionRevocationBatch(t.Context(), *event)
				require.ErrorIs(t, err, model.ErrSessionRevocationStore)
				return
			}
			if scenario == "unknown_version" {
				event := &model.SessionRevocationEvent{EventRef: strings.Repeat("f", 64), ProtocolVersion: 2, UserID: userID, Scope: "all",
					Reason: "session_revoked", State: "pending", Revision: 1, CreatedAt: time.Now().Unix()}
				require.NoError(t, f.db.Create(event).Error)
				require.ErrorIs(t, model.ValidateSessionRevocationStore(), model.ErrSessionRevocationStore)
				copy := source
				copy.SID = "s1-unknown-version"
				require.ErrorIs(t, model.CreateUserSession(&copy), model.ErrSessionRevocationStore)
				return
			}
			if scenario == "missing_store" {
				require.NoError(t, f.db.Migrator().DropTable(&model.SessionRevocationEvent{}))
				_, err := model.RevokeAllUserSessions(userID, "session_revoked")
				require.Error(t, err)
				copy := source
				copy.SID = "s1-missing-store"
				require.Error(t, model.CreateUserSession(&copy))
				require.NoError(t, f.db.Where("sid = ?", sid).First(&source).Error)
				assert.Equal(t, model.UserSessionStatusActive, source.Status)
				return
			}
			if scenario == "credential_intent_rollback" || scenario == "sid_outbox_rollback" || scenario == "claim_pending" {
				grant := &model.OAuthGrant{GrantID: strings.Repeat("a", 43), Issuer: "https://s1.example/", ClientID: "desktop",
					Subject: strconv.Itoa(userID), UserID: userID, ConsentRequestID: "s1-consent", HydraLoginSessionID: "s1-login",
					OriginSID: sid, SessionVersion: 1, UserAuthVersion: 1, Scopes: "[\"profile\"]", PolicyHash: strings.Repeat("b", 64)}
				require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
			}
			if scenario == "credential_intent_rollback" {
				oldHash, err := common.HashAccountPassword("S1-original-password-731")
				require.NoError(t, err)
				require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", userID).Update("password", oldHash).Error)
				forced := errors.New("s1 initial attribution rejected")
				require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("s1:initial-outbox", func(tx *gorm.DB) {
					if job, ok := tx.Statement.Dest.(*model.OAuthCleanupJob); ok && job.SourceSessionEventRef != nil {
						tx.AddError(forced)
					}
				}))
				t.Cleanup(func() { _ = f.db.Callback().Create().Remove("s1:initial-outbox") })
				identity := model.AuthSessionIdentity{UserID: userID, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1}
				err = model.ChangeUserPassword(identity, &model.User{Id: userID, Password: "S1-next-password-927", OriginalPassword: "S1-original-password-731"}, false)
				require.ErrorIs(t, err, forced)
				var user model.User
				require.NoError(t, f.db.First(&user, userID).Error)
				assert.Equal(t, oldHash, user.Password)
				assert.Equal(t, int64(1), user.AuthVersion)
				var events, jobs int64
				require.NoError(t, f.db.Model(&model.SessionRevocationEvent{}).Where("user_id = ?", userID).Count(&events).Error)
				require.NoError(t, f.db.Model(&model.OAuthCleanupJob{}).Where("user_id = ?", userID).Count(&jobs).Error)
				assert.Zero(t, events)
				assert.Zero(t, jobs)
				return
			}
			if scenario == "hard_delete_capacity" {
				seedSessionRevocationSessions(t, f, 500)
				err := f.db.Transaction(func(tx *gorm.DB) error {
					_, event, err := model.AdvanceUserSecurityWithTx(tx, userID, nil)
					if err != nil {
						return err
					}
					_, err = model.RevokeSessionsForUserDeletionWithTx(tx, event)
					return err
				})
				require.ErrorIs(t, err, model.ErrSessionDeletionBlocked)
				var user model.User
				require.NoError(t, f.db.First(&user, userID).Error)
				assert.Equal(t, int64(1), user.AuthVersion)
				var intents int64
				require.NoError(t, f.db.Model(&model.SessionRevocationEvent{}).Where("user_id = ?", userID).Count(&intents).Error)
				assert.Zero(t, intents, "capacity failure rolls back the entire deletion intent")
				return
			}
			if scenario == "http_pending" {
				seedSessionRevocationSessions(t, f, 501)
				require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}, &model.TwoFA{}, &model.PasskeyCredential{}))
				proof := sessionRevocationProof(t, f, "owner", service.VerificationScopeSessionsRevokeOthers, nil)
				status, headers, body := f.request(t, http.MethodPost, "/api/user/sessions/revoke-others", "owner", "", http.Header{"X-Security-Proof": {proof}})
				require.Equal(t, http.StatusServiceUnavailable, status)
				assert.Equal(t, "1", headers.Get("Retry-After"))
				assert.Contains(t, headers.Get("Cache-Control"), "no-store")
				assert.Equal(t, "AUTH_SESSION_REVOCATION_PENDING", body["code"])
				assert.Equal(t, false, body["success"])
				data, ok := body["data"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, false, data["credential_change_committed"])
				assert.Equal(t, false, data["session_revocation_complete"])
				assert.Equal(t, float64(500), data["revoked_count"])
				assert.NotContains(t, data, "event_ref")
				assert.NotContains(t, data, "access_token")
				var event model.SessionRevocationEvent
				require.NoError(t, f.db.Where("user_id = ?", userID).First(&event).Error)
				completed, err := model.RunSessionRevocationBatch(t.Context(), event)
				require.NoError(t, err)
				assert.Equal(t, "local_complete", completed.State)
				assert.Equal(t, int64(501), completed.AffectedCount)
				return
			}
			if scenario == "overlapping_others" {
				copy := source
				copy.SID = "s1-other"
				require.NoError(t, model.CreateUserSession(&copy))
				var first, second *model.SessionRevocationEvent
				require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
					var err error
					first, err = model.StartSessionRevocationWithTx(tx, userID, sid, "session_revoked")
					if err != nil {
						return err
					}
					second, err = model.StartSessionRevocationWithTx(tx, userID, copy.SID, "session_revoked")
					return err
				}))
				a, err := model.RunSessionRevocationBatch(t.Context(), *first)
				require.NoError(t, err)
				b, err := model.RunSessionRevocationBatch(t.Context(), *second)
				require.NoError(t, err)
				assert.Equal(t, int64(1), a.AffectedCount)
				assert.Equal(t, int64(1), b.AffectedCount)
				var active int64
				require.NoError(t, f.db.Model(&model.UserSession{}).Where("user_id = ? AND status = ?", userID, model.UserSessionStatusActive).Count(&active).Error)
				assert.Zero(t, active)
				return
			}
			if scenario == "dynamic_and_stale" {
				seedSessionRevocationSessions(t, f, 500)
			}
			var event *model.SessionRevocationEvent
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
				var err error
				event, err = model.StartSessionRevocationWithTx(tx, userID, "", "session_revoked")
				return err
			}))
			if scenario == "claim_pending" {
				var job model.OAuthCleanupJob
				require.NoError(t, f.db.Where("user_id = ?", userID).First(&job).Error)
				claimed, err := model.ClaimOAuthCleanup(t.Context(), job.JobRef, "s1-cleanup", time.Now().Unix())
				require.NoError(t, err)
				require.Nil(t, claimed)
				require.NoError(t, f.db.Where("job_ref = ?", job.JobRef).First(&job).Error)
				assert.Equal(t, "blocked", job.State)
				assert.Equal(t, "local_pending", job.ErrorCode)
				return
			}
			if scenario == "sid_outbox_rollback" {
				forced := errors.New("s1 per-SID outbox rejected")
				require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("s1:sid-outbox", func(tx *gorm.DB) {
					if job, ok := tx.Statement.Dest.(*model.OAuthCleanupJob); ok && job.Scope == "sid" {
						tx.AddError(forced)
					}
				}))
				t.Cleanup(func() { _ = f.db.Callback().Create().Remove("s1:sid-outbox") })
				_, err := model.RunSessionRevocationBatch(t.Context(), *event)
				require.ErrorIs(t, err, forced)
				var current model.SessionRevocationEvent
				require.NoError(t, f.db.Where("event_ref = ?", event.EventRef).First(&current).Error)
				assert.Equal(t, int64(1), current.Revision)
				assert.Zero(t, current.AffectedCount)
				require.NoError(t, f.db.Where("sid = ?", sid).First(&source).Error)
				assert.Equal(t, model.UserSessionStatusActive, source.Status)
				var jobs []model.OAuthCleanupJob
				require.NoError(t, f.db.Where("user_id = ?", userID).Find(&jobs).Error)
				require.Len(t, jobs, 1, "only committed initial attribution survives")
				require.NotNil(t, jobs[0].SourceSessionEventRef)
				assert.Equal(t, event.EventRef, *jobs[0].SourceSessionEventRef)
				return
			}
			first, err := model.RunSessionRevocationBatch(t.Context(), *event)
			require.NoError(t, err)
			require.Equal(t, "pending", first.State)
			assert.Equal(t, int64(500), first.AffectedCount)
			oldLimit := common.UserSessionIssuanceLimit
			common.UserSessionIssuanceLimit = 2000
			t.Cleanup(func() { common.UserSessionIssuanceLimit = oldLimit })
			early := source
			early.SID = "s1-a-created-before-finalize"
			require.NoError(t, model.CreateUserSession(&early))
			second, err := model.RunSessionRevocationBatch(t.Context(), *first)
			require.NoError(t, err)
			require.Equal(t, "local_complete", second.State)
			assert.Equal(t, int64(502), second.AffectedCount)
			late := source
			late.SID = "s1-created-after-finalize"
			require.NoError(t, model.CreateUserSession(&late))
			_, err = model.RunSessionRevocationBatch(t.Context(), *first)
			require.ErrorIs(t, err, model.ErrSessionRevocationStale)
			require.NoError(t, f.db.Where("sid = ?", late.SID).First(&late).Error)
			assert.Equal(t, model.UserSessionStatusActive, late.Status)
			var legacy int64
			require.NoError(t, f.db.Model(&model.OAuthOperation{}).Where("user_id = ? AND state = ?", userID, "local_pending").Count(&legacy).Error)
			assert.Zero(t, legacy, "new events do not create legacy range identities")
		})
	}
}

// W01-03 author verification: report driver/catalog contracts without altering
// the frozen production candidate or weakening its startup validation.
func TestSessionRevocationS1StoreDiagnostics(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oauthPublicDatabase(t, f)
	stmt := &gorm.Statement{DB: f.db}
	require.NoError(t, stmt.Parse(&model.SessionRevocationEvent{}))
	t.Logf("attribution_field_db_name=%s", stmt.Schema.LookUpField("OAuthAttributionRequired").DBName)
	columns, err := f.db.Migrator().ColumnTypes(&model.SessionRevocationEvent{})
	require.NoError(t, err)
	for _, column := range columns {
		primary, supported := column.PrimaryKey()
		t.Logf("column=%s primary=%v primary_supported=%v", column.Name(), primary, supported)
	}
	indexes, err := f.db.Migrator().GetIndexes(&model.SessionRevocationEvent{})
	require.NoError(t, err)
	for _, index := range indexes {
		t.Logf("index=%s columns=%v", index.Name(), index.Columns())
	}
	if f.db.Dialector.Name() == "postgres" {
		var rows []struct {
			Indexname string
			Indexdef  string
		}
		require.NoError(t, f.db.Raw("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = ? AND schemaname = CURRENT_SCHEMA()", "session_revocation_events").Scan(&rows).Error)
		for _, row := range rows {
			t.Logf("catalog_index=%s definition=%s", row.Indexname, row.Indexdef)
		}
	}
	t.Run("fresh_startup_preflight", func(t *testing.T) { require.NoError(t, model.ValidateSessionOAuthHistoryBeforeMigration()) })
	common.IsMasterNode = true
	require.NoError(t, model.InitOAuthGrantStore(true))
	common.IsMasterNode = false
	t.Run("ready_oauth_store_validation", func(t *testing.T) { require.NoError(t, model.ValidateSessionRevocationStore()) })
}

func TestSessionRevocationS1Namespace(t *testing.T) {
	require.Equal(t, "postgres", os.Getenv("NEWAPI_W01_MAIN_KIND"))
	for _, restricted := range []bool{false, true} {
		t.Run(fmt.Sprintf("restricted_%v", restricted), func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			oauthPublicDatabase(t, f)
			require.NoError(t, model.InitOAuthCleanupStore(false))
			require.NoError(t, f.db.AutoMigrate(&model.OAuthGrant{}, &model.OAuthOperation{}, &model.OAuthArtifact{}, &model.OAuthCleanupJob{}))
			role := "w01s104_" + strings.ToLower(strings.ReplaceAll(common.NewRequestId(), "-", ""))
			if os.Getenv("NEWAPI_BOOTSTRAP_TIER") == "postgres" {
				var receipt struct {
					RestrictedRole string `json:"restricted_role"`
				}
				raw, err := os.ReadFile(os.Getenv("NEWAPI_BOOTSTRAP_PG_RECEIPT"))
				require.NoError(t, err)
				require.NoError(t, common.Unmarshal(raw, &receipt))
				role = receipt.RestrictedRole // Created/granted by the trusted installer.
			} else {
				require.NoError(t, f.db.Exec("CREATE SCHEMA app").Error)
			}
			require.NoError(t, f.db.Exec("ALTER TABLE public.users SET SCHEMA app").Error)
			require.NoError(t, f.db.Exec("ALTER TABLE public.session_revocation_events SET SCHEMA app").Error)
			require.Regexp(t, `^[a-z][a-z0-9_]+$`, role)
			if restricted && os.Getenv("NEWAPI_BOOTSTRAP_TIER") != "postgres" {
				require.NoError(t, f.db.Exec("CREATE ROLE "+role+" NOLOGIN").Error)
				t.Logf("W01-04 owned role=%s", role)
				t.Cleanup(func() {
					require.NoError(t, f.db.Exec("DROP OWNED BY "+role).Error)
					require.NoError(t, f.db.Exec("DROP ROLE "+role).Error)
					t.Logf("W01-04 removed role=%s", role)
				})
				require.NoError(t, f.db.Exec("REVOKE ALL ON SCHEMA public FROM PUBLIC").Error)
				require.NoError(t, f.db.Exec("GRANT USAGE ON SCHEMA app TO "+role).Error)
				require.NoError(t, f.db.Exec("GRANT SELECT, UPDATE ON app.users TO "+role).Error)
				require.NoError(t, f.db.Exec("GRANT SELECT, INSERT, UPDATE ON app.session_revocation_events TO "+role).Error)
			}
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
				require.NoError(t, tx.Exec("SET LOCAL search_path = app, public").Error)
				if restricted {
					require.NoError(t, tx.Exec("SET LOCAL ROLE "+role).Error)
				}
				before := model.DB
				model.DB = tx
				defer func() { model.DB = before }()
				assert.ErrorIs(t, model.ValidateSessionOAuthHistoryBeforeMigration(), model.ErrSessionRevocationStore)
				_, err := model.StartSessionRevocationWithTx(tx, f.users["owner"].Id, "", "session_revoked")
				assert.ErrorIs(t, err, model.ErrSessionRevocationStore)
				return nil
			}))
			var events int64
			require.NoError(t, f.db.Table("app.session_revocation_events").Count(&events).Error)
			assert.Zero(t, events, "hidden history cannot be replaced by a false no-history event")
			for _, table := range []string{"oauth_grants", "o_auth_operations", "o_auth_artifacts", "o_auth_cleanup_jobs"} {
				var count int64
				require.NoError(t, f.db.Raw("SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=?", table).Scan(&count).Error)
				assert.EqualValues(t, 1, count)
			}
		})
	}
}

func sessionRevocationRepairFixture(t *testing.T) *organizationHTTPFixture {
	t.Helper()
	f := newOrganizationHTTPFixture(t)
	oauthPublicDatabase(t, f)
	if os.Getenv("NEWAPI_BOOTSTRAP_TIER") == "postgres-redis" {
		for _, value := range []any{&model.AuthFlow{}, &model.Option{}, &model.UserAccessToken{}, &model.TwoFA{}, &model.TwoFABackupCode{}, &model.PasskeyCredential{}, &model.UserOAuthBinding{}, &model.ExternalIdentityClaim{}, &model.CasbinRule{}, &model.AuthzRole{}} {
			require.NoError(t, f.db.Limit(0).Find(value).Error, "formal producer must create the S1 fixture schema")
		}
	} else {
		require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}, &model.Option{}, &model.UserAccessToken{}, &model.TwoFA{}, &model.TwoFABackupCode{}, &model.PasskeyCredential{}, &model.UserOAuthBinding{}, &model.ExternalIdentityClaim{}, &model.CasbinRule{}, &model.AuthzRole{}))
	}
	common.IsMasterNode = true
	require.NoError(t, model.InitOAuthGrantStore(true))
	require.NoError(t, authz.Init(f.db))
	common.IsMasterNode = false
	return f
}

func sessionRevocationProof(t *testing.T, f *organizationHTTPFixture, actor, scope string, context any) string {
	t.Helper()
	identity, err := service.ParseAccessToken(f.bearer[actor])
	require.NoError(t, err)
	var payload []byte
	if context != nil {
		payload, err = common.Marshal(context)
		require.NoError(t, err)
	}
	binding, err := service.BindVerificationOperation(service.VerificationOperation{Scope: scope, Context: payload})
	require.NoError(t, err)
	proof, _, err := service.IssueSecurityProof(identity, service.VerificationMethodPassword, binding)
	require.NoError(t, err)
	return proof
}

func TestSessionRevocationS1Permissions(t *testing.T) {
	for _, reloadFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("reload_failure_%v", reloadFailure), func(t *testing.T) {
			f := sessionRevocationRepairFixture(t)
			target := f.users["admin"]
			require.NoError(t, f.db.Model(target).Update("role", common.RoleAdminUser).Error)
			require.NoError(t, model.PublishUserAuthCache(target.Id))
			raw := "nap_" + strings.ToLower(strings.ReplaceAll(common.NewRequestId(), "-", ""))
			pat := &model.UserAccessToken{UserId: target.Id, TokenHash: model.AccessTokenFingerprint(raw), Name: "S1 permission regression"}
			require.NoError(t, pat.SetScopes([]string{"channel:read"}))
			require.NoError(t, model.CreateUserAccessToken(target.Id, pat, 10))
			const path = "/w01/s1-permission"
			middleware.DeclareAccessTokenPermissionRoute(http.MethodGet, path, authz.ChannelRead)
			f.engine.GET(path, middleware.UserAuth(), middleware.RequirePermission(authz.ChannelRead), func(c *gin.Context) { c.JSON(200, gin.H{"success": true}) })
			status, _, _ := f.request(t, http.MethodGet, path, raw, "", nil)
			require.Equal(t, 200, status)
			// Fail only post-credential session writes, so a real intent commits and
			// completion returns pending without requiring 501 duplicate fixture rows.
			require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("s1:pending", func(tx *gorm.DB) {
				if tx.Statement.Table == "user_sessions" {
					tx.AddError(errors.New("S1 batch write unavailable"))
				}
			}))
			t.Cleanup(func() { _ = f.db.Callback().Update().Remove("s1:pending") })
			var reloadAttempted atomic.Bool
			if reloadFailure {
				require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("s1:reload", func(tx *gorm.DB) {
					if tx.Statement.Table == "casbin_rule" {
						reloadAttempted.Store(true)
						tx.AddError(errors.New("S1 policy read unavailable"))
					}
				}))
				t.Cleanup(func() { _ = f.db.Callback().Query().Remove("s1:reload") })
			}
			proof := sessionRevocationProof(t, f, "root", service.VerificationScopeAdminUserUpdate, service.AdminUserContext{UserID: target.Id})
			body, err := common.Marshal(map[string]any{"id": target.Id, "username": target.Username, "role": common.RoleAdminUser, "group": "default", "password": "S1-replaced-password-783", "admin_permissions": authz.PermissionsMap{"channel": {"read": false}}})
			require.NoError(t, err)
			status, _, response := f.request(t, http.MethodPut, "/api/user/", "root", string(body), http.Header{"X-Security-Proof": {proof}})
			assert.Equal(t, false, response["success"])
			if reloadFailure {
				assert.True(t, status == 500 || status == 503)
				assert.True(t, reloadAttempted.Load())
			} else {
				assert.Equal(t, 503, status)
				assert.Equal(t, "AUTH_SESSION_REVOCATION_PENDING", response["code"])
			}
			var user model.User
			require.NoError(t, f.db.First(&user, target.Id).Error)
			assert.EqualValues(t, 2, user.AuthVersion)
			assert.True(t, common.ValidatePasswordAndHash("S1-replaced-password-783", user.Password))
			var token model.UserAccessToken
			require.NoError(t, f.db.First(&token, pat.Id).Error)
			status, _, _ = f.request(t, http.MethodGet, path, raw, "", nil)
			assert.Equal(t, http.StatusForbidden, status, "a still-valid PAT cannot retain the committed removed permission")
		})
	}
}

func TestSessionRevocationS1Bindings(t *testing.T) {
	for _, scenario := range []string{"email_bind", "email_replace", "email_intent_rollback", "self_unlink", "admin_clear", "admin_custom_unlink", "builtin_bind", "builtin_replace", "custom_bind", "custom_replace", "telegram_bind", "builtin_intent_rollback", "last_login_method"} {
		t.Run(scenario, func(t *testing.T) {
			f := sessionRevocationRepairFixture(t)
			user := f.users["owner"]
			identity, err := service.ParseAccessToken(f.bearer["owner"])
			require.NoError(t, err)
			forced := errors.New("S1 event insert unavailable")
			if strings.HasSuffix(scenario, "intent_rollback") {
				require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("s1:binding-intent", func(tx *gorm.DB) {
					if _, ok := tx.Statement.Dest.(*model.SessionRevocationEvent); ok {
						tx.AddError(forced)
					}
				}))
				t.Cleanup(func() { _ = f.db.Callback().Create().Remove("s1:binding-intent") })
			}
			switch scenario {
			case "email_bind", "email_replace", "email_intent_rollback":
				current := ""
				if scenario == "email_replace" {
					current = "old-s1@example.com"
				}
				require.NoError(t, f.db.Model(user).Update("email", current).Error)
				hash, err := common.Password2Hash("194638")
				require.NoError(t, err)
				state := model.EmailBindingState{CurrentEmail: current, Email: "new-s1@example.com", NewCodeHash: hash, Authorization: &model.AuthFlowAuthorization{AuthSessionIdentity: identity, ProofID: 1, Scope: service.VerificationScopeAccountBind, ContextHash: "S1-bound-test"}}
				if current != "" {
					state.OldCodeHash = hash
				}
				flow, _, err := model.CreateEmailBinding(identity, state)
				require.NoError(t, err)
				_, err = model.CompleteEmailBinding(identity, flow, state.Email, "194638", "194638")
				if scenario == "email_intent_rollback" {
					assert.ErrorIs(t, err, forced)
				} else {
					require.NoError(t, err)
				}
			case "self_unlink", "admin_custom_unlink":
				require.NoError(t, f.db.Create(&model.UserOAuthBinding{UserId: user.Id, ProviderId: 1, ProviderUserId: "S1-bound-subject"}).Error)
				if scenario == "self_unlink" {
					require.NoError(t, model.UnbindUserOAuthForSession(identity, 1, model.AccountLoginMethods{Password: true}))
				} else {
					require.NoError(t, model.DeleteUserOAuthBinding(user.Id, 1))
				}
			case "builtin_bind", "builtin_replace", "custom_bind", "custom_replace", "telegram_bind", "builtin_intent_rollback":
				if scenario == "builtin_replace" {
					require.NoError(t, f.db.Model(user).Update("github_id", "old-subject").Error)
				}
				if scenario == "custom_replace" {
					require.NoError(t, f.db.Create(&model.UserOAuthBinding{UserId: user.Id, ProviderId: 1, ProviderUserId: "old-subject"}).Error)
				}
				var event *model.SessionRevocationEvent
				err := f.db.Transaction(func(tx *gorm.DB) error {
					var err error
					if strings.HasPrefix(scenario, "custom_") {
						event, err = model.UpdateUserOAuthBindingForSessionWithTx(tx, identity, 1, "new-subject")
					} else if scenario == "telegram_bind" {
						event, err = model.BindTelegramForSessionWithTx(tx, identity, "123456789")
					} else {
						event, err = model.UpdateUserBindColumnForSessionWithTx(tx, identity, "github_id", "new-subject")
					}
					return err
				})
				if scenario == "builtin_intent_rollback" {
					assert.ErrorIs(t, err, forced)
				} else {
					require.NoError(t, err)
					_, err = service.CompleteAccountBinding(identity, event)
					require.NoError(t, err)
				}
			case "last_login_method":
				require.NoError(t, f.db.Create(&model.UserOAuthBinding{UserId: user.Id, ProviderId: 1, ProviderUserId: "only-login"}).Error)
				assert.ErrorIs(t, model.UnbindUserOAuthForSession(identity, 1, model.AccountLoginMethods{}), model.ErrLastLoginMethod)
			case "admin_clear":
				require.NoError(t, f.db.Model(user).Update("github_id", "S1-old-binding").Error)
				require.NoError(t, user.ClearBinding("github"))
			}
			var updated model.User
			require.NoError(t, f.db.First(&updated, user.Id).Error)
			var events []model.SessionRevocationEvent
			require.NoError(t, f.db.Where("user_id = ?", user.Id).Find(&events).Error)
			if strings.HasSuffix(scenario, "intent_rollback") || scenario == "last_login_method" {
				assert.Empty(t, updated.GitHubId)
				assert.EqualValues(t, 1, updated.AuthVersion)
				assert.Empty(t, updated.Email)
				assert.Empty(t, events)
				return
			}
			assert.EqualValues(t, 2, updated.AuthVersion)
			require.Len(t, events, 1)
			assert.Equal(t, "security_changed", events[0].Reason)
			if strings.HasPrefix(scenario, "admin_") {
				assert.Equal(t, "all", events[0].Scope)
			} else {
				assert.Equal(t, "others", events[0].Scope)
				assert.Equal(t, identity.SessionID, events[0].ExcludedSID)
			}
		})
	}
}

func TestSessionRevocationS1ProofRequired(t *testing.T) {
	for _, path := range []string{"/api/user/sessions/revoke-others", "/api/user/sessions/"} {
		t.Run(path, func(t *testing.T) {
			f := sessionRevocationRepairFixture(t)
			method := http.MethodPost
			if strings.HasSuffix(path, "/") {
				method = http.MethodDelete
				var session model.UserSession
				require.NoError(t, f.db.Where("sid = ?", f.sids["owner"]).First(&session).Error)
				session.SID = "s1-proof-target"
				require.NoError(t, model.CreateUserSession(&session))
				path += session.SID
			}
			status, _, body := f.request(t, method, path, "owner", "", nil)
			assert.Equal(t, http.StatusForbidden, status)
			assert.Equal(t, "SECURITY_PROOF_REQUIRED", body["code"])
		})
	}
}

// Pause the business transaction after the separate proof-consumption commit.
// The same production connection-pool interfaces are used by both dialects.
type sessionRevocationActorPausePool struct {
	gorm.ConnPool
	begun   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (p *sessionRevocationActorPausePool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	if p.begun.Add(1) == 2 {
		close(p.entered)
		select {
		case <-p.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if b, ok := p.ConnPool.(gorm.ConnPoolBeginner); ok {
		return b.BeginTx(ctx, opts)
	}
	if b, ok := p.ConnPool.(gorm.TxBeginner); ok {
		return b.BeginTx(ctx, opts)
	}
	return nil, errors.New("fixture cannot begin transaction")
}

func TestSessionRevocationS1StaleActor(t *testing.T) {
	f := sessionRevocationRepairFixture(t)
	var target model.UserSession
	require.NoError(t, f.db.Where("sid = ?", f.sids["owner"]).First(&target).Error)
	target.SID = "s1-actor-target"
	require.NoError(t, model.CreateUserSession(&target))
	grant := &model.OAuthGrant{GrantID: strings.Repeat("x", 43), Issuer: "https://s1-actor.example/", ClientID: "desktop", Subject: strconv.Itoa(target.UserID), UserID: target.UserID, ConsentRequestID: "actor-target-consent", HydraLoginSessionID: "actor-login", OriginSID: target.SID, SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("b", 64)}
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
	proof := sessionRevocationProof(t, f, "owner", "session.revoke", map[string]any{"sid": target.SID})
	pool, statementPool := f.db.Config.ConnPool, f.db.Statement.ConnPool
	pause := &sessionRevocationActorPausePool{ConnPool: pool, entered: make(chan struct{}), release: make(chan struct{})}
	f.db.Config.ConnPool, f.db.Statement.ConnPool = pause, pause
	defer func() { f.db.Config.ConnPool, f.db.Statement.ConnPool = pool, statementPool }()
	done := make(chan int, 1)
	go func() {
		status, _, _ := f.request(t, http.MethodDelete, "/api/user/sessions/"+target.SID, "owner", "", http.Header{"X-Security-Proof": {proof}})
		done <- status
	}()
	select {
	case <-pause.entered:
	case <-time.After(10 * time.Second):
		close(pause.release)
		t.Fatal("business transaction did not reach actor race barrier")
	}
	revoked, err := model.RevokeUserSession(target.UserID, f.sids["owner"], "fixture_actor_terminated")
	close(pause.release)
	require.NoError(t, err)
	require.True(t, revoked)
	select {
	case status := <-done:
		assert.NotEqual(t, http.StatusOK, status)
	case <-time.After(10 * time.Second):
		t.Fatal("single-SID action did not finish")
	}
	require.NoError(t, f.db.Where("sid = ?", target.SID).First(&target).Error)
	assert.Equal(t, model.UserSessionStatusActive, target.Status)
	var jobs int64
	require.NoError(t, f.db.Model(&model.OAuthCleanupJob{}).Where("user_id = ? AND scope = ? AND value = ?", target.UserID, "sid", target.SID).Count(&jobs).Error)
	assert.Zero(t, jobs, "a terminated actor creates no target attribution")
}

func TestSessionRevocationS1ProofBindings(t *testing.T) {
	for _, scenario := range []string{"wrong_action", "wrong_target", "wrong_session", "expired", "replayed", "pat", "correct", "own_logout"} {
		t.Run(scenario, func(t *testing.T) {
			f := sessionRevocationRepairFixture(t)
			var target model.UserSession
			require.NoError(t, f.db.Where("sid = ?", f.sids["owner"]).First(&target).Error)
			target.SID = "s1-proof-binding-target"
			require.NoError(t, model.CreateUserSession(&target))
			raw, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: target.UserID, SessionID: target.SID, UserAuthVersion: 1, SessionVersion: 1})
			require.NoError(t, err)
			f.bearer["second"] = raw
			scope, actor, context := "session.revoke", "owner", any(map[string]any{"sid": target.SID})
			if scenario == "wrong_action" {
				scope, context = service.VerificationScopePasswordChange, nil
			}
			if scenario == "wrong_target" {
				context = map[string]any{"sid": "s1-unrelated-target"}
			}
			if scenario == "wrong_session" {
				actor = "second"
			}
			proof := sessionRevocationProof(t, f, actor, scope, context)
			if scenario == "expired" {
				require.NoError(t, f.db.Model(&model.AuthFlow{}).Where("purpose = ?", model.AuthFlowPurposeSecurityProof).Update("expires_at", time.Now().Add(-time.Second)).Error)
			}
			requestActor, path := "owner", "/api/user/sessions/"+target.SID
			if scenario == "pat" {
				raw := "nap_" + strings.ToLower(common.NewRequestId())
				token := &model.UserAccessToken{UserId: target.UserID, TokenHash: model.AccessTokenFingerprint(raw), Name: "session ceiling"}
				require.NoError(t, token.SetScopes([]string{"account_security:write"}))
				require.NoError(t, model.CreateUserAccessToken(target.UserID, token, 10))
				requestActor = raw
			}
			if scenario == "own_logout" {
				path = "/api/user/sessions/" + f.sids["owner"]
				proof = ""
			}
			status, _, _ := f.request(t, http.MethodDelete, path, requestActor, "", http.Header{"X-Security-Proof": {proof}})
			if scenario == "correct" || scenario == "replayed" || scenario == "own_logout" {
				require.Equal(t, 200, status)
			} else {
				assert.Equal(t, 403, status)
			}
			if scenario == "replayed" {
				status, _, body := f.request(t, http.MethodDelete, path, "owner", "", http.Header{"X-Security-Proof": {proof}})
				assert.Equal(t, 403, status)
				assert.Equal(t, "SECURITY_PROOF_CONSUMED", body["code"])
			}
			require.NoError(t, f.db.Where("sid = ?", target.SID).First(&target).Error)
			if scenario == "correct" || scenario == "replayed" {
				assert.Equal(t, model.UserSessionStatusRevoked, target.Status)
			} else {
				assert.Equal(t, model.UserSessionStatusActive, target.Status)
			}
		})
	}
}

func TestSessionRevocationS1WrongIndexOrder(t *testing.T) {
	f := sessionRevocationRepairFixture(t)
	require.NoError(t, model.ValidateSessionRevocationStore())
	drop := "DROP INDEX idx_session_revocation_due"
	if f.db.Dialector.Name() == "mysql" {
		drop += " ON session_revocation_events"
	}
	require.NoError(t, f.db.Exec(drop).Error)
	require.NoError(t, f.db.Exec("CREATE INDEX idx_session_revocation_due ON session_revocation_events (event_ref,state,next_attempt_at)").Error)
	assert.ErrorIs(t, model.ValidateSessionRevocationStore(), model.ErrSessionRevocationStore)
}

// Every physical key is confined to a random04 namespace. The production Lua
// and values are unchanged; a hook rewrites only declared Redis key arguments.
type sessionRevocationRedisPrefix struct {
	prefix  string
	mu      sync.Mutex
	keys    map[string]struct{}
	delay   atomic.Bool
	entered chan struct{}
	release chan struct{}
	unblock sync.Once
}

func (h *sessionRevocationRedisPrefix) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	args := cmd.Args()
	first, last := 1, 2
	switch cmd.Name() {
	case "eval", "evalsha":
		if len(args) < 3 {
			return ctx, errors.New("fixture Redis shape rejected")
		}
		n, err := strconv.Atoi(fmt.Sprint(args[2]))
		if err != nil || n < 1 {
			return ctx, errors.New("fixture Redis key count rejected")
		}
		first, last = 3, 3+n
	case "del", "exists":
		last = len(args)
	case "get", "set", "setnx", "hget", "hgetall", "hset", "hmget", "expire", "pexpire", "ttl", "pttl":
	case "ping":
		return ctx, nil
	default:
		return ctx, errors.New("fixture Redis command rejected")
	}
	if last > len(args) {
		return ctx, errors.New("fixture Redis key shape rejected")
	}
	h.mu.Lock()
	for i := first; i < last; i++ {
		key := h.prefix + fmt.Sprint(args[i])
		args[i] = key
		h.keys[key] = struct{}{}
	}
	h.mu.Unlock()
	if cmd.Name() == "eval" && last == 4 && len(args) > 8 && fmt.Sprint(args[8]) == "active" && h.delay.CompareAndSwap(true, false) {
		close(h.entered)
		select {
		case <-h.release:
		case <-ctx.Done():
			return ctx, ctx.Err()
		}
	}
	return ctx, nil
}
func (*sessionRevocationRedisPrefix) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (h *sessionRevocationRedisPrefix) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
	for _, cmd := range cmds {
		var err error
		ctx, err = h.BeforeProcess(ctx, cmd)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}
func (*sessionRevocationRedisPrefix) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}

// Compare private SQL state by digest so a failing assertion cannot print
// credentials, session identifiers, source bindings or usable Token keys.
func s1RevocationStateDigest(t *testing.T, db *gorm.DB) string {
	t.Helper()
	h := sha256.New()
	for _, table := range []string{"users", "user_sessions", "oauth_grants", "tokens", "oauth_derived_token_sources", "o_auth_operations", "o_auth_cleanup_jobs", "session_revocation_events", "oauth_derived_token_history", "oauth_derived_token_bootstrap_identity"} {
		var rows []map[string]any
		require.NoError(t, db.Table(table).Find(&rows).Error)
		encoded := make([]string, len(rows))
		for i := range rows {
			data, err := common.Marshal(rows[i])
			require.NoError(t, err)
			encoded[i] = string(data)
		}
		slices.Sort(encoded)
		for _, row := range encoded {
			_, err := h.Write([]byte(row))
			require.NoError(t, err)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestSessionRevocationS1RealRedis(t *testing.T) {
	t.Run("nonempty_source_restricted_rollback", func(t *testing.T) {
		f := sessionRevocationRepairFixture(t)
		require.Equal(t, "postgres", f.db.Dialector.Name())
		userID := f.users["owner"].Id
		grant := &model.OAuthGrant{GrantID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{46}, 32)),
			Issuer: "https://s1-seed.invalid/", ClientID: "s1-seed-client", Subject: strconv.Itoa(userID), UserID: userID,
			ConsentRequestID: "s1-seed-consent", HydraLoginSessionID: "s1-seed-login", OriginSID: f.sids["owner"],
			SessionVersion: 1, UserAuthVersion: 1, Scopes: `["tokens:write"]`, PolicyHash: strings.Repeat("b", 64)}
		require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
		// Synthetic active grant input only; this is not the K2 issuance path.
		require.NoError(t, f.db.Model(grant).UpdateColumn("state", "active").Error)
		key, err := common.GenerateRandomCharsKey(40)
		require.NoError(t, err)
		token := &model.Token{UserId: userID, Name: "s1-seed-token", Key: key, Status: common.TokenStatusEnabled,
			RemainQuota: 1000, ExpiredTime: time.Now().Unix() + 300}
		require.NoError(t, token.Insert())
		client := os.Getenv("NEWAPI_BOOTSTRAP_CLIENT")
		ident := strings.TrimSuffix(filepath.Base(os.Getenv("OAUTH_BOOTSTRAP_JOURNAL")), ".json")
		require.Regexp(t, `^[0-9a-f]{32}$`, ident)
		action := "s1-seed:" + ident
		// Real fixed IPC negative controls. Neither a claimed actor nor an
		// arbitrary SQL/DSN is accepted. All bad requests precede the sole seed.
		for _, bad := range []string{"s1-seed:" + strings.Repeat("0", 32), action + ":actor:1"} {
			_, err := exec.Command(client, bad).Output()
			require.Error(t, err)
		}
		conn, err := net.Dial("unix", filepath.Join(filepath.Dir(client), "installer.sock"))
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = io.WriteString(conn, action+"\n")
		require.NoError(t, err)
		require.NoError(t, conn.(*net.UnixConn).CloseWrite())
		response, _ := io.ReadAll(conn)
		require.NoError(t, conn.Close())
		require.Empty(t, response, "the test process itself is not its direct-child installer client")
		for _, fault := range []string{"foreign_user", "foreign_grant", "expired"} {
			switch fault {
			case "foreign_user":
				require.NoError(t, f.db.Model(token).UpdateColumn("user_id", f.users["foreign"].Id).Error)
			case "foreign_grant":
				require.NoError(t, f.db.Model(grant).UpdateColumn("client_id", "other-client").Error)
			case "expired":
				require.NoError(t, f.db.Model(token).UpdateColumn("expired_time", time.Now().Unix()-1).Error)
			}
			_, err := exec.Command(client, action).Output()
			require.Error(t, err, fault)
			var count int64
			require.NoError(t, f.db.Model(&model.OAuthDerivedTokenSource{}).Count(&count).Error)
			require.Zero(t, count, "rejected input must have no source side effect")
			require.NoError(t, f.db.Model(token).Updates(map[string]any{"user_id": userID, "expired_time": time.Now().Unix() + 300}).Error)
			require.NoError(t, f.db.Model(grant).UpdateColumn("client_id", "s1-seed-client").Error)
		}
		var canUpdate bool
		require.NoError(t, f.db.Raw("SELECT has_any_column_privilege(current_user, 'public.oauth_derived_token_sources', 'UPDATE')").Scan(&canUpdate).Error)
		require.False(t, canUpdate)
		raw, err := exec.Command(client, action).Output()
		require.NoError(t, err, "root-controlled fixed seed must use this already born database")
		require.JSONEq(t, `{"seeded":true}`, string(raw))
		_, err = exec.Command(client, action).Output()
		require.Error(t, err, "each born database permits only one seed")
		kind, err := model.ClassifyOAuthDerivedToken(t.Context(), token.Id)
		require.NoError(t, err, "the seed must satisfy real history and source/Token binding")
		require.Equal(t, model.OAuthDerivedTokenBound, kind)
		before := s1RevocationStateDigest(t, f.db)
		var lockDenied atomic.Bool
		require.NoError(t, f.db.Callback().Query().After("gorm:query").Register("s1:source-lock-state", func(tx *gorm.DB) {
			if tx.Statement.Table == "oauth_derived_token_sources" && strings.Contains(tx.Statement.SQL.String(), "FOR UPDATE") {
				var state interface{ SQLState() string }
				if errors.As(tx.Error, &state) && state.SQLState() == "42501" {
					lockDenied.Store(true)
				}
			}
		}))
		t.Cleanup(func() { require.NoError(t, f.db.Callback().Query().Remove("s1:source-lock-state")) })
		err = f.db.Transaction(func(tx *gorm.DB) error {
			_, err := model.StartSessionRevocationWithTx(tx, userID, "", "session_revoked")
			return err
		}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		require.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
		require.True(t, lockDenied.Load(), "real ordinary-role source row lock must fail with SQLSTATE 42501")
		assert.Equal(t, before, s1RevocationStateDigest(t, f.db), "all security state and amounts must roll back atomically")
		for _, column := range []string{"grant_ref", "user_id", "schema_version", "quota_limit", "expires_at", "policy_hash", "binding_hash", "verified_at", "proof_expires_at", "permit_deadline", "verified_method", "proof_flow_id", "token_id", "key_ref", "idem_hash", "request_hash", "created_at", "terminal_at", "terminal_reason"} {
			var state interface{ SQLState() string }
			err := f.db.Exec("UPDATE oauth_derived_token_sources SET " + column + "=" + column + " WHERE false").Error
			require.ErrorAs(t, err, &state)
			assert.Equal(t, "42501", state.SQLState(), column)
		}
		for _, statement := range []string{
			"INSERT INTO oauth_derived_token_sources (grant_ref) SELECT grant_ref FROM oauth_derived_token_sources WHERE false",
			"DELETE FROM oauth_derived_token_sources WHERE false",
			"ALTER TABLE oauth_derived_token_sources ADD COLUMN forbidden_seed_service INTEGER",
		} {
			var state interface{ SQLState() string }
			err := f.db.Exec(statement).Error
			require.ErrorAs(t, err, &state)
			assert.Equal(t, "42501", state.SQLState())
		}
		for _, table := range []string{"oauth_derived_token_history", "oauth_derived_token_bootstrap_identity"} {
			var state interface{ SQLState() string }
			err := f.db.Exec("DELETE FROM " + table + " WHERE false").Error
			require.ErrorAs(t, err, &state)
			assert.Equal(t, "42501", state.SQLState(), table)
		}
		require.NoError(t, f.db.Raw("SELECT has_any_column_privilege(current_user, 'public.oauth_derived_token_sources', 'UPDATE')").Scan(&canUpdate).Error)
		require.False(t, canUpdate, "root input construction must not confer service UPDATE rights")
		assert.Equal(t, before, s1RevocationStateDigest(t, f.db))
		t.Log("S1 source lock SQLSTATE=42501; ordinary-role privileges unchanged; complete security transaction rolled back")
	})

	// Ordinary S1's source role is SELECT-only. Empty provenance is safe only
	// under the same existing User lock and an observed READ COMMITTED snapshot.
	for _, scenario := range []string{"empty_read_committed", "empty_repeatable_read", "missing_user", "isolation_unavailable", "unknown_isolation", "source_select_error", "without_transaction"} {
		t.Run(scenario, func(t *testing.T) {
			f := sessionRevocationRepairFixture(t)
			require.Equal(t, "postgres", f.db.Dialector.Name())
			userID := f.users["owner"].Id
			var canUpdate bool
			require.NoError(t, f.db.Raw("SELECT has_any_column_privilege(current_user, 'public.oauth_derived_token_sources', 'UPDATE')").Scan(&canUpdate).Error)
			require.False(t, canUpdate, "ordinary S1 must not acquire lifecycle test-owner rights")
			if scenario == "missing_user" {
				userID = 2147483647
			}
			if scenario == "isolation_unavailable" || scenario == "unknown_isolation" {
				require.NoError(t, f.db.Callback().Row().Before("gorm:row").Register("empty-source:isolation", func(tx *gorm.DB) {
					if tx.Statement.SQL.String() == "SHOW transaction_isolation" {
						if scenario == "unknown_isolation" {
							tx.Statement.SQL.Reset()
							tx.Statement.SQL.WriteString("SELECT 'unknown' AS transaction_isolation")
						} else {
							tx.AddError(errors.New("isolation observation unavailable"))
						}
					}
				}))
				t.Cleanup(func() { require.NoError(t, f.db.Callback().Row().Remove("empty-source:isolation")) })
			}
			var isolationObserved atomic.Bool
			if scenario == "source_select_error" {
				require.NoError(t, f.db.Callback().Row().After("gorm:row").Register("empty-source:observed", func(tx *gorm.DB) {
					if tx.Statement.SQL.String() == "SHOW transaction_isolation" {
						isolationObserved.Store(true)
					}
				}))
				t.Cleanup(func() { require.NoError(t, f.db.Callback().Row().Remove("empty-source:observed")) })
				require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("empty-source:read", func(tx *gorm.DB) {
					if isolationObserved.Load() && tx.Statement.Table == "oauth_derived_token_sources" {
						tx.AddError(errors.New("source observation unavailable"))
					}
				}))
				t.Cleanup(func() { require.NoError(t, f.db.Callback().Query().Remove("empty-source:read")) })
			}
			if scenario == "without_transaction" {
				// Do not create an outbox in autocommit mode merely to test the
				// derived substep's transaction requirement.
				assert.ErrorIs(t, model.RevokeOAuthWithTx(f.db, userID, "user", "", "session_revoked"), model.ErrOAuthDerivedTokenUnknown)
				return
			}
			opts := &sql.TxOptions{Isolation: sql.LevelReadCommitted}
			if scenario == "empty_repeatable_read" {
				opts.Isolation = sql.LevelRepeatableRead
			}
			err := f.db.Transaction(func(tx *gorm.DB) error {
				_, err := model.StartSessionRevocationWithTx(tx, userID, "", "session_revoked")
				return err
			}, opts)
			if scenario == "source_select_error" {
				require.True(t, isolationObserved.Load(), "fault must reach the new empty-source read after the provenance preflight")
			}
			var count int64
			require.NoError(t, f.db.Model(&model.SessionRevocationEvent{}).Where("user_id = ?", userID).Count(&count).Error)
			if scenario == "empty_read_committed" {
				require.NoError(t, err)
				assert.EqualValues(t, 1, count)
			} else {
				assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
				assert.Zero(t, count, "rejected source observation rolls back the whole security transaction")
			}
		})
	}
	for _, scenario := range []string{"deny_wrong_type", "outbox_rollback", "late_active_fill", "credential_rollback"} {
		t.Run(scenario, func(t *testing.T) {
			f := sessionRevocationRepairFixture(t)
			if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") != "" {
				organizationTrustedRedis(t)
				defer organizationTrustedRedis(t)
			}
			endpoint := os.Getenv("NEWAPI_W01_REDIS_ADDR")
			host, port, err := net.SplitHostPort(endpoint)
			require.NoError(t, err)
			require.Equal(t, "127.0.0.1", host)
			require.True(t, port == os.Getenv("NEWAPI_W01_REDIS_ALLOWED_PORT"))
			nonce := make([]byte, 12)
			_, err = rand.Read(nonce)
			require.NoError(t, err)
			prefix := "w01:s104:" + fmt.Sprintf("%x", nonce) + ":"
			database := 1 + int(nonce[0])%14
			control := redis.NewClient(&redis.Options{Addr: endpoint, DB: database, MaxRetries: -1, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
			require.True(t, control.Ping(t.Context()).Err() == nil, "authorized real Redis unavailable")
			info, err := control.Info(t.Context(), "server").Result()
			require.NoError(t, err)
			version := ""
			for line := range strings.SplitSeq(info, "\n") {
				if value, ok := strings.CutPrefix(line, "redis_version:"); ok {
					version = strings.TrimSpace(value)
				}
			}
			t.Logf("real Redis version=%s", version)
			var initialCursor uint64
			for {
				before, next, err := control.Scan(t.Context(), initialCursor, prefix+"*", 100).Result()
				require.NoError(t, err)
				require.Empty(t, before)
				if next == 0 {
					break
				}
				initialCursor = next
			}
			hook := &sessionRevocationRedisPrefix{prefix: prefix, keys: map[string]struct{}{}, entered: make(chan struct{}), release: make(chan struct{})}
			client := redis.NewClient(&redis.Options{Addr: endpoint, DB: database, MaxRetries: -1, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
			client.AddHook(hook)
			oldEnabled, oldClient := common.RedisEnabled, common.RDB
			common.RedisEnabled, common.RDB = true, client
			var background sync.WaitGroup
			t.Logf("W01-04 owned redis_prefix=%s db=%d", prefix, database)
			combinedFixtureEvent(t, "created", map[string]any{"kind": "redis_prefix", "identity": fmt.Sprintf("redis:%d/%s", database, prefix)})
			t.Cleanup(func() {
				hook.unblock.Do(func() { close(hook.release) })
				background.Wait()
				common.RedisEnabled, common.RDB = oldEnabled, oldClient
				require.NoError(t, client.Close())
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var keys []string
				for key := range hook.keys {
					require.True(t, strings.HasPrefix(key, prefix))
					keys = append(keys, key)
				}
				if len(keys) > 0 {
					require.NoError(t, control.Del(ctx, keys...).Err())
				}
				var cursor uint64
				for {
					remaining, next, err := control.Scan(ctx, cursor, prefix+"*", 100).Result()
					require.NoError(t, err)
					require.Empty(t, remaining)
					if next == 0 {
						break
					}
					cursor = next
				}
				require.NoError(t, control.Close())
				combinedFixtureEvent(t, "removed", map[string]any{"kind": "redis_prefix", "identity": fmt.Sprintf("redis:%d/%s", database, prefix)})
				t.Logf("W01-04 removed redis_prefix=%s db=%d keys=%d", prefix, database, len(keys))
			})
			userID, sid := f.users["owner"].Id, f.sids["owner"]
			_, err = model.GetUserSessionCached(sid)
			require.NoError(t, err)
			physical := ""
			hook.mu.Lock()
			for key := range hook.keys {
				if strings.HasPrefix(key, prefix+"auth:session:") {
					physical = key
				}
			}
			hook.mu.Unlock()
			require.NotEmpty(t, physical, "observe the real cache key instead of duplicating its HMAC naming")
			if scenario == "credential_rollback" {
				require.NoError(t, model.PublishUserAuthCache(userID))
				forced := errors.New("S1 event create failed")
				require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("s1:redis-intent", func(tx *gorm.DB) {
					if _, ok := tx.Statement.Dest.(*model.SessionRevocationEvent); ok {
						tx.AddError(forced)
					}
				}))
				_, err := model.BumpUserAuthVersion(userID)
				assert.ErrorIs(t, err, forced)
				require.NoError(t, f.db.Callback().Create().Remove("s1:redis-intent"))
				var user model.User
				require.NoError(t, f.db.First(&user, userID).Error)
				assert.EqualValues(t, 1, user.AuthVersion)
				floor, err := control.Get(t.Context(), prefix+fmt.Sprintf("auth:user:version:%d", userID)).Int64()
				require.NoError(t, err)
				assert.EqualValues(t, 1, floor, "a rolled back credential cannot publish committed version2")
				var count int64
				require.NoError(t, f.db.Model(&model.SessionRevocationEvent{}).Where("user_id = ?", userID).Count(&count).Error)
				assert.Zero(t, count)
				return
			}
			var event *model.SessionRevocationEvent
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
				var err error
				event, err = model.StartSessionRevocationWithTx(tx, userID, "", "session_revoked")
				return err
			}))
			if scenario == "outbox_rollback" {
				grant := &model.OAuthGrant{GrantID: strings.Repeat("g", 43), Issuer: "https://s1-redis.example/", ClientID: "desktop", Subject: strconv.Itoa(userID), UserID: userID, ConsentRequestID: "redis-consent", HydraLoginSessionID: "redis-login", OriginSID: sid, SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("b", 64)}
				// The event already blocks fresh grants; seed existing authoritative
				// history directly to exercise a transaction's per-SID outbox failure.
				grant.GrantRef = model.OAuthGrantRef(grant.Issuer, grant.GrantID)
				grant.State = "active"
				grant.Revision = 1
				grant.ExpiresAt = time.Now().Unix() + 3600
				require.NoError(t, f.db.Create(grant).Error)
				forced := errors.New("S1 SID attribution failed")
				require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("s1:redis-outbox", func(tx *gorm.DB) {
					if job, ok := tx.Statement.Dest.(*model.OAuthCleanupJob); ok && job.Scope == "sid" {
						tx.AddError(forced)
					}
				}))
				_, err := model.RunSessionRevocationBatch(t.Context(), *event)
				assert.ErrorIs(t, err, forced)
				require.NoError(t, f.db.Callback().Create().Remove("s1:redis-outbox"))
				status, err := control.HGet(t.Context(), physical, "Status").Result()
				require.NoError(t, err)
				assert.Equal(t, "revoking", status)
				var session model.UserSession
				require.NoError(t, f.db.Where("sid = ?", sid).First(&session).Error)
				assert.Equal(t, model.UserSessionStatusActive, session.Status)
				var current model.SessionRevocationEvent
				require.NoError(t, f.db.Where("event_ref = ?", event.EventRef).First(&current).Error)
				assert.EqualValues(t, 1, current.Revision)
				assert.Zero(t, current.AffectedCount)
			}
			if scenario == "deny_wrong_type" {
				require.NoError(t, control.Set(t.Context(), physical, "wrong-type", time.Minute).Err())
				_, err := model.RunSessionRevocationBatch(t.Context(), *event)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WRONGTYPE")
				var session model.UserSession
				require.NoError(t, f.db.Where("sid = ?", sid).First(&session).Error)
				assert.Equal(t, model.UserSessionStatusActive, session.Status)
				var current model.SessionRevocationEvent
				require.NoError(t, f.db.Where("event_ref = ?", event.EventRef).First(&current).Error)
				assert.EqualValues(t, 1, current.Revision)
				assert.Zero(t, current.AffectedCount)
				require.NoError(t, control.Del(t.Context(), physical).Err())
			}
			var late chan error
			if scenario == "late_active_fill" {
				require.NoError(t, control.Del(t.Context(), physical).Err())
				hook.delay.Store(true)
				late = make(chan error, 1)
				background.Go(func() { _, err := model.GetUserSessionCached(sid); late <- err })
				select {
				case <-hook.entered:
				case <-time.After(10 * time.Second):
					t.Fatal("positive fill did not reach real Redis barrier")
				}
			}
			complete, err := model.RunSessionRevocationBatch(t.Context(), *event)
			require.NoError(t, err)
			assert.Equal(t, "local_complete", complete.State)
			assert.EqualValues(t, 1, complete.AffectedCount)
			hook.unblock.Do(func() { close(hook.release) })
			if late != nil {
				select {
				case err := <-late:
					assert.ErrorIs(t, err, model.ErrUserSessionInactive)
				case <-time.After(10 * time.Second):
					t.Fatal("late fill did not complete")
				}
			}
			status, err := control.HGet(t.Context(), physical, "Status").Result()
			require.NoError(t, err)
			assert.Equal(t, "revoked", status)
			_, err = model.RunSessionRevocationBatch(t.Context(), *event)
			assert.ErrorIs(t, err, model.ErrSessionRevocationStale)
		})
	}
}

func TestSessionRevocationS1CreatorFinalizeRaces(t *testing.T) {
	for _, creator := range []string{"direct", "login_flow", "organization_rotation"} {
		for _, creatorFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s_creator_first_%v", creator, creatorFirst), func(t *testing.T) {
				f := sessionRevocationRepairFixture(t)
				userID := f.users["owner"].Id
				identity, err := service.ParseAccessToken(f.bearer["owner"])
				require.NoError(t, err)
				var source model.UserSession
				require.NoError(t, f.db.Where("sid = ?", identity.SessionID).First(&source).Error)
				next := source
				next.SID = "s1-a-concurrent-new-session"
				next.Version = 1
				next.RevokedAt = 0
				next.RevokedReason = ""
				var token string
				if creator == "login_flow" {
					token, _, err = model.CreateAuthFlow(model.AuthFlowCreate{Purpose: model.AuthFlowPurposeLoginVerification, UserId: userID, ExpiresAt: time.Now().Add(time.Minute)})
					require.NoError(t, err)
				}
				var event *model.SessionRevocationEvent
				require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
					var err error
					event, err = model.StartSessionRevocationWithTx(tx, userID, source.SID, "session_revoked")
					return err
				}))
				hint := *event
				if creatorFirst {
					// Existing rows use higher SIDs, so this also catches a persisted SID
					// cursor that would skip the newly inserted lower lexical member.
					seedSessionRevocationSessions(t, f, 501)
					oldIssuanceLimit := common.UserSessionIssuanceLimit
					common.UserSessionIssuanceLimit = 2000
					t.Cleanup(func() { common.UserSessionIssuanceLimit = oldIssuanceLimit })
					first, err := model.RunSessionRevocationBatch(t.Context(), hint)
					require.NoError(t, err)
					require.Equal(t, "pending", first.State)
					hint = *first
				}
				create := func() error {
					switch creator {
					case "direct":
						return model.CreateUserSession(&next)
					case "login_flow":
						return model.CreateUserSessionFromLoginFlow(token, &next, func(*gorm.DB, *model.AuthFlow, *model.UserVerificationState) error { return nil })
					default:
						return model.RotateOrganizationSessionWithContext(t.Context(), identity, &next, func(*gorm.DB, *model.UserVerificationState) error { return nil })
					}
				}
				entered, release, attempted := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var enterOnce, attemptOnce, releaseOnce sync.Once
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
				callback := "s1:race-" + creator
				if creatorFirst {
					require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
						if row, ok := tx.Statement.Dest.(*model.UserSession); ok && row.SID == next.SID {
							enterOnce.Do(func() { close(entered) })
							select {
							case <-release:
							case <-t.Context().Done():
								tx.AddError(t.Context().Err())
							}
						}
					}))
					t.Cleanup(func() { _ = f.db.Callback().Create().Remove(callback) })
				} else {
					require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register(callback, func(tx *gorm.DB) {
						if tx.Statement.Table == "session_revocation_events" {
							if changes, ok := tx.Statement.Dest.(map[string]any); ok && changes["state"] == "local_complete" {
								enterOnce.Do(func() { close(entered) })
								select {
								case <-release:
								case <-t.Context().Done():
									tx.AddError(t.Context().Err())
								}
							}
						}
					}))
					t.Cleanup(func() { _ = f.db.Callback().Update().Remove(callback) })
				}
				created := make(chan error, 1)
				finished := make(chan error, 1)
				finalize := func() { _, err := model.RunSessionRevocationBatch(t.Context(), hint); finished <- err }
				if creatorFirst {
					go func() { created <- create() }()
				} else {
					go finalize()
				}
				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					t.Fatal("first transaction did not reach shared-lock race barrier")
				}
				require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("s1:race-attempt", func(tx *gorm.DB) {
					if tx.Statement.Table == "users" {
						attemptOnce.Do(func() { close(attempted) })
					}
				}))
				require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("s1:race-attempt", func(tx *gorm.DB) {
					if tx.Statement.Table == "users" {
						attemptOnce.Do(func() { close(attempted) })
					}
				}))
				t.Cleanup(func() { _ = f.db.Callback().Update().Remove("s1:race-attempt") })
				t.Cleanup(func() { _ = f.db.Callback().Query().Remove("s1:race-attempt") })
				if creatorFirst {
					go finalize()
				} else {
					go func() { created <- create() }()
				}
				select {
				case <-attempted:
				case <-time.After(10 * time.Second):
					t.Fatal("second operation did not attempt user lock")
				}
				releaseOnce.Do(func() { close(release) })
				require.NoError(t, <-finished)
				err = <-created
				if err != nil {
					require.True(t, creatorFirst && errors.Is(err, model.ErrUserSessionInactive), "creation may withhold its bundle after an immediately following revocation")
				}
				var actual model.UserSession
				require.NoError(t, f.db.Where("sid = ?", next.SID).First(&actual).Error)
				if creatorFirst {
					assert.Equal(t, model.UserSessionStatusRevoked, actual.Status)
				} else {
					assert.Equal(t, model.UserSessionStatusActive, actual.Status)
				}
				var done model.SessionRevocationEvent
				require.NoError(t, f.db.Where("event_ref = ?", event.EventRef).First(&done).Error)
				assert.Equal(t, "local_complete", done.State)
				assert.Equal(t, source.SID, done.ExcludedSID)
				if creatorFirst {
					assert.EqualValues(t, 502, done.AffectedCount)
				} else {
					assert.Zero(t, done.AffectedCount)
				}
				_, err = model.RunSessionRevocationBatch(t.Context(), hint)
				assert.ErrorIs(t, err, model.ErrSessionRevocationStale)
			})
		}
	}
}

func TestSessionRevocationS1CommitAcknowledgementLost(t *testing.T) {
	f := sessionRevocationRepairFixture(t)
	var event *model.SessionRevocationEvent
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
		var err error
		event, err = model.StartSessionRevocationWithTx(tx, f.users["owner"].Id, "", "session_revoked")
		return err
	}))
	var fired atomic.Bool
	pool, statementPool := f.db.Config.ConnPool, f.db.Statement.ConnPool
	wrapper := &clientEventsUncertainPool{ConnPool: pool, fired: &fired}
	f.db.Config.ConnPool, f.db.Statement.ConnPool = wrapper, wrapper
	err := model.CompleteSessionSecurityChange(event, false)
	f.db.Config.ConnPool, f.db.Statement.ConnPool = pool, statementPool
	require.True(t, fired.Load(), "a real commit completed before its acknowledgement was lost")
	require.NoError(t, err, "only the exact committed event may resolve an uncertain batch")
	var current model.SessionRevocationEvent
	require.NoError(t, f.db.Where("event_ref = ?", event.EventRef).First(&current).Error)
	assert.Equal(t, "local_complete", current.State)
	assert.EqualValues(t, 1, current.AffectedCount)
	assert.EqualValues(t, 2, current.Revision)
	_, err = model.RunSessionRevocationBatch(t.Context(), *event)
	assert.ErrorIs(t, err, model.ErrSessionRevocationStale)
	require.NoError(t, f.db.Where("event_ref = ?", event.EventRef).First(&current).Error)
	assert.EqualValues(t, 1, current.AffectedCount)
}

// K1a uses organizationTestDB through the shared fixture: each selected engine
// gets a fresh private database and the existing ownership/DSN/cleanup guards.
// NEWAPI_S2_MAIN selects the engine; a supplied W01 selector must agree rather
// than silently leaving this suite on SQLite. The controller owns runtime tags.
func newOAuthDerivedK1aDatabaseFixture(t *testing.T) *organizationHTTPFixture {
	t.Helper()
	kind := os.Getenv("NEWAPI_S2_MAIN")
	if kind == "" {
		kind = "sqlite"
	}
	require.Contains(t, []string{"sqlite", "mysql", "postgres"}, kind)
	if selected := os.Getenv("NEWAPI_W01_MAIN_KIND"); selected != "" {
		require.Equal(t, selected, kind, "K1a consumes NEWAPI_S2_MAIN and NEWAPI_S2_MAIN_DSN; selectors must agree")
	}
	if source := os.Getenv("NEWAPI_W01_MAIN_DSN"); source != "" {
		require.True(t, source == os.Getenv("NEWAPI_S2_MAIN_DSN"), "K1a consumes NEWAPI_S2_MAIN_DSN; a supplied W01 DSN must agree")
	}
	if kind == "sqlite" {
		require.True(t, os.Getenv("NEWAPI_S2_MAIN_DSN") == "", "SQLite uses a fresh temporary file and must not ignore a supplied main DSN")
	}
	logKind := os.Getenv("NEWAPI_S2_LOG")
	if logKind == "sqlite" || logKind == "" && kind == "sqlite" {
		require.True(t, os.Getenv("NEWAPI_S2_LOG_DSN") == "", "SQLite uses a fresh temporary file and must not ignore a supplied log DSN")
	}
	f := newOrganizationHTTPFixture(t)
	require.Equal(t, kind, f.db.Dialector.Name(), "the selected engine must not fall back")
	return f
}

// Only these ready-state domain/handler fixtures explicitly create the K1a
// tables and seed a test seal. Schema tests start without either table. Neither
// fixture enables a public tokens:read producer or a real Hydra GET chain.
func newOAuthDerivedK1aFixture(t *testing.T) *organizationHTTPFixture {
	t.Helper()
	f := newOAuthDerivedK1aDatabaseFixture(t)
	common.IsMasterNode = true
	require.NoError(t, model.InitOAuthGrantStore(true))
	common.IsMasterNode = false
	require.NoError(t, f.db.AutoMigrate(&model.OAuthDerivedTokenSource{}, &model.OAuthDerivedTokenHistory{}))
	var birthHistory model.OAuthDerivedTokenHistory
	require.NoError(t, f.db.First(&birthHistory).Error)
	return f
}

func seedOAuthDerivedK1aSource(t *testing.T, f *organizationHTTPFixture) (*model.OAuthGrant, *model.OAuthDerivedTokenSource, *model.Token) {
	t.Helper()
	random := make([]byte, 32)
	_, err := rand.Read(random)
	require.NoError(t, err)
	id := base64.RawURLEncoding.EncodeToString(random)
	scopes := []string{"profile", "tokens:read", "tokens:write"}
	encoded, err := common.Marshal(scopes)
	require.NoError(t, err)
	userID := f.users["owner"].Id
	grant := &model.OAuthGrant{GrantID: id, Issuer: "https://gateway.example/", ClientID: "k1a-client", Subject: strconv.Itoa(userID), UserID: userID,
		ConsentRequestID: "k1a-" + id, HydraLoginSessionID: "k1a-login-" + id, OriginSID: f.sids["owner"], SessionVersion: 1, UserAuthVersion: 1,
		Scopes: string(encoded), PolicyHash: strings.Repeat("a", 64)}
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
	require.NoError(t, model.ApproveOAuthGrant(t.Context(), grant))
	_, err = model.AuthorizeOAuthGrant(t.Context(), model.OAuthGrantAuthorization{Issuer: grant.Issuer, GrantID: grant.GrantID, ClientID: grant.ClientID, Subject: grant.Subject,
		UserID: userID, AuthVersion: 1, GrantExpiresAt: grant.ExpiresAt, TokenExpiresAt: time.Now().Unix() + 600, Scopes: scopes, Activate: true})
	require.NoError(t, err)
	require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).First(grant).Error)
	now := time.Now().Unix()
	key, err := common.GenerateKey()
	require.NoError(t, err)
	token := &model.Token{UserId: userID, Key: key, Status: common.TokenStatusEnabled, Name: "K1a private fixture", CreatedTime: now, ExpiredTime: min(now+600, grant.ExpiresAt), RemainQuota: 900, UsedQuota: 100}
	require.NoError(t, f.db.Create(token).Error)
	keyRef, idem, requestHash := model.OAuthDerivedTokenKeyRef(key), model.OAuthDerivedTokenKeyRef("idem-"+id), model.OAuthDerivedTokenKeyRef("request-"+id)
	source := &model.OAuthDerivedTokenSource{GrantRef: grant.GrantRef, UserID: userID, SchemaVersion: 1, QuotaLimit: 1000, ExpiresAt: token.ExpiredTime,
		PolicyHash: strings.Repeat("b", 64), BindingHash: strings.Repeat("c", 64), VerifiedAt: grant.CreatedAt, ProofExpiresAt: grant.CreatedAt + 60, PermitDeadline: grant.CreatedAt + 60,
		VerifiedMethod: "password", ProofFlowID: int64(token.Id), TokenID: &token.Id, KeyRef: &keyRef, IdemHash: &idem, RequestHash: &requestHash, CreatedAt: &now}
	require.NoError(t, f.db.Create(source).Error)
	return grant, source, token
}

func TestOAuthDerivedK1aSchema(t *testing.T) {
	f := newOAuthDerivedK1aDatabaseFixture(t)
	require.NoError(t, f.db.Migrator().DropTable(&model.OAuthDerivedTokenSource{}, &model.OAuthDerivedTokenHistory{}, &model.OAuthDerivedTokenBootstrapIdentity{}))
	require.False(t, f.db.Migrator().HasTable(&model.OAuthDerivedTokenSource{}))
	require.False(t, f.db.Migrator().HasTable(&model.OAuthDerivedTokenHistory{}))
	assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
	assert.False(t, f.db.Migrator().HasTable(&model.OAuthDerivedTokenHistory{}), "validation must never bootstrap")
	require.NoError(t, f.db.AutoMigrate(&model.OAuthDerivedTokenSource{}, &model.OAuthDerivedTokenHistory{}))
	assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
	history := &model.OAuthDerivedTokenHistory{ID: 1, SchemaVersion: 1, HistorySeal: strings.Repeat("a", 64), SealedAt: time.Now().Unix()}
	require.NoError(t, f.db.Create(history).Error)
	assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown, "arbitrary seal is never birth evidence")
	f = newOAuthDerivedK1aFixture(t)
	require.NoError(t, f.db.First(history).Error)
	originalHistory := *history
	require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
	for _, tc := range []struct {
		name    string
		updates map[string]any
	}{
		{"unknown seal version", map[string]any{"schema_version": 2}},
		{"malformed seal", map[string]any{"history_seal": "not-a-seal"}},
		{"future seal", map[string]any{"sealed_at": time.Now().Unix() + 3600}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, f.db.Model(history).Updates(tc.updates).Error)
			assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
			require.NoError(t, f.db.Model(history).Updates(map[string]any{"schema_version": originalHistory.SchemaVersion, "history_seal": originalHistory.HistorySeal, "sealed_at": originalHistory.SealedAt}).Error)
		})
	}
	for _, name := range []string{"uq_oauth_derived_proof", "uq_oauth_derived_token", "uq_oauth_derived_key", "uq_oauth_derived_grant_idem", "idx_oauth_derived_user_created"} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, f.db.Migrator().DropIndex(&model.OAuthDerivedTokenSource{}, name))
			assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
			require.NoError(t, f.db.Migrator().CreateIndex(&model.OAuthDerivedTokenSource{}, name))
			require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
		})
	}
	require.NoError(t, f.db.Migrator().DropIndex(&model.OAuthDerivedTokenSource{}, "uq_oauth_derived_token"))
	require.NoError(t, f.db.Exec("CREATE UNIQUE INDEX uq_oauth_derived_token ON oauth_derived_token_sources(user_id)").Error)
	assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown, "index name alone does not prove its columns")
	require.NoError(t, f.db.Migrator().DropTable(&model.OAuthDerivedTokenSource{}))
	require.NoError(t, f.db.Exec("CREATE TABLE oauth_derived_token_sources (grant_ref CHAR(64) PRIMARY KEY)").Error)
	assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
}

func TestOAuthDerivedK1aIndexCoverage(t *testing.T) {
	if os.Getenv("NEWAPI_S2_MAIN") == "mysql" {
		t.Log("not applicable: partial proof index admits duplicate valid proofs; MySQL has no partial indexes")
	} else {
		t.Run("partial proof index admits duplicate valid proofs", func(t *testing.T) {
			f := newOAuthDerivedK1aFixture(t)
			_, source, _ := seedOAuthDerivedK1aSource(t, f)
			_, second, _ := seedOAuthDerivedK1aSource(t, f)
			require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
			require.NoError(t, f.db.Migrator().DropIndex(&model.OAuthDerivedTokenSource{}, "uq_oauth_derived_proof"))
			require.NoError(t, f.db.Exec("CREATE UNIQUE INDEX uq_oauth_derived_proof ON oauth_derived_token_sources(proof_flow_id) WHERE proof_flow_id < 0").Error)
			assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
			// The audit counterexample: every individually valid source is outside
			// this index, so SQL permits reuse of an already bound positive proof.
			require.NoError(t, f.db.Model(second).UpdateColumn("proof_flow_id", source.ProofFlowID).Error)
			var rows []model.OAuthDerivedTokenSource
			require.NoError(t, f.db.Where("proof_flow_id = ?", source.ProofFlowID).Find(&rows).Error)
			require.Len(t, rows, 2)
			for i := range rows {
				require.NoError(t, rows[i].Validate(time.Now().Unix()))
			}
			assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
			// Restore distinct proofs before restoring the full unique constraint.
			require.NoError(t, f.db.Model(second).UpdateColumn("proof_flow_id", source.ProofFlowID+1).Error)
			require.NoError(t, f.db.Migrator().DropIndex(&model.OAuthDerivedTokenSource{}, "uq_oauth_derived_proof"))
			require.NoError(t, f.db.Migrator().CreateIndex(&model.OAuthDerivedTokenSource{}, "uq_oauth_derived_proof"))
			require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
			assert.Error(t, f.db.Model(second).UpdateColumn("proof_flow_id", source.ProofFlowID).Error)
		})
	}
	for _, tc := range []struct {
		name, index, definition string
		partial                 bool
	}{
		{"partial token", "uq_oauth_derived_token", "token_id) WHERE token_id < 0", true},
		{"partial key", "uq_oauth_derived_key", "key_ref) WHERE user_id < 0", true},
		{"partial grant idempotency", "uq_oauth_derived_grant_idem", "grant_ref, idem_hash) WHERE user_id < 0", true},
		{"truncated key", "uq_oauth_derived_key", "substr(key_ref, 1, 8))", false},
	} {
		if tc.partial && os.Getenv("NEWAPI_S2_MAIN") == "mysql" {
			t.Logf("not applicable: %s; MySQL has no partial indexes", tc.name)
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			f := newOAuthDerivedK1aFixture(t)
			definition := tc.definition
			if f.db.Dialector.Name() == "mysql" {
				definition = "key_ref(8))"
			}
			seedOAuthDerivedK1aSource(t, f)
			require.NoError(t, f.db.Migrator().DropIndex(&model.OAuthDerivedTokenSource{}, tc.index))
			require.NoError(t, f.db.Exec("CREATE UNIQUE INDEX "+tc.index+" ON oauth_derived_token_sources("+definition).Error)
			assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
			require.NoError(t, f.db.Migrator().DropIndex(&model.OAuthDerivedTokenSource{}, tc.index))
			require.NoError(t, f.db.Migrator().CreateIndex(&model.OAuthDerivedTokenSource{}, tc.index))
			require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
		})
	}
	metadataQueries := []string{"pragma_index_list", "pragma_index_xinfo"}
	switch os.Getenv("NEWAPI_S2_MAIN") {
	case "mysql":
		metadataQueries = []string{"information_schema.statistics"}
	case "postgres":
		metadataQueries = []string{"pg_catalog.pg_index"}
	}
	for _, metadata := range metadataQueries {
		t.Run("unreadable "+metadata, func(t *testing.T) {
			f := newOAuthDerivedK1aFixture(t)
			require.NoError(t, f.db.Callback().Row().Before("gorm:row").Register("k1a_metadata_error", func(tx *gorm.DB) {
				if strings.Contains(tx.Statement.SQL.String(), metadata) {
					tx.AddError(errors.New("private K1a metadata read failure"))
				}
			}))
			t.Cleanup(func() { _ = f.db.Callback().Row().Remove("k1a_metadata_error") })
			assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(t.Context()), model.ErrOAuthDerivedTokenUnknown)
			require.NoError(t, f.db.Callback().Row().Remove("k1a_metadata_error"))
			require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
		})
	}
}

func TestOAuthDerivedK1aMetadata(t *testing.T) {
	f := newOAuthDerivedK1aFixture(t)
	grant, source, token := seedOAuthDerivedK1aSource(t, f)
	other, _, otherToken := seedOAuthDerivedK1aSource(t, f)
	snapshot, err := model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
	require.NoError(t, err)
	require.Len(t, snapshot.Items, 1)
	assert.Equal(t, model.OAuthDerivedTokenMetadata{TokenID: strconv.Itoa(token.Id), Status: "active", QuotaLimit: 1000, RemainingQuota: common.GetPointer(int64(900)), UsedQuota: common.GetPointer(int64(100)), ExpiresAt: token.ExpiredTime}, snapshot.Items[0])
	wire, err := common.Marshal(snapshot.Items)
	require.NoError(t, err)
	var items []map[string]any
	require.NoError(t, common.Unmarshal(wire, &items))
	assert.Len(t, items[0], 6)
	for _, secret := range []string{token.Key, *source.KeyRef, source.PolicyHash, source.BindingHash, *source.IdemHash} {
		assert.NotContains(t, string(wire), secret)
	}
	assert.NotEqual(t, strconv.Itoa(otherToken.Id), snapshot.Items[0].TokenID)
	assert.NotEqual(t, other.GrantRef, grant.GrantRef)
	_, err = model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, f.users["foreign"].Id)
	assert.ErrorIs(t, err, model.ErrOAuthGrantInvalid)

	for _, tc := range []struct {
		name            string
		updates         map[string]any
		status          string
		remaining, used int64
	}{
		{"disabled", map[string]any{"status": common.TokenStatusDisabled}, "disabled", 900, 100},
		{"exhausted", map[string]any{"status": common.TokenStatusExhausted, "remain_quota": 0, "used_quota": 1000}, "exhausted", 0, 1000},
		{"legitimate over-estimate settlement", map[string]any{"status": common.TokenStatusExhausted, "remain_quota": -100, "used_quota": 1100}, "exhausted", -100, 1100},
		{"recorded token expiry", map[string]any{"status": common.TokenStatusExpired, "expired_time": time.Now().Unix() - 1}, "expired", 900, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(tc.updates).Error)
			got, err := model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
			require.NoError(t, err)
			require.Len(t, got.Items, 1)
			assert.Equal(t, tc.status, got.Items[0].Status)
			assert.Equal(t, tc.remaining, *got.Items[0].RemainingQuota)
			assert.Equal(t, tc.used, *got.Items[0].UsedQuota)
			wantExpiry := source.ExpiresAt
			if expiry, ok := tc.updates["expired_time"].(int64); ok {
				wantExpiry = expiry
			}
			assert.Equal(t, wantExpiry, got.Items[0].ExpiresAt)
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(map[string]any{"status": common.TokenStatusEnabled, "remain_quota": 900, "used_quota": 100, "expired_time": source.ExpiresAt}).Error)
		})
	}
	require.NoError(t, f.db.Model(source).UpdateColumn("terminal_reason", "deleted").Error)
	_, err = model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
	assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown, "a partial terminal tuple is unknown")
	now := time.Now().Unix()
	require.NoError(t, f.db.Model(source).UpdateColumn("terminal_at", now).Error)
	require.NoError(t, f.db.Delete(token).Error)
	got, err := model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
	require.NoError(t, err)
	require.Len(t, got.Items, 1)
	assert.Equal(t, "deleted", got.Items[0].Status)
	assert.Nil(t, got.Items[0].RemainingQuota)
	assert.Nil(t, got.Items[0].UsedQuota)
	require.NoError(t, f.db.Unscoped().Delete(token).Error)
	_, err = model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
	assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown, "physical absence never reconstructs owner-effective values")
	var retained model.OAuthDerivedTokenSource
	require.NoError(t, f.db.First(&retained, "grant_ref = ?", grant.GrantRef).Error)
	assert.Equal(t, *source.CreatedAt, *retained.CreatedAt)
	assert.Equal(t, *source.TokenID, *retained.TokenID)
	// Historical verification is not a fresh-auth requirement on metadata.
	agedGrant, agedSource, agedToken := seedOAuthDerivedK1aSource(t, f)
	past := time.Now().Unix() - 180
	require.NoError(t, f.db.Model(agedGrant).UpdateColumns(map[string]any{"created_at": past, "approved_at": past}).Error)
	require.NoError(t, f.db.Model(agedSource).UpdateColumns(map[string]any{"verified_at": past, "proof_expires_at": past + 60, "permit_deadline": past + 60, "created_at": past + 1, "expires_at": past + 120}).Error)
	aged, err := model.ReadOAuthDerivedTokenMetadata(t.Context(), agedGrant.GrantRef, agedGrant.UserID)
	require.NoError(t, err)
	require.Len(t, aged.Items, 1)
	assert.Equal(t, "expired", aged.Items[0].Status)
	assert.Equal(t, strconv.Itoa(agedToken.Id), aged.Items[0].TokenID)
	assert.Equal(t, past+120, aged.Items[0].ExpiresAt)

}

func TestOAuthDerivedK1aClassification(t *testing.T) {
	f := newOAuthDerivedK1aFixture(t)
	var birthHistory model.OAuthDerivedTokenHistory
	require.NoError(t, f.db.First(&birthHistory).Error)
	grant, source, token := seedOAuthDerivedK1aSource(t, f)
	kind, err := model.ClassifyOAuthDerivedToken(t.Context(), token.Id)
	require.NoError(t, err)
	assert.Equal(t, model.OAuthDerivedTokenBound, kind)
	key, err := common.GenerateKey()
	require.NoError(t, err)
	manual := &model.Token{UserId: grant.UserID, Key: key, Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true}
	require.NoError(t, f.db.Create(manual).Error)
	kind, err = model.ClassifyOAuthDerivedToken(t.Context(), manual.Id)
	require.NoError(t, err)
	assert.Equal(t, model.OAuthDerivedTokenManualProven, kind)
	require.NoError(t, f.db.Delete(&model.OAuthDerivedTokenHistory{}, 1).Error)
	kind, err = model.ClassifyOAuthDerivedToken(t.Context(), manual.Id)
	assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
	assert.Equal(t, model.OAuthDerivedTokenUnknown, kind)
	require.NoError(t, f.db.Create(&birthHistory).Error)
	t.Run("missing both lookup members cannot become manual", func(t *testing.T) {
		keyRef := *source.KeyRef
		require.NoError(t, f.db.Model(source).UpdateColumns(map[string]any{"token_id": nil, "key_ref": nil}).Error)
		kind, err := model.ClassifyOAuthDerivedToken(t.Context(), token.Id)
		assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
		assert.Equal(t, model.OAuthDerivedTokenUnknown, kind)
		require.NoError(t, f.db.Model(source).UpdateColumns(map[string]any{"token_id": token.Id, "key_ref": keyRef}).Error)
	})

	for _, tc := range []struct {
		name, column   string
		value, restore any
	}{
		{"missing success member", "request_hash", nil, *source.RequestHash},
		{"invalid token id", "token_id", 0, token.Id},
		{"unsafe token id", "token_id", model.OAuthUsageMaxInteger + 1, token.Id},
		{"mismatched user", "user_id", f.users["foreign"].Id, source.UserID},
		{"unsafe quota", "quota_limit", model.OAuthUsageMaxInteger + 1, source.QuotaLimit},
		{"future verification", "verified_at", time.Now().Unix() + 3600, source.VerifiedAt},
		{"extended deadline", "permit_deadline", source.VerifiedAt + 61, source.PermitDeadline},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, f.db.Model(source).UpdateColumn(tc.column, tc.value).Error)
			kind, err := model.ClassifyOAuthDerivedToken(t.Context(), token.Id)
			assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
			assert.Equal(t, model.OAuthDerivedTokenUnknown, kind)
			_, err = model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
			assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
			require.NoError(t, f.db.Model(source).UpdateColumn(tc.column, tc.restore).Error)
		})
	}
	for _, tc := range []struct {
		name, column   string
		value, restore any
	}{
		{"unsafe remaining", "remain_quota", model.OAuthUsageMaxInteger + 1, 900},
		{"unsafe used", "used_quota", model.OAuthUsageMaxInteger + 1, 100},
		{"unsafe expiry", "expired_time", model.OAuthUsageMaxInteger + 1, source.ExpiresAt},
		{"unlimited contradiction", "unlimited_quota", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).UpdateColumn(tc.column, tc.value).Error)
			_, err := model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
			assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).UpdateColumn(tc.column, tc.restore).Error)
		})
	}

	require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("state", "prepared").Error)
	_, err = model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
	assert.ErrorIs(t, err, model.ErrOAuthGrantInvalid)
	require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).Delete(&model.OAuthGrant{}).Error)
	kind, err = model.ClassifyOAuthDerivedToken(t.Context(), token.Id)
	assert.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
	assert.Equal(t, model.OAuthDerivedTokenUnknown, kind)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	assert.ErrorIs(t, model.ValidateOAuthDerivedTokenStore(cancelled), model.ErrOAuthDerivedTokenUnknown)
}

func TestOAuthDerivedK1aPermitUniqueness(t *testing.T) {
	f := newOAuthDerivedK1aFixture(t)
	grant, source, _ := seedOAuthDerivedK1aSource(t, f)
	other, second, _ := seedOAuthDerivedK1aSource(t, f)
	for _, tc := range []struct {
		name, column string
		value        any
	}{
		{"token", "token_id", *source.TokenID},
		{"key", "key_ref", *source.KeyRef},
		{"proof", "proof_flow_id", source.ProofFlowID},
	} {
		t.Run(tc.name, func(t *testing.T) { assert.Error(t, f.db.Model(second).UpdateColumn(tc.column, tc.value).Error) })
	}
	duplicate := *source
	duplicate.ProofFlowID += 1000000
	assert.Error(t, f.db.Create(&duplicate).Error, "another idem cannot create a second grant row")
	for _, row := range []*model.OAuthDerivedTokenSource{source, second} {
		require.NoError(t, f.db.Model(row).Updates(map[string]any{"token_id": nil, "key_ref": nil, "idem_hash": nil, "request_hash": nil, "created_at": nil}).Error)
	}
	for _, current := range []*model.OAuthGrant{grant, other} {
		got, err := model.ReadOAuthDerivedTokenMetadata(t.Context(), current.GrantRef, current.UserID)
		require.NoError(t, err)
		assert.Empty(t, got.Items)
		assert.NotNil(t, got.Items)
	}
	require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).Delete(&model.OAuthDerivedTokenSource{}).Error)
	got, err := model.ReadOAuthDerivedTokenMetadata(t.Context(), grant.GrantRef, grant.UserID)
	require.NoError(t, err)
	assert.Empty(t, got.Items)
}

func TestOAuthDerivedK1aHandlerBoundary(t *testing.T) {
	f := newOAuthDerivedK1aFixture(t)
	grant, _, _ := seedOAuthDerivedK1aSource(t, f)
	// Existing public scopes are intentionally unchanged. A real profile access
	// can reach the private handler but cannot acquire tokens:read in K1a.
	require.NoError(t, f.db.Model(grant).UpdateColumn("scopes", `["profile"]`).Error)
	var calls atomic.Int64
	var revokeAt atomic.Int64
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == revokeAt.Load() {
			require.NoError(t, f.db.Model(grant).UpdateColumns(map[string]any{"state": "revoked", "revoked_at": time.Now().Unix()}).Error)
		}
		data, err := common.Marshal(map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": grant.Issuer, "aud": []string{"k1a"}, "client_id": grant.ClientID, "sub": grant.Subject,
			"exp": time.Now().Unix() + 600, "scope": "profile", "ext": map[string]any{"newapi_auth_version": "1", "newapi_grant_id": grant.GrantID, "newapi_grant_expires_at": strconv.FormatInt(grant.ExpiresAt, 10)}})
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(admin.Close)
	roots := x509.NewCertPool()
	roots.AddCert(admin.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: grant.Issuer, Audience: "k1a", ClientIDs: []string{grant.ClientID}}, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{Enabled: true, RevocationEnabled: true, AdminBaseURL: admin.URL, AuthorizationURL: grant.Issuer + "oauth2/auth"}, resource)
	require.NoError(t, err)
	_, err = service.NewOAuthPublic(service.OAuthPublicConfig{Enabled: true, BaseURL: "https://k1a-private.example"}, bridge)
	require.NoError(t, err)
	engine := gin.New()
	engine.RedirectTrailingSlash, engine.RedirectFixedPath = false, false
	engine.Any("/api/v1/oauth/tokens", middleware.OAuthUserInfoAuth(resource), controller.GetOAuthDerivedTokenMetadata)
	engine.Any("/api/v1/oauth/tokens/*trailing", controller.GetOAuthDerivedTokenMetadata)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/tokens", nil)
	request.Header.Set("Authorization", "Bearer k1a-fixture-opaque")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, request)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, `Bearer error="insufficient_scope", scope="tokens:read"`, w.Header().Get("WWW-Authenticate"))
	assert.Equal(t, int64(2), calls.Load(), "reuse real current resource authorization before scope denial")
	assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
	assert.Empty(t, w.Header().Get("Location"))

	// Recheck a real resource identity after middleware, even before a scope
	// denial; this does not claim the unreachable post-encoding success branch.
	revokeAt.Store(calls.Load() + 2)
	late := httptest.NewRecorder()
	lateRequest := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/tokens", nil)
	lateRequest.Header.Set("Authorization", "Bearer k1a-fixture-opaque")
	engine.ServeHTTP(late, lateRequest)
	assert.Equal(t, http.StatusUnauthorized, late.Code)
	assert.NotContains(t, late.Body.String(), "data")

	private := gin.New()
	private.RedirectTrailingSlash, private.RedirectFixedPath = false, false
	private.Any("/api/v1/oauth/tokens", controller.GetOAuthDerivedTokenMetadata)
	private.Any("/api/v1/oauth/tokens/*trailing", controller.GetOAuthDerivedTokenMetadata)
	for _, tc := range []struct {
		method, path, body string
		org                bool
		want               int
	}{
		{"GET", "/api/v1/oauth/tokens", "", false, 401},
		{"GET", "/api/v1/oauth/tokens?user_id=1", "", false, 400},
		{"GET", "/api/v1/oauth/tokens?", "", false, 400},
		{"GET", "/api/v1/oauth/tokens", "{}", false, 400},
		{"GET", "/api/v1/oauth/tokens", "", true, 400},
		{"POST", "/api/v1/oauth/tokens", "", false, 400},
		{"GET", "/api/v1/oauth/tokens/", "", false, 400},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.org {
			req.Header.Set("X-Organization-Id", "0")
		}
		response := httptest.NewRecorder()
		private.ServeHTTP(response, req)
		assert.Equal(t, tc.want, response.Code, tc.path)
		assert.Contains(t, response.Header().Get("Cache-Control"), "no-store")
		assert.Equal(t, "no-referrer", response.Header().Get("Referrer-Policy"))
		assert.Empty(t, response.Header().Get("Location"))
		assert.NotContains(t, response.Body.String(), "k1a-fixture-opaque")
	}
}

// oauthBootstrapDiagnostics keeps stderr separate from the secret birth response.
// Dropped diagnostic bytes never fail the child process or change its exit status.
type oauthBootstrapDiagnostics struct {
	data      []byte
	truncated bool
}

func (d *oauthBootstrapDiagnostics) Write(p []byte) (int, error) {
	n := min(len(p), 8192-len(d.data))
	d.data = append(d.data, p[:n]...)
	d.truncated = d.truncated || n != len(p)
	return len(p), nil
}

func (d *oauthBootstrapDiagnostics) log(t *testing.T, label string, elapsed time.Duration, err error) {
	t.Helper()
	exitCode := 0
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		exitCode = exitError.ExitCode()
	} else if err != nil {
		exitCode = -1
	}
	t.Logf("bootstrap fixture=%s client_exit=%d elapsed_ms=%d diagnostics_truncated=%t", label, exitCode, elapsed.Milliseconds(), d.truncated)
	for i, line := range strings.Split(string(d.data), "\n") {
		if i >= 16 {
			t.Log("bootstrap diagnostics=event_limit")
			break
		}
		if line == "" {
			continue
		}
		var event struct {
			Version     int    `json:"bootstrap_observation"`
			Side        string `json:"side"`
			Phase       string `json:"phase"`
			Label       string `json:"label"`
			RequestID   string `json:"request_id"`
			Outcome     string `json:"outcome"`
			Category    string `json:"category"`
			Errno       *int   `json:"errno"`
			ElapsedMS   int64  `json:"elapsed_ms"`
			MonotonicNS int64  `json:"monotonic_ns"`
		}
		if common.Unmarshal([]byte(line), &event) != nil || event.Version != 1 || event.Side != "client" ||
			!slices.Contains([]string{"oauth_birth", "organization_task_read", "unspecified"}, event.Label) ||
			!slices.Contains([]string{"begin", "connect", "peer_check", "request_write", "response_read", "decode", "stdout_write", "complete"}, event.Phase) ||
			!slices.Contains([]string{"progress", "success", "error"}, event.Outcome) ||
			!slices.Contains([]string{"none", "cli_timeout", "socket_timeout", "connection_reset", "broken_pipe", "connection_refused", "not_found", "permission", "json_decode", "os_error", "validation", "key_error", "runtime_error", "other"}, event.Category) ||
			event.ElapsedMS < 0 || event.ElapsedMS > 86400000 || event.MonotonicNS < 0 ||
			(event.Errno != nil && (*event.Errno < 0 || *event.Errno > 4095)) {
			t.Log("bootstrap diagnostics=unclassified_redacted")
			continue
		}
		pid, parseErr := strconv.Atoi(strings.TrimPrefix(event.RequestID, "pid-"))
		if parseErr != nil || pid <= 0 || event.RequestID != "pid-"+strconv.Itoa(pid) {
			t.Log("bootstrap diagnostics=invalid_request_id")
			continue
		}
		errno := 0
		if event.Errno != nil {
			errno = *event.Errno
		}
		t.Logf("bootstrap request_id=pid-%d fixture=%s phase=%s outcome=%s category=%s errno=%d elapsed_ms=%d monotonic_ns=%d", pid, event.Label, event.Phase, event.Outcome, event.Category, errno, event.ElapsedMS, event.MonotonicNS)
	}
}

// oauthBirthFixture obtains a new namespace from an external trusted installer.
// Tests run as the service principal; neither this helper nor the client seals it.
func oauthBirthFixture(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	client := os.Getenv("NEWAPI_BOOTSTRAP_CLIENT")
	require.NotEmpty(t, client, "a separate trusted installer is required for provenance fixtures")
	label := "oauth_birth"
	if strings.HasPrefix(t.Name(), "TestOrganizationTaskReadLifecycle/") {
		label = "organization_task_read"
	}
	cmd := exec.Command(client)
	cmd.Env = append(os.Environ(), "NEWAPI_BOOTSTRAP_DIAGNOSTIC_LABEL="+label)
	var diagnostic oauthBootstrapDiagnostics
	cmd.Stderr = &diagnostic
	started := time.Now()
	raw, err := cmd.Output()
	diagnostic.log(t, label, time.Since(started), err)
	require.NoError(t, err, "permanent bootstrap fixture producer failed")
	var birth struct{ Engine, DSN, Journal, ResourceReceipt string }
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
		require.Contains(t, []string{"postgres", "postgres-redis"}, os.Getenv("NEWAPI_BOOTSTRAP_TIER"))
		var receipt struct {
			ID             string `json:"id"`
			Database       string `json:"database"`
			Role           string `json:"role"`
			RestrictedRole string `json:"restricted_role"`
			SocketDir      string `json:"socket_dir"`
			Port           uint16 `json:"port"`
			ServiceUID     int    `json:"service_uid"`
			Journal        string `json:"journal"`
			JournalHash    string `json:"journal_sha256"`
		}
		root := filepath.Dir(filepath.Dir(birth.Journal))
		require.Equal(t, filepath.Join(root, "client"), client)
		for _, file := range []string{client, birth.Journal, birth.ResourceReceipt} {
			for path := file; ; path = filepath.Dir(path) {
				info, err := os.Lstat(path)
				require.NoError(t, err)
				require.Zero(t, info.Mode()&os.ModeSymlink)
				require.Zero(t, info.Mode().Perm()&0o022)
				owner := reflect.Indirect(reflect.ValueOf(info.Sys())).FieldByName("Uid")
				require.True(t, owner.IsValid())
				require.Zero(t, owner.Uint())
				if path == "/" {
					break
				}
			}
		}
		resource, err := os.ReadFile(birth.ResourceReceipt)
		require.NoError(t, err)
		require.NoError(t, common.Unmarshal(resource, &receipt))
		require.Regexp(t, `^[0-9a-f]{32}$`, receipt.ID)
		require.Equal(t, filepath.Join(root, "pg-resource-"+receipt.ID+".json"), birth.ResourceReceipt)
		require.Equal(t, filepath.Join(root, "journals", receipt.ID+".json"), birth.Journal)
		require.Equal(t, birth.Journal, receipt.Journal)
		require.Equal(t, os.Getuid(), receipt.ServiceUID)
		require.NotZero(t, receipt.ServiceUID)
		require.Equal(t, filepath.Join(root, "pg-socket"), receipt.SocketDir)
		require.EqualValues(t, 5432, receipt.Port)
		journal, err := os.ReadFile(birth.Journal)
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(journal)), receipt.JournalHash)
		current, err := exec.Command(client, "pg:"+receipt.ID).Output()
		require.NoError(t, err, "current PG kernel/journal qualification required")
		require.JSONEq(t, string(resource), string(current))
		parsed, err := url.Parse(birth.DSN)
		require.NoError(t, err)
		require.Equal(t, "postgresql", parsed.Scheme)
		require.Empty(t, parsed.Host)
		require.Empty(t, parsed.Fragment)
		require.Equal(t, "/"+receipt.Database, parsed.Path)
		require.Equal(t, receipt.Role, parsed.User.Username())
		require.Equal(t, url.Values{"host": {receipt.SocketDir}, "sslmode": {"disable"}}, parsed.Query())
		for _, key := range []string{"PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS"} {
			require.Empty(t, os.Getenv(key), key)
		}
		config, err := pgx.ParseConfig(birth.DSN)
		require.NoError(t, err)
		require.Equal(t, receipt.SocketDir, config.Host)
		require.Equal(t, receipt.Port, config.Port)
		require.Equal(t, receipt.Database, config.Database)
		require.Equal(t, receipt.Role, config.User)
		require.Nil(t, config.TLSConfig)
		require.Empty(t, config.Fallbacks)
		require.Empty(t, config.RuntimeParams)
		connection := stdlib.OpenDB(*config)
		t.Cleanup(func() { require.NoError(t, connection.Close()) })
		var database, user string
		require.NoError(t, connection.QueryRow("SELECT current_database(), current_user").Scan(&database, &user))
		require.Equal(t, receipt.Database, database)
		require.Equal(t, receipt.Role, user)
		var elevated, canAdmin bool
		require.NoError(t, connection.QueryRow("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user").Scan(&elevated))
		require.False(t, elevated)
		require.NoError(t, connection.QueryRow("SELECT admin_option FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND roleid=(SELECT oid FROM pg_roles WHERE rolname=$1)", receipt.RestrictedRole).Scan(&canAdmin))
		require.False(t, canAdmin)
		_, err = connection.Exec("CREATE ROLE forbidden_fixture_role NOLOGIN")
		require.Error(t, err, "service cannot manage roles")
		for _, table := range []string{"oauth_derived_token_history", "oauth_derived_token_bootstrap_identity"} {
			_, err = connection.Exec("DELETE FROM public." + table + " WHERE false")
			require.Error(t, err, "history/identity must remain installer-owned and read-only")
		}
		foreign := config.Copy()
		foreign.Database = "postgres"
		foreignDB := stdlib.OpenDB(*foreign)
		require.Error(t, foreignDB.PingContext(t.Context()), "service cannot connect to maintenance database")
		require.NoError(t, foreignDB.Close())
		require.Error(t, os.Chmod(birth.Journal, 0o666), "service cannot mutate protected journal")
		t.Setenv("NEWAPI_BOOTSTRAP_PG_RECEIPT", birth.ResourceReceipt)
		dialect = postgres.New(postgres.Config{Conn: connection, PreferSimpleProtocol: true})
	default:
		t.Fatalf("unsupported trusted fixture engine %q", birth.Engine)
	}
	db, err := gorm.Open(dialect, &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	var rows int64
	require.NoError(t, db.Table("tokens").Count(&rows).Error)
	require.Zero(t, rows, "producer must return a fresh namespace without token writers")
	return db, birth.DSN
}

func TestOAuthTokensNamespacePrivacy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.RedirectTrailingSlash, engine.RedirectFixedPath = false, false
	var logs bytes.Buffer
	old := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() { gin.DefaultWriter = old })
	middleware.SetUpLogger(engine)
	engine.Use(middleware.OAuthTokensBoundary)
	SetOAuthResourceRouter(engine, nil)
	engine.NoRoute(func(c *gin.Context) { c.String(200, "frontend") })
	for _, tc := range []struct {
		method, path, body, header string
		status                     int
	}{
		{"GET", "/api/v1/oauth/tokens", "", "", 401},
		{"GET", "/api/v1/oauth/tokens?", "", "", 400},
		{"GET", "/api/v1/oauth/tokens?access_token=TOKENS_QUERY_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/tokens/TOKENS_PATH_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/tokens/", "", "", 400},
		{"GET", "/api/v1/oauth/%74okens", "", "", 400},
		{"GET", "/api/v1/oauth/%252574okens/TOKENS_PATH_CANARY", "", "", 400},
		{"GET", "/api//v1/oauth/tokens", "", "", 400},
		{"GET", "/API/V1/OAUTH/TOKENS", "", "", 400},
		{"POST", "/api/v1/oauth/tokens", "", "", 400},
		{"HEAD", "/api/v1/oauth/tokens", "", "", 400},
		{"GET", "/api/v1/oauth/tokens", "{}", "", 400},
		{"GET", "/api/v1/oauth/tokens", "", "X-Organization-Id", 400},
		{"GET", "/api/v1/oauth/tokens", "", "X-HTTP-Method-Override", 400},
	} {
		t.Run(tc.method+tc.path+tc.body+tc.header, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.header != "" {
				req.Header[tc.header] = []string{""}
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			assert.Equal(t, tc.status, w.Code)
			assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
			assert.Empty(t, w.Header().Get("Location"))
			assert.NotContains(t, w.Body.String(), "frontend")
			assert.NotContains(t, w.Body.String(), "TOKENS_")
		})
	}
	assert.NotContains(t, logs.String(), "TOKENS_QUERY_CANARY")
	assert.NotContains(t, logs.String(), "TOKENS_PATH_CANARY")
}

// This HTTP consumer fixture uses the real CLI-born store and actual model
// checks. TLS introspection is synthetic; only the separate Hydra test proves
// public code/PKCE/consent/refresh issuance. No source or key is issued here.
// This bounded fixture is database-owner test code, not a gateway principal.
// It consumes the unchanged owner grants and birth protocol; no source rows,
// schema migration or privilege changes are needed for an empty metadata read.
func oauthMetadataFixture(t *testing.T) *organizationHTTPFixture {
	t.Helper()
	if !strings.HasPrefix(os.Getenv("NEWAPI_BOOTSTRAP_TIER"), "metadata-") {
		return newOrganizationHTTPFixture(t)
	}
	require.Equal(t, "TestOAuthTokensConsumerHTTP", t.Name())
	client := os.Getenv("NEWAPI_BOOTSTRAP_CLIENT")
	require.NotEmpty(t, client)
	raw, err := exec.Command(client).Output()
	require.NoError(t, err)
	var birth struct{ Engine, DSN, Journal, ResourceReceipt string }
	require.NoError(t, common.Unmarshal(raw, &birth))
	require.Equal(t, "metadata-"+birth.Engine, os.Getenv("NEWAPI_BOOTSTRAP_TIER"))
	require.Equal(t, birth.Engine, os.Getenv("NEWAPI_BOOTSTRAP_ENGINE"))
	root := filepath.Dir(client)
	require.Equal(t, filepath.Join(root, "owner-client"), client)
	manifestPath := filepath.Join(root, "bundle/manifest.json")
	for _, file := range []string{client, birth.ResourceReceipt, birth.Journal, manifestPath} {
		require.True(t, filepath.IsAbs(file))
		for path := file; ; path = filepath.Dir(path) {
			st, e := os.Lstat(path)
			require.NoError(t, e)
			require.Zero(t, st.Mode()&os.ModeSymlink)
			require.Zero(t, st.Mode().Perm()&0o022)
			owner := reflect.Indirect(reflect.ValueOf(st.Sys())).FieldByName("Uid")
			require.True(t, owner.IsValid())
			require.Zero(t, owner.Uint())
			if path == "/" {
				break
			}
		}
	}
	var receipt struct {
		ID, RoleClass, Engine, Database, DBUser, Endpoint, Journal string
		JournalSHA256, DSNSHA256, BinarySHA256, ManifestSHA256     string
		OwnerUID                                                   int
		Version                                                    string
	}
	resource, err := os.ReadFile(birth.ResourceReceipt)
	require.NoError(t, err)
	require.NoError(t, common.Unmarshal(resource, &receipt))
	require.Regexp(t, `^[0-9a-f]{32}$`, receipt.ID)
	require.Equal(t, filepath.Join(root, "wallet-"+receipt.ID+".json"), birth.ResourceReceipt)
	require.Equal(t, filepath.Join(root, "journals", receipt.ID+".json"), birth.Journal)
	require.Equal(t, "TRUSTED_DB_TEST_OWNER", receipt.RoleClass)
	require.Equal(t, os.Getuid(), receipt.OwnerUID)
	require.NotZero(t, receipt.OwnerUID)
	require.Equal(t, birth.Engine, receipt.Engine)
	require.Equal(t, birth.Journal, receipt.Journal)
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(birth.DSN))), receipt.DSNSHA256)
	executable, err := os.Executable()
	require.NoError(t, err)
	binary, err := os.ReadFile(executable)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(binary)), receipt.BinarySHA256)
	manifest, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(manifest)), receipt.ManifestSHA256)
	journal, err := os.ReadFile(birth.Journal)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(journal)), receipt.JournalSHA256)
	var phase struct{ Phase, Engine, Target string }
	require.NoError(t, common.Unmarshal(journal, &phase))
	require.Equal(t, "READY", phase.Phase)
	require.Equal(t, birth.Engine, phase.Engine)
	require.Equal(t, receipt.Database, phase.Target)
	qualify := func() {
		current, e := exec.Command(client, "qualify:"+receipt.ID).Output()
		require.NoError(t, e, "current kernel/birth binding required")
		require.JSONEq(t, string(resource), string(current))
	}
	qualify()
	t.Cleanup(qualify)
	var dialect gorm.Dialector
	switch birth.Engine {
	case "sqlite":
		require.Equal(t, receipt.Database, birth.DSN)
		require.Equal(t, receipt.Database, receipt.Endpoint)
		dialect = sqlite.Open(birth.DSN)
	case "mysql":
		cfg, e := sqlmysql.ParseDSN(birth.DSN)
		require.True(t, e == nil, "invalid protected MySQL configuration")
		require.Equal(t, "unix", cfg.Net)
		require.Equal(t, filepath.Join(root, "mysql-socket/mysql.sock"), cfg.Addr)
		require.Equal(t, receipt.Endpoint, cfg.Addr)
		require.Equal(t, receipt.Database, cfg.DBName)
		require.Equal(t, receipt.DBUser, cfg.User)
		require.Empty(t, cfg.Params)
		require.Empty(t, cfg.TLSConfig)
		require.False(t, cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.MultiStatements)
		dialect = mysql.Open(cfg.FormatDSN())
	case "postgres":
		for _, key := range []string{"PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS"} {
			require.Empty(t, os.Getenv(key))
		}
		cfg, e := pgx.ParseConfig(birth.DSN)
		require.True(t, e == nil, "invalid protected PostgreSQL configuration")
		require.Equal(t, filepath.Join(root, "pg-socket"), cfg.Host)
		require.Equal(t, filepath.Join(cfg.Host, ".s.PGSQL.5432"), receipt.Endpoint)
		require.EqualValues(t, 5432, cfg.Port)
		require.Equal(t, receipt.Database, cfg.Database)
		require.Equal(t, receipt.DBUser, cfg.User)
		require.Empty(t, cfg.Fallbacks)
		require.Empty(t, cfg.RuntimeParams)
		require.Nil(t, cfg.TLSConfig)
		dialect = postgres.New(postgres.Config{Conn: stdlib.OpenDB(*cfg), PreferSimpleProtocol: true})
	default:
		t.Fatal("unsupported metadata engine")
	}
	db, err := gorm.Open(dialect, &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	connection, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	oldDB, oldLog, oldKind, oldLogKind := model.DB, model.LOG_DB, common.MainDatabaseType(), common.LogDatabaseType()
	oldMaster, oldRedis, oldMemory, oldPath := common.IsMasterNode, common.RedisEnabled, common.MemoryCacheEnabled, common.SQLitePath
	oldReady := model.OAuthCleanupReady()
	t.Cleanup(func() {
		model.DB, model.LOG_DB = oldDB, oldLog
		common.SetDatabaseTypes(oldKind, oldLogKind)
		common.IsMasterNode, common.RedisEnabled, common.MemoryCacheEnabled, common.SQLitePath = oldMaster, oldRedis, oldMemory, oldPath
		require.NoError(t, model.InitOAuthCleanupStore(oldReady))
	})
	model.DB = db
	common.SetDatabaseTypes(common.DatabaseType(birth.Engine), common.DatabaseType(birth.Engine))
	common.IsMasterNode, common.RedisEnabled, common.MemoryCacheEnabled = false, false, false
	t.Setenv("OAUTH_BOOTSTRAP_JOURNAL", birth.Journal)
	t.Setenv("SQL_DSN", birth.DSN)
	if birth.Engine == "sqlite" {
		common.SQLitePath = birth.DSN
		t.Setenv("SQL_DSN", "")
	}
	t.Setenv("LOG_SQL_DSN", "")
	require.NoError(t, model.InitLogDB()) // public initialization of dialect quoting, no schema writes
	require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
	if birth.Engine != "sqlite" {
		var database, role string
		query := "SELECT DATABASE(), CURRENT_USER()"
		if birth.Engine == "postgres" {
			query = "SELECT current_database(), current_user"
		}
		require.NoError(t, connection.QueryRow(query).Scan(&database, &role))
		require.Equal(t, receipt.Database, database)
		if birth.Engine == "mysql" {
			require.Equal(t, receipt.DBUser+"@localhost", role)
		} else {
			require.Equal(t, receipt.DBUser, role)
		}
		for _, table := range []string{"oauth_derived_token_history", "oauth_derived_token_bootstrap_identity"} {
			_, e := connection.Exec("DELETE FROM " + table + " WHERE 1=0")
			require.Error(t, e, "immutable provenance remains SELECT-only")
		}
	}
	require.Error(t, os.Chmod(birth.Journal, 0o666))
	var count int64
	require.NoError(t, db.Model(&model.Token{}).Count(&count).Error)
	require.Zero(t, count)
	f := &organizationHTTPFixture{db: db, mainDSN: birth.DSN, mainKind: birth.Engine, users: map[string]*model.User{}, sids: map[string]string{}}
	for i, label := range []string{"owner", "foreign"} {
		u := &model.User{Id: 61000 + i, Username: "metadata-" + label, Password: "fixture-not-login-password", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: fmt.Sprint(61000 + i)}
		require.NoError(t, db.Create(u).Error)
		f.users[label] = u
		sid := "metadata-" + common.NewRequestId()
		f.sids[label] = sid
		require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: u.Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("a", 64), LoginMethod: "password", ExpiresAt: time.Now().Unix() + 3600}))
	}
	key, err := common.GenerateRandomCharsKey(40)
	require.NoError(t, err)
	require.NoError(t, db.Create(&model.Token{UserId: f.users["owner"].Id, Key: key, Status: common.TokenStatusEnabled, ExpiredTime: -1}).Error)
	if birth.Engine == "sqlite" {
		require.NoError(t, connection.QueryRow("SELECT sqlite_version()").Scan(&receipt.Version))
	}
	t.Logf("metadata qualification engine=%s version=%s role=TRUSTED_DB_TEST_OWNER same_born_database=true", birth.Engine, receipt.Version)
	return f
}

func TestOAuthTokensConsumerHTTP(t *testing.T) {
	f := oauthMetadataFixture(t)
	// Bootstrap owns provenance; the existing grant-store startup initializes
	// only its ordinary grant/cleanup schema, as in adjacent OAuth fixtures.
	master := common.IsMasterNode
	common.IsMasterNode = !f.db.Migrator().HasTable(&model.OAuthGrant{})
	err := model.InitOAuthGrantStore(true)
	common.IsMasterNode = master
	require.NoError(t, err)
	require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
	random := make([]byte, 32)
	_, err = rand.Read(random)
	require.NoError(t, err)
	scopes := []string{"profile", "tokens:read"}
	encoded, err := common.Marshal(scopes)
	require.NoError(t, err)
	grant := &model.OAuthGrant{GrantID: base64.RawURLEncoding.EncodeToString(random), Issuer: "https://gateway.example/", ClientID: "metadata-client", Subject: strconv.Itoa(f.users["owner"].Id), UserID: f.users["owner"].Id, ConsentRequestID: "metadata-consent", HydraLoginSessionID: "metadata-login", OriginSID: f.sids["owner"], SessionVersion: 1, UserAuthVersion: 1, Scopes: string(encoded), PolicyHash: strings.Repeat("a", 64)}
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
	require.NoError(t, model.ApproveOAuthGrant(t.Context(), grant))
	_, err = model.AuthorizeOAuthGrant(t.Context(), model.OAuthGrantAuthorization{Issuer: grant.Issuer, GrantID: grant.GrantID, ClientID: grant.ClientID, Subject: grant.Subject, UserID: grant.UserID, AuthVersion: 1, GrantExpiresAt: grant.ExpiresAt, TokenExpiresAt: time.Now().Unix() + 600, Scopes: scopes, Activate: true})
	require.NoError(t, err)
	require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).First(grant).Error)
	claims := map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": grant.Issuer, "aud": []string{"metadata"}, "client_id": grant.ClientID, "sub": grant.Subject, "exp": time.Now().Unix() + 600, "scope": "profile tokens:read", "ext": map[string]any{"newapi_auth_version": "1", "newapi_grant_id": grant.GrantID, "newapi_grant_expires_at": strconv.FormatInt(grant.ExpiresAt, 10)}}
	var calls atomic.Int32
	var mutate func()
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 3 && mutate != nil {
			mutate()
		}
		b, e := common.Marshal(claims)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(admin.Close)
	roots := x509.NewCertPool()
	roots.AddCert(admin.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: admin.URL + "/admin/oauth2/introspect", Issuer: grant.Issuer, Audience: "metadata", ClientIDs: []string{grant.ClientID}}, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{Enabled: true, RevocationEnabled: true, AdminBaseURL: admin.URL, AuthorizationURL: grant.Issuer + "oauth2/auth"}, resource)
	require.NoError(t, err)
	engine := gin.New()
	engine.Use(middleware.OAuthTokensBoundary)
	SetOAuthResourceRouter(engine, resource)
	request := func() *httptest.ResponseRecorder {
		calls.Store(0)
		r := httptest.NewRequest("GET", "/api/v1/oauth/tokens", nil)
		r.Header.Set("Authorization", "Bearer synthetic-metadata")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, r)
		return w
	}
	t.Run("bridge_only_rejected", func(t *testing.T) { assert.Equal(t, 401, request().Code) })
	_, err = service.NewOAuthPublic(service.OAuthPublicConfig{Enabled: true, BaseURL: "https://private-hydra.example"}, bridge)
	require.NoError(t, err)
	journal, err := os.ReadFile(os.Getenv("OAUTH_BOOTSTRAP_JOURNAL"))
	require.NoError(t, err)
	var history model.OAuthDerivedTokenHistory
	require.NoError(t, f.db.First(&history).Error)
	var identity model.OAuthDerivedTokenBootstrapIdentity
	require.NoError(t, f.db.First(&identity).Error)
	var userBefore model.User
	require.NoError(t, f.db.First(&userBefore, grant.UserID).Error)
	var tokensBefore []model.Token
	require.NoError(t, f.db.Order("id").Find(&tokensBefore).Error)
	require.NotEmpty(t, tokensBefore, "the shared fixture includes an unrelated manual key")
	beforeBytes, err := common.Marshal(tokensBefore)
	require.NoError(t, err)
	t.Run("empty_current_grant_no_writes", func(t *testing.T) {
		w := request()
		require.Equal(t, 200, w.Code, w.Body.String())
		assert.JSONEq(t, fmt.Sprintf(`{"success":true,"message":"","data":[],"quota_per_unit":%g}`, common.QuotaPerUnit), w.Body.String())
		assert.EqualValues(t, 3, calls.Load())
		var sources int64
		require.NoError(t, f.db.Model(&model.OAuthDerivedTokenSource{}).Count(&sources).Error)
		assert.Zero(t, sources)
		var tokensAfter []model.Token
		require.NoError(t, f.db.Order("id").Find(&tokensAfter).Error)
		afterBytes, err := common.Marshal(tokensAfter)
		require.NoError(t, err)
		assert.Equal(t, sha256.Sum256(beforeBytes), sha256.Sum256(afterBytes), "existing manual key and all quota fields remain unchanged and undisclosed")
		var after model.User
		require.NoError(t, f.db.First(&after, grant.UserID).Error)
		assert.Equal(t, userBefore, after)
		var afterHistory model.OAuthDerivedTokenHistory
		require.NoError(t, f.db.First(&afterHistory).Error)
		assert.Equal(t, history, afterHistory)
		var afterIdentity model.OAuthDerivedTokenBootstrapIdentity
		require.NoError(t, f.db.First(&afterIdentity).Error)
		assert.Equal(t, identity, afterIdentity)
		afterJournal, e := os.ReadFile(os.Getenv("OAUTH_BOOTSTRAP_JOURNAL"))
		require.NoError(t, e)
		assert.Equal(t, journal, afterJournal)
	})
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"wrong_client", "client_id", "other-client"}, {"wrong_actor", "sub", strconv.Itoa(f.users["foreign"].Id)},
		{"wrong_audience", "aud", []string{"other"}}, {"wrong_issuer", "iss", "https://other.example/"},
		{"refresh_bearer", "token_use", "refresh_token"}, {"expired", "exp", int64(1)}, {"future", "nbf", time.Now().Unix() + 3600}, {"write_scope_not_supported", "scope", "profile tokens:read tokens:write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, exists := claims[tc.key]
			claims[tc.key] = tc.value
			defer func() {
				if exists {
					claims[tc.key] = old
				} else {
					delete(claims, tc.key)
				}
			}()
			w := request()
			assert.Equal(t, 401, w.Code)
			assert.NotContains(t, w.Body.String(), "data")
		})
	}
	t.Run("old_grant_missing_read_scope", func(t *testing.T) {
		claims["scope"] = "profile"
		require.NoError(t, f.db.Model(grant).UpdateColumn("scopes", `["profile"]`).Error)
		defer func() {
			claims["scope"] = "profile tokens:read"
			require.NoError(t, f.db.Model(grant).UpdateColumn("scopes", string(encoded)).Error)
		}()
		w := request()
		assert.Equal(t, 403, w.Code)
		assert.Equal(t, `Bearer error="insufficient_scope", scope="tokens:read"`, w.Header().Get("WWW-Authenticate"))
	})
	t.Run("post_encoding_revocation_discards_empty_success", func(t *testing.T) {
		mutate = func() { require.NoError(t, f.db.Model(grant).UpdateColumn("state", "revoked").Error) }
		defer func() { mutate = nil; require.NoError(t, f.db.Model(grant).UpdateColumn("state", "active").Error) }()
		w := request()
		assert.Equal(t, 401, w.Code)
		assert.NotContains(t, w.Body.String(), "data")
	})
	t.Run("missing_store_is_not_empty", func(t *testing.T) {
		name := "tokens-metadata-store-error"
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
			if tx.Statement.Table == "oauth_derived_token_sources" {
				tx.AddError(errors.New("synthetic store unavailable"))
			}
		}))
		defer func() { require.NoError(t, f.db.Callback().Query().Remove(name)) }()
		w := request()
		assert.Equal(t, 503, w.Code)
		assert.NotContains(t, w.Body.String(), "data")
	})
}

// tokenMetadata checks the metadata envelope without treating it as a usage feed.
func (c *oauthHydraClient) tokenMetadata(token string, want int) map[string]any {
	c.t.Helper()
	status, headers, raw := c.request("GET", c.input.Issuer+"api/v1/oauth/tokens", "", "", token)
	require.Equal(c.t, want, status)
	assert.Contains(c.t, headers.Get("Cache-Control"), "no-store")
	assert.Equal(c.t, "no-referrer", headers.Get("Referrer-Policy"))
	assert.Empty(c.t, headers.Get("Location"))
	var body map[string]any
	require.NoError(c.t, common.Unmarshal(raw, &body))
	if want != 200 {
		assert.NotContains(c.t, body, "data")
		if want == 403 {
			assert.Equal(c.t, `Bearer error="insufficient_scope", scope="tokens:read"`, headers.Get("WWW-Authenticate"))
		}
		return body
	}
	assert.ElementsMatch(c.t, []string{"success", "message", "data", "quota_per_unit"}, slices.Collect(maps.Keys(body)))
	assert.Equal(c.t, true, body["success"])
	assert.Equal(c.t, "", body["message"])
	assert.Equal(c.t, common.QuotaPerUnit, body["quota_per_unit"])
	return body
}
