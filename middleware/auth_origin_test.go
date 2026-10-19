package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func runOriginGuardRequest(t *testing.T, origin, referer string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/user/auth/refresh", SessionCookieOriginGuard(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, "https://panel.example.com/api/user/auth/refresh", nil)
	request.Host = "panel.example.com"
	request.Header.Set("Origin", origin)
	if origin == "" {
		request.Header.Del("Origin")
	}
	if referer != "" {
		request.Header.Set("Referer", referer)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestSessionCookieOriginGuard(t *testing.T) {
	previousSecure := common.SessionCookieSecure
	previousTrustedURLs := common.SessionCookieTrustedURLs
	common.SessionCookieSecure = true
	common.SessionCookieTrustedURLs = []string{"https://trusted.example.com"}
	t.Cleanup(func() {
		common.SessionCookieSecure = previousSecure
		common.SessionCookieTrustedURLs = previousTrustedURLs
	})

	tests := []struct {
		name     string
		origin   string
		referer  string
		expected int
	}{
		{name: "same origin", origin: "https://panel.example.com", expected: http.StatusNoContent},
		{name: "trusted exact origin", origin: "https://trusted.example.com", expected: http.StatusNoContent},
		{name: "referer fallback", referer: "https://panel.example.com/profile", expected: http.StatusNoContent},
		{name: "missing both", expected: http.StatusForbidden},
		{name: "null origin", origin: "null", expected: http.StatusForbidden},
		{name: "suffix attack", origin: "https://trusted.example.com.evil.test", expected: http.StatusForbidden},
		{name: "scheme mismatch", origin: "http://panel.example.com", expected: http.StatusForbidden},
		{name: "path in origin", origin: "https://panel.example.com/profile", expected: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := runOriginGuardRequest(t, test.origin, test.referer)
			assert.Equal(t, test.expected, response.Code)
			assert.Empty(t, response.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestSessionCookieOriginGuardDevelopmentCompatibility(t *testing.T) {
	previousSecure := common.SessionCookieSecure
	previousTrustedURLs := common.SessionCookieTrustedURLs
	t.Cleanup(func() {
		common.SessionCookieSecure = previousSecure
		common.SessionCookieTrustedURLs = previousTrustedURLs
	})
	common.SessionCookieTrustedURLs = nil

	tests := []struct {
		name     string
		secure   bool
		origin   string
		expected int
	}{
		{name: "insecure mode allows mismatched development origins", origin: "http://localhost:3001", expected: http.StatusNoContent},
		{name: "insecure mode allows missing origin", expected: http.StatusNoContent},
		{name: "secure mode rejects mismatched development origins", secure: true, origin: "http://localhost:3001", expected: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			common.SessionCookieSecure = test.secure

			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/api/user/auth/refresh", SessionCookieOriginGuard(), func(c *gin.Context) {
				c.Status(http.StatusNoContent)
			})
			request := httptest.NewRequest(http.MethodPost, "http://localhost:3000/api/user/auth/refresh", nil)
			request.Host = "localhost:3000"
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			assert.Equal(t, test.expected, response.Code)
			assert.Empty(t, response.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestSessionCookieOriginGuardDoesNotTrustForwardedProtoFromClient(t *testing.T) {
	previousSecure := common.SessionCookieSecure
	previousTrustedURLs := common.SessionCookieTrustedURLs
	common.SessionCookieSecure = true
	common.SessionCookieTrustedURLs = nil
	t.Cleanup(func() {
		common.SessionCookieSecure = previousSecure
		common.SessionCookieTrustedURLs = previousTrustedURLs
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/user/auth/refresh", SessionCookieOriginGuard(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, "http://panel.example.com/api/user/auth/refresh", nil)
	request.Host = "panel.example.com"
	request.Header.Set("Origin", "https://panel.example.com")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusForbidden, response.Code)
}

func TestOrganizationOriginUsesConfiguredTrustEvenWithoutSecureCookies(t *testing.T) {
	oldAddress, oldTrusted, oldSecure := system_setting.ServerAddress, common.SessionCookieTrustedURLs, common.SessionCookieSecure
	system_setting.ServerAddress = "https://panel.example.com"
	common.SessionCookieTrustedURLs = []string{"https://trusted.example.com"}
	common.SessionCookieSecure = false
	t.Cleanup(func() {
		system_setting.ServerAddress, common.SessionCookieTrustedURLs, common.SessionCookieSecure = oldAddress, oldTrusted, oldSecure
	})
	for _, tc := range []struct {
		name    string
		headers http.Header
		allowed bool
	}{
		{"native", http.Header{}, true},
		{"configured", http.Header{"Origin": {"https://panel.example.com"}}, true},
		{"trusted referer", http.Header{"Referer": {"https://trusted.example.com/account"}}, true},
		{"host spoof", http.Header{"Origin": {"https://attacker.example.com"}}, false},
		{"forwarded spoof", http.Header{"Origin": {"https://attacker.example.com"}, "X-Forwarded-Host": {"attacker.example.com"}}, false},
		{"null", http.Header{"Origin": {"null"}}, false},
		{"multiple", http.Header{"Origin": {"https://panel.example.com", "https://panel.example.com"}}, false},
		{"metadata without origin", http.Header{"Sec-Fetch-Site": {"same-origin"}}, false},
		{"bad referer", http.Header{"Referer": {"https://attacker.example.com/page"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://attacker.example.com/api/organizations", nil)
			r.Header = tc.headers
			assert.Equal(t, tc.allowed, OrganizationOriginAllowed(r))
		})
	}
}
