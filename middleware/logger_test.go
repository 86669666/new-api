package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetUpLoggerMasksQueryCredentials(t *testing.T) {
	previousMode, previousWriter := gin.Mode(), gin.DefaultWriter
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(previousMode); gin.DefaultWriter = previousWriter })

	for _, tc := range []struct {
		name, target, safeRoute, loggedPath string
		task                                bool
	}{
		{name: "encoded and repeated credentials", target: "/v1/models?%6bey=first&key=second&API-Key=third&session_token=fourth&alt=sse", loggedPath: "/v1/models?API-Key=%2A%2A%2Amasked%2A%2A%2A&alt=sse&key=%2A%2A%2Amasked%2A%2A%2A&session_token=%2A%2A%2Amasked%2A%2A%2A"},
		{name: "literal hashes", target: "/v1/models%23test%25?key=#secret&alt=#sse", loggedPath: "/v1/models#test%?alt=%23sse&key=%2A%2A%2Amasked%2A%2A%2A"},
		{name: "malformed query", target: "/v1/models?key=bad%ZZ&%ZZ=bad&token=bad;other=true&alt=sse", loggedPath: "/v1/models?alt=sse"},
		{name: "only malformed credential", target: "/v1/models?key=bad%ZZ", loggedPath: "/v1/models?"},
		{name: "ordinary query", target: "/v1/models?alt=sse&api-version=2024-02-01", loggedPath: "/v1/models?alt=sse&api-version=2024-02-01"},
		{name: "no query", target: "/v1/models", loggedPath: "/v1/models"},
		{name: "callback", target: "/%61pi/oauth/test?code=secret&state=secret", loggedPath: "/api/oauth/test"},
		{name: "token resource", target: "/api/v1/oauth/tokens/private-resource?key=secret", loggedPath: "/api/v1/oauth/tokens/[resource]"},
		{name: "encoded usage resource", target: "/api/v1/oauth/%2575sage/private-resource?key=secret", loggedPath: "/api/v1/oauth/usage/[resource]"},
		{name: "public protocol", target: "/oauth2/authorize/private-resource?code=secret", loggedPath: "/oauth2/[protocol]"},
		{name: "provider challenge", target: "/oauth/provider/login/private-challenge?code=secret", loggedPath: "/oauth/provider/[authorization]"},
		{name: "organization route", target: "/organizations/private-resource?key=secret", safeRoute: "/organizations/:id", loggedPath: "/organizations/:id"},
		{name: "task capability", target: "/v1/tasks/task-1/artifacts/video/content?access=private-capability&key=secret&keep=ok", loggedPath: "/v1/tasks/task-1/artifacts/video/content?keep=ok&key=%2A%2A%2Amasked%2A%2A%2A", task: true},
		{name: "legacy video capability", target: "/v1/videos/video-1/content?access=private-capability&key=secret", loggedPath: "/v1/videos/video-1/content?key=%2A%2A%2Amasked%2A%2A%2A", task: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			gin.DefaultWriter = &output
			router := gin.New()
			SetUpLogger(router)
			request := httptest.NewRequest(http.MethodGet, tc.target, nil)
			originalURL := *request.URL
			router.NoRoute(func(c *gin.Context) {
				if tc.safeRoute != "" {
					c.Set(organizationSafeLogKey, tc.safeRoute)
				}
				if tc.task {
					assert.Equal(t, "private-capability", c.GetString(taskArtifactAccessRawContextKey))
					assert.Empty(t, c.Query("access"))
					assert.Equal(t, "secret", c.Query("key"))
				} else {
					assert.Equal(t, originalURL, *c.Request.URL)
					assert.Equal(t, tc.target, c.Request.RequestURI)
				}
				c.Status(http.StatusUnauthorized)
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusUnauthorized, response.Code)
			_, loggedPath, found := strings.Cut(strings.TrimSuffix(output.String(), "\n"), "GET ")
			require.True(t, found)
			assert.Equal(t, tc.loggedPath, loggedPath)
			if !tc.task {
				assert.Equal(t, originalURL, *request.URL)
				assert.Equal(t, tc.target, request.RequestURI)
			}
		})
	}
}

func TestAccessAndPanicLogsFollowLogRotation(t *testing.T) {
	previousMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	firstPath := filepath.Join(t.TempDir(), "first.log")
	secondPath := filepath.Join(t.TempDir(), "second.log")
	first, err := os.Create(firstPath)
	require.NoError(t, err)
	defer first.Close()
	second, err := os.Create(secondPath)
	require.NoError(t, err)
	defer second.Close()
	common.LogWriterMu.Lock()
	previousOut, previousErr := gin.DefaultWriter, gin.DefaultErrorWriter
	gin.DefaultWriter, gin.DefaultErrorWriter = first, first
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter, gin.DefaultErrorWriter = previousOut, previousErr
		common.LogWriterMu.Unlock()
		gin.SetMode(previousMode)
	})
	router := gin.New()
	SetUpLogger(router)
	router.Use(HTTPPanicRecover())
	router.GET("/before", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.GET("/after", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.GET("/panic", func(c *gin.Context) { panic("rotation-panic-marker") })
	before := httptest.NewRecorder()
	router.ServeHTTP(before, httptest.NewRequest(http.MethodGet, "/before", nil))
	require.Equal(t, http.StatusNoContent, before.Code)
	common.LogWriterMu.Lock()
	gin.DefaultWriter, gin.DefaultErrorWriter = second, second
	closeErr := first.Close()
	common.LogWriterMu.Unlock()
	require.NoError(t, closeErr)
	after := httptest.NewRecorder()
	router.ServeHTTP(after, httptest.NewRequest(http.MethodGet, "/after", nil))
	assert.Equal(t, http.StatusNoContent, after.Code)
	recovered := httptest.NewRecorder()
	router.ServeHTTP(recovered, httptest.NewRequest(http.MethodGet, "/panic", nil))
	assert.Equal(t, http.StatusInternalServerError, recovered.Code)
	firstLog, err := os.ReadFile(firstPath)
	require.NoError(t, err)
	secondLog, err := os.ReadFile(secondPath)
	require.NoError(t, err)
	assert.Contains(t, string(firstLog), "GET /before")
	assert.NotContains(t, string(firstLog), "GET /after")
	assert.NotContains(t, string(firstLog), "rotation-panic-marker")
	assert.Contains(t, string(secondLog), "[GIN]")
	assert.Contains(t, string(secondLog), "GET /after")
	assert.Contains(t, string(secondLog), "GET /panic")
	assert.NotContains(t, string(secondLog), "GET /before")
	assert.Contains(t, string(secondLog), "[SYS]")
	assert.Contains(t, string(secondLog), "rotation-panic-marker")
}
