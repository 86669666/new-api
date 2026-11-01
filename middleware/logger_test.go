package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
