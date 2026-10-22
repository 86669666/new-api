package middleware

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
)

const RouteTagKey = "route_tag"

// OAuthProviderPagePath recognizes only the two reserved authorization pages
// and their descendants, including one additional escaped/slash variant.
// It never changes the request used by routing or authentication.
func OAuthProviderPagePath(path string) bool {
	for attempt := range 2 {
		if strings.HasPrefix(path, "/") {
			collapsed := "/" + strings.Join(strings.FieldsFunc(path, func(r rune) bool { return r == '/' }), "/")
			for _, page := range []string{"/oauth/provider/login", "/oauth/provider/consent"} {
				if collapsed == page || strings.HasPrefix(collapsed, page+"/") {
					return true
				}
			}
		}
		if attempt == 0 {
			decoded, err := url.PathUnescape(path)
			if err != nil || decoded == path {
				break
			}
			path = decoded
		}
	}
	return false
}

func RouteTag(tag string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(RouteTagKey, tag)
		c.Next()
	}
}

func SetUpLogger(server *gin.Engine) {
	server.Use(redactTaskArtifactAccessQuery())
	server.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		var requestID string
		if param.Keys != nil {
			requestID, _ = param.Keys[common.RequestIdKey].(string)
		}
		tag, _ := param.Keys[RouteTagKey].(string)
		if tag == "" {
			tag = "web"
		}
		path := param.Path
		if safeRoute, ok := param.Keys[organizationSafeLogKey].(string); ok {
			path = safeRoute
		}
		// OAuth callbacks carry one-time codes and state in the query string.
		// Redact the log value only; the handler still needs the original query.
		resourcePath, _, _ := strings.Cut(path, "?")
		if OAuthProviderPagePath(param.Request.URL.Path) {
			path = "/oauth/provider/[authorization]"
		}
		if strings.HasPrefix(path, "/api/oauth/") || strings.HasPrefix(path, "/oauth/") || strings.HasPrefix(resourcePath, "/oauth2/") || strings.HasPrefix(resourcePath, "/.well-known/") || OAuthRevocationPath(resourcePath) || strings.TrimSuffix(resourcePath, "/") == "/api/v1/oauth/userinfo" || strings.TrimRight(resourcePath, "/") == "/api/events" {
			path, _, _ = strings.Cut(path, "?")
		}
		return fmt.Sprintf("[GIN] %s | %s | %s | %3d | %13v | %15s | %7s %s\n",
			param.TimeStamp.Format("2006/01/02 - 15:04:05"),
			tag,
			requestID,
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.Method,
			path,
		)
	}))
}
