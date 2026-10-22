package router

import (
	"net/http"

	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func SetOAuthPublicRouter(router *gin.Engine, bridge *service.OAuthProviderBridge) {
	public := bridge.Public()
	routes := map[string]struct {
		method  string
		handler gin.HandlerFunc
	}{
		"/oauth2/auth":                            {http.MethodGet, controller.OAuthPublicAuthorize(public)},
		"/oauth2/token":                           {http.MethodPost, controller.OAuthPublicToken(public)},
		"/oauth2/error":                           {http.MethodGet, func(c *gin.Context) { middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest) }},
		"/.well-known/openid-configuration":       {http.MethodGet, controller.OAuthPublicDocument(public)},
		"/.well-known/oauth-authorization-server": {http.MethodGet, controller.OAuthPublicDocument(public)},
		"/.well-known/jwks.json":                  {http.MethodGet, controller.OAuthPublicDocument(public)},
	}
	router.Use(func(c *gin.Context) {
		if !middleware.OAuthPublicPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		c.Header("Cache-Control", "private, no-store")
		c.Header("Pragma", "no-cache")
		c.Header("Referrer-Policy", "no-referrer")
		// Revocation has its own independent off switch and existing boundary.
		if middleware.OAuthRevocationPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		route, exists := routes[c.Request.URL.EscapedPath()]
		if !exists || public == nil {
			middleware.WriteOAuthPublicError(c, &service.OAuthPublicError{Status: 404, Code: "not_found"})
			return
		}
		if c.Request.Method != route.method {
			middleware.WriteOAuthPublicError(c, &service.OAuthPublicError{Status: 405, Code: "invalid_request"})
			return
		}
		c.Next()
	})
	for path, route := range routes {
		router.Any(path, middleware.RouteTag("api"), middleware.OAuthPublicRateFailure, middleware.GlobalAPIRateLimit(), middleware.CriticalRateLimit(), route.handler)
		router.Any(path+"/*trailing", func(c *gin.Context) { middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest) })
	}
}
