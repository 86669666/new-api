package router

import (
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

func SetOAuthProviderRouter(router *gin.Engine, bridge *service.OAuthProviderBridge) {
	// Reserve this exact credential path even while off and for unmatched verbs.
	// Otherwise NoRoute can copy its query into a frontend redirect or SPA.
	router.Use(func(c *gin.Context) {
		if middleware.OAuthRevocationPath(c.Request.URL.Path) {
			c.Header("Cache-Control", "private, no-store")
			if !bridge.RevocationEnabled() {
				middleware.WriteOAuthRevocationError(c, http.StatusNotFound, "not_found")
				return
			}
			if c.Request.Method != http.MethodPost {
				middleware.WriteOAuthRevocationError(c, http.StatusMethodNotAllowed, "invalid_request")
				return
			}
			if c.Request.URL.EscapedPath() != "/oauth2/revoke" {
				middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
				return
			}
		}
		if bridge.PublicProxyEnabled() && middleware.OAuthPublicSurface(c.Request.URL.Path) {
			c.Header("Cache-Control", "private, no-store")
			path := c.Request.URL.Path
			if c.Request.URL.EscapedPath() != path {
				middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
				return
			}
			if controller.OAuthPublicKnownPath(path) {
				if !controller.OAuthPublicMethodAllowed(c.Request.Method, path) {
					middleware.WriteOAuthRevocationError(c, http.StatusMethodNotAllowed, "invalid_request")
					return
				}
			} else {
				middleware.WriteOAuthRevocationError(c, http.StatusNotFound, "not_found")
				return
			}
		}
		c.Next()
	})
	revocation := router.Group("/oauth2")
	revocation.Use(middleware.RouteTag("api"), middleware.GlobalAPIRateLimit(), middleware.CriticalRateLimit())
	revocation.Any("/revoke", middleware.OAuthRevocationBoundary, controller.RevokeOAuthToken(bridge))
	// A catch-all also consumes repeated slashes before Gin can issue a TSR.
	revocation.Any("/revoke/*trailing", func(c *gin.Context) {
		middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
	})
	if bridge != nil && bridge.PublicProxyEnabled() {
		public := []gin.HandlerFunc{middleware.RouteTag("api"), middleware.OAuthResourceNoStore, middleware.GlobalAPIRateLimit(), middleware.CriticalRateLimit()}
		router.GET("/oauth2/auth", append(public, controller.ProxyOAuthAuthorization(bridge))...)
		router.POST("/oauth2/token", append(public, controller.ProxyOAuthToken(bridge))...)
		router.GET("/.well-known/openid-configuration", append(public, controller.ProxyOAuthDiscovery(bridge, "openid"))...)
		router.GET("/.well-known/oauth-authorization-server", append(public, controller.ProxyOAuthDiscovery(bridge, "oauth"))...)
		router.GET("/.well-known/jwks.json", append(public, controller.ProxyOAuthJWKS(bridge))...)
	}
	if bridge == nil {
		return
	}
	group := router.Group("/api/oauth/provider")
	group.Use(middleware.RouteTag("api"), middleware.OAuthResourceNoStore, middleware.GlobalAPIRateLimit(), middleware.CriticalRateLimit())
	for _, phase := range []string{"login", "consent"} {
		for _, preview := range []bool{true, false} {
			path := "/" + phase
			if preview {
				path += "/preview"
			}
			// Never reflect a challenge in Gin's automatic slash Location.
			group.POST(path+"/", func(c *gin.Context) { middleware.WriteOAuthProviderError(c, service.ErrOAuthProviderRequest) })
			group.POST(path, middleware.OAuthProviderBoundary, middleware.UserAuth(), middleware.OAuthProviderSessionOnly,
				controller.OAuthProviderHandler(bridge, phase, preview))
		}
	}
}
