package router

import (
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func SetOAuthProviderRouter(router *gin.Engine, bridge *service.OAuthProviderBridge) {
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
