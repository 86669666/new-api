package router

import (
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func SetOAuthResourceRouter(router *gin.Engine, resource *service.OAuthUserInfoResource) {
	if resource == nil {
		return
	}
	group := router.Group("/api/v1/oauth")
	group.Use(middleware.RouteTag("api"), middleware.OAuthResourceNoStore, middleware.GlobalAPIRateLimit())
	group.Any("/tokens", middleware.OAuthTokensBoundary, middleware.OAuthOrdinaryTokenAudit(), middleware.OAuthTokensAuth(resource), func(c *gin.Context) {
		if c.Request.Method == "POST" {
			controller.CreateOAuthOrdinaryToken(c)
			return
		}
		controller.GetOAuthDerivedTokenMetadata(c)
	})
	group.Any("/tokens/*trailing", middleware.OAuthTokensBoundary)
	group.Any("/balance", middleware.OAuthBalanceBoundary, middleware.OAuthBalanceAuth(resource), controller.GetOAuthBalance)
	group.Any("/balance/*trailing", middleware.OAuthBalanceBoundary)
	group.Any("/usage/logs", middleware.OAuthUsageBoundary, middleware.OAuthUsageAuth(resource), controller.GetOAuthUsageLogs)
	group.Any("/usage/logs/*trailing", middleware.OAuthUsageBoundary)
	group.Any("/usage/stat", middleware.OAuthUsageBoundary, middleware.OAuthUsageAuth(resource), controller.GetOAuthUsageStat)
	group.Any("/usage/stat/*trailing", middleware.OAuthUsageBoundary)
	// Explicitly reject the slash variant instead of letting Gin redirect and
	// reflect a rejected URL credential in Location. It never serves a profile.
	group.GET("/userinfo/", func(c *gin.Context) { middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken) })
	group.GET("/userinfo", middleware.OAuthUserInfoAuth(resource), controller.GetOAuthUserInfo)
}
