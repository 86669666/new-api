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
	// Explicitly reject the slash variant instead of letting Gin redirect and
	// reflect a rejected URL credential in Location. It never serves a profile.
	group.GET("/userinfo/", func(c *gin.Context) { middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken) })
	group.GET("/userinfo", middleware.OAuthUserInfoAuth(resource), controller.GetOAuthUserInfo)
}
