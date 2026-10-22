package router

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

func SetRouter(router *gin.Engine, assets WebAssets) {
	frontendBaseUrl := os.Getenv("FRONTEND_BASE_URL")
	if common.IsMasterNode && frontendBaseUrl != "" {
		frontendBaseUrl = ""
		common.SysLog(common.LogText("FRONTEND_BASE_URL is ignored on master node"))
	}
	// These pages handle short-lived capabilities. Use the stock embed rather
	// than IndexPage, which may already contain administrator analytics scripts.
	stockIndex, stockIndexErr := assets.BuildFS.ReadFile("web/dist/index.html")
	providerPage := func(c *gin.Context) {
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Cache-Control", "private, no-store")
		c.Header("Content-Security-Policy", "frame-ancestors 'none'")
		c.Header("X-Frame-Options", "DENY")
		path := c.Request.URL.EscapedPath()
		if frontendBaseUrl != "" {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not_found"})
			return
		}
		if (path != "/oauth/provider/login" && path != "/oauth/provider/consent") ||
			(c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if stockIndexErr != nil || len(stockIndex) == 0 {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "temporarily_unavailable"})
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		if c.Request.Method == http.MethodGet {
			c.Data(http.StatusOK, "text/html; charset=utf-8", stockIndex)
		} else {
			c.Status(http.StatusOK)
		}
		c.Abort()
	}
	router.Use(func(c *gin.Context) {
		if middleware.OAuthProviderPagePath(c.Request.URL.Path) {
			providerPage(c)
			return
		}
		c.Next()
	})
	// Consume slash variants before Gin can produce a query-bearing redirect.
	for _, page := range []string{"login", "consent"} {
		router.Any("/oauth/provider/"+page, providerPage)
		router.Any("/oauth/provider/"+page+"/*trailing", providerPage)
	}
	router.Use(middleware.OAuthBalanceBoundary)
	router.Use(middleware.OAuthUsageBoundary)
	router.Use(middleware.OrganizationSelectionBoundary())
	SetApiRouter(router)
	SetOAuthResourceRouter(router, service.CurrentOAuthUserInfoResource())
	SetOAuthProviderRouter(router, service.CurrentOAuthProviderBridge())
	SetDashboardRouter(router)
	SetRelayRouter(router)
	SetTaskPluginProtocolRouter(router)
	SetVideoRouter(router)
	SetTaskRouter(router)
	pluginDispatcher := SetPluginRouter(router)
	if frontendBaseUrl == "" {
		SetWebRouter(router, assets, pluginDispatcher)
	} else {
		frontendBaseUrl = strings.TrimSuffix(frontendBaseUrl, "/")
		router.NoRoute(
			pluginDispatcher,
			middleware.RouteTag("web"),
			middleware.AccessTokenAudit(),
			func(c *gin.Context) {
				c.Redirect(http.StatusMovedPermanently, fmt.Sprintf("%s%s", frontendBaseUrl, c.Request.RequestURI))
			},
		)
	}
}
