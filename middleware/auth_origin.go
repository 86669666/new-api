package middleware

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
)

// SessionCookieOriginGuard protects cookie-authenticated refresh/logout
// endpoints when secure cookie mode is enabled. In insecure local development
// mode it preserves the legacy behavior and intentionally performs no Origin
// validation. It never adds CORS response headers and must not be installed on
// relay routes.
func SessionCookieOriginGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !common.SessionCookieSecure {
			c.Next()
			return
		}
		origin, ok := requestBrowserOrigin(c.Request)
		if !ok || !isAllowedSessionOrigin(c.Request, origin) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"code":    "AUTH_ORIGIN_FORBIDDEN",
				"message": "request origin is not allowed",
			})
			return
		}
		c.Next()
	}
}

func requestBrowserOrigin(request *http.Request) (string, bool) {
	originValues := request.Header.Values("Origin")
	if len(originValues) > 1 {
		return "", false
	}
	if len(originValues) == 1 {
		if strings.Contains(originValues[0], ",") {
			return "", false
		}
		origin, err := common.NormalizeOrigin(originValues[0])
		return origin, err == nil
	}
	refererValues := request.Header.Values("Referer")
	if len(refererValues) != 1 {
		return "", false
	}
	referer, err := url.Parse(strings.TrimSpace(refererValues[0]))
	if err != nil || referer.Scheme == "" || referer.Host == "" || referer.User != nil {
		return "", false
	}
	origin, err := common.NormalizeOrigin(referer.Scheme + "://" + referer.Host)
	return origin, err == nil
}

func isAllowedSessionOrigin(request *http.Request, origin string) bool {
	requestScheme := "http"
	if request.TLS != nil {
		requestScheme = "https"
	}
	requestOrigin, err := common.NormalizeOrigin(requestScheme + "://" + request.Host)
	if err == nil && subtle.ConstantTimeCompare([]byte(origin), []byte(requestOrigin)) == 1 {
		return true
	}
	for _, trustedOrigin := range common.SessionCookieTrustedURLs {
		if subtle.ConstantTimeCompare([]byte(origin), []byte(trustedOrigin)) == 1 {
			return true
		}
	}
	return false
}

// OrganizationOriginAllowed uses configured public origins only. Request Host,
// forwarding headers and the secure-cookie development switch confer no trust.
func OrganizationOriginAllowed(request *http.Request) bool {
	if len(request.Header.Values("Origin")) == 0 && len(request.Header.Values("Referer")) == 0 {
		for key := range request.Header {
			if strings.HasPrefix(strings.ToLower(key), "sec-fetch-") {
				return false
			}
		}
		return true
	}
	origin, ok := requestBrowserOrigin(request)
	if !ok {
		return false
	}
	for _, candidate := range append([]string{system_setting.ServerAddress}, common.SessionCookieTrustedURLs...) {
		configured, err := common.NormalizeOrigin(candidate)
		if err == nil && subtle.ConstantTimeCompare([]byte(origin), []byte(configured)) == 1 {
			return true
		}
	}
	return false
}
