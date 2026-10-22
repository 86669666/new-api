package middleware

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// Recognition is deliberately broader than routing, so rejected capabilities
// cannot escape into a frontend redirect or access log.
func OAuthPublicPath(path string) bool {
	for range 3 {
		collapsed := "/" + strings.Join(strings.FieldsFunc(path, func(r rune) bool { return r == '/' }), "/")
		if collapsed == "/oauth2" || strings.HasPrefix(collapsed, "/oauth2/") {
			return true
		}
		for _, p := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/.well-known/jwks.json"} {
			if collapsed == p || strings.HasPrefix(collapsed, p+"/") {
				return true
			}
		}
		decoded, err := url.PathUnescape(path)
		if err != nil || decoded == path {
			break
		}
		path = decoded
	}
	return false
}
func WriteOAuthPublicError(c *gin.Context, err error) {
	status, code := http.StatusServiceUnavailable, "temporarily_unavailable"
	var public *service.OAuthPublicError
	if errors.As(err, &public) {
		status, code = public.Status, public.Code
	} else if errors.Is(err, service.ErrOAuthProviderRequest) {
		status, code = 400, "invalid_request"
	}
	c.Header("Cache-Control", "private, no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Referrer-Policy", "no-referrer")
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}

func OAuthPublicProviderOrigin(bridge *service.OAuthProviderBridge) gin.HandlerFunc {
	return func(c *gin.Context) {
		if bridge.Public() != nil && !bridge.Public().ProviderRequestAllowed(c.Request) {
			WriteOAuthProviderError(c, service.ErrOAuthProviderDenied)
			return
		}
		c.Next()
	}
}

// Preserve the shared rate limiter while giving protocol callers a machine error.
func OAuthPublicRateFailure(c *gin.Context) {
	c.Next()
	if !c.IsAborted() || c.Writer.Written() {
		return
	}
	switch c.Writer.Status() {
	case http.StatusTooManyRequests:
		WriteOAuthPublicError(c, &service.OAuthPublicError{Status: 429, Code: "temporarily_unavailable"})
	case http.StatusInternalServerError:
		WriteOAuthPublicError(c, service.ErrOAuthResourceUnavailable)
	}
}
