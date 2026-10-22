package middleware

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

const oauthUserInfoAccessKey = "oauth_userinfo_access"

// OAuthResourceNoStore runs before the resource limiter and authentication.
func OAuthResourceNoStore(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	c.Next()
}

func OAuthUserInfoAuth(resource *service.OAuthUserInfoResource) gin.HandlerFunc {
	return func(c *gin.Context) {
		query, err := url.ParseQuery(c.Request.URL.RawQuery)
		if err != nil {
			WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
			return
		}
		for key := range query {
			if strings.EqualFold(key, "access_token") {
				WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
				return
			}
		}
		values := []string{}
		for key, entries := range c.Request.Header {
			if strings.EqualFold(key, "Authorization") {
				values = append(values, entries...)
			}
		}
		if len(values) != 1 {
			WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
			return
		}
		scheme, credential, ok := strings.Cut(values[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || credential == "" || credential[0] == '=' || len(credential) > 4096 {
			WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
			return
		}
		padding := false
		for _, b := range credential {
			if b == '=' {
				padding = true
				continue
			}
			if padding || !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~+/", b)) {
				WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
				return
			}
		}
		access, err := resource.Authorize(c.Request.Context(), credential)
		if err != nil {
			WriteOAuthResourceError(c, err)
			return
		}
		c.Set(oauthUserInfoAccessKey, access)
		c.Next()
	}
}

func GetOAuthUserInfoAccess(c *gin.Context) (*service.OAuthUserInfoAccess, bool) {
	value, exists := c.Get(oauthUserInfoAccessKey)
	access, ok := value.(*service.OAuthUserInfoAccess)
	return access, exists && ok && access != nil
}

func WriteOAuthResourceError(c *gin.Context, err error) {
	writeOAuthResourceError(c, err, "profile")
}

func WriteOAuthResourceScopeError(c *gin.Context, err error, scope string) {
	writeOAuthResourceError(c, err, scope)
}

func writeOAuthResourceError(c *gin.Context, err error, scope string) {
	status, code := http.StatusServiceUnavailable, "temporarily_unavailable"
	if errors.Is(err, service.ErrOAuthInvalidToken) {
		status, code = http.StatusUnauthorized, "invalid_token"
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	} else if errors.Is(err, service.ErrOAuthResourceRequest) {
		status, code = http.StatusBadRequest, "invalid_request"
	} else if errors.Is(err, service.ErrOAuthInsufficientScope) {
		status, code = http.StatusForbidden, "insufficient_scope"
		if scope == "" {
			scope = "profile"
		}
		c.Header("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
	}
	c.Header("Cache-Control", "private, no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}
