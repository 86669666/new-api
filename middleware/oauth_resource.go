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
	c.Header("Referrer-Policy", "no-referrer")
	c.Next()
}

func OAuthUserInfoAuth(resource *service.OAuthUserInfoResource) gin.HandlerFunc {
	return oauthResourceAuth(resource, "profile")
}

func OAuthBalanceAuth(resource *service.OAuthUserInfoResource) gin.HandlerFunc {
	return oauthResourceAuth(resource, "balance:read")
}

func oauthResourceAuth(resource *service.OAuthUserInfoResource, scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		query, err := url.ParseQuery(c.Request.URL.RawQuery)
		if err != nil {
			WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, scope)
			return
		}
		for key := range query {
			if strings.EqualFold(key, "access_token") {
				WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, scope)
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
			WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, scope)
			return
		}
		scheme, credential, ok := strings.Cut(values[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || credential == "" || credential[0] == '=' || len(credential) > 4096 {
			WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, scope)
			return
		}
		padding := false
		for _, b := range credential {
			if b == '=' {
				padding = true
				continue
			}
			if padding || !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~+/", b)) {
				WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, scope)
				return
			}
		}
		access, err := resource.Authorize(c.Request.Context(), credential)
		if err != nil {
			WriteOAuthResourceError(c, err, scope)
			return
		}
		if scope == "balance:read" {
			if err := access.RequireBalanceScope(); err != nil {
				WriteOAuthResourceError(c, err, scope)
				return
			}
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

func WriteOAuthResourceError(c *gin.Context, err error, requiredScope ...string) {
	status, code := http.StatusServiceUnavailable, "temporarily_unavailable"
	if errors.Is(err, service.ErrOAuthInvalidToken) {
		status, code = http.StatusUnauthorized, "invalid_token"
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	} else if errors.Is(err, service.ErrOAuthInsufficientScope) {
		status, code = http.StatusForbidden, "insufficient_scope"
		scope := "profile"
		if len(requiredScope) == 1 && requiredScope[0] == "balance:read" {
			scope = "balance:read"
		}
		c.Header("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
	}
	c.Header("Cache-Control", "private, no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}

// OAuthBalancePath recognizes rejected variants for root privacy and logging.
// Recognition is intentionally broader than the single routable URL.
func OAuthBalancePath(path string) bool {
	for range 3 {
		collapsed := "/" + strings.Join(strings.FieldsFunc(path, func(r rune) bool { return r == '/' }), "/")
		if strings.EqualFold(collapsed, "/api/v1/oauth/balance") || strings.HasPrefix(strings.ToLower(collapsed), "/api/v1/oauth/balance/") {
			return true
		}
		decoded, err := url.PathUnescape(path)
		if err != nil || decoded == path {
			break
		}
		path = decoded
	}
	return false
}

// OAuthBalanceBoundary must also run before the root organization boundary and
// fallback dispatch. Rejected selectors never become another resource identity.
func OAuthBalanceBoundary(c *gin.Context) {
	if !OAuthBalancePath(c.Request.URL.EscapedPath()) {
		c.Next()
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.Header("Referrer-Policy", "no-referrer")
	invalid := c.Request.Method != http.MethodGet || c.Request.URL.EscapedPath() != "/api/v1/oauth/balance" || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery
	for key := range c.Request.Header {
		if strings.EqualFold(key, "X-Organization-Id") || strings.EqualFold(key, "X-HTTP-Method-Override") || strings.EqualFold(key, "X-Method-Override") || strings.EqualFold(key, "X-HTTP-Method") {
			invalid = true
		}
	}
	if invalid {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	if c.FullPath() == "" {
		// Public mode may be off; the reserved resource still cannot fall back
		// to frontend routing or a plugin handler.
		WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, "balance:read")
		return
	}
	c.Next()
}
