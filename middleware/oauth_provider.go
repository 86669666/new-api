package middleware

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// OAuthRevocationPath also recognizes encoded and trailing-slash variants so
// rejected credential queries never reach the frontend or its access log.
func OAuthRevocationPath(path string) bool {
	decoded, err := url.PathUnescape(path)
	return path == "/oauth2/revoke" || strings.HasPrefix(path, "/oauth2/revoke/") || err == nil && (decoded == "/oauth2/revoke" || strings.HasPrefix(decoded, "/oauth2/revoke/"))
}

func OAuthRevocationBoundary(c *gin.Context) {
	if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
		WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	contentTypes := []string{}
	for key, values := range c.Request.Header {
		if strings.EqualFold(key, "Authorization") {
			WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		if strings.EqualFold(key, "Content-Type") {
			contentTypes = append(contentTypes, values...)
		}
	}
	if len(contentTypes) != 1 {
		WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	c.Next()
}

func WriteOAuthRevocationError(c *gin.Context, status int, code string) {
	c.Header("Cache-Control", "private, no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}

func WriteOAuthRevocationFailure(c *gin.Context, err error) {
	if errors.Is(err, service.ErrOAuthProviderRequest) {
		WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
	} else if errors.Is(err, service.ErrOAuthRevocationClient) {
		WriteOAuthRevocationError(c, http.StatusUnauthorized, "invalid_client")
	} else {
		WriteOAuthRevocationError(c, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

// OAuthProviderBoundary keeps this POST-only ceremony separate from cookie
// authentication and checks configured origins before any flow or Admin work.
func OAuthProviderBoundary(c *gin.Context) {
	if c.Request.URL.RawQuery != "" {
		WriteOAuthProviderError(c, service.ErrOAuthProviderRequest)
		return
	}
	for _, name := range []string{"Authorization", "Origin", "Referer", "Content-Type"} {
		count := 0
		for key, values := range c.Request.Header {
			if strings.EqualFold(key, name) {
				count += len(values)
			}
		}
		if name == "Authorization" && count == 0 {
			WriteOAuthProviderError(c, service.ErrOAuthInvalidToken)
			return
		}
		if count > 1 || name == "Content-Type" && count != 1 {
			WriteOAuthProviderError(c, service.ErrOAuthProviderRequest)
			return
		}
	}
	for key, values := range c.Request.Header {
		if !strings.HasPrefix(strings.ToLower(key), "sec-fetch-") {
			continue
		}
		if len(values) != 1 || values[0] == "" || strings.Contains(values[0], ",") || strings.EqualFold(key, "Sec-Fetch-Site") && !slices.Contains([]string{"same-origin", "same-site", "none"}, values[0]) {
			WriteOAuthProviderError(c, service.ErrOAuthProviderDenied)
			return
		}
	}
	if !OrganizationOriginAllowed(c.Request) {
		WriteOAuthProviderError(c, service.ErrOAuthProviderDenied)
		return
	}
	mediaType, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		WriteOAuthProviderError(c, service.ErrOAuthProviderRequest)
		return
	}
	scheme, credential, ok := strings.Cut(c.GetHeader("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || credential == "" || len(credential) > 4096 {
		WriteOAuthProviderError(c, service.ErrOAuthInvalidToken)
		return
	}
	for _, ch := range credential {
		if ch < 0x21 || ch > 0x7e || ch == ',' {
			WriteOAuthProviderError(c, service.ErrOAuthInvalidToken)
			return
		}
	}
	c.Next()
}

// The identity must be the typed value established by UserAuth, never fallback
// context fields. The service rechecks persisted state and both versions.
func OAuthProviderSessionOnly(c *gin.Context) {
	identity, ok := GetAuthIdentity(c)
	if !ok || c.GetBool("use_access_token") || identity.UserID <= 0 || identity.SessionID == "" || identity.UserAuthVersion <= 0 || identity.SessionVersion <= 0 || strings.HasPrefix(identity.SessionID, "pat:") || strings.HasPrefix(identity.SessionID, "legacy") {
		WriteOAuthProviderError(c, service.ErrOAuthInvalidToken)
		return
	}
	c.Next()
}

func WriteOAuthProviderError(c *gin.Context, err error) {
	status, code := http.StatusServiceUnavailable, "temporarily_unavailable"
	switch {
	case errors.Is(err, service.ErrOAuthProviderRequest):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, service.ErrOAuthProviderDenied):
		status, code = http.StatusForbidden, "access_denied"
	case errors.Is(err, service.ErrOAuthProviderReplay):
		status, code = http.StatusConflict, "invalid_grant"
	case errors.Is(err, service.ErrOAuthInvalidToken):
		status, code = http.StatusUnauthorized, "invalid_token"
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	c.Header("Cache-Control", "private, no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}
