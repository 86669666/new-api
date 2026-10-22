package controller

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func ProxyOAuthAuthorization(bridge *service.OAuthProviderBridge) gin.HandlerFunc {
	return func(c *gin.Context) {
		forbidden := oauthCallerHosts(c)
		result, err := bridge.ProxyAuthorize(c.Request.Context(), c.Request.URL.RawQuery, forbidden)
		writeOAuthPublicResult(c, result, err)
	}
}

func ProxyOAuthToken(bridge *service.OAuthProviderBridge) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		contentTypes := []string{}
		for key, values := range c.Request.Header {
			if strings.EqualFold(key, "Authorization") {
				middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
				return
			}
			if strings.EqualFold(key, "Content-Type") {
				contentTypes = append(contentTypes, values...)
			}
		}
		if len(contentTypes) != 1 {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		mediaType, params, err := mime.ParseMediaType(contentTypes[0])
		if err != nil || mediaType != "application/x-www-form-urlencoded" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, 8193))
		if err != nil || len(data) > 8192 {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		form, err := url.ParseQuery(string(data))
		if err != nil {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		result, err := bridge.ProxyToken(c.Request.Context(), form)
		if errors.Is(err, service.ErrOAuthUnsupportedGrant) {
			body, marshalErr := service.OAuthPublicFixedError("unsupported_grant_type")
			if marshalErr != nil {
				middleware.WriteOAuthRevocationError(c, http.StatusServiceUnavailable, "temporarily_unavailable")
				return
			}
			c.Header("Cache-Control", "private, no-store")
			c.Data(http.StatusBadRequest, "application/json", body)
			c.Abort()
			return
		}
		writeOAuthPublicResult(c, result, err)
	}
}

func ProxyOAuthDiscovery(bridge *service.OAuthProviderBridge, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		result, err := bridge.ProxyDiscovery(c.Request.Context(), kind)
		writeOAuthPublicResult(c, result, err)
	}
}

func ProxyOAuthJWKS(bridge *service.OAuthProviderBridge) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		result, err := bridge.ProxyJWKS(c.Request.Context())
		writeOAuthPublicResult(c, result, err)
	}
}

func writeOAuthPublicResult(c *gin.Context, result *service.OAuthPublicResult, err error) {
	if errors.Is(err, service.ErrOAuthProviderRequest) {
		middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if err != nil || result == nil {
		middleware.WriteOAuthRevocationError(c, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	c.Header("Cache-Control", "private, no-store")
	if result.Location != "" {
		c.Redirect(result.Status, result.Location)
		c.Abort()
		return
	}
	contentType := result.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	c.Data(result.Status, contentType, result.Body)
	c.Abort()
}

func oauthCallerHosts(c *gin.Context) []string {
	forwarded := []string{}
	for key, values := range c.Request.Header {
		if strings.EqualFold(key, "X-Forwarded-Host") || strings.EqualFold(key, "Forwarded") {
			forwarded = append(forwarded, values...)
		}
	}
	return service.OAuthForbiddenHosts(c.Request.Host, forwarded)
}

func OAuthPublicMethodAllowed(method, path string) bool {
	switch path {
	case "/oauth2/auth", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/.well-known/jwks.json":
		return method == http.MethodGet
	case "/oauth2/token":
		return method == http.MethodPost
	default:
		return false
	}
}

func OAuthPublicKnownPath(path string) bool {
	return slices.Contains([]string{
		"/oauth2/auth", "/oauth2/token",
		"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/.well-known/jwks.json",
	}, path)
}
