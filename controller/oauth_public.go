package controller

import (
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

func OAuthPublicDocument(public *service.OAuthPublic) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
			return
		}
		data, err := public.Document(c.Request.Context(), c.Request.URL.Path)
		if err != nil {
			middleware.WriteOAuthPublicError(c, err)
			return
		}
		c.Data(200, "application/json", data)
	}
}
func OAuthPublicAuthorize(public *service.OAuthPublic) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, err := public.Authorize(c.Request.Context(), c.Request)
		if err != nil {
			middleware.WriteOAuthPublicError(c, err)
			return
		}
		for _, cookie := range result.Cookies {
			http.SetCookie(c.Writer, cookie)
		}
		c.Header("Location", result.Location)
		c.Status(result.Status)
	}
}
func OAuthPublicToken(public *service.OAuthPublic) gin.HandlerFunc {
	return func(c *gin.Context) {
		contentTypes := []string{}
		for key, values := range c.Request.Header {
			if strings.EqualFold(key, "Authorization") {
				middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
				return
			}
			if strings.EqualFold(key, "Content-Type") {
				contentTypes = append(contentTypes, values...)
			}
		}
		mediaType := ""
		var params map[string]string
		var err error
		if len(contentTypes) == 1 {
			mediaType, params, err = mime.ParseMediaType(contentTypes[0])
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || len(contentTypes) != 1 || err != nil || mediaType != "application/x-www-form-urlencoded" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
			middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
			return
		}
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, 16385))
		if err != nil || len(data) > 16384 {
			middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
			return
		}
		form, err := url.ParseQuery(string(data))
		if err != nil {
			middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
			return
		}
		grant := form.Get("grant_type")
		allowed := []string{"grant_type", "client_id"}
		switch grant {
		case "authorization_code":
			allowed = append(allowed, "code", "redirect_uri", "code_verifier")
		case "refresh_token":
			allowed = append(allowed, "refresh_token")
		default:
			middleware.WriteOAuthPublicError(c, &service.OAuthPublicError{Status: 400, Code: "unsupported_grant_type"})
			return
		}
		if raw, exists := form["scope"]; exists {
			code := "invalid_request"
			if len(raw) == 1 {
				for scope := range strings.SplitSeq(raw[0], " ") {
					if !slices.Contains([]string{"openid", "profile", "email", "offline_access"}, scope) {
						code = "invalid_scope"
					}
				}
			}
			middleware.WriteOAuthPublicError(c, &service.OAuthPublicError{Status: 400, Code: code})
			return
		}
		for key, values := range form {
			if !slices.Contains(allowed, key) || len(values) != 1 || values[0] == "" || len(values[0]) > 4096 {
				middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
				return
			}
			for _, ch := range values[0] {
				if ch < 0x21 || ch > 0x7e {
					middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
					return
				}
			}
		}
		for _, key := range allowed {
			if form.Get(key) == "" {
				middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
				return
			}
		}
		if len(form.Get("client_id")) > 256 {
			middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
			return
		}
		if grant == "authorization_code" {
			verifier := form.Get("code_verifier")
			if len(verifier) < 43 || len(verifier) > 128 {
				middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
				return
			}
			for _, ch := range verifier {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-._~", ch)) {
					middleware.WriteOAuthPublicError(c, service.ErrOAuthProviderRequest)
					return
				}
			}
		}
		result, err := public.Exchange(c.Request.Context(), form)
		if err != nil {
			middleware.WriteOAuthPublicError(c, err)
			return
		}
		c.Data(200, "application/json", result)
	}
}
