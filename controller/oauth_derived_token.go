package controller

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// GetOAuthDerivedTokenMetadata has no production route in K1a. A future resource
// route must retain the same credential/privacy boundary before invoking it.
func GetOAuthDerivedTokenMetadata(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	c.Header("Referrer-Policy", "no-referrer")
	invalid := c.Request.Method != http.MethodGet || c.Request.URL.EscapedPath() != "/api/v1/oauth/tokens" ||
		c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || c.Request.ContentLength != 0 || len(c.Request.TransferEncoding) != 0
	if !invalid && c.Request.Body != nil && c.Request.Body != http.NoBody {
		var first [1]byte
		n, err := c.Request.Body.Read(first[:])
		invalid = n != 0 || err != io.EOF
	}
	for name := range c.Request.Header {
		if strings.EqualFold(name, "X-Organization-Id") {
			invalid = true
		}
	}
	if invalid {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
		return
	}
	data, err := access.PrepareDerivedTokenMetadata(c.Request.Context())
	if errors.Is(err, service.ErrOAuthInsufficientScope) {
		c.Header("WWW-Authenticate", `Bearer error="insufficient_scope", scope="tokens:read"`)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient_scope"})
		return
	}
	if err != nil {
		middleware.WriteOAuthResourceError(c, err)
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}
