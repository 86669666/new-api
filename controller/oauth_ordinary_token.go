package controller

import (
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// CreateOAuthAPIToken discloses a newly committed key once.
func CreateOAuthAPIToken(c *gin.Context) {
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, "tokens:write")
		return
	}
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
	var fields map[string]common.RawMessage
	var name string
	if err != nil || len(data) > 4096 || common.ValidateStrictJSONObject(data) != nil || common.Unmarshal(data, &fields) != nil || len(fields) != 1 || common.Unmarshal(fields["name"], &name) != nil || strings.TrimSpace(name) == "" || len(name) > 30 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	token, err := access.CreateAPIToken(c.Request.Context(), name, c.Request.Header.Values("Idempotency-Key"))
	if err != nil {
		middleware.WriteOAuthResourceError(c, err, "tokens:write")
		return
	}
	params := tokenAuditParams(c)
	params["id"], params["derived"] = token.ID, token.Derived
	params["receipt_only"] = token.Derived && token.Key == ""
	common.SetContextKey(c, constant.ContextKeyTokenAuditSucceeded, token.Key != "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": token})
}
