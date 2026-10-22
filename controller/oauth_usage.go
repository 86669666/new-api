package controller

import (
	"context"
	"errors"
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func GetOAuthUsageLogs(c *gin.Context) { getOAuthUsage(c, false) }
func GetOAuthUsageStat(c *gin.Context) { getOAuthUsage(c, true) }

// getOAuthUsage is a defensive handler boundary. Root namespace recognition and
// log redaction must still be wired before routing/fallback by integration owner.
func getOAuthUsage(c *gin.Context, stat bool) {
	c.Header("Cache-Control", "private, no-store")
	c.Header("Referrer-Policy", "no-referrer")
	path := "/api/v1/oauth/usage/logs"
	if stat {
		path = "/api/v1/oauth/usage/stat"
	}
	invalid := c.Request.Method != http.MethodGet || c.Request.URL.EscapedPath() != path
	values, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		invalid = true
	}
	for key := range values {
		switch strings.ToLower(key) {
		case "access_token", "org_id", "organization_id", "user_id", "username", "token_id", "token_name", "client_id", "grant_id":
			invalid = true
		}
	}
	for key := range c.Request.Header {
		switch strings.ToLower(key) {
		case "x-organization-id", "x-http-method-override", "x-method-override", "x-http-method":
			invalid = true
		}
	}
	if c.Request.Body != nil {
		var one [1]byte
		n, readErr := io.ReadFull(c.Request.Body, one[:])
		if n != 0 || readErr != nil && readErr != io.EOF {
			invalid = true
		}
	}
	if invalid {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, "usage:read")
		return
	}
	if err := access.RequireUsageScope(); err != nil {
		middleware.WriteOAuthResourceError(c, err, "usage:read")
		return
	}
	query, ok := parseUsageQuery(c, stat, "USAGE")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	var data []byte
	if stat {
		data, err = access.PrepareUsageStat(ctx, query.start, query.end, query.granularity)
	} else {
		data, err = access.PrepareUsageLogs(ctx, query.start, query.end, query.modelName, query.page, query.size)
	}
	if err != nil {
		code := "USAGE_QUERY_FAILED"
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, service.ErrUsageLogsDisabled):
			code = "USAGE_LOGS_DISABLED"
			status = http.StatusServiceUnavailable
		case errors.Is(err, service.ErrUsageStatUnavailable):
			code = "USAGE_STAT_UNAVAILABLE"
			status = http.StatusServiceUnavailable
		case !errors.Is(err, service.ErrUsageQueryFailed):
			middleware.WriteOAuthResourceError(c, err, "usage:read")
			return
		}
		common.ApiErrorStatus(c, status, errors.New(i18n.T(c, "usage."+strings.ToLower(strings.TrimPrefix(code, "USAGE_")))), gin.H{"code": code})
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}
