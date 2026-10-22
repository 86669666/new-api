package controller

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
)

type tokenUsageQuery struct {
	start, end  int64
	page, size  int
	modelName   string
	granularity string
}

// parseTokenUsageQuery deliberately opts into strict parsing only for the new
// API-key endpoints. Dashboard history retains its existing compatibility rules.
func parseTokenUsageQuery(c *gin.Context, stat bool) (tokenUsageQuery, bool) {
	query := tokenUsageQuery{page: 1, size: min(max(common.ItemsPerPage, 1), 100), granularity: "hour"}
	values, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		common.ApiErrorStatus(c, http.StatusBadRequest, errors.New(i18n.T(c, i18n.MsgTokenUsageQueryInvalid)), gin.H{"code": "TOKEN_USAGE_QUERY_INVALID"})
		return query, false
	}
	for name, entries := range values {
		allowed := name == "start_timestamp" || name == "end_timestamp" || name == "org_id"
		if stat {
			allowed = allowed || name == "granularity"
		} else {
			allowed = allowed || name == "p" || name == "page" || name == "page_size" || name == "model_name"
		}
		if !allowed || len(entries) != 1 {
			common.ApiErrorStatus(c, http.StatusBadRequest, errors.New(i18n.T(c, i18n.MsgTokenUsageQueryInvalid)), gin.H{"code": "TOKEN_USAGE_QUERY_INVALID"})
			return query, false
		}
	}
	query.end = common.GetTimestamp()
	for _, name := range []string{"end_timestamp", "start_timestamp", "p", "page", "page_size"} {
		if !values.Has(name) || name == "page" && values.Has("p") {
			continue
		}
		number, valid := middleware.ParseOrganizationDecimal(values.Get(name))
		if !valid || (name == "p" || name == "page" || name == "page_size") && (number == 0 || number > 100001) || name == "page_size" && number > 100 {
			common.ApiErrorStatus(c, http.StatusBadRequest, errors.New(i18n.T(c, i18n.MsgTokenUsageQueryInvalid)), gin.H{"code": "TOKEN_USAGE_QUERY_INVALID"})
			return query, false
		}
		switch name {
		case "end_timestamp":
			query.end = min(query.end, number)
		case "start_timestamp":
			query.start = number
		case "p", "page":
			query.page = int(number)
		case "page_size":
			query.size = int(number)
		}
	}
	if (query.page-1)*query.size > 100000 || len(values.Get("model_name")) > 256 {
		common.ApiErrorStatus(c, http.StatusBadRequest, errors.New(i18n.T(c, i18n.MsgTokenUsageQueryInvalid)), gin.H{"code": "TOKEN_USAGE_QUERY_INVALID"})
		return query, false
	}
	query.modelName = values.Get("model_name")
	if values.Has("granularity") {
		query.granularity = values.Get("granularity")
		if query.granularity != "hour" && query.granularity != "day" {
			common.ApiErrorStatus(c, http.StatusBadRequest, errors.New(i18n.T(c, i18n.MsgTokenUsageQueryInvalid)), gin.H{"code": "TOKEN_USAGE_QUERY_INVALID"})
			return query, false
		}
	}
	maxRange := operation_setting.GetLogSetting().MaxRangeSeconds()
	if !values.Has("start_timestamp") {
		query.start = max(0, query.end-maxRange)
	}
	if query.start > query.end {
		common.ApiErrorStatus(c, http.StatusBadRequest, errors.New(i18n.T(c, i18n.MsgTokenUsageRangeInvalid)), gin.H{"code": "TOKEN_USAGE_RANGE_INVALID"})
		return query, false
	}
	if query.end-query.start > maxRange {
		common.ApiErrorStatus(c, http.StatusBadRequest, common.NewMessage("The time range cannot exceed {{days}} days", map[string]any{"days": maxRange / 86400}), gin.H{"code": "LOG_RANGE_TOO_WIDE", "message": i18n.T(c, i18n.MsgTokenUsageRangeTooWide, map[string]any{"Days": maxRange / 86400})})
		return query, false
	}
	return query, true
}

func GetTokenUsageLogs(c *gin.Context) {
	token, ok := middleware.GetTokenUsageToken(c)
	if !ok {
		common.ApiErrorStatus(c, http.StatusUnauthorized, errors.New(i18n.T(c, i18n.MsgTokenInvalid)), gin.H{"code": "TOKEN_USAGE_AUTH_INVALID"})
		return
	}
	query, ok := parseTokenUsageQuery(c, false)
	if !ok {
		return
	}
	if !common.LogConsumeEnabled {
		common.ApiErrorStatus(c, http.StatusServiceUnavailable, errors.New(i18n.T(c, i18n.MsgTokenUsageLogsDisabled)), gin.H{"code": "TOKEN_USAGE_LOGS_DISABLED"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	items, total, err := model.GetTokenUsageLogs(ctx, token.UserId, token.Id, query.start, query.end, query.modelName, (query.page-1)*query.size, query.size)
	if err != nil {
		common.ApiErrorStatus(c, http.StatusInternalServerError, errors.New(i18n.T(c, i18n.MsgTokenUsageQueryFailed)), gin.H{"code": "TOKEN_USAGE_QUERY_FAILED"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "", "data": gin.H{"items": items, "total": total, "page": query.page, "page_size": query.size}, "quota_per_unit": common.QuotaPerUnit, "data_complete": false})
}

func GetTokenUsageStat(c *gin.Context) {
	token, ok := middleware.GetTokenUsageToken(c)
	if !ok {
		common.ApiErrorStatus(c, http.StatusUnauthorized, errors.New(i18n.T(c, i18n.MsgTokenInvalid)), gin.H{"code": "TOKEN_USAGE_AUTH_INVALID"})
		return
	}
	query, ok := parseTokenUsageQuery(c, true)
	if !ok {
		return
	}
	if !common.DataExportEnabled || !common.LogConsumeEnabled {
		common.ApiErrorStatus(c, http.StatusServiceUnavailable, errors.New(i18n.T(c, i18n.MsgTokenUsageStatUnavailable)), gin.H{"code": "TOKEN_USAGE_STAT_UNAVAILABLE"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	buckets, err := model.GetTokenUsageStat(ctx, token.UserId, token.Id, query.start, query.end, query.granularity)
	if err != nil {
		common.ApiErrorStatus(c, http.StatusInternalServerError, errors.New(i18n.T(c, i18n.MsgTokenUsageQueryFailed)), gin.H{"code": "TOKEN_USAGE_QUERY_FAILED"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "", "data": buckets, "quota_per_unit": common.QuotaPerUnit, "granularity": query.granularity, "data_complete": false})
}
