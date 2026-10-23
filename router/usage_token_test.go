package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/QuantumNous/new-api/service"
	"gorm.io/gorm"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenUsageReadOnlyHTTP(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.QuotaData{}))
	// A distinct log database proves the history reader does not accidentally
	// use the primary DB, even when both happen to use the same dialect.
	if model.LOG_DB == f.db {
		logDB, _ := organizationTestDB(t, f.mainKind, os.Getenv("NEWAPI_S2_MAIN_DSN"))
		require.NoError(t, logDB.AutoMigrate(&model.Log{}))
		model.LOG_DB = logDB
	}
	combinedFixtureDatabase(t, "main", f.db)
	combinedFixtureDatabase(t, "log", model.LOG_DB)
	oldExport, oldConsume, oldQuota := common.DataExportEnabled, common.LogConsumeEnabled, common.QuotaPerUnit
	oldRange := operation_setting.GetLogSetting().MaxRangeDays
	model.CacheQuotaDataLock.Lock()
	oldCache := model.CacheQuotaData
	model.CacheQuotaData = make(map[string]*model.QuotaData)
	model.CacheQuotaDataLock.Unlock()
	t.Cleanup(func() {
		common.DataExportEnabled, common.LogConsumeEnabled, common.QuotaPerUnit = oldExport, oldConsume, oldQuota
		operation_setting.GetLogSetting().MaxRangeDays = oldRange
		model.CacheQuotaDataLock.Lock()
		model.CacheQuotaData = oldCache
		model.CacheQuotaDataLock.Unlock()
	})
	common.DataExportEnabled, common.LogConsumeEnabled, common.QuotaPerUnit = true, true, 500000
	operation_setting.GetLogSetting().MaxRangeDays = 2
	base := time.Now().UTC().Truncate(24 * time.Hour).Add(-48 * time.Hour).Unix()
	start, end := base+23*3600+1, base+25*3600+20
	window := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", start, end)
	tokens := map[string]*model.Token{}
	for _, actor := range []string{"A", "B", "foreign"} {
		key, err := common.GenerateRandomCharsKey(40)
		require.NoError(t, err)
		user := f.users["owner"]
		if actor == "foreign" {
			user = f.users["foreign"]
		}
		token := &model.Token{UserId: user.Id, Key: key, Name: "usage-" + actor, Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true}
		require.NoError(t, f.db.Create(token).Error)
		tokens[actor] = token
		f.bearer[actor] = "sk-" + key
	}
	logs := []model.Log{
		{UserId: tokens["A"].UserId, TokenId: tokens["A"].Id, CreatedAt: start, Type: model.LogTypeConsume, ModelName: "alpha", Quota: 11, PromptTokens: 2, CompletionTokens: 3, UseTime: 4, IsStream: true, Group: "premium"},
		{UserId: tokens["A"].UserId, TokenId: tokens["A"].Id, CreatedAt: base + 24*3600, Type: model.LogTypeConsume, ModelName: "beta", Quota: 13},
		{UserId: tokens["A"].UserId, TokenId: tokens["A"].Id, CreatedAt: end, Type: model.LogTypeConsume, ModelName: "alpha", Quota: 17},
		{UserId: tokens["A"].UserId, TokenId: tokens["A"].Id, CreatedAt: start - 1, Type: model.LogTypeConsume, ModelName: "before", Quota: 900},
		{UserId: tokens["A"].UserId, TokenId: tokens["A"].Id, CreatedAt: end + 1, Type: model.LogTypeConsume, ModelName: "after", Quota: 900},
		{UserId: tokens["A"].UserId, TokenId: tokens["A"].Id, CreatedAt: time.Now().Unix() + 3600, Type: model.LogTypeConsume, ModelName: "future", Quota: 900},
		{UserId: tokens["B"].UserId, TokenId: tokens["B"].Id, CreatedAt: start, Type: model.LogTypeConsume, ModelName: "same-user-B", Quota: 1000},
		{UserId: tokens["foreign"].UserId, TokenId: tokens["foreign"].Id, CreatedAt: start, Type: model.LogTypeConsume, ModelName: "foreign", Quota: 2000},
		{UserId: tokens["foreign"].UserId, TokenId: tokens["A"].Id, CreatedAt: start, Type: model.LogTypeConsume, ModelName: "wrong-owner", Quota: 3000},
		{UserId: tokens["A"].UserId, TokenId: tokens["A"].Id, CreatedAt: start, Type: model.LogTypeRefund, ModelName: "refund", Quota: 4000},
	}
	for i := range logs {
		logs[i].Ip, logs[i].ChannelId, logs[i].Other = "203.0.113.19", 999, `{"secret":"not-public"}`
		logs[i].RequestId = fmt.Sprintf("usage-private-%d", i)
		require.NoError(t, model.LOG_DB.Create(&logs[i]).Error)
	}
	hour := base + 23*3600
	rows := []model.QuotaData{
		{UserID: tokens["A"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour, ModelName: "alpha", UseGroup: "one", Quota: 11, Count: 1, TokenUsed: 5},
		{UserID: tokens["A"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour, ModelName: "beta", UseGroup: "two", Quota: 7, Count: 2, TokenUsed: 10},
		{UserID: tokens["A"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour + 3600, Quota: 13, Count: 3, TokenUsed: 20},
		{UserID: tokens["A"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour + 7200, Quota: 17, Count: 4, TokenUsed: 30},
		{UserID: tokens["A"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour - 3600, Quota: 900, Count: 900},
		{UserID: tokens["A"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour + 10800, Quota: 900, Count: 900},
		{UserID: tokens["B"].UserId, TokenID: tokens["B"].Id, CreatedAt: hour, Quota: 1000, Count: 10, TokenUsed: 100},
		{UserID: tokens["foreign"].UserId, TokenID: tokens["foreign"].Id, CreatedAt: hour, Quota: 2000, Count: 20, TokenUsed: 200},
		{UserID: tokens["foreign"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour, Quota: 3000, Count: 30, TokenUsed: 300},
		{UserID: tokens["A"].UserId, TokenID: 0, CreatedAt: hour, Quota: 4000, Count: 40, TokenUsed: 400},
	}
	require.NoError(t, f.db.Create(&rows).Error)
	model.LogQuotaData(model.QuotaDataLogParams{UserID: tokens["A"].UserId, TokenID: tokens["A"].Id, CreatedAt: hour, Quota: 5000, TokenUsed: 500})

	t.Run("logs_projection_pagination_and_isolation", func(t *testing.T) {
		for _, tc := range []struct {
			actor, query, model string
			total, page         float64
		}{
			{"A", "p=2&page=1&page_size=1", "beta", 3, 2},
			{"A", "page=2&page_size=1", "beta", 3, 2},
			{"A", "p=1&page=invalid&page_size=1", "alpha", 3, 1},
			{"A", "model_name=beta&page_size=1", "beta", 1, 1},
			{"B", "page_size=1", "same-user-B", 1, 1},
			{"foreign", "page_size=1", "foreign", 1, 1},
		} {
			status, headers, body := f.request(t, "GET", "/api/usage/token/logs?"+window+"&"+tc.query, tc.actor, "", nil)
			require.Equal(t, http.StatusOK, status)
			assert.Contains(t, headers.Get("Cache-Control"), "no-store")
			assert.Equal(t, true, body["success"])
			assert.Equal(t, false, body["data_complete"])
			assert.Equal(t, float64(500000), body["quota_per_unit"])
			data := body["data"].(map[string]any)
			assert.Equal(t, tc.total, data["total"])
			assert.Equal(t, tc.page, data["page"])
			assert.Equal(t, float64(1), data["page_size"])
			items := data["items"].([]any)
			require.Len(t, items, 1)
			item := items[0].(map[string]any)
			assert.Equal(t, tc.model, item["model_name"])
			assert.ElementsMatch(t, []string{"created_at", "model_name", "prompt_tokens", "completion_tokens", "quota", "use_time", "is_stream", "group"}, slices.Collect(maps.Keys(item)))
		}
		_, _, body := f.request(t, "GET", "/api/usage/token/logs?"+window+"&model_name=%25", "A", "", nil)
		data := body["data"].(map[string]any)
		assert.Equal(t, float64(0), data["total"], "model filters are exact, not SQL wildcard patterns")
		assert.Equal(t, []any{}, data["items"])
		_, _, body = f.request(t, "GET", "/api/usage/token/logs?"+window+"&page=10", "A", "", nil)
		assert.Equal(t, []any{}, body["data"].(map[string]any)["items"])
		_, _, body = f.request(t, "GET", fmt.Sprintf("/api/usage/token/logs?start_timestamp=%d&end_timestamp=%d", start, start), "A", "", nil)
		item := body["data"].(map[string]any)["items"].([]any)[0].(map[string]any)
		assert.Equal(t, float64(11), item["quota"])
		assert.Equal(t, float64(2), item["prompt_tokens"])
		assert.Equal(t, float64(3), item["completion_tokens"])
		assert.Equal(t, float64(4), item["use_time"])
		assert.Equal(t, true, item["is_stream"])
		assert.Equal(t, "premium", item["group"])
		sample, err := common.Marshal(body)
		require.NoError(t, err)
		t.Logf("logs_sample=%s", sample)
		status, _, body := f.request(t, "GET", "/api/usage/token/logs?end_timestamp=9223372036854775807", "A", "", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, float64(5), body["data"].(map[string]any)["total"], "future end is capped to now and default start is bounded")
	})
	t.Run("utc_hours_days_and_unknown_coverage", func(t *testing.T) {
		for _, tc := range []struct {
			granularity string
			want        []model.TokenUsageBucket
		}{
			{"hour", []model.TokenUsageBucket{{TS: hour, Quota: 18, Requests: 3, Tokens: 15}, {TS: hour + 3600, Quota: 13, Requests: 3, Tokens: 20}, {TS: hour + 7200, Quota: 17, Requests: 4, Tokens: 30}}},
			{"day", []model.TokenUsageBucket{{TS: base, Quota: 18, Requests: 3, Tokens: 15}, {TS: base + 86400, Quota: 30, Requests: 7, Tokens: 50}}},
		} {
			status, _, body := f.request(t, "GET", "/api/usage/token/stat?"+window+"&granularity="+tc.granularity, "A", "", nil)
			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, tc.granularity, body["granularity"])
			assert.Equal(t, false, body["data_complete"])
			assert.Equal(t, float64(500000), body["quota_per_unit"])
			encoded, err := common.Marshal(body["data"])
			require.NoError(t, err)
			var actual []model.TokenUsageBucket
			require.NoError(t, common.Unmarshal(encoded, &actual))
			assert.Equal(t, tc.want, actual, "legacy token_id=0, wrong-user, other-key, and pending cache rows must stay excluded")
			sample, err := common.Marshal(body)
			require.NoError(t, err)
			t.Logf("%s_sample=%s", tc.granularity, sample)
		}
		for _, tc := range []struct {
			actor string
			quota float64
		}{{"B", 1000}, {"foreign", 2000}} {
			status, _, body := f.request(t, "GET", "/api/usage/token/stat?"+window, tc.actor, "", nil)
			require.Equal(t, http.StatusOK, status)
			data := body["data"].([]any)
			require.Len(t, data, 1)
			assert.Equal(t, tc.quota, data[0].(map[string]any)["quota"])
		}
		status, _, body := f.request(t, "GET", fmt.Sprintf("/api/usage/token/stat?start_timestamp=%d&end_timestamp=%d", hour+36000, hour+40000), "A", "", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, []any{}, body["data"], "missing hours are not fabricated as zero buckets")
		assert.Equal(t, false, body["data_complete"])
	})
	t.Run("query_validation", func(t *testing.T) {
		for _, path := range []string{"logs", "stat"} {
			for _, query := range []string{
				"start_timestamp=", "end_timestamp=bad", "start_timestamp=-1", "end_timestamp=9223372036854775808",
				"start_timestamp=01", "end_timestamp=%2B1", "start_timestamp=1&start_timestamp=2", "end_timestamp=1&end_timestamp=1",
				"user_id=1", "token_id=1", "unknown=1", "start_timestamp=%zz", "a=1;b=2",
			} {
				status, _, body := f.request(t, "GET", "/api/usage/token/"+path+"?"+query, "A", "", nil)
				require.Equal(t, http.StatusBadRequest, status, "%s %s", path, query)
				assert.Equal(t, "TOKEN_USAGE_QUERY_INVALID", body["code"])
			}
			status, _, body := f.request(t, "GET", "/api/usage/token/"+path+"?start_timestamp=2&end_timestamp=1", "A", "", nil)
			require.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "TOKEN_USAGE_RANGE_INVALID", body["code"])
			status, _, body = f.request(t, "GET", "/api/usage/token/"+path+"?start_timestamp=0&end_timestamp=172801", "A", "", nil)
			require.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "LOG_RANGE_TOO_WIDE", body["code"])
			status, _, _ = f.request(t, "GET", "/api/usage/token/"+path+"?start_timestamp=0&end_timestamp=172800", "A", "", nil)
			assert.Equal(t, http.StatusOK, status, "exact range limit is accepted")
			status, _, body = f.request(t, "GET", fmt.Sprintf("/api/usage/token/%s?start_timestamp=%d", path, time.Now().Unix()+3600), "A", "", nil)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "TOKEN_USAGE_RANGE_INVALID", body["code"])
		}
		for _, query := range []string{"p=0", "p=-1", "page=bad", "p=", "p=100002", "page_size=0", "page_size=101", "p=1002&page_size=100", "p=2&p=2", "p=1&page=2&page=3", "page_size=1&page_size=2", "model_name=a&model_name=b", "model_name=" + strings.Repeat("a", 257)} {
			status, _, body := f.request(t, "GET", "/api/usage/token/logs?"+query, "A", "", nil)
			require.Equal(t, http.StatusBadRequest, status, query)
			assert.Equal(t, "TOKEN_USAGE_QUERY_INVALID", body["code"])
		}
		for _, query := range []string{"granularity=week", "granularity=", "granularity=hour&granularity=day", "p=1", "model_name=a"} {
			status, _, body := f.request(t, "GET", "/api/usage/token/stat?"+query, "A", "", nil)
			require.Equal(t, http.StatusBadRequest, status, query)
			assert.Equal(t, "TOKEN_USAGE_QUERY_INVALID", body["code"])
		}
	})
	t.Run("authentication_and_organization_boundary", func(t *testing.T) {
		for _, path := range []string{"logs", "stat"} {
			for _, actor := range []string{"", "sk-unknown", "owner"} {
				status, _, body := f.request(t, "GET", "/api/usage/token/"+path, actor, "", nil)
				assert.Equal(t, http.StatusUnauthorized, status)
				assert.Equal(t, false, body["success"])
			}
			for _, state := range []int{common.TokenStatusExpired, common.TokenStatusExhausted} {
				require.NoError(t, f.db.Model(tokens["A"]).Updates(map[string]any{"status": state, "expired_time": 1, "remain_quota": 0, "unlimited_quota": false}).Error)
				status, _, _ := f.request(t, "GET", "/api/usage/token/"+path+"?"+window, "A", "", nil)
				assert.Equal(t, http.StatusOK, status)
			}
			require.NoError(t, f.db.Model(tokens["A"]).Update("status", common.TokenStatusDisabled).Error)
			status, _, _ := f.request(t, "GET", "/api/usage/token/"+path, "A", "", nil)
			assert.Equal(t, http.StatusUnauthorized, status)
			require.NoError(t, f.db.Model(tokens["A"]).Updates(map[string]any{"status": common.TokenStatusEnabled, "allow_ips": "192.0.2.1"}).Error)
			status, _, _ = f.request(t, "GET", "/api/usage/token/"+path, "A", "", nil)
			assert.Equal(t, http.StatusForbidden, status)
			require.NoError(t, f.db.Model(tokens["A"]).Update("allow_ips", "").Error)
			status, _, body := f.request(t, "GET", "/api/usage/token/"+path+"?org_id=1", "A", "", nil)
			assert.Equal(t, http.StatusForbidden, status)
			assert.Equal(t, "ORG_RESOURCE_UNSUPPORTED", body["code"])
			status, _, body = f.request(t, "GET", "/api/usage/token/"+path, "A", "", http.Header{"X-Organization-Id": {"1"}})
			assert.Equal(t, http.StatusForbidden, status)
			assert.Equal(t, "ORG_RESOURCE_UNSUPPORTED", body["code"])
			status, _, _ = f.request(t, "GET", "/api/usage/token/"+path+"?org_id=0", "A", "", nil)
			assert.Equal(t, http.StatusOK, status)
			require.NoError(t, f.db.Model(f.users["owner"]).Update("status", common.UserStatusDisabled).Error)
			status, _, _ = f.request(t, "GET", "/api/usage/token/"+path, "A", "", nil)
			assert.Equal(t, http.StatusForbidden, status)
			require.NoError(t, f.db.Model(f.users["owner"]).Update("status", common.UserStatusEnabled).Error)
		}
	})
	t.Run("collection_switches_preserve_legacy_history", func(t *testing.T) {
		common.DataExportEnabled = false
		status, _, _ := f.request(t, "GET", "/api/usage/token/logs?"+window, "A", "", nil)
		assert.Equal(t, http.StatusOK, status, "logs do not depend on the dashboard export switch")
		status, _, body := f.request(t, "GET", "/api/usage/token/stat?"+window, "A", "", nil)
		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, "TOKEN_USAGE_STAT_UNAVAILABLE", body["code"])
		status, _, body = f.request(t, "GET", "/api/data/self?"+window, "owner", "", nil)
		require.Equal(t, http.StatusOK, status)
		assert.NotEmpty(t, body["data"], "turning off collection must not hide existing legacy user history")
		common.DataExportEnabled, common.LogConsumeEnabled = true, false
		for _, path := range []string{"logs", "stat"} {
			status, _, body := f.request(t, "GET", "/api/usage/token/"+path+"?"+window, "A", "", nil)
			assert.Equal(t, http.StatusServiceUnavailable, status)
			assert.Equal(t, false, body["success"])
			assert.NotContains(t, body, "data")
		}
		common.LogConsumeEnabled = true
	})
	t.Run("complete_single_authorization", func(t *testing.T) {
		valid := "Bearer " + f.bearer["A"]
		for _, path := range []string{"logs", "stat"} {
			for _, tc := range []struct {
				name    string
				headers http.Header
			}{
				{"numeric_suffix", http.Header{"Authorization": {valid + "-999"}}},
				{"opaque_suffix", http.Header{"Authorization": {valid + "-arbitrary"}}},
				{"empty_suffix", http.Header{"Authorization": {valid + "-"}}},
				{"multiple_suffixes", http.Header{"Authorization": {valid + "--other-999"}}},
				{"appended_characters", http.Header{"Authorization": {valid + "xyz"}}},
				{"duplicate_same", http.Header{"Authorization": {valid, valid}}},
				{"duplicate_empty_last", http.Header{"Authorization": {valid, ""}}},
				{"duplicate_empty_first", http.Header{"Authorization": {"", valid}}},
				{"duplicate_case", http.Header{"Authorization": {valid}, "authorization": {valid}}},
				{"comma_values", http.Header{"Authorization": {valid + ", " + valid}}},
				{"comma_suffix", http.Header{"Authorization": {valid + "-999," + valid}}},
				{"extra_space", http.Header{"Authorization": {"Bearer  " + f.bearer["A"]}}},
				{"trailing_non_ascii_space", http.Header{"Authorization": {valid + "\u00a0"}}},
				{"no_scheme", http.Header{"Authorization": {f.bearer["A"]}}},
				{"wrong_scheme", http.Header{"Authorization": {"Basic " + f.bearer["A"]}}},
				{"extra_token", http.Header{"Authorization": {valid + " extra"}}},
			} {
				t.Run(path+"/"+tc.name, func(t *testing.T) {
					status, headers, body := f.request(t, "GET", "/api/usage/token/"+path+"?"+window, "", "", tc.headers)
					assert.Equal(t, http.StatusUnauthorized, status)
					assert.Contains(t, headers.Get("Cache-Control"), "no-store")
					assert.Equal(t, false, body["success"])
					assert.NotContains(t, body, "data")
				})
			}
			for _, authorization := range []string{valid, "bearer " + f.bearer["A"], "bEaReR " + f.bearer["A"], "Bearer " + tokens["A"].Key} {
				status, _, _ := f.request(t, "GET", "/api/usage/token/"+path+"?"+window, "", "", http.Header{"Authorization": {authorization}})
				assert.Equal(t, http.StatusOK, status, "single complete credential")
			}
		}
		// Exercise a mixed-case key against case-insensitive SQL collations too.
		caseToken := &model.Token{UserId: tokens["A"].UserId, Key: "UsageCaseSensitiveKey0000000000000000000001", Status: common.TokenStatusEnabled, ExpiredTime: -1}
		require.NoError(t, f.db.Create(caseToken).Error)
		for _, path := range []string{"logs", "stat"} {
			status, _, _ := f.request(t, "GET", "/api/usage/token/"+path, "", "", http.Header{"Authorization": {"Bearer sk-" + strings.ToLower(caseToken.Key)}})
			assert.Equal(t, http.StatusUnauthorized, status, "credential bytes must match even on case-insensitive storage")
		}
		legacy := gin.New()
		legacy.GET("/legacy", middleware.TokenAuthReadOnly(), func(c *gin.Context) {
			_, _, authenticated := middleware.GetReadOnlyToken(c)
			c.JSON(http.StatusOK, gin.H{"authenticated": authenticated})
		})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/legacy", nil)
		request.Header.Set("Authorization", valid+"-999")
		legacy.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusOK, recorder.Code, "old middleware keeps its legacy suffix semantics")
	})
	t.Run("localized_usage_errors", func(t *testing.T) {
		for _, tc := range []struct {
			path, code, en, zh, tw string
			status                 int
		}{
			{"logs?p=0", "TOKEN_USAGE_QUERY_INVALID", "Invalid token usage query.", "令牌用量查询参数无效", "令牌用量查詢參數無效", http.StatusBadRequest},
			{"stat?granularity=week", "TOKEN_USAGE_QUERY_INVALID", "Invalid token usage query.", "令牌用量查询参数无效", "令牌用量查詢參數無效", http.StatusBadRequest},
			{"stat?start_timestamp=2&end_timestamp=1", "TOKEN_USAGE_RANGE_INVALID", "Invalid token usage time range.", "令牌用量时间范围无效", "令牌用量時間範圍無效", http.StatusBadRequest},
			{"logs?start_timestamp=0&end_timestamp=172801", "LOG_RANGE_TOO_WIDE", "The time range cannot exceed 2 days", "时间范围不能超过 2 天", "時間範圍不能超過 2 天", http.StatusBadRequest},
		} {
			for _, language := range []struct{ tag, message string }{{"en", tc.en}, {"zh-CN", tc.zh}, {"zh-TW", tc.tw}} {
				status, _, body := f.request(t, "GET", "/api/usage/token/"+tc.path, "A", "", http.Header{"Accept-Language": {language.tag}})
				assert.Equal(t, tc.status, status)
				assert.Equal(t, tc.code, body["code"])
				assert.Equal(t, language.message, body["message"])
			}
		}
		common.LogConsumeEnabled = false
		defer func() { common.LogConsumeEnabled = true }()
		for _, tc := range []struct{ path, code, en, zh, tw string }{
			{"logs", "TOKEN_USAGE_LOGS_DISABLED", "Token usage log collection is disabled.", "令牌用量日志采集已关闭", "令牌用量日誌收集已關閉"},
			{"stat", "TOKEN_USAGE_STAT_UNAVAILABLE", "Token usage statistics are unavailable.", "令牌用量统计暂不可用", "令牌用量統計暫不可用"},
		} {
			for _, language := range []struct{ tag, message string }{{"en", tc.en}, {"zh-CN", tc.zh}, {"zh-TW", tc.tw}} {
				status, _, body := f.request(t, "GET", "/api/usage/token/"+tc.path, "A", "", http.Header{"Accept-Language": {language.tag}})
				assert.Equal(t, http.StatusServiceUnavailable, status)
				assert.Equal(t, tc.code, body["code"])
				assert.Equal(t, language.message, body["message"])
			}
		}
	})
	t.Run("trusted_snapshot_required", func(t *testing.T) {
		for _, handler := range []gin.HandlerFunc{controller.GetTokenUsageLogs, controller.GetTokenUsageStat} {
			router := gin.New()
			router.GET("/usage", func(c *gin.Context) {
				c.Set("id", tokens["A"].UserId)
				c.Set("token_id", tokens["A"].Id)
				c.Set("token_key", tokens["A"].Key)
			}, handler)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest("GET", "/usage", nil))
			assert.Equal(t, http.StatusUnauthorized, recorder.Code, "loose context keys cannot replace a validated read-only snapshot")
			for _, field := range []string{"id", "token_id", "token_key"} {
				router := gin.New()
				router.GET("/usage", middleware.TokenUsageCredentialBoundary(), middleware.TokenAuthReadOnly(), func(c *gin.Context) {
					if field == "token_key" {
						c.Set(field, tokens["B"].Key)
					} else {
						c.Set(field, -1)
					}
				}, handler)
				recorder := httptest.NewRecorder()
				request := httptest.NewRequest("GET", "/usage", nil)
				request.Header.Set("Authorization", "Bearer "+f.bearer["A"])
				router.ServeHTTP(recorder, request)
				assert.Equal(t, http.StatusUnauthorized, recorder.Code, "mismatched %s cannot replace trusted identity", field)
			}
		}
	})
	// Query parse failures and the public projection must never disclose seeded
	// metadata; raw credentials are also absent from server logs.
	assert.NotContains(t, f.logs.snapshot(), tokens["A"].Key)
}

// Pure numeric and transport regressions run without DB, issuer or socket I/O.
func TestOAuthUsageNamespacePrivacy(t *testing.T) {
	oldMaster := common.IsMasterNode
	common.IsMasterNode = false
	t.Cleanup(func() { common.IsMasterNode = oldMaster })
	t.Setenv("FRONTEND_BASE_URL", "https://frontend.invalid")
	require.Nil(t, service.CurrentOAuthUserInfoResource())
	var logs bytes.Buffer
	oldWriter := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() { gin.DefaultWriter = oldWriter })
	engine := gin.New()
	middleware.SetUpLogger(engine)
	SetRouter(engine, WebAssets{})
	for _, tc := range []struct {
		method, path, body string
		header             string
		status             int
	}{
		{"GET", "/api/v1/oauth/usage/logs", "", "", 401},
		{"GET", "/api/v1/oauth/usage/stat?granularity=day", "", "", 401},
		{"GET", "/api/v1/oauth/usage/logs?access_token=USAGE_QUERY_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/usage/logs?ORG_ID=0", "", "", 400},
		{"GET", "/api/v1/oauth/usage/stat?user_id=1", "", "", 400},
		{"GET", "/api/v1/oauth/usage/logs?x=%ZZ", "", "", 400},
		{"GET", "/api/v1/oauth/usage/logs/USAGE_PATH_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/usage/logs/", "", "", 400},
		{"GET", "/api/v1/oauth/%75sage/logs", "", "", 400},
		{"GET", "/api/v1/oauth/%2575sage/stat", "", "", 400},
		{"GET", "/api/v1/oauth/%252575sage/logs?access_token=USAGE_QUERY_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/%25252575sage/stat?access_token=USAGE_QUERY_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/%2575sage/logs%25ZZ?access_token=USAGE_QUERY_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/%252575sage/stat%25?access_token=USAGE_QUERY_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/%25%37%35sage/logs%25ZZ?access_token=USAGE_QUERY_CANARY", "", "", 400},
		{"GET", "/api/v1/oauth/%252%35%37%35sage/logs?access_token=USAGE_QUERY_CANARY", "", "", 400},
		{"GET", "/api//v1/oauth/usage/logs", "", "", 400},
		{"GET", "/API/V1/OAUTH/USAGE/LOGS", "", "", 400},
		{"GET", "/api/v1/oauth/usage", "", "", 400},
		{"POST", "/api/v1/oauth/usage/logs", "", "", 400},
		{"HEAD", "/api/v1/oauth/usage/stat", "", "", 400},
		{"GET", "/api/v1/oauth/usage/logs", "x", "", 400},
		{"GET", "/api/v1/oauth/usage/logs", "", "X-Organization-Id", 400},
		{"GET", "/api/v1/oauth/usage/stat", "", "X-HTTP-Method-Override", 400},
	} {
		t.Run(tc.method+tc.path+tc.header+tc.body, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.header != "" {
				req.Header[tc.header] = []string{""}
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			assert.Equal(t, tc.status, w.Code, w.Body.String())
			assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
			assert.Empty(t, w.Header().Get("Location"))
			assert.NotContains(t, w.Body.String(), "USAGE_")
		})
	}
	assert.NotContains(t, logs.String(), "USAGE_QUERY_CANARY")
	assert.NotContains(t, logs.String(), "USAGE_PATH_CANARY")
}

func TestOAuthUsagePureContracts(t *testing.T) {
	const safe = model.OAuthUsageMaxInteger
	for _, tc := range []struct {
		name        string
		hours       []model.TokenUsageBucket
		granularity string
		want        []model.TokenUsageBucket
		bad         bool
	}{
		{"empty", nil, "hour", []model.TokenUsageBucket{}, false},
		{"signed", []model.TokenUsageBucket{{TS: 0, Quota: -7, Requests: 1, Tokens: 3}}, "hour", []model.TokenUsageBucket{{TS: 0, Quota: -7, Requests: 1, Tokens: 3}}, false},
		{"utc_sparse", []model.TokenUsageBucket{{TS: 82800, Quota: 1}, {TS: 86400, Quota: 2}}, "day", []model.TokenUsageBucket{{TS: 0, Quota: 1}, {TS: 86400, Quota: 2}}, false},
		{"safe_max", []model.TokenUsageBucket{{TS: 0, Quota: safe}}, "day", []model.TokenUsageBucket{{TS: 0, Quota: safe}}, false},
		{"hour_unsafe", []model.TokenUsageBucket{{TS: 0, Tokens: safe + 1}}, "hour", nil, true},
		{"day_unsafe", []model.TokenUsageBucket{{TS: 0, Quota: safe}, {TS: 3600, Quota: 1}}, "day", nil, true},
		{"negative_unsafe", []model.TokenUsageBucket{{TS: 0, Requests: -safe}, {TS: 3600, Requests: -1}}, "day", nil, true},
		{"int64_max", []model.TokenUsageBucket{{TS: 0, Quota: math.MaxInt64}}, "hour", nil, true},
		{"int64_min", []model.TokenUsageBucket{{TS: 0, Quota: math.MinInt64}}, "hour", nil, true},
		{"prefix_cannot_cancel", []model.TokenUsageBucket{{TS: 0, Quota: safe}, {TS: 3600, Quota: 1}, {TS: 7200, Quota: -1}}, "day", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := model.FoldOAuthUsageHours(tc.hours, tc.granularity)
			if tc.bad {
				require.ErrorIs(t, err, model.ErrOAuthUsageNumeric)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
	for _, tc := range []struct {
		method, path, body string
		headers            map[string]string
		status             int
	}{
		{"GET", "/api/v1/oauth/usage/logs?org_id=0", "", nil, 400},
		{"GET", "/api/v1/oauth/usage/stat?user_id=1", "", nil, 400},
		{"GET", "/api/v1/oauth/usage/logs?ACCESS_TOKEN=secret", "", nil, 400},
		{"GET", "/api/v1/oauth/usage/logs", "", map[string]string{"X-Organization-Id": ""}, 400},
		{"GET", "/api/v1/oauth/usage/logs", "", map[string]string{"X-HTTP-Method-Override": "POST"}, 400},
		{"GET", "/api/v1/oauth/usage/logs", "x", nil, 400},
		{"POST", "/api/v1/oauth/usage/logs", "", nil, 400},
		{"GET", "/api/v1/oauth/usage/logs", "", nil, 401},
	} {
		engine := gin.New()
		engine.Use(func(c *gin.Context) { c.Set("id", 1); c.Set("role", common.RoleRootUser); c.Next() })
		engine.Any("/api/v1/oauth/usage/logs", controller.GetOAuthUsageLogs)
		engine.Any("/api/v1/oauth/usage/stat", controller.GetOAuthUsageStat)
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		for k, v := range tc.headers {
			req.Header[k] = []string{v}
		}
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		assert.Equal(t, tc.status, w.Code, tc.path)
		assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
		assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
		assert.Empty(t, w.Header().Get("Location"))
	}
}

// The resource is served through the formal OAuth router; only the issuer's TLS
// introspection response is synthetic. Local authority and usage reads use DBs.
func TestOAuthUsageConsumerHTTP(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	if model.LOG_DB == f.db {
		logDB, _ := organizationTestDB(t, f.mainKind, os.Getenv("NEWAPI_S2_MAIN_DSN"))
		require.NoError(t, logDB.AutoMigrate(&model.Log{}))
		model.LOG_DB = logDB
	}
	combinedFixtureDatabase(t, "main", f.db)
	combinedFixtureDatabase(t, "log", model.LOG_DB)
	require.NotSame(t, f.db, model.LOG_DB, "usage history must read its independently configured log database")
	require.NoError(t, f.db.AutoMigrate(&model.QuotaData{}))
	common.IsMasterNode = true
	require.NoError(t, model.InitOAuthGrantStore(true))
	common.IsMasterNode = false
	oldLog, oldExport, oldUnit := common.LogConsumeEnabled, common.DataExportEnabled, common.QuotaPerUnit
	common.LogConsumeEnabled, common.DataExportEnabled, common.QuotaPerUnit = true, true, 500000
	t.Cleanup(func() {
		common.LogConsumeEnabled, common.DataExportEnabled, common.QuotaPerUnit = oldLog, oldExport, oldUnit
	})
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	const issuer = "https://gateway.example/"
	grant := &model.OAuthGrant{GrantID: base64.RawURLEncoding.EncodeToString(b), Issuer: issuer, ClientID: "usage-client", Subject: strconv.Itoa(f.users["owner"].Id), UserID: f.users["owner"].Id, ConsentRequestID: "usage-consent", HydraLoginSessionID: "usage-login", OriginSID: f.sids["owner"], SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile","usage:read"]`, PolicyHash: strings.Repeat("a", 64)}
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
	require.NoError(t, model.ApproveOAuthGrant(t.Context(), grant))
	_, err = model.AuthorizeOAuthGrant(t.Context(), model.OAuthGrantAuthorization{Issuer: issuer, GrantID: grant.GrantID, ClientID: grant.ClientID, Subject: grant.Subject, UserID: grant.UserID, AuthVersion: 1, GrantExpiresAt: grant.ExpiresAt, TokenExpiresAt: time.Now().Unix() + 600, Scopes: []string{"profile", "usage:read"}, Activate: true})
	require.NoError(t, err)
	var calls atomic.Int32
	var change func()
	scope := "profile usage:read"
	expires := time.Now().Unix() + 600
	var notBefore int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 2 && change != nil {
			change()
		}
		data, e := common.Marshal(map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": issuer, "aud": []string{"userinfo"}, "client_id": grant.ClientID, "sub": grant.Subject, "exp": expires, "nbf": notBefore, "scope": scope, "ext": map[string]any{"newapi_auth_version": "1", "newapi_grant_id": grant.GrantID, "newapi_grant_expires_at": strconv.FormatInt(grant.ExpiresAt, 10)}})
		if e != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: server.URL + "/admin/oauth2/introspect", Issuer: issuer, Audience: "userinfo", ClientIDs: []string{grant.ClientID}}, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{Enabled: true, RevocationEnabled: true, AdminBaseURL: server.URL, AuthorizationURL: issuer + "oauth2/auth"}, resource)
	require.NoError(t, err)
	_, err = service.NewOAuthPublic(service.OAuthPublicConfig{Enabled: true, BaseURL: "https://hydra-private.example"}, bridge)
	require.NoError(t, err)
	engine := gin.New()
	engine.Use(middleware.OAuthUsageBoundary)
	SetOAuthResourceRouter(engine, resource)
	base := time.Now().UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour).Unix()
	for _, row := range []model.Log{{UserId: grant.UserID, TokenId: 0, CreatedAt: base, Type: model.LogTypeConsume, ModelName: "zero", Quota: 3}, {UserId: grant.UserID, TokenId: 987654, CreatedAt: base, Type: model.LogTypeConsume, ModelName: "deleted", Quota: 5}, {UserId: f.users["foreign"].Id, CreatedAt: base, Type: model.LogTypeConsume, ModelName: "foreign", Quota: 999}} {
		row.Ip = "203.0.113.1"
		row.Other = `{"secret":"private"}`
		require.NoError(t, model.LOG_DB.Create(&row).Error)
	}
	request := func(path string) *httptest.ResponseRecorder {
		calls.Store(0)
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer synthetic-usage-token")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}
	logs := fmt.Sprintf("/api/v1/oauth/usage/logs?start_timestamp=%d&end_timestamp=%d", base, base+7200)
	stat := fmt.Sprintf("/api/v1/oauth/usage/stat?start_timestamp=%d&end_timestamp=%d&granularity=day", base, base+7200)
	t.Run("subject_history_and_projection", func(t *testing.T) {
		w := request(logs)
		require.Equal(t, 200, w.Code, w.Body.String())
		var body map[string]any
		require.NoError(t, common.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, false, body["data_complete"])
		data := body["data"].(map[string]any)
		assert.Equal(t, float64(2), data["total"])
		for _, item := range data["items"].([]any) {
			assert.Len(t, item.(map[string]any), 8)
		}
		assert.NotContains(t, w.Body.String(), "foreign")
		assert.NotContains(t, w.Body.String(), "private")
		assert.NotContains(t, w.Body.String(), "203.0.113")
	})
	t.Run("missing_scope", func(t *testing.T) {
		scope = "profile"
		require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("scopes", `["profile"]`).Error)
		defer func() {
			scope = "profile usage:read"
			require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("scopes", `["profile","usage:read"]`).Error)
		}()
		w := request(logs)
		assert.Equal(t, 403, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), `scope="usage:read"`)
	})
	t.Run("expired", func(t *testing.T) {
		expires = time.Now().Unix() - 1
		defer func() { expires = time.Now().Unix() + 600 }()
		assert.Equal(t, 401, request(logs).Code)
	})
	t.Run("final_guard", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			table     any
			where     string
			id        any
			column    string
			bad, good any
		}{{"grant", &model.OAuthGrant{}, "grant_ref = ?", grant.GrantRef, "state", "revoked", "active"}, {"revision", &model.OAuthGrant{}, "grant_ref = ?", grant.GrantRef, "revision", 4, 3}, {"source_sid", &model.UserSession{}, "sid = ?", grant.OriginSID, "revoked_at", 1, 0}, {"auth_version", &model.User{}, "id = ?", grant.UserID, "auth_version", 2, 1}, {"scope_changed", &model.OAuthGrant{}, "grant_ref = ?", grant.GrantRef, "scopes", `["profile"]`, `["profile","usage:read"]`}, {"disabled", &model.User{}, "id = ?", grant.UserID, "status", 2, common.UserStatusEnabled}} {
			t.Run(tc.name, func(t *testing.T) {
				var mutationErr error
				change = func() {
					mutationErr = f.db.Model(tc.table).Where(tc.where, tc.id).UpdateColumn(tc.column, tc.bad).Error
				}
				for _, path := range []string{logs, stat} {
					w := request(path)
					require.NoError(t, mutationErr)
					require.NoError(t, f.db.Model(tc.table).Where(tc.where, tc.id).UpdateColumn(tc.column, tc.good).Error)
					assert.Equal(t, 401, w.Code)
					assert.NotContains(t, w.Body.String(), `"data":`)
				}
				change = nil
			})
		}
	})

	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		t.Run("clickhouse_owned_storage_and_read_guard_schema", func(t *testing.T) {
			// organizationTestDB created this random DB with collision-failing CREATE
			// and registered DROP only after success. No existing business table is used.
			dsn := os.Getenv("LOG_SQL_DSN")
			require.NoError(t, organizationFixtureDSN("clickhouse", dsn, os.Getenv("NEWAPI_S2_CLICKHOUSE_PORT")))
			parsed, err := url.Parse(dsn)
			require.NoError(t, err)
			var database string
			require.NoError(t, model.LOG_DB.Raw("SELECT currentDatabase()").Scan(&database).Error)
			require.Regexp(t, `^newapi_s2_[a-z0-9]+$`, database)
			require.Equal(t, "/"+database, parsed.Path)
			t.Logf("exclusive ClickHouse fixture verified: database=%s", database)
			var columns []struct {
				Name string
				Type string
			}
			require.NoError(t, model.LOG_DB.Raw("SELECT name, type FROM system.columns WHERE database = currentDatabase() AND table = 'logs' AND name IN ('quota','prompt_tokens','completion_tokens','use_time') ORDER BY name").Scan(&columns).Error)
			require.Len(t, columns, 4)
			for _, column := range columns {
				assert.Equal(t, "Int32", column.Type)
				t.Logf("production-schema column=%s type=%s", column.Name, column.Type)
			}
			for _, value := range []int64{math.MaxInt32, math.MinInt32} {
				row := model.Log{UserId: grant.UserID, CreatedAt: base + 1, Type: model.LogTypeConsume, ModelName: "ch-int32", Quota: int(value)}
				require.NoError(t, model.LOG_DB.Create(&row).Error)
				var stored int64
				require.NoError(t, model.LOG_DB.Model(&model.Log{}).Select("quota").Where("model_name = ?", row.ModelName).Scan(&stored).Error)
				assert.Equal(t, value, stored)
				w := request(logs + "&model_name=ch-int32")
				assert.Equal(t, 200, w.Code, w.Body.String())
				assert.Contains(t, w.Body.String(), strconv.FormatInt(value, 10))
				require.NoError(t, model.LOG_DB.Exec("ALTER TABLE logs DELETE WHERE model_name = ? SETTINGS mutations_sync = 2", row.ModelName).Error)
			}
			// Int32 cannot represent JS-unsafe integers. This test-only widening
			// exercises the reader guard on retained Int64 values, not migrations.
			for _, column := range []string{"quota", "prompt_tokens", "completion_tokens", "use_time"} {
				sql := "ALTER TABLE logs MODIFY COLUMN " + column + " Int64"
				t.Logf("private test-only schema SQL: %s", sql)
				require.NoError(t, model.LOG_DB.Exec(sql).Error)
			}
		})
	}
	t.Run("log_overflow", func(t *testing.T) {
		row := model.Log{UserId: grant.UserID, CreatedAt: base + 1, Type: model.LogTypeConsume, ModelName: "oauth-unsafe", Quota: int(model.OAuthUsageMaxInteger + 1)}
		require.NoError(t, model.LOG_DB.Create(&row).Error)
		var stored int64
		require.NoError(t, model.LOG_DB.Model(&model.Log{}).Select("quota").Where("user_id = ? AND model_name = ?", grant.UserID, row.ModelName).Scan(&stored).Error)
		require.Equal(t, int64(row.Quota), stored, "unsafe integer must survive storage before testing the read guard")
		assert.Equal(t, 500, request(logs).Code)
		if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
			require.NoError(t, model.LOG_DB.Exec("ALTER TABLE logs DELETE WHERE model_name = ? SETTINGS mutations_sync = 2", row.ModelName).Error)
		} else {
			require.NoError(t, model.LOG_DB.Where("user_id = ? AND model_name = ?", grant.UserID, row.ModelName).Delete(&model.Log{}).Error)
		}
	})
	t.Run("hours_and_daily_overflow", func(t *testing.T) {
		require.NoError(t, f.db.Create(&model.QuotaData{UserID: grant.UserID, CreatedAt: base, Quota: int(model.OAuthUsageMaxInteger), Count: 1}).Error)
		require.NoError(t, f.db.Create(&model.QuotaData{UserID: grant.UserID, CreatedAt: base + 3600, Quota: 1, Count: 1}).Error)
		assert.Equal(t, 500, request(stat).Code)
		require.NoError(t, f.db.Where("user_id = ?", grant.UserID).Delete(&model.QuotaData{}).Error)
	})
	t.Run("collection_matrix", func(t *testing.T) {
		for _, enabled := range []bool{false, true} {
			for _, export := range []bool{false, true} {
				common.LogConsumeEnabled, common.DataExportEnabled = enabled, export
				for _, path := range []string{logs, stat} {
					want, code := 200, ""
					if !enabled {
						want, code = 503, "USAGE_LOGS_DISABLED"
					}
					if path == stat && (!enabled || !export) {
						want, code = 503, "USAGE_STAT_UNAVAILABLE"
					}
					w := request(path)
					assert.Equal(t, want, w.Code, "consume=%v export=%v path=%s", enabled, export, path)
					if code != "" {
						assert.Contains(t, w.Body.String(), code)
						assert.NotContains(t, w.Body.String(), `"data":`)
					}
				}
			}
		}
		common.LogConsumeEnabled, common.DataExportEnabled = true, true
	})
	t.Run("subject_root_and_sparse_projection", func(t *testing.T) {
		original := grant
		defer func() { grant = original }()
		for _, actor := range []string{"owner", "foreign", "root"} {
			user := f.users[actor]
			if actor != "owner" {
				b := make([]byte, 32)
				_, err := rand.Read(b)
				require.NoError(t, err)
				grant = &model.OAuthGrant{GrantID: base64.RawURLEncoding.EncodeToString(b), Issuer: issuer, ClientID: "usage-client", Subject: strconv.Itoa(user.Id), UserID: user.Id, ConsentRequestID: "usage-" + actor, HydraLoginSessionID: "usage-" + actor, OriginSID: f.sids[actor], SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile","usage:read"]`, PolicyHash: strings.Repeat("a", 64)}
				require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error { return model.CreateOAuthGrantWithTx(tx, grant) }))
				require.NoError(t, model.ApproveOAuthGrant(t.Context(), grant))
				_, err = model.AuthorizeOAuthGrant(t.Context(), model.OAuthGrantAuthorization{Issuer: issuer, GrantID: grant.GrantID, ClientID: grant.ClientID, Subject: grant.Subject, UserID: grant.UserID, AuthVersion: 1, GrantExpiresAt: grant.ExpiresAt, TokenExpiresAt: expires, Scopes: []string{"profile", "usage:read"}, Activate: true})
				require.NoError(t, err)
			}
			w := request(logs)
			require.Equal(t, 200, w.Code, w.Body.String())
			var body map[string]any
			require.NoError(t, common.Unmarshal(w.Body.Bytes(), &body))
			want := map[string]float64{"owner": 2, "foreign": 1, "root": 0}[actor]
			assert.Equal(t, want, body["data"].(map[string]any)["total"], actor)
			if actor == "root" {
				assert.Equal(t, []any{}, body["data"].(map[string]any)["items"])
			}
			quota := map[string]int{"owner": -3, "foreign": 999, "root": 7}[actor]
			require.NoError(t, f.db.Create(&model.QuotaData{UserID: user.Id, TokenID: 0, CreatedAt: base, Quota: quota, Count: 1, TokenUsed: 2}).Error)
			require.NoError(t, f.db.Create(&model.QuotaData{UserID: user.Id, TokenID: 987654, CreatedAt: base, Quota: 5, Count: 2, TokenUsed: 3}).Error)
			w = request(stat)
			require.Equal(t, 200, w.Code, w.Body.String())
			require.NoError(t, common.Unmarshal(w.Body.Bytes(), &body))
			buckets := body["data"].([]any)
			require.Len(t, buckets, 1)
			item := buckets[0].(map[string]any)
			assert.ElementsMatch(t, []string{"ts", "quota", "requests", "tokens"}, slices.Collect(maps.Keys(item)))
			assert.Equal(t, float64(quota+5), item["quota"])
			assert.Equal(t, float64(3), item["requests"])
			assert.Equal(t, float64(5), item["tokens"])
			require.NoError(t, f.db.Where("user_id = ?", user.Id).Delete(&model.QuotaData{}).Error)
			w = request(stat)
			require.Equal(t, 200, w.Code)
			require.NoError(t, common.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, []any{}, body["data"])
		}
	})
	t.Run("numeric_sql_boundaries", func(t *testing.T) {
		const safe = model.OAuthUsageMaxInteger
		for _, tc := range []struct {
			name                string
			values              []int64
			column, granularity string
			want                int
		}{
			{"safe_max", []int64{safe}, "quota", "day", 200},
			{"negative_safe", []int64{-safe}, "quota", "day", 200},
			{"hour_max_plus_one", []int64{safe, 1}, "quota", "hour", 500},
			{"sql_int64_sum_overflow", []int64{math.MaxInt64, 1}, "quota", "hour", 500},
			{"sql_int64_sum_underflow", []int64{math.MinInt64, -1}, "quota", "hour", 500},
			{"requests_max_plus_one", []int64{safe, 1}, "count", "hour", 500},
			{"tokens_max_plus_one", []int64{safe, 1}, "token_used", "hour", 500},
			{"daily_prefix_cannot_cancel", []int64{safe, 1, -1}, "quota", "day", 500},
			{"negative_daily_prefix_cannot_cancel", []int64{-safe, -1, 1}, "quota", "day", 500},
		} {
			t.Run(tc.name, func(t *testing.T) {
				for i, value := range tc.values {
					ts := base
					if strings.Contains(tc.name, "daily_prefix") {
						ts += int64(i) * 3600
					}
					row := model.QuotaData{UserID: grant.UserID, CreatedAt: ts, ModelName: fmt.Sprint(i)}
					require.NoError(t, f.db.Create(&row).Error)
					require.NoError(t, f.db.Model(&row).UpdateColumn(tc.column, value).Error)
				}
				w := request(strings.Replace(stat, "granularity=day", "granularity="+tc.granularity, 1))
				assert.Equal(t, tc.want, w.Code, w.Body.String())
				if tc.want == 500 {
					assert.NotContains(t, w.Body.String(), `"data":`)
				} else {
					assert.Contains(t, w.Body.String(), strconv.FormatInt(tc.values[0], 10))
				}
				require.NoError(t, f.db.Where("user_id = ?", grant.UserID).Delete(&model.QuotaData{}).Error)
			})
		}
		for _, value := range []int64{safe, -safe} {
			row := model.Log{UserId: grant.UserID, CreatedAt: base + 1, Type: model.LogTypeConsume, ModelName: "oauth-safe", Quota: int(value)}
			require.NoError(t, model.LOG_DB.Create(&row).Error)
			w := request(logs)
			assert.Equal(t, 200, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), strconv.FormatInt(value, 10))
			if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
				require.NoError(t, model.LOG_DB.Exec("ALTER TABLE logs DELETE WHERE model_name = ? SETTINGS mutations_sync = 2", row.ModelName).Error)
			} else {
				require.NoError(t, model.LOG_DB.Where("user_id = ? AND model_name = ?", grant.UserID, row.ModelName).Delete(&model.Log{}).Error)
			}
		}
	})
	t.Run("final_fence_and_temporal_guards", func(t *testing.T) {
		for _, path := range []string{logs, stat} {
			for _, scenario := range []string{"cleanup_fence", "source_session_expiry", "token_expiry", "not_before", "full_scope_change"} {
				t.Run(fmt.Sprintf("%s/%s", strings.Split(path, "?")[0], scenario), func(t *testing.T) {
					var mutationErr error
					change = func() {
						switch scenario {
						case "cleanup_fence":
							mutationErr = f.db.Create(&model.OAuthCleanupJob{JobRef: strings.Repeat("b", 64), Issuer: issuer, UserID: grant.UserID, Subject: grant.Subject, Scope: "grant", Value: grant.GrantRef, Targets: "[]", Reason: "test", State: "pending"}).Error
						case "source_session_expiry":
							mutationErr = f.db.Model(&model.UserSession{}).Where("sid = ?", grant.OriginSID).UpdateColumn("expires_at", time.Now().Unix()-1).Error
						case "token_expiry":
							expires = time.Now().Unix() - 1
						case "not_before":
							notBefore = time.Now().Unix() + 3600
						case "full_scope_change":
							scope = "profile email usage:read"
							mutationErr = f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("scopes", `["profile","email","usage:read"]`).Error
						}
					}
					w := request(path)
					change = nil
					require.NoError(t, mutationErr)
					want := 401
					if scenario == "cleanup_fence" {
						want = 503
					}
					assert.Equal(t, want, w.Code, w.Body.String())
					assert.NotContains(t, w.Body.String(), `"data":`)
					require.NoError(t, f.db.Where("job_ref = ?", strings.Repeat("b", 64)).Delete(&model.OAuthCleanupJob{}).Error)
					require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", grant.OriginSID).UpdateColumn("expires_at", grant.ExpiresAt).Error)
					expires, notBefore, scope = time.Now().Unix()+600, 0, "profile usage:read"
					require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("scopes", `["profile","usage:read"]`).Error)
				})
			}
		}
	})
	t.Run("query_completion_revocation", func(t *testing.T) {
		for _, path := range []string{logs, stat} {
			conn, table := model.LOG_DB, "logs"
			if path == stat {
				conn, table = f.db, "quota_data"
			}
			fired := false
			var mutationErr error
			name := "oauth_usage_query_completion"
			require.NoError(t, conn.Callback().Row().After("gorm:row").Register(name, func(tx *gorm.DB) {
				if !fired && tx.Statement.Table == table {
					fired = true
					mutationErr = f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("state", "revoked").Error
				}
			}))
			w := request(path)
			require.NoError(t, conn.Callback().Row().Remove(name))
			require.True(t, fired, "real usage query barrier must execute")
			require.NoError(t, mutationErr)
			assert.Equal(t, 401, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), `"data":`)
			require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("state", "active").Error)
		}
	})
	t.Run("real_commit_deadline", func(t *testing.T) {
		var savedSession model.UserSession
		require.NoError(t, f.db.Where("sid = ?", grant.OriginSID).First(&savedSession).Error)
		var savedGrant model.OAuthGrant
		require.NoError(t, f.db.Where("grant_ref = ?", grant.GrantRef).First(&savedGrant).Error)
		sqlDB, err := f.db.DB()
		require.NoError(t, err)
		for _, deadline := range []string{"token", "grant", "session"} {
			t.Run(deadline, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					now := time.Now().Unix()
					tokenExpiry, grantExpiry, sessionExpiry := now+60, now+60, now+60
					switch deadline {
					case "token":
						tokenExpiry = now + 1
					case "grant":
						grantExpiry = now + 1
					case "session":
						sessionExpiry = now + 1
						grantExpiry = sessionExpiry
					}
					require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", grant.OriginSID).UpdateColumn("expires_at", sessionExpiry).Error)
					require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("expires_at", grantExpiry).Error)
					db := f.db.Session(&gorm.Session{NewDB: true}).WithContext(context.Background())
					db.Statement.ConnPool = &oauthCommitDelayPool{DB: sqlDB}
					model.DB = db
					require.NoError(t, model.InitOAuthCleanupStore(true))
					_, authorizeErr := model.AuthorizeOAuthGrant(context.Background(), model.OAuthGrantAuthorization{Issuer: issuer, GrantID: grant.GrantID, ClientID: grant.ClientID, Subject: grant.Subject, UserID: grant.UserID, AuthVersion: 1, GrantExpiresAt: grantExpiry, TokenExpiresAt: tokenExpiry, Scopes: []string{"profile", "usage:read"}})
					model.DB = f.db
					require.NoError(t, model.InitOAuthCleanupStore(true))
					require.ErrorIs(t, authorizeErr, model.ErrOAuthGrantInvalid)
				})
			})
		}
		require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", grant.OriginSID).UpdateColumn("expires_at", savedSession.ExpiresAt).Error)
		require.NoError(t, f.db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).UpdateColumn("expires_at", savedGrant.ExpiresAt).Error)
	})
	t.Run("read_failure", func(t *testing.T) {
		name := "usage_read_fault"
		require.NoError(t, model.LOG_DB.Callback().Row().Before("gorm:row").Register(name, func(tx *gorm.DB) {
			if tx.Statement.Table == "logs" {
				tx.AddError(fmt.Errorf("private diagnostic"))
			}
		}))
		w := request(logs)
		require.NoError(t, model.LOG_DB.Callback().Row().Remove(name))
		assert.Equal(t, 500, w.Code)
		assert.NotContains(t, w.Body.String(), "diagnostic")
	})
}

// Numeric publication is checked after real storage and through the formal
// sk-key route. This is read-only reporting, not quota settlement.
func TestTokenUsageNumericHTTP(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.QuotaData{}))
	oldExport, oldConsume := common.DataExportEnabled, common.LogConsumeEnabled
	common.DataExportEnabled, common.LogConsumeEnabled = true, true
	t.Cleanup(func() { common.DataExportEnabled, common.LogConsumeEnabled = oldExport, oldConsume })
	key, err := common.GenerateRandomCharsKey(40)
	require.NoError(t, err)
	token := model.Token{UserId: f.users["owner"].Id, Key: key, Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true}
	require.NoError(t, f.db.Create(&token).Error)
	f.bearer["numeric"] = "sk-" + key
	base := time.Now().UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour).Unix()
	window := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", base, base+3*3600)
	const safe = model.OAuthUsageMaxInteger

	t.Run("stat", func(t *testing.T) {
		for _, tc := range []struct {
			name, column, granularity string
			values                    []int64
			separateHours             bool
			want                      int
		}{
			{"safe_max", "quota", "hour", []int64{safe}, false, 200},
			{"negative_safe", "quota", "day", []int64{-safe}, false, 200},
			{"zero", "quota", "day", []int64{0}, false, 200},
			{"hour_max_plus_one", "quota", "hour", []int64{safe, 1}, false, 500},
			{"hour_negative_unsafe", "quota", "hour", []int64{-safe, -1}, false, 500},
			{"requests_unsafe", "count", "hour", []int64{safe, 1}, false, 500},
			{"tokens_unsafe", "token_used", "hour", []int64{safe, 1}, false, 500},
			{"day_prefix_cannot_cancel", "quota", "day", []int64{safe, 1, -1}, true, 500},
			{"negative_day_prefix_cannot_cancel", "quota", "day", []int64{-safe, -1, 1}, true, 500},
			{"sql_sum_overflow", "quota", "hour", []int64{math.MaxInt64, 1}, false, 500},
			{"sql_sum_underflow", "quota", "hour", []int64{math.MinInt64, -1}, false, 500},
		} {
			t.Run(tc.name, func(t *testing.T) {
				for i, value := range tc.values {
					ts := base
					if tc.separateHours {
						ts += int64(i) * 3600
					}
					row := model.QuotaData{UserID: token.UserId, TokenID: token.Id, CreatedAt: ts, ModelName: fmt.Sprint(i)}
					require.NoError(t, f.db.Create(&row).Error)
					require.NoError(t, f.db.Model(&row).UpdateColumn(tc.column, value).Error)
					var stored int64
					require.NoError(t, f.db.Model(&row).Select(tc.column).Scan(&stored).Error)
					require.Equal(t, value, stored)
				}
				status, _, body := f.request(t, "GET", "/api/usage/token/stat?"+window+"&granularity="+tc.granularity, "numeric", "", nil)
				assert.Equal(t, tc.want, status)
				if tc.want == 500 {
					assert.Equal(t, "TOKEN_USAGE_QUERY_FAILED", body["code"])
					assert.NotContains(t, body, "data")
				} else {
					require.Equal(t, true, body["success"])
					items := body["data"].([]any)
					require.Len(t, items, 1)
					assert.Equal(t, float64(tc.values[0]), items[0].(map[string]any)["quota"])
				}
				if strings.HasPrefix(tc.name, "sql_sum_") {
					// Assert a real SQL SUM/driver scan failure, independently of
					// the numeric guard, without relying on dialect error text.
					var sum int64
					err := f.db.Model(&model.QuotaData{}).Select("SUM(quota)").Where("token_id = ?", token.Id).Scan(&sum).Error
					require.Error(t, err)
				}
				require.NoError(t, f.db.Where("token_id = ?", token.Id).Delete(&model.QuotaData{}).Error)
			})
		}
	})

	t.Run("logs", func(t *testing.T) {
		if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
			// The native log writer uses narrower columns. As in the existing
			// OAuth test, widen only this disposable fixture to represent a
			// retained Int64 log store; production schema is unchanged.
			for _, column := range []string{"quota", "prompt_tokens", "completion_tokens", "use_time"} {
				require.NoError(t, model.LOG_DB.Exec("ALTER TABLE logs MODIFY COLUMN "+column+" Int64").Error)
			}
		}
		for _, column := range []string{"quota", "prompt_tokens", "completion_tokens", "use_time"} {
			for _, value := range []int64{safe, -safe, safe + 1, -safe - 1} {
				t.Run(fmt.Sprintf("%s/%d", column, value), func(t *testing.T) {
					name := fmt.Sprintf("numeric_%s_%d", column, value)
					row := model.Log{UserId: token.UserId, TokenId: token.Id, CreatedAt: base + 1, Type: model.LogTypeConsume, ModelName: name, RequestId: name}
					switch column {
					case "quota":
						row.Quota = int(value)
					case "prompt_tokens":
						row.PromptTokens = int(value)
					case "completion_tokens":
						row.CompletionTokens = int(value)
					case "use_time":
						row.UseTime = int(value)
					}
					require.NoError(t, model.LOG_DB.Create(&row).Error)
					var stored int64
					require.NoError(t, model.LOG_DB.Model(&model.Log{}).Select(column).Where("model_name = ?", name).Scan(&stored).Error)
					require.Equal(t, value, stored)
					status, _, body := f.request(t, "GET", "/api/usage/token/logs?"+window+"&model_name="+url.QueryEscape(name), "numeric", "", nil)
					if value > safe || value < -safe {
						assert.Equal(t, 500, status)
						assert.Equal(t, "TOKEN_USAGE_QUERY_FAILED", body["code"])
						assert.NotContains(t, body, "data")
					} else {
						require.Equal(t, 200, status)
						data := body["data"].(map[string]any)
						assert.Equal(t, float64(1), data["total"])
						items := data["items"].([]any)
						require.Len(t, items, 1)
						assert.Equal(t, float64(value), items[0].(map[string]any)[column])
					}
				})
			}
		}
	})

	t.Run("count_publication", func(t *testing.T) {
		// Cardinalities above 2^53 cannot be materialized in a bounded fixture.
		// Replace only the completed COUNT observation; real route/auth and
		// query still execute. This is not a claim of a quadrillion-row DB test.
		for _, value := range []int64{safe, safe + 1, -1} {
			t.Run(strconv.FormatInt(value, 10), func(t *testing.T) {
				name := "token_usage_numeric_count"
				require.NoError(t, model.LOG_DB.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
					if count, ok := tx.Statement.Dest.(*int64); ok && strings.Contains(strings.ToLower(tx.Statement.SQL.String()), "count(") {
						*count = value
					}
				}))
				t.Cleanup(func() { require.NoError(t, model.LOG_DB.Callback().Query().Remove(name)) })
				status, _, body := f.request(t, "GET", "/api/usage/token/logs?"+window+"&model_name=no-such-numeric-row", "numeric", "", nil)
				if value == safe {
					require.Equal(t, 200, status)
					assert.Equal(t, float64(safe), body["data"].(map[string]any)["total"])
				} else {
					assert.Equal(t, 500, status)
					assert.Equal(t, "TOKEN_USAGE_QUERY_FAILED", body["code"])
					assert.NotContains(t, body, "data")
				}
			})
		}
	})
}
