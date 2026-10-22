package router

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
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
