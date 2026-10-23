package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// callLogHandler runs a log handler as the given user and returns the JSON
// lines of the response.
func callLogHandler(t *testing.T, handler gin.HandlerFunc, userId int, role int, query string) []map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/log?"+query, nil)
	ctx.Set("id", userId)
	ctx.Set("auth_identity", service.AuthIdentity{UserID: userId})
	ctx.Set("role", role)
	handler(ctx)
	var lines []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(recorder.Body.String()), "\n") {
		var value map[string]any
		require.NoError(t, common.UnmarshalJsonStr(line, &value))
		lines = append(lines, value)
	}
	return lines
}

func exportedRequestIds(lines []map[string]any) []any {
	ids := make([]any, 0, len(lines))
	for _, line := range lines[:len(lines)-1] {
		ids = append(ids, line["request_id"])
	}
	return ids
}

// seedExportLogs stores logs of two users: three in the last hour and one
// from 400 days ago.
func seedExportLogs(t *testing.T, mainDB *gorm.DB, logDB *gorm.DB, now int64) {
	t.Helper()
	require.NoError(t, mainDB.Create(&model.Channel{Id: 9, Name: "primary"}).Error)
	logs := []model.Log{
		{UserId: 1, Username: "alice", CreatedAt: now - 3600, Type: model.LogTypeConsume, ModelName: "gpt-a", ChannelId: 9, Quota: 10, RequestId: "a-1", Other: `{"admin_info":{"use_channel":["9"]}}`},
		{UserId: 2, Username: "bob", CreatedAt: now - 1800, Type: model.LogTypeConsume, ModelName: "gpt-b", ChannelId: 9, Quota: 20, RequestId: "b-1"},
		{UserId: 1, Username: "alice", CreatedAt: now - 60, Type: model.LogTypeError, ModelName: "gpt-a", RequestId: "a-2"},
		{UserId: 1, Username: "alice", CreatedAt: now - 400*24*3600, Type: model.LogTypeConsume, ModelName: "gpt-a", RequestId: "a-old"},
	}
	for i := range logs {
		require.NoError(t, logDB.Create(&logs[i]).Error)
	}
}

func useLogExportDatabases(t *testing.T, mainDB *gorm.DB, logDB *gorm.DB, mainType common.DatabaseType, logType common.DatabaseType) {
	t.Helper()
	previousDB, previousLogDB := model.DB, model.LOG_DB
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	previousRedis, previousMemory := common.RedisEnabled, common.MemoryCacheEnabled
	model.DB, model.LOG_DB = mainDB, logDB
	common.SetDatabaseTypes(mainType, logType)
	common.RedisEnabled, common.MemoryCacheEnabled = false, false
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLogDB
		common.SetDatabaseTypes(previousMain, previousLog)
		common.RedisEnabled, common.MemoryCacheEnabled = previousRedis, previousMemory
	})
}

func TestLogExportDatabaseMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousMaster := common.IsMasterNode
	common.IsMasterNode = true
	t.Cleanup(func() { common.IsMasterNode = previousMaster })
	for _, tc := range []struct {
		kind, env string
		typ       common.DatabaseType
	}{
		{"sqlite", "", common.DatabaseTypeSQLite},
		{"mysql", "AUDIT_MYSQL_DSN", common.DatabaseTypeMySQL},
		{"postgres", "AUDIT_POSTGRES_DSN", common.DatabaseTypePostgreSQL},
		{"clickhouse", "AUDIT_CLICKHOUSE_DSN", common.DatabaseTypeClickHouse},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dsn := os.Getenv(tc.env)
			if tc.env != "" && dsn == "" {
				t.Skip(tc.env + " is not configured")
			}
			db, isolatedDSN := newAuditTestDatabase(t, tc.kind, dsn)
			mainDB, mainType := db, tc.typ
			if tc.kind == "clickhouse" {
				mainDB, _ = newAuditTestDatabase(t, "sqlite", "")
				mainType = common.DatabaseTypeSQLite
			}
			useLogExportDatabases(t, mainDB, db, mainType, tc.typ)
			require.NoError(t, mainDB.AutoMigrate(&model.Channel{}))
			if tc.kind == "clickhouse" {
				t.Setenv("LOG_SQL_DSN", isolatedDSN)
				require.NoError(t, model.InitLogDB())
			} else {
				require.NoError(t, db.AutoMigrate(&model.Log{}))
			}
			versionSQL := "SELECT version()"
			if tc.kind == "sqlite" {
				versionSQL = "SELECT sqlite_version()"
			}
			var version string
			require.NoError(t, model.LOG_DB.Raw(versionSQL).Scan(&version).Error)
			t.Logf("log database: %s %s", tc.kind, version)
			now := time.Now().Unix()
			seedExportLogs(t, mainDB, model.LOG_DB, now)
			query := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-2*24*3600, now+3600)

			listed := callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, query)[0]
			require.Equal(t, true, listed["success"])
			assert.EqualValues(t, 2, listed["data"].(map[string]any)["total"])
			listed = callLogHandler(t, GetAllLogs, 3, common.RoleAdminUser, query+"&username=alice")[0]
			require.Equal(t, true, listed["success"])
			assert.EqualValues(t, 2, listed["data"].(map[string]any)["total"])

			own := callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, query)
			require.Len(t, own, 3)
			assert.Equal(t, []any{"a-2", "a-1"}, exportedRequestIds(own))
			assert.Equal(t, map[string]any{"success": true, "message": "", "data": map[string]any{"count": float64(2)}}, own[2])
			assert.Equal(t, float64(1), own[0]["id"], "user exports carry list positions, not row ids")
			assert.Empty(t, own[1]["channel_name"])
			assert.NotContains(t, own[1]["other"], "admin_info")

			all := callLogHandler(t, ExportAllLogs, 3, common.RoleAdminUser, query+"&model_name=gpt-%25")
			require.Len(t, all, 4)
			assert.Equal(t, []any{"a-2", "b-1", "a-1"}, exportedRequestIds(all))
			assert.Equal(t, "primary", all[2]["channel_name"])
			assert.Contains(t, all[2]["other"], "admin_info")
			assert.Equal(t, true, all[3]["success"])
		})
	}
}

func TestUserLogPageAlias(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := newAuditTestDatabase(t, "sqlite", "")
	useLogExportDatabases(t, db, db, common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	require.NoError(t, db.AutoMigrate(&model.Channel{}, &model.Log{}))
	now := time.Now().Unix()
	seedExportLogs(t, db, db, now)
	require.NoError(t, db.Create(&model.Log{UserId: 1, Username: "alice", CreatedAt: now - 30, Type: model.LogTypeConsume, ModelName: "gpt-b", RequestId: "a-3"}).Error)
	logSetting := operation_setting.GetLogSetting()
	previousSetting := *logSetting
	logSetting.MaxRangeDays = 365
	t.Cleanup(func() { *logSetting = previousSetting })
	recent := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d&", now-2*24*3600, now)
	for _, tc := range []struct {
		name, query, requestID string
		page, total            int
	}{
		{"alias second", "page=2", "a-2", 2, 3},
		{"canonical second", "p=2", "a-2", 2, 3},
		{"canonical first wins", "p=1&page=2", "a-3", 1, 3},
		{"canonical second wins", "p=2&page=1", "a-2", 2, 3},
		{"empty canonical wins", "p=&page=2", "a-3", 1, 3},
		{"bare canonical wins", "p&page=2", "a-3", 1, 3},
		{"invalid canonical wins", "p=bad&page=2", "a-3", 1, 3},
		{"zero canonical wins", "p=0&page=2", "a-3", 1, 3},
		{"repeated empty canonical", "p=&p=2&page=2", "a-3", 1, 3},
		{"repeated invalid canonical", "p=bad&p=2&page=2", "a-3", 1, 3},
		{"repeated valid canonical", "p=2&p=1&page=1", "a-2", 2, 3},
		{"encoded canonical key", "%70=2&page=1", "a-2", 2, 3},
		{"default page", "", "a-3", 1, 3},
		{"empty alias", "page=", "a-3", 1, 3},
		{"invalid alias", "page=bad", "a-3", 1, 3},
		{"zero alias", "page=0", "a-3", 1, 3},
		{"repeated alias", "page=2&page=1", "a-2", 2, 3},
		{"repeated empty alias", "page=&page=2", "a-3", 1, 3},
		{"owner remains selected", "page=2&user_id=2&username=bob", "a-2", 2, 3},
		{"filter before pagination", "page=2&model_name=gpt-a", "a-1", 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, recent+tc.query+"&page_size=1")[0]
			require.Equal(t, true, response["success"])
			data, ok := response["data"].(map[string]any)
			require.True(t, ok)
			assert.EqualValues(t, tc.page, data["page"])
			assert.EqualValues(t, 1, data["page_size"])
			assert.EqualValues(t, tc.total, data["total"])
			items, ok := data["items"].([]any)
			require.True(t, ok)
			require.Len(t, items, 1)
			assert.Equal(t, tc.requestID, items[0].(map[string]any)["request_id"])
		})
	}
	parse := func(t *testing.T, query string, alias bool) *common.PageInfo {
		t.Helper()
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/log/self?"+query, nil)
		canonical, alternate := ctx.Query("p"), ctx.Query("page") // Prime Gin's existing query cache.
		var info *common.PageInfo
		if alias {
			info = common.GetPageQueryWithPageAlias(ctx)
		} else {
			info = common.GetPageQuery(ctx)
		}
		assert.Equal(t, query, ctx.Request.URL.RawQuery)
		assert.Equal(t, canonical, ctx.Query("p"))
		assert.Equal(t, alternate, ctx.Query("page"))
		return info
	}
	maxInt := int(^uint(0) >> 1)
	for _, tc := range []struct {
		name, raw string
		expected  int
	}{
		{"empty", "", 1}, {"invalid", "bad", 1}, {"zero", "0", 1}, {"negative", "-2", -2},
		{"positive overflow", "999999999999999999999999999999", maxInt},
		{"negative overflow", "-999999999999999999999999999999", -maxInt - 1},
	} {
		t.Run("legacy parser/"+tc.name, func(t *testing.T) {
			value := url.QueryEscape(tc.raw)
			original := parse(t, "p="+value+"&page_size=1", false)
			assert.Equal(t, tc.expected, original.Page)
			assert.Equal(t, original, parse(t, "page="+value+"&page_size=1", true))
			assert.Equal(t, original, parse(t, "p="+value+"&page=2&page_size=1", true))
		})
	}
	for _, tc := range []struct {
		name, query string
		expected    int
	}{
		{"default", "", common.ItemsPerPage},
		{"page_size first", "page_size=2&ps=3&size=4", 2},
		{"zero falls to ps", "page_size=0&ps=3&size=4", 3},
		{"invalid falls to size", "page_size=bad&ps=0&size=4", 4},
		{"cap", "page_size=101", 100},
		{"negative retained", "page_size=-2&ps=3", -2},
		{"first duplicate retained", "page_size=0&page_size=5&ps=2", 2},
		{"size fallback", "ps=bad&size=4", 4},
	} {
		t.Run("page size/"+tc.name, func(t *testing.T) {
			original := parse(t, "p=2&"+tc.query, false)
			assert.Equal(t, tc.expected, original.PageSize)
			assert.Equal(t, original, parse(t, "page=2&"+tc.query, true))
			assert.Equal(t, original, parse(t, "p=2&page=1&"+tc.query, true))
		})
	}
	t.Run("admin and default do not opt in", func(t *testing.T) {
		assert.Equal(t, 1, parse(t, "page=2&page_size=1", false).Page)
		for _, tc := range []struct {
			query, requestID string
			page             int
		}{{"page=2", "a-3", 1}, {"p=2", "a-2", 2}} {
			response := callLogHandler(t, GetAllLogs, 3, common.RoleAdminUser, recent+tc.query+"&page_size=1")[0]
			require.Equal(t, true, response["success"])
			data := response["data"].(map[string]any)
			assert.EqualValues(t, tc.page, data["page"])
			assert.EqualValues(t, 4, data["total"])
			items := data["items"].([]any)
			require.Len(t, items, 1)
			assert.Equal(t, tc.requestID, items[0].(map[string]any)["request_id"])
		}
	})
	t.Run("time range error unchanged", func(t *testing.T) {
		tooLong := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d&page_size=1&", now-366*24*3600, now)
		canonical := callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, tooLong+"p=2")[0]
		alias := callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, tooLong+"page=2")[0]
		assert.Equal(t, canonical, alias)
		assert.Equal(t, false, alias["success"])
		assert.Equal(t, "The time range cannot exceed {{days}} days", alias["message_key"])
	})
}

func TestUserLogRangeErrorStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := newAuditTestDatabase(t, "sqlite", "")
	useLogExportDatabases(t, db, db, common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	require.NoError(t, db.AutoMigrate(&model.Channel{}, &model.Log{}))
	// A past, nonzero end makes min(now, end) deterministic without a clock hook.
	end := time.Now().Unix() - 3600
	seedExportLogs(t, db, db, end+60)
	setting := operation_setting.GetLogSetting()
	previousSetting := *setting
	t.Cleanup(func() { *setting = previousSetting })
	require.Equal(t, 365, setting.MaxRangeDays, "default limit in a fresh test process")
	for _, days := range []int{365, 7} {
		setting.MaxRangeDays = days
		span := int64(days) * 24 * 60 * 60
		for _, tc := range []struct {
			name   string
			role   int
			start  int64
			status int
		}{
			{"exact_boundary", common.RoleCommonUser, end - span, http.StatusOK},
			{"one_second_too_wide", common.RoleCommonUser, end - span - 1, http.StatusBadRequest},
			{"missing_start", common.RoleCommonUser, 0, http.StatusOK},
			{"admin_exempt", common.RoleAdminUser, end - span - 1, http.StatusOK},
		} {
			t.Run(fmt.Sprintf("days_%d/%s", days, tc.name), func(t *testing.T) {
				query := url.Values{
					"end_timestamp": {fmt.Sprint(end)}, "p": {"1"}, "page_size": {"10"},
					"user_id": {"2"}, "username": {"bob"},
				}
				if tc.start != 0 {
					query.Set("start_timestamp", fmt.Sprint(tc.start))
				}
				recorder := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(recorder)
				ctx.Request = httptest.NewRequest(http.MethodGet, "/api/log/self?"+query.Encode(), nil)
				ctx.Set("id", 1)
				ctx.Set("auth_identity", service.AuthIdentity{UserID: 1})
				ctx.Set("role", tc.role)
				GetUserLogs(ctx)
				var body map[string]any
				require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &body))
				code, hasCode := body["code"]
				t.Logf("role=%d max_days=%d start=%d end=%d HTTP=%d has_code=%t code=%v", tc.role, days, tc.start, end, recorder.Code, hasCode, code)
				assert.Equal(t, tc.status, recorder.Code)
				if tc.status == http.StatusBadRequest {
					assert.Equal(t, map[string]any{
						"success": false, "code": "LOG_RANGE_TOO_WIDE",
						"message":        fmt.Sprintf("The time range cannot exceed %d days", days),
						"message_key":    "The time range cannot exceed {{days}} days",
						"message_params": map[string]any{"days": float64(days)},
					}, body)
					return
				}
				require.Equal(t, true, body["success"])
				assert.False(t, hasCode)
				data, ok := body["data"].(map[string]any)
				require.True(t, ok)
				items, ok := data["items"].([]any)
				require.True(t, ok)
				var requestIDs []any
				for _, item := range items {
					log, ok := item.(map[string]any)
					require.True(t, ok)
					requestIDs = append(requestIDs, log["request_id"])
				}
				assert.EqualValues(t, 2, data["total"])
				assert.Equal(t, []any{"a-2", "a-1"}, requestIDs, "the self endpoint ignores another user selected by query")
			})
		}
	}
}

func TestUserQuotaRangeErrorStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := newAuditTestDatabase(t, "sqlite", "")
	useLogExportDatabases(t, db, db, common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	require.NoError(t, db.AutoMigrate(&model.QuotaData{}))
	setting := operation_setting.GetLogSetting()
	previousSetting := *setting
	t.Cleanup(func() { *setting = previousSetting })
	require.Equal(t, 365, setting.MaxRangeDays, "default limit in a fresh test process")
	// The fixed past end keeps the exact boundary independent of elapsed time.
	end := time.Now().Unix() - 3600
	for _, days := range []int{365, 7} {
		setting.MaxRangeDays = days
		span := int64(days) * 24 * 60 * 60
		for _, tc := range []struct {
			name   string
			role   int
			start  int64
			status int
		}{
			{"exact_boundary", common.RoleCommonUser, end - span, http.StatusOK},
			{"one_second_too_wide", common.RoleCommonUser, end - span - 1, http.StatusBadRequest},
			{"missing_start", common.RoleCommonUser, 0, http.StatusOK},
			{"admin_still_limited", common.RoleAdminUser, end - span - 1, http.StatusBadRequest},
			{"root_still_limited", common.RoleRootUser, end - span - 1, http.StatusBadRequest},
		} {
			t.Run(fmt.Sprintf("days_%d/%s", days, tc.name), func(t *testing.T) {
				query := url.Values{"end_timestamp": {fmt.Sprint(end)}}
				if tc.start != 0 {
					query.Set("start_timestamp", fmt.Sprint(tc.start))
				}
				recorder := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(recorder)
				ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/self?"+query.Encode(), nil)
				ctx.Set("id", 1)
				ctx.Set("auth_identity", service.AuthIdentity{UserID: 1})
				ctx.Set("role", tc.role)
				GetUserQuotaDates(ctx)
				var body map[string]any
				require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &body))
				code, hasCode := body["code"]
				t.Logf("role=%d max_days=%d start=%d end=%d HTTP=%d has_code=%t code=%v", tc.role, days, tc.start, end, recorder.Code, hasCode, code)
				assert.Equal(t, tc.status, recorder.Code)
				if tc.status == http.StatusBadRequest {
					assert.Equal(t, map[string]any{
						"success": false, "code": "LOG_RANGE_TOO_WIDE",
						"message":        fmt.Sprintf("The time range cannot exceed %d days", days),
						"message_key":    "The time range cannot exceed {{days}} days",
						"message_params": map[string]any{"days": float64(days)},
					}, body)
					return
				}
				assert.Equal(t, map[string]any{
					"success": true, "message": "", "data": []any{},
					"granularity": "hour", "quota_per_unit": common.QuotaPerUnit,
					"data_complete": false, "enable_data_export": common.DataExportEnabled,
				}, body)
			})
		}
	}
}

func TestUserQuotaDataSeriesContract(t *testing.T) {
	previousMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(previousMode) })
	db, _ := newAuditTestDatabase(t, "sqlite", "")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	useLogExportDatabases(t, db, db, common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	require.NoError(t, db.AutoMigrate(&model.QuotaData{}))
	previousExport := common.DataExportEnabled
	previousQuotaPerUnit := common.QuotaPerUnit
	common.DataExportEnabled = true
	common.QuotaPerUnit = 123456.75
	model.CacheQuotaDataLock.Lock()
	previousCache := model.CacheQuotaData
	model.CacheQuotaData = make(map[string]*model.QuotaData)
	model.CacheQuotaDataLock.Unlock()
	setting := operation_setting.GetLogSetting()
	previousSetting := *setting
	setting.MaxRangeDays = 365
	t.Cleanup(func() {
		common.DataExportEnabled = previousExport
		common.QuotaPerUnit = previousQuotaPerUnit
		*setting = previousSetting
		model.CacheQuotaDataLock.Lock()
		model.CacheQuotaData = previousCache
		model.CacheQuotaDataLock.Unlock()
	})

	bucket := time.Now().Unix() - 7200
	bucket -= bucket % 3600
	for _, sample := range []model.QuotaDataLogParams{
		{UserID: 1, Username: "alice", ModelName: "owned-a", CreatedAt: bucket + 1, Quota: 12, TokenUsed: 3},
		{UserID: 1, Username: "alice", ModelName: "owned-a", CreatedAt: bucket + 3599, Quota: 7, TokenUsed: 5},
		{UserID: 1, Username: "alice", ModelName: "owned-b", CreatedAt: bucket + 3601, Quota: 6, TokenUsed: 2},
		{UserID: 2, Username: "bob", ModelName: "other-owner", CreatedAt: bucket + 17, Quota: 99, TokenUsed: 20},
	} {
		model.LogQuotaData(sample)
	}
	model.SaveQuotaDataCache()
	var expected []any
	require.NoError(t, common.UnmarshalJsonStr(fmt.Sprintf(`[
		{"id":0,"user_id":1,"username":"alice","model_name":"owned-a","created_at":%d,"use_group":"","token_id":0,"channel_id":0,"node_name":"","token_used":8,"count":2,"quota":19},
		{"id":0,"user_id":1,"username":"alice","model_name":"owned-b","created_at":%d,"use_group":"","token_id":0,"channel_id":0,"node_name":"","token_used":2,"count":1,"quota":6}
	]`, bucket, bucket+3600), &expected))
	for _, tc := range []struct {
		name    string
		enabled bool
		start   int64
		end     string
		want    []any
	}{
		{"hourly_owner_only_inclusive_bounds", true, bucket, fmt.Sprint(bucket + 3600), expected},
		{"disabled_preserves_history", false, bucket, fmt.Sprint(bucket + 3600), expected},
		{"disabled_empty_bucket_interval", false, bucket + 1, fmt.Sprint(bucket + 3599), []any{}},
		{"missing_end_stays_zero_in_SQL", false, bucket, "", []any{}},
		{"syntax_invalid_end_stays_zero_in_SQL", false, bucket, "invalid", []any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.DataExportEnabled = tc.enabled
			query := url.Values{"start_timestamp": {fmt.Sprint(tc.start)}}
			if tc.end != "" {
				query.Set("end_timestamp", tc.end)
			}
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/self?"+query.Encode(), nil)
			ctx.Set("id", 1)
			ctx.Set("auth_identity", service.AuthIdentity{UserID: 1})
			ctx.Set("role", common.RoleCommonUser)
			GetUserQuotaDates(ctx)
			var body map[string]any
			require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &body))
			require.Equal(t, http.StatusOK, recorder.Code)
			require.Len(t, body, 7)
			assert.Equal(t, true, body["success"])
			assert.Equal(t, "", body["message"])
			assert.Equal(t, "hour", body["granularity"])
			assert.Equal(t, float64(123456.75), body["quota_per_unit"])
			assert.Equal(t, false, body["data_complete"])
			assert.Equal(t, tc.enabled, body["enable_data_export"])
			rows, ok := body["data"].([]any)
			require.True(t, ok, "the actual empty success value is an array, not null")
			assert.ElementsMatch(t, tc.want, rows, "hourly aggregates have no ordering guarantee")
		})
	}
	t.Run("admin_series_keeps_existing_root_fields", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		query := url.Values{"start_timestamp": {fmt.Sprint(bucket)}, "end_timestamp": {fmt.Sprint(bucket + 3600)}}
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data?"+query.Encode(), nil)
		ctx.Set("role", common.RoleAdminUser)
		GetAllQuotaDates(ctx)
		var body map[string]any
		require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &body))
		require.Equal(t, http.StatusOK, recorder.Code)
		assert.Len(t, body, 3)
		assert.Equal(t, true, body["success"])
		assert.Equal(t, "", body["message"])
		assert.Contains(t, body, "data")
	})
}

func TestLogExportRules(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := newAuditTestDatabase(t, "sqlite", "")
	useLogExportDatabases(t, db, db, common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	require.NoError(t, db.AutoMigrate(&model.Channel{}, &model.Log{}, &model.QuotaData{}))
	now := time.Now().Unix()
	seedExportLogs(t, db, db, now)
	logSetting := operation_setting.GetLogSetting()
	previousSetting := *logSetting
	t.Cleanup(func() { *logSetting = previousSetting })
	recent := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-2*24*3600, now)
	tooLong := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-366*24*3600, now)

	t.Run("time range", func(t *testing.T) {
		rejected := callLogHandler(t, ExportAllLogs, 3, common.RoleAdminUser, tooLong)
		require.Len(t, rejected, 1)
		assert.Equal(t, false, rejected[0]["success"])
		assert.Equal(t, "The time range cannot exceed {{days}} days", rejected[0]["message_key"])
		assert.Equal(t, map[string]any{"days": float64(365)}, rejected[0]["message_params"])

		assert.Equal(t, false, callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, tooLong)[0]["success"])
		assert.Equal(t, false, callLogHandler(t, GetLogsSelfStat, 1, common.RoleCommonUser, tooLong)[0]["success"])
		assert.Equal(t, true, callLogHandler(t, GetUserLogs, 3, common.RoleAdminUser, tooLong)[0]["success"], "administrators search their own logs without a limit")

		// The dashboard follows the same range instead of its old one-month limit.
		fortyDays := fmt.Sprintf("start_timestamp=%d&end_timestamp=%d", now-40*24*3600, now)
		for _, handler := range []gin.HandlerFunc{GetUserQuotaDates, GetUserFlowQuotaDates} {
			assert.Equal(t, "The time range cannot exceed {{days}} days", callLogHandler(t, handler, 1, common.RoleCommonUser, tooLong)[0]["message_key"])
			assert.Equal(t, true, callLogHandler(t, handler, 1, common.RoleCommonUser, fortyDays)[0]["success"])
		}

		// Without a start, a user's search reaches back the whole range.
		listed := callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, "")[0]
		assert.Equal(t, true, listed["success"])
		assert.EqualValues(t, 2, listed["data"].(map[string]any)["total"])

		logSetting.MaxRangeDays = 400
		assert.Equal(t, true, callLogHandler(t, GetUserLogs, 1, common.RoleCommonUser, tooLong)[0]["success"])
		logSetting.MaxRangeDays = previousSetting.MaxRangeDays
	})

	t.Run("user export switch", func(t *testing.T) {
		logSetting.UserExportEnabled = false
		t.Cleanup(func() { logSetting.UserExportEnabled = previousSetting.UserExportEnabled })
		disabled := callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, recent)
		require.Len(t, disabled, 1)
		assert.Equal(t, "Log export is disabled", disabled[0]["message_key"])
		assert.Equal(t, true, callLogHandler(t, ExportUserLogs, 3, common.RoleAdminUser, recent)[0]["success"], "administrators export their own logs even when users cannot")
	})

	t.Run("one export per user", func(t *testing.T) {
		release, ok, err := service.AcquireLogExportLock(1)
		require.NoError(t, err)
		require.True(t, ok)
		busy := callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, recent)
		require.Len(t, busy, 1)
		assert.Equal(t, "Another log export is running. Try again after it finishes.", busy[0]["message_key"])
		other := callLogHandler(t, ExportUserLogs, 2, common.RoleCommonUser, recent)
		assert.Equal(t, true, other[len(other)-1]["success"], "other users are not blocked")
		release()
		assert.Len(t, callLogHandler(t, ExportUserLogs, 1, common.RoleCommonUser, recent), 3)
	})
}

func TestAcquireLogExportLock(t *testing.T) {
	for _, useRedis := range []bool{false, true} {
		t.Run(fmt.Sprintf("redis=%v", useRedis), func(t *testing.T) {
			previousRedis, previousClient := common.RedisEnabled, common.RDB
			common.RedisEnabled = useRedis
			if useRedis {
				server := miniredis.RunT(t)
				common.RDB = redis.NewClient(&redis.Options{Addr: server.Addr()})
				require.NoError(t, common.RDB.Ping(context.Background()).Err())
			}
			t.Cleanup(func() { common.RedisEnabled, common.RDB = previousRedis, previousClient })

			release, ok, err := service.AcquireLogExportLock(1)
			require.NoError(t, err)
			require.True(t, ok)
			_, ok, err = service.AcquireLogExportLock(1)
			require.NoError(t, err)
			assert.False(t, ok, "a second export of the same user must wait")
			releaseOther, ok, err := service.AcquireLogExportLock(2)
			require.NoError(t, err)
			assert.True(t, ok)
			releaseOther()
			release()
			releaseAgain, ok, err := service.AcquireLogExportLock(1)
			require.NoError(t, err)
			assert.True(t, ok, "a finished export frees the user")
			releaseAgain()
		})
	}
}
