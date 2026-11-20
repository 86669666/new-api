package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// These tests call the real handler and model against a private database. The
// authenticated context is a fixture, not a test of authentication middleware.
func TestPersonalQuotaDaily(t *testing.T) {
	previousMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/daily.db"), &gorm.Config{})
	require.NoError(t, err)
	connection, err := db.DB()
	require.NoError(t, err)
	previousDB, previousExport, previousUnits := model.DB, common.DataExportEnabled, common.QuotaPerUnit
	previousLocal := time.Local
	setting := operation_setting.GetLogSetting()
	previousSetting := *setting
	model.DB = db
	common.DataExportEnabled = false
	common.QuotaPerUnit = 123456.75
	setting.MaxRangeDays = 7
	// UTC bucketing must be independent of the host's local zone, including
	// zones whose offset does not align with an hour.
	time.Local = time.FixedZone("fixture+0545", 5*3600+45*60)
	t.Cleanup(func() {
		model.DB, common.DataExportEnabled, common.QuotaPerUnit = previousDB, previousExport, previousUnits
		*setting = previousSetting
		time.Local = previousLocal
		gin.SetMode(previousMode)
		require.NoError(t, connection.Close())
	})
	require.NoError(t, db.AutoMigrate(&model.QuotaData{}))
	var sqliteVersion string
	require.NoError(t, db.Raw("select sqlite_version()").Scan(&sqliteVersion).Error)
	t.Logf("SQLite %s", sqliteVersion)

	const day int64 = 1704067200 // 2024-01-01 00:00:00 UTC
	rows := []model.QuotaData{
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day - 3600, Quota: 99},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day, Count: 1, Quota: 10, TokenUsed: 2, CacheReadTokens: 3, CacheCreationTokens: 4},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day, TokenID: 8, ChannelID: 9, UseGroup: "other", NodeName: "other", Count: 2, Quota: 20, TokenUsed: 5, CacheReadTokens: 6, CacheCreationTokens: 7},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 3600, Count: 3, Quota: 30, TokenUsed: 8, CacheReadTokens: 9, CacheCreationTokens: 10},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 23*3600, Count: 4, Quota: -2, TokenUsed: 11, CacheReadTokens: 12, CacheCreationTokens: 13},
		{UserID: 1, Username: "alice", ModelName: "b", CreatedAt: day + 3600, Count: 5, Quota: 40, TokenUsed: 14},
		{UserID: 1, Username: "old-name", ModelName: "a", CreatedAt: day + 3600, Count: 6, Quota: 50},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 86400, Count: 7, Quota: 60},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 3*86400, Count: 8, Quota: 70},
		{UserID: 2, Username: "alice", ModelName: "a", CreatedAt: day, Count: 100, Quota: 900},
	}
	require.NoError(t, db.Create(&rows).Error)
	wantDay := []model.QuotaData{
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day, Count: 10, Quota: 58, TokenUsed: 26, CacheReadTokens: 30, CacheCreationTokens: 34},
		{UserID: 1, Username: "alice", ModelName: "b", CreatedAt: day, Count: 5, Quota: 40, TokenUsed: 14},
		{UserID: 1, Username: "old-name", ModelName: "a", CreatedAt: day, Count: 6, Quota: 50},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 86400, Count: 7, Quota: 60},
	}
	wantHours := []model.QuotaData{
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day, Count: 3, Quota: 30, TokenUsed: 7, CacheReadTokens: 9, CacheCreationTokens: 11},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 3600, Count: 3, Quota: 30, TokenUsed: 8, CacheReadTokens: 9, CacheCreationTokens: 10},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 23*3600, Count: 4, Quota: -2, TokenUsed: 11, CacheReadTokens: 12, CacheCreationTokens: 13},
		{UserID: 1, Username: "alice", ModelName: "b", CreatedAt: day + 3600, Count: 5, Quota: 40, TokenUsed: 14},
		{UserID: 1, Username: "old-name", ModelName: "a", CreatedAt: day + 3600, Count: 6, Quota: 50},
		{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 86400, Count: 7, Quota: 60},
	}
	for _, tc := range []struct {
		name, granularity, start, end string
		user                          int
		enabled                       bool
		want                          []model.QuotaData
	}{
		{"default_hour", "", fmt.Sprint(day), fmt.Sprint(day + 86400), 1, false, wantHours},
		{"explicit_hour", "&granularity=hour", fmt.Sprint(day), fmt.Sprint(day + 86400), 1, false, wantHours},
		{"empty_hour", "&granularity=", fmt.Sprint(day), fmt.Sprint(day + 86400), 1, false, wantHours},
		{"utc_days_disabled_history", "&granularity=day", fmt.Sprint(day), fmt.Sprint(day + 86400), 1, false, wantDay},
		{"utc_days_enabled_history", "&granularity=day", fmt.Sprint(day), fmt.Sprint(day + 86400), 1, true, wantDay},
		{"partial_day_inclusive", "&granularity=day", fmt.Sprint(day + 1), fmt.Sprint(day + 23*3600), 1, false, []model.QuotaData{
			{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day, Count: 7, Quota: 28, TokenUsed: 19, CacheReadTokens: 21, CacheCreationTokens: 23},
			wantDay[1], wantDay[2],
		}},
		{"exact_midnight", "&granularity=day", fmt.Sprint(day + 86400), fmt.Sprint(day + 86400), 1, false, wantDay[3:]},
		{"no_zero_fill", "&granularity=day", fmt.Sprint(day + 86400), fmt.Sprint(day + 3*86400), 1, false, []model.QuotaData{wantDay[3], {UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 3*86400, Count: 8, Quota: 70}}},
		{"other_user_same_name_model", "&granularity=day", fmt.Sprint(day), fmt.Sprint(day + 86400), 2, false, []model.QuotaData{{UserID: 2, Username: "alice", ModelName: "a", CreatedAt: day, Count: 100, Quota: 900}}},
		{"no_rows", "&granularity=day", fmt.Sprint(day), fmt.Sprint(day + 86400), 3, false, []model.QuotaData{}},
		{"missing_start_fallback", "&granularity=day", "", fmt.Sprint(day + 7*86400), 1, false, append(append([]model.QuotaData{}, wantDay...), model.QuotaData{UserID: 1, Username: "alice", ModelName: "a", CreatedAt: day + 3*86400, Count: 8, Quota: 70})},
		{"missing_end_compatibility", "&granularity=day", fmt.Sprint(time.Now().Unix()), "", 1, false, []model.QuotaData{}},
		{"invalid_end_compatibility", "&granularity=day", fmt.Sprint(time.Now().Unix()), "invalid", 1, false, []model.QuotaData{}},
		{"reversed_range_compatibility", "&granularity=day", fmt.Sprint(day + 1), fmt.Sprint(day), 1, false, []model.QuotaData{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.DataExportEnabled = tc.enabled
			query := url.Values{"start_timestamp": {tc.start}, "end_timestamp": {tc.end}, "user_id": {"2"}, "username": {"other"}}
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/self?"+query.Encode()+tc.granularity, nil)
			ctx.Set("id", tc.user)
			ctx.Set("role", common.RoleCommonUser)
			GetUserQuotaDates(ctx)
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			var body map[string]any
			require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &body))
			require.Len(t, body, 7)
			assert.Equal(t, true, body["success"])
			assert.Equal(t, "", body["message"])
			wantGranularity := "hour"
			if tc.granularity == "&granularity=day" {
				wantGranularity = "day"
			}
			assert.Equal(t, wantGranularity, body["granularity"])
			assert.Equal(t, false, body["data_complete"])
			assert.Equal(t, tc.enabled, body["enable_data_export"])
			assert.Equal(t, 123456.75, body["quota_per_unit"])
			data, ok := body["data"].([]any)
			require.True(t, ok, "empty results remain []")
			expectedJSON, err := common.Marshal(tc.want)
			require.NoError(t, err)
			var expected []any
			require.NoError(t, common.Unmarshal(expectedJSON, &expected))
			assert.ElementsMatch(t, expected, data)
		})
	}

	for _, role := range []int{common.RoleCommonUser, common.RoleAdminUser, common.RoleRootUser} {
		for _, granularity := range []string{"", "hour", "day"} {
			for _, extra := range []int64{0, 1} {
				t.Run(fmt.Sprintf("range/role%d/%s/extra%d", role, granularity, extra), func(t *testing.T) {
					recorder := httptest.NewRecorder()
					ctx, _ := gin.CreateTestContext(recorder)
					ctx.Request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/data/self?start_timestamp=%d&end_timestamp=%d&granularity=%s", day-7*86400-extra, day, granularity), nil)
					ctx.Set("id", 3)
					ctx.Set("role", role)
					GetUserQuotaDates(ctx)
					if extra == 0 {
						assert.Equal(t, http.StatusOK, recorder.Code)
						return
					}
					assert.Equal(t, http.StatusBadRequest, recorder.Code)
					assert.JSONEq(t, `{"success":false,"code":"LOG_RANGE_TOO_WIDE","message":"The time range cannot exceed 7 days","message_key":"The time range cannot exceed {{days}} days","message_params":{"days":7}}`, recorder.Body.String())
				})
			}
		}
	}
	for _, value := range []string{"week", "Day", " day", "day ", "1"} {
		t.Run("invalid_granularity/"+value, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/self?granularity="+url.QueryEscape(value), nil)
			ctx.Set("id", 1)
			GetUserQuotaDates(ctx)
			assert.Equal(t, http.StatusBadRequest, recorder.Code)
			assert.JSONEq(t, `{"success":false,"code":"INVALID_GRANULARITY","message":"Invalid parameters","message_key":"Invalid parameters"}`, recorder.Body.String())
		})
	}
	t.Run("model_preserves_integer_precision", func(t *testing.T) {
		// Stored quota has no floating-point conversion, even above 2^53.
		require.NoError(t, db.Create(&[]model.QuotaData{
			{UserID: 4, Username: "integer", ModelName: "a", CreatedAt: day, Quota: 9007199254740993},
			{UserID: 4, Username: "integer", ModelName: "a", CreatedAt: day + 3600, Quota: -2},
		}).Error)
		daily, err := model.GetDailyQuotaDataByUserId(4, day, day+3600)
		require.NoError(t, err)
		require.Len(t, daily, 1)
		assert.Equal(t, &model.QuotaData{UserID: 4, Username: "integer", ModelName: "a", CreatedAt: day, Quota: 9007199254740991}, daily[0])
	})
	t.Run("query_failure_no_partial_data", func(t *testing.T) {
		require.NoError(t, db.Migrator().DropTable(&model.QuotaData{}))
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/data/self?granularity=day", nil)
		ctx.Set("id", 1)
		GetUserQuotaDates(ctx)
		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.JSONEq(t, `{"success":false,"code":"USAGE_QUERY_FAILED","message":"Failed to query statistics","message_key":"Failed to query statistics"}`, recorder.Body.String())
	})
}
