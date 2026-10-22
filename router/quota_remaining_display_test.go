package router

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestQuotaRemainingDisplayHTTP(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oldCount, oldBatch, oldExport, oldUnit := constant.CountToken, common.BatchUpdateEnabled, common.DataExportEnabled, common.QuotaPerUnit
	oldSettings := *operation_setting.GetQuotaSetting()
	oldDisplay := *operation_setting.GetGeneralSetting()
	oldPrice := ratio_setting.ModelPrice2JSONString()
	t.Cleanup(func() {
		constant.CountToken, common.BatchUpdateEnabled, common.DataExportEnabled, common.QuotaPerUnit = oldCount, oldBatch, oldExport, oldUnit
		*operation_setting.GetQuotaSetting() = oldSettings
		*operation_setting.GetGeneralSetting() = oldDisplay
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(oldPrice))
	})
	constant.CountToken, common.BatchUpdateEnabled, common.DataExportEnabled, common.QuotaPerUnit = false, false, false, 500000
	*operation_setting.GetQuotaSetting() = operation_setting.QuotaSetting{TrustQuotaUSD: 0, PreConsumeMultiplier: 1}
	operation_setting.GetGeneralSetting().QuotaDisplayType = "USD"
	require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"deepseek-search":0.001}`))
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}))
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("wallet rejection reached provider")
		w.WriteHeader(500)
	}))
	t.Cleanup(provider.Close)
	base := provider.URL
	channel := &model.Channel{Type: constant.ChannelTypeDeepSeek, Name: "wallet privacy", Key: "fixture-upstream", Status: common.ChannelStatusEnabled, BaseURL: &base, Models: "deepseek-search", Group: "default"}
	require.NoError(t, channel.Insert())
	var token model.Token
	require.NoError(t, f.db.Where("user_id = ?", f.users["owner"].Id).Take(&token).Error)
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Updates(map[string]any{"quota": 100, "setting": `{"billing_preference":"wallet_only"}`}).Error)
	require.NoError(t, f.db.Model(&token).Updates(map[string]any{"remain_quota": 1000000, "allow_user_quota_query": false}).Error)
	for _, lang := range []string{"en", "zh-CN", "zh-TW"} {
		for _, allowed := range []bool{false, true} {
			require.NoError(t, f.db.Model(&token).Update("allow_user_quota_query", allowed).Error)
			status, _, body := f.request(t, http.MethodPost, "/v1/tools/search", "relay", `{"query":"wallet privacy"}`, http.Header{"Accept-Language": {lang}})
			require.Equal(t, 403, status, "%v", body)
			detail, ok := body["error"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "insufficient_user_quota", detail["code"])
			if allowed {
				assert.Equal(t, "$0.0002", detail["remaining_display"])
			} else {
				assert.NotContains(t, detail, "remaining_display")
				safe := map[string]string{"en": "Insufficient user quota", "zh-CN": "用户额度不足", "zh-TW": "使用者額度不足"}[lang]
				assert.Contains(t, detail["message"], safe)
				assert.NotContains(t, detail["message"], "0.000200")
				assert.NotContains(t, detail["message"], "remaining")
			}
		}
	}

	t.Run("native_HTTP_safe_default", func(t *testing.T) {
		require.NoError(t, f.db.Model(&token).Update("allow_user_quota_query", true).Error)
		for _, tc := range []struct{ path, body string }{
			{"/v1/messages", `{"model":"deepseek-search","max_tokens":1,"messages":[{"role":"user","content":"hello"}]}`},
			{"/v1beta/models/deepseek-search:generateContent", `{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`},
		} {
			status, _, body := f.request(t, http.MethodPost, tc.path, "relay", tc.body, http.Header{"Content-Type": {"application/json"}})
			require.Equal(t, 403, status, "%s %v", tc.path, body)
			raw, err := common.Marshal(body)
			require.NoError(t, err)
			assert.Contains(t, string(raw), "Insufficient user quota")
			assert.NotContains(t, string(raw), "remaining_display")
			assert.NotContains(t, string(raw), "0.000200")
		}
	})
	t.Run("final_permission_and_identity", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			changes map[string]any
			fault   bool
		}{
			{name: "permission_revoked", changes: map[string]any{"allow_user_quota_query": false}},
			{name: "disabled", changes: map[string]any{"status": common.TokenStatusDisabled}},
			{name: "expired", changes: map[string]any{"expired_time": time.Now().Unix() - 1}},
			{name: "owner_changed", changes: map[string]any{"user_id": f.users["foreign"].Id}},
			{name: "key_changed", changes: map[string]any{"key": strings.Repeat("z", 40)}},
			{name: "permission_read_fault", fault: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(map[string]any{"allow_user_quota_query": true, "status": common.TokenStatusEnabled, "expired_time": -1, "key": token.Key, "user_id": token.UserId}).Error)
				var observed, failed atomic.Bool
				callback := "wallet_final_" + tc.name
				require.NoError(t, f.db.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
					if tx.Statement.Table == "users" && len(tx.Statement.Selects) == 1 && tx.Statement.Selects[0] == "quota" && observed.CompareAndSwap(false, true) && !tc.fault {
						assert.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(tc.changes).Error)
					}
					if tc.fault && observed.Load() && tx.Statement.Table == "tokens" {
						failed.Store(true)
						tx.AddError(errors.New("private permission storage failure"))
					}
				}))
				status, _, body := f.request(t, http.MethodPost, "/v1/tools/search", "relay", `{"query":"wallet revoke"}`, nil)
				require.NoError(t, f.db.Callback().Query().Remove(callback))
				assert.True(t, observed.Load())
				if tc.fault {
					assert.True(t, failed.Load())
				}
				require.Equal(t, 403, status, "%v", body)
				detail := body["error"].(map[string]any)
				assert.NotContains(t, detail, "remaining_display")
				assert.Contains(t, detail["message"], "Insufficient user quota")
				raw, err := common.Marshal(body)
				require.NoError(t, err)
				assert.NotContains(t, string(raw), "0.000200")
				assert.NotContains(t, string(raw), "private permission storage failure")
				assert.NotContains(t, string(raw), token.Key)
			})
		}
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(map[string]any{"allow_user_quota_query": true, "status": common.TokenStatusEnabled, "expired_time": -1, "key": token.Key, "user_id": token.UserId}).Error)
	})
	t.Run("atomic_rejection_and_observation_fault", func(t *testing.T) {
		for _, readFault := range []bool{false, true} {
			t.Run(fmt.Sprintf("fault_%t", readFault), func(t *testing.T) {
				require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", 1000).Error)
				var reads atomic.Int32
				callback := "wallet_atomic_reject"
				require.NoError(t, f.db.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
					if tx.Statement.Table != "users" || len(tx.Statement.Selects) != 1 || tx.Statement.Selects[0] != "quota" {
						return
					}
					switch reads.Add(1) {
					case 1:
						assert.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", 0).Error)
					case 2:
						if readFault {
							tx.AddError(errors.New("private quota observation failure"))
						}
					}
				}))
				status, _, body := f.request(t, http.MethodPost, "/v1/tools/search", "relay", `{"query":"wallet atomic failure"}`, nil)
				require.NoError(t, f.db.Callback().Query().Remove(callback))
				require.Equal(t, 403, status, "%v", body)
				assert.Equal(t, int32(2), reads.Load())
				detail := body["error"].(map[string]any)
				if readFault {
					assert.NotContains(t, detail, "remaining_display")
					assert.Contains(t, detail["message"], "Insufficient user quota")
					assert.NotContains(t, detail["message"], "0.000000")
				} else {
					assert.Equal(t, "$0", detail["remaining_display"])
				}
				var after model.Token
				require.NoError(t, f.db.First(&after, token.Id).Error)
				assert.Equal(t, 1000000, after.RemainQuota)
			})
		}
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", 100).Error)
	})
	t.Run("wallet_image_top_up_keeps_accounting", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Request.Header.Set("Accept-Language", "en")
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", 1000).Error)
		info := &relaycommon.RelayInfo{RequestId: common.NewRequestId(), UserId: token.UserId, TokenId: token.Id, TokenKey: token.Key, ImageRequestCount: 1, Request: &dto.ImageRequest{}, UserSetting: dto.UserSetting{BillingPreference: "wallet_only"}}
		session, apiErr := service.NewBillingSession(c, info, 100)
		require.Nil(t, apiErr)
		require.NotNil(t, session)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", 50).Error)
		reserveErr := session.Reserve(200)
		require.Error(t, reserveErr)
		var host *types.NewAPIError
		require.ErrorAs(t, reserveErr, &host)
		message, display := service.WalletQuotaErrorPresentation(host)
		assert.Equal(t, "wallet quota insufficient", message)
		assert.Equal(t, "$0.0001", display)
		assert.Equal(t, 100, session.GetPreConsumedQuota())
		session.Refund(c)
		require.Eventually(t, func() bool {
			var u model.User
			var k model.Token
			return f.db.First(&u, token.UserId).Error == nil && f.db.First(&k, token.Id).Error == nil && u.Quota == 150 && k.RemainQuota == 1000000
		}, 3*time.Second, 5*time.Millisecond)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", 100).Error)
	})
	t.Run("host_provenance_and_native_redaction", func(t *testing.T) {
		require.NoError(t, f.db.AutoMigrate(&model.SubscriptionPlan{}, &model.UserSubscription{}, &model.SubscriptionPreConsumeRecord{}))
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Request.Header.Set("Accept-Language", "en")
		info := &relaycommon.RelayInfo{RequestId: common.NewRequestId(), UserId: token.UserId, TokenId: token.Id, TokenKey: token.Key, UserSetting: dto.UserSetting{BillingPreference: "wallet_only"}}
		_, host := service.NewBillingSession(c, info, 500)
		require.NotNil(t, host)
		assert.Equal(t, "Insufficient user quota", host.Error())
		assert.Equal(t, "Insufficient user quota", host.ToClaudeError().Message)
		raw, err := common.Marshal(host.ToOpenAIError())
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "0.000200")
		message, display := service.WalletQuotaErrorPresentation(host)
		assert.Contains(t, message, "0.000200")
		assert.Equal(t, "$0.0002", display)
		for _, untrusted := range []*types.NewAPIError{
			types.NewErrorWithStatusCode(errors.New("same public code"), types.ErrorCodeInsufficientUserQuota, 403),
			types.WithOpenAIError(types.OpenAIError{Message: "upstream failure", Code: "insufficient_user_quota", Type: "upstream_error"}, 403),
			types.NewErrorWithStatusCode(errors.New("token shortfall"), types.ErrorCodePreConsumeTokenQuotaFailed, 403),
		} {
			message, display = service.WalletQuotaErrorPresentation(untrusted)
			assert.Equal(t, untrusted.Error(), message)
			assert.Empty(t, display)
		}
		info.UserSetting.BillingPreference = "wallet_first"
		_, fallback := service.NewBillingSession(c, info, 500)
		require.NotNil(t, fallback)
		assert.Equal(t, types.ErrorCodeInsufficientUserQuota, fallback.GetErrorCode())
		message, display = service.WalletQuotaErrorPresentation(fallback)
		assert.Empty(t, display)
		assert.NotContains(t, message, "0.000200")
		assert.NotContains(t, message, "remaining")
		plan := model.SubscriptionPlan{Title: "wallet fallback", QuotaResetPeriod: "never"}
		require.NoError(t, f.db.Create(&plan).Error)
		sub := model.UserSubscription{UserId: token.UserId, PlanId: plan.Id, AmountTotal: 1000, Status: "active", StartTime: time.Now().Unix(), EndTime: time.Now().Unix() + 3600}
		require.NoError(t, f.db.Create(&sub).Error)
		info.RequestId = common.NewRequestId()
		session, fallbackErr := service.NewBillingSession(c, info, 500)
		require.Nil(t, fallbackErr)
		require.NotNil(t, session)
		assert.Equal(t, service.BillingSourceSubscription, info.BillingSource)
		require.NoError(t, session.Settle(500))
		var saved model.UserSubscription
		require.NoError(t, f.db.First(&saved, sub.Id).Error)
		assert.Equal(t, int64(500), saved.AmountUsed)
		var fundedUser model.User
		require.NoError(t, f.db.First(&fundedUser, token.UserId).Error)
		assert.Equal(t, 100, fundedUser.Quota, "subscription fallback must leave wallet unchanged")
		var consumedToken model.Token
		require.NoError(t, f.db.First(&consumedToken, token.Id).Error)
		assert.Equal(t, 999500, consumedToken.RemainQuota)
		assert.Equal(t, 500, consumedToken.UsedQuota)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(map[string]any{"remain_quota": 1000000, "used_quota": 0}).Error)
		// A source whose observation read failed cannot fabricate a wallet zero.
		callback := "wallet_observation_fault"
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
			if tx.Statement.Table == "users" && len(tx.Statement.Selects) == 1 && tx.Statement.Selects[0] == "quota" {
				tx.AddError(errors.New("quota read failed"))
			}
		}))
		info.UserSetting.BillingPreference = "wallet_only"
		_, failed := service.NewBillingSession(c, info, 500)
		require.NotNil(t, failed)
		require.NoError(t, f.db.Callback().Query().Remove(callback))
		_, display = service.WalletQuotaErrorPresentation(failed)
		assert.Empty(t, display)
		assert.Equal(t, types.ErrorCodeQueryDataError, failed.GetErrorCode())
	})
	t.Run("console_en_US_profile", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Request.Header.Set("Accept-Language", "en")
		info := &relaycommon.RelayInfo{RequestId: common.NewRequestId(), UserId: token.UserId, TokenId: token.Id, TokenKey: token.Key, UserSetting: dto.UserSetting{BillingPreference: "wallet_only"}}
		for _, tc := range []struct {
			mode         string
			quota        int
			rate         float64
			symbol, want string
		}{
			{"USD", 0, 1, "", "$0"}, {"USD", 1, 1, "", "$0.0001"}, {"USD", -1, 1, "", "-$0.0001"},
			{"USD", 499999, 1, "", "$1"}, {"USD", 500000, 1, "", "$1"}, {"USD", 502500, 1, "", "$1.01"},
			{"USD", 500000000, 1, "", "$1,000"}, {"CNY", 502500, 7, "", "¥7.03"},
			{"CUSTOM", 502500, 2, " 🐱 ", "🐱 2.01"}, {"CUSTOM", 500000000, 2, " ", "¤ 2,000"},
			{"TOKENS", 999, 1, "", "999"}, {"TOKENS", 1000, 1, "", "1k"}, {"TOKENS", 1050, 1, "", "1.1k"},
			{"TOKENS", 1250, 1, "", "1.3k"}, {"TOKENS", -1250, 1, "", "-1.3k"}, {"TOKENS", 502500, 1, "", "502.5k"},
			{"USD", 9007199254740992, 1, "", ""}, {"INVALID", 100, 1, "", ""},
			{"CNY", 100, math.NaN(), "", ""}, {"CUSTOM", 100, 0, "x", ""}, {"CUSTOM", 100, 2, "x\ny", ""},
		} {
			t.Run(fmt.Sprintf("%s_%d_%s", tc.mode, tc.quota, tc.symbol), func(t *testing.T) {
				cfg := operation_setting.GetGeneralSetting()
				cfg.QuotaDisplayType = tc.mode
				cfg.CustomCurrencySymbol = tc.symbol
				cfg.CustomCurrencyExchangeRate = tc.rate
				rate := operation_setting.USDExchangeRate
				operation_setting.USDExchangeRate = tc.rate
				defer func() { operation_setting.USDExchangeRate = rate }()
				require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", tc.quota).Error)
				_, host := service.NewBillingSession(c, info, max(1, tc.quota+1))
				require.NotNil(t, host)
				_, display := service.WalletQuotaErrorPresentation(host)
				assert.Equal(t, tc.want, display)
			})
		}
		operation_setting.GetGeneralSetting().QuotaDisplayType = "USD"
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Update("quota", 100).Error)
		for _, unit := range []float64{0, -1, math.NaN(), math.Inf(1)} {
			common.QuotaPerUnit = unit
			_, host := service.NewBillingSession(c, info, 500)
			require.NotNil(t, host)
			_, display := service.WalletQuotaErrorPresentation(host)
			assert.Empty(t, display)
		}
		common.QuotaPerUnit = 500000
	})
	t.Run("redis_observation_current_DB_permission", func(t *testing.T) {
		endpoint := os.Getenv("NEWAPI_W02_REDIS_ADDR")
		if endpoint == "" {
			t.Skip("owned Redis endpoint not supplied")
		}
		oldEnabled, oldRDB := common.RedisEnabled, common.RDB
		rdb := redis.NewClient(&redis.Options{Addr: endpoint, DB: 15})
		require.NoError(t, rdb.Ping(context.Background()).Err())
		redisUser := *f.users["owner"]
		redisUser.Id = int(time.Now().UnixNano()%1_000_000_000) + 1_000_000_000
		redisUser.Username = fmt.Sprintf("w02-quota-%d", redisUser.Id)
		redisUser.AffCode = redisUser.Username
		redisUser.Quota = 100
		require.NoError(t, f.db.Create(&redisUser).Error)
		redisToken := token
		redisToken.Id = 0
		redisToken.UserId = redisUser.Id
		redisToken.Key = common.NewRequestId()
		redisToken.AllowUserQuotaQuery = true
		require.NoError(t, f.db.Create(&redisToken).Error)
		key := fmt.Sprintf("user:%d", redisUser.Id)
		keys := []string{key, fmt.Sprintf("auth:user:fence:%d", redisUser.Id), fmt.Sprintf("auth:user:version:%d", redisUser.Id)}
		existed, err := rdb.Exists(context.Background(), keys...).Result()
		require.NoError(t, err)
		require.Zero(t, existed, "fixture must not replace another owner's Redis key")
		t.Cleanup(func() {
			common.RedisEnabled, common.RDB = oldEnabled, oldRDB
			require.NoError(t, rdb.Del(context.Background(), keys...).Err())
			require.NoError(t, rdb.Close())
		})
		common.RedisEnabled, common.RDB = true, rdb
		cached, err := model.GetUserCache(redisUser.Id)
		require.NoError(t, err)
		assert.Equal(t, 100, cached.Quota)
		require.NoError(t, rdb.HSet(context.Background(), key, "Quota", 37).Err())
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Request.Header.Set("Accept-Language", "en")
		info := &relaycommon.RelayInfo{UserId: redisToken.UserId, TokenId: redisToken.Id, TokenKey: redisToken.Key, UserSetting: dto.UserSetting{BillingPreference: "wallet_only"}}
		_, host := service.NewBillingSession(c, info, 500)
		require.NotNil(t, host)
		message, display := service.WalletQuotaErrorPresentation(host)
		assert.Contains(t, message, "0.000074")
		assert.Equal(t, "$0.0001", display)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", redisToken.Id).Update("allow_user_quota_query", false).Error)
		message, display = service.WalletQuotaErrorPresentation(host)
		assert.Empty(t, display)
		assert.Equal(t, "Insufficient user quota", message)
		common.RedisEnabled, common.RDB = oldEnabled, oldRDB
	})
	var afterUser model.User
	var afterToken model.Token
	require.NoError(t, f.db.First(&afterUser, token.UserId).Error)
	require.NoError(t, f.db.First(&afterToken, token.Id).Error)
	assert.Equal(t, 100, afterUser.Quota)
	assert.Zero(t, afterUser.UsedQuota)
	assert.Zero(t, afterUser.RequestCount)
	assert.Equal(t, 1000000, afterToken.RemainQuota)
	assert.Zero(t, afterToken.UsedQuota)
	var logs int64
	require.NoError(t, model.LOG_DB.Model(&model.Log{}).Where("type = ?", model.LogTypeConsume).Count(&logs).Error)
	assert.Zero(t, logs)
}
