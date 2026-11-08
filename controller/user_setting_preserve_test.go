package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateUserSettingPreservesPreferences(t *testing.T) {
	db := setupManageUserTestDB(t)
	gin.SetMode(gin.TestMode)
	disabled := false
	for _, tc := range []struct {
		name    string
		role    int
		request UpdateUserSettingRequest
	}{
		{"email", common.RoleCommonUser, UpdateUserSettingRequest{QuotaWarningType: dto.NotifyTypeEmail, NotificationEmail: "notify@example.com", UpstreamModelUpdateNotifyEnabled: &disabled}},
		{"webhook", common.RoleAdminUser, UpdateUserSettingRequest{QuotaWarningType: dto.NotifyTypeWebhook, WebhookUrl: "https://example.com/hook", WebhookSecret: "replacement"}},
		{"webhook empty secret", common.RoleCommonUser, UpdateUserSettingRequest{QuotaWarningType: dto.NotifyTypeWebhook, WebhookUrl: "https://example.com/hook"}},
		{"bark", common.RoleCommonUser, UpdateUserSettingRequest{QuotaWarningType: dto.NotifyTypeBark, BarkUrl: "https://example.com/bark"}},
		{"gotify", common.RoleAdminUser, UpdateUserSettingRequest{QuotaWarningType: dto.NotifyTypeGotify, GotifyUrl: "https://example.com/gotify", GotifyToken: "replacement", GotifyPriority: 11, UpstreamModelUpdateNotifyEnabled: &disabled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := dto.UserSetting{
				NotifyType: dto.NotifyTypeWebhook, QuotaWarningThreshold: 10,
				WebhookUrl: "https://example.com/old", WebhookSecret: "old",
				NotificationEmail: "old@example.com", BarkUrl: "https://example.com/old-bark",
				GotifyUrl: "https://example.com/old-gotify", GotifyToken: "old", GotifyPriority: 8,
				UpstreamModelUpdateNotifyEnabled: true,
				SidebarModules:                   `{"chat":false}`, BillingPreference: "wallet_only", Language: "ja",
			}
			user := model.User{Username: "settings-" + tc.name, Role: tc.role, AffCode: common.GetRandomString(8)}
			user.SetSetting(existing)
			require.NoError(t, db.Create(&user).Error)
			tc.request.QuotaWarningThreshold = 25
			tc.request.AcceptUnsetModelRatioModel = true
			tc.request.RecordIpLog = true
			body, err := common.Marshal(tc.request)
			require.NoError(t, err)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPut, "/api/user/setting", bytes.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Set("id", user.Id)
			UpdateUserSetting(c)
			require.Equal(t, http.StatusOK, recorder.Code)
			var response struct {
				Success bool `json:"success"`
			}
			require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &response))
			require.True(t, response.Success, recorder.Body.String())
			var saved model.User
			require.NoError(t, db.First(&saved, user.Id).Error)
			expected := dto.UserSetting{
				NotifyType: tc.request.QuotaWarningType, QuotaWarningThreshold: 25,
				UpstreamModelUpdateNotifyEnabled: true, AcceptUnsetRatioModel: true, RecordIpLog: true,
				SidebarModules: existing.SidebarModules, BillingPreference: existing.BillingPreference, Language: existing.Language,
				WebhookUrl: tc.request.WebhookUrl, WebhookSecret: tc.request.WebhookSecret,
				NotificationEmail: tc.request.NotificationEmail, BarkUrl: tc.request.BarkUrl,
				GotifyUrl: tc.request.GotifyUrl, GotifyToken: tc.request.GotifyToken,
			}
			if tc.request.QuotaWarningType == dto.NotifyTypeGotify {
				expected.GotifyPriority = 5
			}
			if tc.role >= common.RoleAdminUser && tc.request.UpstreamModelUpdateNotifyEnabled != nil {
				expected.UpstreamModelUpdateNotifyEnabled = *tc.request.UpstreamModelUpdateNotifyEnabled
			}
			assert.Equal(t, expected, saved.GetSetting())
		})
	}
}
