package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateOptionRejectsRetiredFrontendTheme(t *testing.T) {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(
		http.MethodPut,
		"/api/option/",
		strings.NewReader(`{"key":"theme.frontend","value":"classic"}`),
	)

	UpdateOption(context)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.JSONEq(t, `{"success":false,"message":"The Classic frontend has been removed. The theme can only be set to default","message_key":"The Classic frontend has been removed. The theme can only be set to default"}`, response.Body.String())
}

func TestGetStatusAdvertisesDefaultDashboard(t *testing.T) {
	previousMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() { common.OptionMap = previousMap })
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/status", nil)

	GetStatus(context)

	var payload struct {
		Success bool           `json:"success"`
		Data    map[string]any `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &payload))
	assert.True(t, payload.Success)
	assert.Equal(t, "default", payload.Data["theme"])
	assert.Equal(t, map[string]any{"enabled": false}, payload.Data["oauth"])
	features, ok := payload.Data["client_features"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, features["oauth"])
	assert.Equal(t, false, features["token_usage_logs"])
	assert.Equal(t, false, features["model_metadata"])
}

func TestGetStatusOAuthStaysDisabledUntilTopologyValidated(t *testing.T) {
	const issuer = "https://auth.example.com/"
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: "https://hydra-admin.example:4445/admin/oauth2/introspect",
		Issuer: issuer, Audience: "status-userinfo", ClientIDs: []string{"desktop-client", "second-client"},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{
		Enabled: true, RevocationEnabled: true, AdminBaseURL: "https://hydra-admin.example:4445/",
		AuthorizationURL: issuer + "oauth2/auth",
	}, resource)
	require.NoError(t, err)
	_, err = service.NewOAuthPublic(service.OAuthPublicConfig{Enabled: true, BaseURL: "https://hydra-public.example:4444/"}, bridge)
	require.NoError(t, err)
	previous := service.SwapOAuthProviderBridge(bridge)
	t.Cleanup(func() { service.SwapOAuthProviderBridge(previous) })
	oldAddress := system_setting.ServerAddress
	system_setting.ServerAddress = issuer
	t.Setenv("FRONTEND_BASE_URL", "")
	t.Cleanup(func() { system_setting.ServerAddress = oldAddress })

	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	GetStatus(context)

	var payload struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &payload))
	assert.Equal(t, map[string]any{"enabled": false}, payload.Data["oauth"])
	features := payload.Data["client_features"].(map[string]any)
	assert.Equal(t, false, features["oauth"])
	assert.Equal(t, false, features["token_usage_logs"])
	assert.Equal(t, false, features["model_metadata"])
	assert.NotContains(t, response.Body.String(), "desktop-client")
	assert.NotContains(t, response.Body.String(), "hydra-admin.example")
	assert.NotContains(t, response.Body.String(), "hydra-public.example")
}
