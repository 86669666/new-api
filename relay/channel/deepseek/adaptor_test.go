package deepseek

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepSeekToolsSearchRequestURL(t *testing.T) {
	for _, baseURL := range []string{"https://provider.example", "https://provider.example/"} {
		t.Run(baseURL, func(t *testing.T) {
			info := &relaycommon.RelayInfo{
				RelayMode:   relayconstant.RelayModeToolsSearch,
				ChannelMeta: &relaycommon.ChannelMeta{ChannelBaseUrl: baseURL},
			}
			actual, err := (&Adaptor{}).GetRequestURL(info)
			require.NoError(t, err)
			assert.Equal(t, "https://provider.example/v1/tools/search", actual)
		})
	}
}

func TestDeepSeekV4FlashOpenAIThinkingSuffix(t *testing.T) {
	settings := model_setting.GetGlobalSettings()
	previous := settings.ThinkingModelBlacklist
	settings.ThinkingModelBlacklist = nil
	t.Cleanup(func() { settings.ThinkingModelBlacklist = previous })
	for _, testCase := range []struct {
		model    string
		thinking string
		effort   string
	}{
		{model: "deepseek-v4-flash-max", thinking: "enabled", effort: "max"},
		{model: "deepseek-v4-flash-none", thinking: "disabled"},
	} {
		t.Run(testCase.model, func(t *testing.T) {
			zero := 0.0
			request := &dto.GeneralOpenAIRequest{Model: testCase.model, Temperature: &zero}
			info := &relaycommon.RelayInfo{ChannelMeta: &relaycommon.ChannelMeta{UpstreamModelName: testCase.model}}
			converted, err := (&Adaptor{}).ConvertOpenAIRequest(nil, info, request)
			require.NoError(t, err)
			assert.Same(t, request, converted)
			assert.Equal(t, "deepseek-v4-flash", request.Model)
			assert.Equal(t, request.Model, info.UpstreamModelName)
			assert.JSONEq(t, `{"type":"`+testCase.thinking+`"}`, string(request.THINKING))
			assert.Equal(t, testCase.effort, request.ReasoningEffort)
			encoded, err := common.Marshal(request)
			require.NoError(t, err)
			assert.Contains(t, string(encoded), `"temperature":0`)
		})
	}
}
