package deepseek

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepSeekClaudeSchemaOrderAndThinkingSuffix(t *testing.T) {
	const format = `{"type":"json_schema","schema":{"type":"object","properties":{"reasoning":{"type":"string"},"answer":{"type":"string"}}}}`
	settings := model_setting.GetGlobalSettings()
	original := settings.ThinkingModelBlacklist
	t.Cleanup(func() { settings.ThinkingModelBlacklist = original })
	settings.ThinkingModelBlacklist = []string{"deepseek-v4-pro-max"}
	for _, tt := range []struct {
		model, origin, wantModel, thinking, effort string
	}{
		{"deepseek-v4-flash-max", "", "deepseek-v4-flash", "enabled", "max"},
		{"deepseek-v4-flash-none", "", "deepseek-v4-flash", "disabled", ""},
		{"deepseek-v4-pro-max", "", "deepseek-v4-pro-max", "", "low"},
		{"deepseek-v4-flash-max", "deepseek-v4-pro-max", "deepseek-v4-flash-max", "", "low"},
	} {
		t.Run(tt.model+"/"+tt.origin, func(t *testing.T) {
			request := &dto.ClaudeRequest{Model: tt.model, OutputConfig: common.RawMessage(`{"effort":"low","format":` + format + `,"extra":{"z":1,"a":2}}`)}
			info := &relaycommon.RelayInfo{OriginModelName: tt.origin, ChannelMeta: &relaycommon.ChannelMeta{UpstreamModelName: tt.model}}
			require.NoError(t, applyDeepSeekV4ClaudeThinkingSuffix(info, request))
			assert.Equal(t, tt.wantModel, request.Model)
			assert.Equal(t, tt.wantModel, info.UpstreamModelName)
			var output map[string]common.RawMessage
			require.NoError(t, common.Unmarshal(request.OutputConfig, &output))
			assert.Equal(t, format, string(output["format"]))
			assert.Equal(t, `{"z":1,"a":2}`, string(output["extra"]))
			if tt.effort == "" {
				assert.NotContains(t, output, "effort")
			} else {
				assert.Equal(t, `"`+tt.effort+`"`, string(output["effort"]))
			}
			if tt.thinking == "" {
				assert.Nil(t, request.Thinking)
			} else {
				require.NotNil(t, request.Thinking)
				assert.Equal(t, tt.thinking, request.Thinking.Type)
				assert.Equal(t, tt.effort, info.GetReasoningEffort())
			}
		})
	}
}
