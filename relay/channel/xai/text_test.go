package xai

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXAIStreamHandlerUsageDetails(t *testing.T) {
	oldTimeout := constant.StreamingTimeout
	constant.StreamingTimeout = 30
	t.Cleanup(func() { constant.StreamingTimeout = oldTimeout })

	for _, tc := range []struct {
		name    string
		details string
		prompt  dto.InputTokenDetails
		output  dto.OutputTokenDetails
	}{
		{
			name:    "cache and completion details",
			details: `,"prompt_tokens_details":{"cached_tokens":60,"text_tokens":80,"image_tokens":20},"completion_tokens_details":{"reasoning_tokens":15,"text_tokens":25}`,
			prompt:  dto.InputTokenDetails{CachedTokens: 60, TextTokens: 80, ImageTokens: 20},
			output:  dto.OutputTokenDetails{ReasoningTokens: 15, TextTokens: 25},
		},
		{name: "details absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			body := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n" +
				`data: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":25,"total_tokens":140` + tc.details + "}}\n\ndata: [DONE]\n\n"
			resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
			info := &relaycommon.RelayInfo{ChannelMeta: &relaycommon.ChannelMeta{UpstreamModelName: "grok-3-mini"}, DisablePing: true}

			usage, apiErr := xAIStreamHandler(c, info, resp)
			require.Nil(t, apiErr)
			require.NotNil(t, usage)
			assert.Equal(t, 100, usage.PromptTokens)
			assert.Equal(t, 140, usage.TotalTokens)
			assert.Equal(t, 40, usage.CompletionTokens)
			assert.Equal(t, tc.prompt, usage.PromptTokensDetails)
			assert.Equal(t, tc.output, usage.CompletionTokenDetails)

			var forwarded *dto.Usage
			for line := range strings.SplitSeq(w.Body.String(), "\n") {
				data, ok := strings.CutPrefix(line, "data: ")
				if !ok || data == "[DONE]" {
					continue
				}
				var chunk dto.ChatCompletionsStreamResponse
				require.NoError(t, common.UnmarshalJsonStr(data, &chunk))
				if chunk.Usage != nil {
					forwarded = chunk.Usage
				}
			}
			require.NotNil(t, forwarded)
			assert.Equal(t, 40, forwarded.CompletionTokens)
			assert.Equal(t, tc.prompt, forwarded.PromptTokensDetails)
			assert.Equal(t, tc.output, forwarded.CompletionTokenDetails)
			assert.Contains(t, w.Body.String(), "data: [DONE]")
		})
	}
}
