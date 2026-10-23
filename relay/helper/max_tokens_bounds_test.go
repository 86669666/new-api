package helper

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaxTokensBounds guards the billing invariant that user-supplied max
// token fields are bounded on every relay format. These values feed
// pre-consume quota math (preConsumedTokens * ratio); a huge or
// wrapped-negative value (e.g. 18446744073686646784 parsed into *uint) must
// be rejected at validation instead of corrupting the pre-charge.
func TestMaxTokensBounds(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newJSONContext := func(t *testing.T, body string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBufferString(body))
		c.Request.Header.Set("Content-Type", "application/json")
		return c
	}

	const hugeN = "18446744073686646784"

	t.Run("openai max_tokens overflow rejected", func(t *testing.T) {
		c := newJSONContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_tokens":`+hugeN+`}`)
		_, err := GetAndValidateTextRequest(c, relayconstant.RelayModeChatCompletions)
		require.Error(t, err)
		require.Contains(t, err.Error(), "max_tokens is invalid")
	})

	t.Run("openai max_completion_tokens overflow rejected", func(t *testing.T) {
		c := newJSONContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":`+hugeN+`}`)
		_, err := GetAndValidateTextRequest(c, relayconstant.RelayModeChatCompletions)
		require.Error(t, err)
		require.Contains(t, err.Error(), "max_tokens is invalid")
	})

	t.Run("claude max_tokens overflow rejected", func(t *testing.T) {
		c := newJSONContext(t, `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":`+hugeN+`}`)
		_, err := GetAndValidateClaudeRequest(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "max_tokens is invalid")
	})

	t.Run("claude normal max_tokens accepted", func(t *testing.T) {
		c := newJSONContext(t, `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":8192}`)
		req, err := GetAndValidateClaudeRequest(c)
		require.NoError(t, err)
		require.EqualValues(t, 8192, *req.MaxTokens)
	})

	t.Run("gemini maxOutputTokens overflow rejected", func(t *testing.T) {
		c := newJSONContext(t, `{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":`+hugeN+`}}`)
		_, err := GetAndValidateGeminiRequest(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "maxOutputTokens is invalid")
	})

	t.Run("responses max_output_tokens overflow rejected", func(t *testing.T) {
		c := newJSONContext(t, `{"model":"gpt-4o","input":"hi","max_output_tokens":`+hugeN+`}`)
		_, err := GetAndValidateResponsesRequest(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "max_output_tokens is invalid")
	})
}

func TestSGLangMinTokensBounds(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"0", true}, {"8192", true}, {"-1", false}, {"18446744073686646784", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"served-model","messages":[{"role":"user","content":"hi"}],"min_tokens":`+tc.value+`}`))
			c.Request.Header.Set("Content-Type", "application/json")
			request, err := GetAndValidateTextRequest(c, relayconstant.RelayModeChatCompletions)
			if !tc.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, request.MinTokens)
		})
	}
}

func TestValidateOAuthDerivedTextRequest(t *testing.T) {
	const valid = `{"model":"selected-model","messages":[{"role":"user","content":"hi"}],"max_tokens":1}`
	const message = `{"role":"user","content":"hi"}`
	type requestCase struct {
		name       string
		body       string
		ok         bool
		completion bool
		max        uint
		n          bool
		stream     bool
	}
	cases := []requestCase{
		{name: "minimal", body: valid, ok: true},
		{name: "explicit_n_stream", body: strings.Replace(valid, `"max_tokens":`, `"n":1,"stream":false,"max_tokens":`, 1), ok: true, n: true, stream: true},
		{name: "explicit_n", body: strings.Replace(valid, `"max_tokens":`, `"n":1,"max_tokens":`, 1), ok: true, n: true},
		{name: "explicit_stream", body: strings.Replace(valid, `"max_tokens":`, `"stream":false,"max_tokens":`, 1), ok: true, stream: true},
		{name: "all_roles", body: strings.Replace(valid, message, `{"role":"system","content":"rules"},`+message+`,{"role":"assistant","content":"reply"}`, 1), ok: true},
		{name: "surrounding_whitespace_preserved", body: strings.ReplaceAll(strings.Replace(valid, `"hi"`, `"  hi\n "`, 1), `"selected-model"`, `" selected-model "`), ok: true},
		{name: "escaped_keys", body: strings.ReplaceAll(strings.Replace(valid, `"model"`, `"mo\u0064el"`, 1), `"content"`, `"cont\u0065nt"`), ok: true},
		{name: "unicode_content", body: strings.Replace(valid, `"hi"`, `"你好 🌍"`, 1), ok: true},
		{name: "missing_model", body: strings.Replace(valid, `"model":"selected-model",`, "", 1)},
		{name: "null_model", body: strings.Replace(valid, `"selected-model"`, `null`, 1)},
		{name: "empty_model", body: strings.Replace(valid, `"selected-model"`, `""`, 1)},
		{name: "whitespace_model", body: strings.Replace(valid, `"selected-model"`, `" \t\n\u3000"`, 1)},
		{name: "object_model", body: strings.Replace(valid, `"selected-model"`, `{}`, 1)},
		{name: "missing_messages", body: strings.Replace(valid, `"messages":[`+message+`],`, "", 1)},
		{name: "null_messages", body: strings.Replace(valid, `[`+message+`]`, `null`, 1)},
		{name: "empty_messages", body: strings.Replace(valid, `[`+message+`]`, `[]`, 1)},
		{name: "object_messages", body: strings.Replace(valid, `[`+message+`]`, message, 1)},
		{name: "string_messages", body: strings.Replace(valid, `[`+message+`]`, `"hi"`, 1)},
		{name: "missing_max", body: strings.Replace(valid, `,"max_tokens":1`, "", 1)},
		{name: "both_max", body: strings.Replace(valid, `"max_tokens":1`, `"max_tokens":1,"max_completion_tokens":1`, 1)},
		{name: "both_max_one_null", body: strings.Replace(valid, `"max_tokens":1`, `"max_tokens":1,"max_completion_tokens":null`, 1)},
		{name: "no_user", body: strings.Replace(valid, `"user"`, `"system"`, 1)},
		{name: "unsupported_role", body: strings.Replace(valid, `"user"`, `"tool"`, 1)},
		{name: "whitespace_role", body: strings.Replace(valid, `"user"`, `" user "`, 1)},
		{name: "null_role", body: strings.Replace(valid, `"user"`, `null`, 1)},
		{name: "nonstring_role", body: strings.Replace(valid, `"user"`, `1`, 1)},
		{name: "missing_role", body: strings.Replace(valid, `"role":"user",`, "", 1)},
		{name: "missing_content", body: strings.Replace(valid, `,"content":"hi"`, "", 1)},
		{name: "null_content", body: strings.Replace(valid, `"hi"`, `null`, 1)},
		{name: "empty_content", body: strings.Replace(valid, `"hi"`, `""`, 1)},
		{name: "whitespace_content", body: strings.Replace(valid, `"hi"`, `" \t\n\u3000"`, 1)},
		{name: "object_content", body: strings.Replace(valid, `"hi"`, `{"text":"hi"}`, 1)},
		{name: "nested_content", body: strings.Replace(valid, `"hi"`, `[["hi"]]`, 1)},
		{name: "typed_text_content", body: strings.Replace(valid, `"hi"`, `[{"type":"text","text":"hi"}]`, 1)},
		{name: "number_content", body: strings.Replace(valid, `"hi"`, `123`, 1)},
		{name: "null_message", body: strings.Replace(valid, message, `null`, 1)},
		{name: "array_message", body: strings.Replace(valid, message, `[]`, 1)},
		{name: "string_message", body: strings.Replace(valid, message, `"hi"`, 1)},
		{name: "invalid_later_message", body: strings.Replace(valid, message, message+`,{"role":"assistant","content":[]}`, 1)},
		{name: "duplicate_model", body: strings.Replace(valid, `"model":`, `"model":"other","model":`, 1)},
		{name: "escaped_duplicate_model", body: strings.Replace(valid, `"model":`, `"mo\u0064el":"other","model":`, 1)},
		{name: "duplicate_messages", body: strings.Replace(valid, `"messages":`, `"messages":[],"messages":`, 1)},
		{name: "duplicate_n", body: strings.Replace(valid, `"model":`, `"n":2,"n":1,"model":`, 1)},
		{name: "escaped_duplicate_stream", body: strings.Replace(valid, `"model":`, `"str\u0065am":true,"stream":false,"model":`, 1)},
		{name: "duplicate_role", body: strings.Replace(valid, `"role":`, `"role":"tool","role":`, 1)},
		{name: "escaped_duplicate_content", body: strings.Replace(valid, `"content":`, `"cont\u0065nt":[],"content":`, 1)},
		{name: "duplicate_later_message", body: strings.Replace(valid, message, message+`,{"role":"assistant","role":"user","content":"hi"}`, 1)},
		{name: "empty_body"},
		{name: "invalid_json", body: `{"model":"private-input-canary"`},
		{name: "trailing_json", body: valid + `{}`},
		{name: "null_envelope", body: `null`},
		{name: "array_envelope", body: `[` + valid + `]`},
		{name: "invalid_utf8", body: strings.Replace(valid, "hi", "\xff", 1)},
	}
	for _, field := range []string{"max_tokens", "max_completion_tokens"} {
		body := strings.Replace(valid, "max_tokens", field, 1)
		cases = append(cases,
			requestCase{name: field + "_at_limit", body: strings.Replace(body, `:1}`, fmt.Sprintf(":%d}", maxTokensLimit), 1), ok: true, max: maxTokensLimit, completion: field == "max_completion_tokens"},
			requestCase{name: field + "_minimum", body: body, ok: true, completion: field == "max_completion_tokens"},
			requestCase{name: field + "_duplicate", body: strings.Replace(body, `"`+field+`":`, `"`+field+`":2,"`+field+`":`, 1)},
			requestCase{name: field + "_escaped_duplicate", body: strings.Replace(body, `"`+field+`":`, `"`+strings.Replace(field, "tokens", `to\u006bens`, 1)+`":2,"`+field+`":`, 1)},
		)
		for _, value := range []string{"0", "-0", "-1", "1.0", "1e0", "null", `"1"`, "true", "[]", "{}", "18446744073686646784", "18446744073709551616", fmt.Sprint(maxTokensLimit + 1)} {
			cases = append(cases, requestCase{name: field + "_reject_" + value, body: strings.Replace(body, `:1}`, ":"+value+"}", 1)})
		}
	}
	for _, optional := range []struct {
		field  string
		values []string
	}{
		{"n", []string{"0", "-1", "2", "1.0", "1e0", "null", `"1"`, "true", "[]", "{}", "18446744073686646784"}},
		{"stream", []string{"true", "null", `"false"`, "0", "[]", "{}"}},
	} {
		field := optional.field
		for _, value := range optional.values {
			cases = append(cases, requestCase{name: field + "_reject_" + value, body: strings.Replace(valid, `"model":`, `"`+field+`":`+value+`,"model":`, 1)})
		}
	}
	for _, field := range []string{"tools", "tool_choice", "functions", "function_call", "audio", "modalities", "image", "stream_options", "temperature", "service_tier", "user", "unknown", "Model", "max_output_tokens"} {
		cases = append(cases, requestCase{name: "unsupported_" + field, body: strings.Replace(valid, `"model":`, `"`+field+`":null,"model":`, 1)})
	}
	for _, field := range []string{"tools", "function_call", "audio", "image", "name", "tool_call_id", "unknown"} {
		cases = append(cases, requestCase{name: "unsupported_message_" + field, body: strings.Replace(valid, `"role":`, `"`+field+`":null,"role":`, 1)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			request, err := ValidateOAuthDerivedTextRequest(body)
			assert.Equal(t, tc.body, string(body), "validation must not modify input")
			if !tc.ok {
				require.EqualError(t, err, "invalid OAuth derived text request")
				assert.Nil(t, request)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, request)
			maxValue := tc.max
			if maxValue == 0 {
				maxValue = 1
			}
			if tc.completion {
				require.NotNil(t, request.MaxCompletionTokens)
				assert.Equal(t, maxValue, *request.MaxCompletionTokens)
				assert.Nil(t, request.MaxTokens)
			} else {
				require.NotNil(t, request.MaxTokens)
				assert.Equal(t, maxValue, *request.MaxTokens)
				assert.Nil(t, request.MaxCompletionTokens)
			}
			if tc.n {
				require.NotNil(t, request.N)
				assert.Equal(t, 1, *request.N)
			} else {
				assert.Nil(t, request.N)
			}
			if tc.stream {
				require.NotNil(t, request.Stream)
				assert.False(t, *request.Stream)
			} else {
				assert.Nil(t, request.Stream)
			}
			var original map[string]any
			require.NoError(t, common.Unmarshal(body, &original))
			assert.Equal(t, original["model"], request.Model)
			for i, raw := range original["messages"].([]any) {
				msg := raw.(map[string]any)
				assert.Equal(t, msg["role"], request.Messages[i].Role)
				assert.Equal(t, msg["content"], request.Messages[i].Content)
			}
			encoded, err := common.Marshal(request)
			require.NoError(t, err)
			for i := range body {
				body[i] = ' '
			}
			afterMutation, err := common.Marshal(request)
			require.NoError(t, err)
			assert.Equal(t, encoded, afterMutation, "returned DTO must not retain borrowed input")
		})
	}
}
