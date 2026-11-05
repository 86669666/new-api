package relay

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAlphaSearchRequestBodyPreservesUnknownFields(t *testing.T) {
	raw := []byte(`{
		"id":"req_1",
		"model":"gpt-5.1",
		"input":[{"role":"user","content":"hi"}],
		"commands":{"search_query":[{"q":"weather","recency":1}]},
		"settings":{"locale":"en"},
		"future_field":{"nested":true}
	}`)

	out, err := buildAlphaSearchRequestBody(raw, "gpt-5.1", "gpt-5.1-mapped")
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, common.Unmarshal(out, &body))
	assert.Equal(t, "gpt-5.1-mapped", body["model"])
	assert.Equal(t, "req_1", body["id"])
	require.Contains(t, body, "commands")
	require.Contains(t, body, "settings")
	require.Contains(t, body, "future_field")
	require.Contains(t, body, "input")

	commands, ok := body["commands"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, commands, "search_query")

	future, ok := body["future_field"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, future["nested"])
}

func TestBuildAlphaSearchRequestBodyNoMappingKeepsRawBytes(t *testing.T) {
	raw := []byte(`{"model":"gpt-5.1","commands":{"search_query":[{"q":"x"}]},"future_field":1}`)
	out, err := buildAlphaSearchRequestBody(raw, "gpt-5.1", "gpt-5.1")
	require.NoError(t, err)
	assert.Equal(t, raw, out)
}

func TestBuildAlphaSearchRequestBodyRewritesModel(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"single model keeps its place", `{"model":"gpt-5.1","input":[]}`, `{"model":"gpt-5.1-mapped","input":[]}`},
		{"repeated model collapses", `{"model":"gpt-5.1","input":[],"model":"gpt-5.5-pro"}`, `{"input":[],"model":"gpt-5.1-mapped"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := buildAlphaSearchRequestBody([]byte(tt.raw), "gpt-5.1", "gpt-5.1-mapped")
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(out))
		})
	}
}

func TestDeepSeekToolsSearchRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		invalid bool
	}{
		{name: "valid optional values", body: `{"query":"weather","count":50,"need_content":false,"ori_question":null,"localization":"","extension":{"keep":true}}`},
		{name: "missing query", body: `{"count":1}`, invalid: true},
		{name: "count above maximum", body: `{"query":"weather","count":51}`, invalid: true},
		{name: "invalid content flag", body: `{"query":"weather","need_content":0}`, invalid: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := helper.ValidateDeepSeekSearchBody([]byte(testCase.body))
			if testCase.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDeepSeekToolsSearchResponseValidation(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		nonempty bool
		invalid  bool
	}{
		{name: "nonempty result", body: `{"results":[{"title":"title","url":"https://example.invalid","snippet":"snippet","summary":"summary","content":"body","rerank_score":2.5,"authority":-1,"site_name":null,"site_icon":null,"date":null}]}`, nonempty: true},
		{name: "empty results", body: `{"results":[]}`},
		{name: "invalid score", body: `{"results":[{"title":"title","url":"https://example.invalid","snippet":"snippet","summary":"summary","content":"body","rerank_score":4,"authority":-1,"site_name":null,"site_icon":null,"date":null}]}`, invalid: true},
		{name: "missing results array", body: `{"results":null}`, invalid: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			nonempty, err := validToolsSearchResponse([]byte(testCase.body))
			if testCase.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.nonempty, nonempty)
			}
		})
	}
}
