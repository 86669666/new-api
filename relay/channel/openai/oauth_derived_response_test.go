package openai

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type oauthDerivedResponseBody struct {
	reader     io.Reader
	readError  error
	closeError error
	bytesRead  int
	closeCount int
}

// Reader success preserves an opaque usage object; only the strict calculator
// can accept its quantities. This boundary does not reserve or settle a charge.
func TestReadOAuthDerivedTextResponseQuotaBoundary(t *testing.T) {
	const cachedUsage = `{ "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12, "prompt_tokens_details": { "cached_tokens": 4 } }`
	const responseText = "private-response-canary"
	frozenFacts := model.OAuthTextFacts{
		Model: "selected-text", ModelRatio: 2, CompletionRatio: 3,
		GroupRatio: .5, CacheRatio: .25,
	}
	for _, tc := range []struct {
		name, usage, observedModel string
		ok                         bool
	}{
		{name: "cached_text", usage: cachedUsage, observedModel: "selected-text", ok: true},
		{name: "observed_model_cannot_replace_selected_facts", usage: cachedUsage, observedModel: "upstream-search-preview", ok: true},
		{name: "duplicate_numeric", usage: `{"prompt_tokens":9,"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}`},
		{name: "escaped_duplicate_numeric", usage: `{"prompt_tokens":9,"prompt_\u0074okens":10,"completion_tokens":2,"total_tokens":12}`},
		{name: "escaped_duplicate_cached_detail", usage: `{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"prompt_tokens_details":{"cached_tokens":0,"cached_\u0074okens":4}}`},
		{name: "missing_numeric", usage: `{"prompt_tokens":10,"total_tokens":12}`},
		{name: "audio_detail", usage: `{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"prompt_tokens_details":{"audio_tokens":1}}`},
		{name: "reasoning_detail", usage: `{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"completion_tokens_details":{"reasoning_tokens":1}}`},
		{name: "unknown_detail_even_zero", usage: `{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"prompt_tokens_details":{"private-response-canary":0}}`},
		{name: "inconsistent_total", usage: `{"prompt_tokens":10,"completion_tokens":2,"total_tokens":11}`},
		{name: "cached_exceeds_prompt", usage: `{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"prompt_tokens_details":{"cached_tokens":11}}`},
		{name: "oversized_numeric", usage: `{"prompt_tokens":18446744073709551615,"completion_tokens":2,"total_tokens":12}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observedModel := tc.observedModel
			if observedModel == "" {
				observedModel = "upstream-observed-model"
			}
			original := `{"id":"chatcmpl-boundary","object":"chat.completion","created":1,"model":"` + observedModel + `","choices":[{"index":0,"message":{"role":"assistant","content":"` + responseText + `"},"finish_reason":"stop"}],"usage":` + tc.usage + `}`
			body := &oauthDerivedResponseBody{reader: strings.NewReader(original)}
			resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: -1}
			rawBody, rawUsage, err := ReadOAuthDerivedTextResponse(resp)
			assert.Equal(t, 1, body.closeCount)
			require.NoError(t, err)
			assert.Equal(t, original, string(rawBody))
			require.Equal(t, tc.usage, string(rawUsage), "usage must reach the calculator without DTO normalization")

			facts := frozenFacts
			quota, usage, err := service.CalculateOAuthDerivedTextQuota(facts, rawUsage)
			assert.Equal(t, frozenFacts, facts)
			assert.Equal(t, tc.usage, string(rawUsage))
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, 13, quota)
				assert.Equal(t, model.OAuthTextUsage{Prompt: 10, Completion: 2, Total: 12, Cached: 4}, usage)
			} else {
				require.ErrorIs(t, err, model.ErrOAuthTextCharge)
				assert.Zero(t, quota, "reader success must not authorize billing of rejected usage")
				assert.NotContains(t, err.Error(), original)
				assert.NotContains(t, err.Error(), tc.usage)
				assert.NotContains(t, err.Error(), responseText)
			}
		})
	}
}

func (b *oauthDerivedResponseBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.bytesRead += n
	if err == io.EOF && b.readError != nil {
		err = b.readError
	}
	return n, err
}

func (b *oauthDerivedResponseBody) Close() error {
	b.closeCount++
	return b.closeError
}

func TestReadOAuthDerivedTextResponse(t *testing.T) {
	const rawUsage = `{ "prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3, "prompt_tokens_details": { "cached_tokens": 0 } }`
	const valid = `{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"selected-model","choices":[{"index":0,"message":{"role":"assistant","content":"hello\\nworld","refusal":null,"annotations":[]},"finish_reason":"stop","logprobs":null}],"usage":` + rawUsage + `,"system_fingerprint":null,"service_tier":"default"}`
	const limit = 8 << 20
	const secret = "private-response-canary"
	const duplicateUsage = `{"prompt_tokens":2,"prompt_tokens":3,"prompt_tokens_details":{"cached_tokens":0,"cached_\u0074okens":1}}`
	type responseCase struct {
		name          string
		body          string
		ok            bool
		usage         string
		contentType   string
		encoding      []string
		status        int
		declared      bool
		length        int64
		uncompressed  bool
		readError     error
		closeError    error
		noRead        bool
		nilResponse   bool
		nilBody       bool
		duplicateType bool
	}
	cases := []responseCase{
		{name: "exact_body_and_usage", body: valid, ok: true},
		{name: "utf8_charset_identity", body: valid, contentType: "application/json; charset=UTF-8", encoding: []string{"identity"}, ok: true},
		{name: "correct_content_length", body: valid, declared: true, length: int64(len(valid)), ok: true},
		{name: "length_finish", body: strings.Replace(valid, `"stop"`, `"length"`, 1), ok: true},
		{name: "empty_text", body: strings.Replace(valid, `"hello\\nworld"`, `""`, 1), ok: true},
		{name: "escaped_single_usage_key", body: strings.Replace(valid, `"usage":`, `"us\u0061ge":`, 1), ok: true},
		{name: "opaque_usage_for_quota_validation", body: strings.Replace(valid, rawUsage, duplicateUsage, 1), usage: duplicateUsage, ok: true},
		{name: "no_usage_estimation", body: strings.Replace(valid, rawUsage, `{}`, 1), usage: `{}`, ok: true},
		{name: "exact_8mib", body: valid + strings.Repeat(" ", limit-len(valid)), ok: true},
		{name: "limit_plus_one", body: valid + strings.Repeat(" ", limit+1-len(valid))},
		{name: "oversize_not_drained", body: valid + strings.Repeat(" ", limit+100-len(valid))},
		{name: "declared_short", body: valid, declared: true, length: 1},
		{name: "declared_long", body: valid, declared: true, length: 1 << 60},
		{name: "declared_zero", body: valid, declared: true, length: 0},
		{name: "oversize_despite_short_length", body: valid + strings.Repeat(" ", limit+100-len(valid)), declared: true, length: 1},
		{name: "truncated_json", body: valid[:len(valid)-1]},
		{name: "truncated_transport", body: valid, readError: io.ErrUnexpectedEOF},
		{name: "read_error_after_valid_json", body: valid, readError: errors.New(secret)},
		{name: "immediate_read_error", readError: errors.New(secret)},
		{name: "close_error", body: valid, closeError: errors.New(secret)},
		{name: "outer_duplicate_usage", body: strings.Replace(valid, `"usage":`, `"usage":{},"usage":`, 1)},
		{name: "escaped_duplicate_usage", body: strings.Replace(valid, `"usage":`, `"us\u0061ge":{},"usage":`, 1)},
		{name: "outer_duplicate_id", body: strings.Replace(valid, `"id":`, `"id":"other","id":`, 1)},
		{name: "missing_usage", body: strings.Replace(valid, `,"usage":`+rawUsage, "", 1)},
		{name: "null_usage", body: strings.Replace(valid, rawUsage, `null`, 1)},
		{name: "array_usage", body: strings.Replace(valid, rawUsage, `[]`, 1)},
		{name: "string_usage", body: strings.Replace(valid, rawUsage, `"usage"`, 1)},
		{name: "error_envelope", body: `{"error":{"message":"` + secret + `"}}`},
		{name: "error_with_success", body: strings.Replace(valid, `{"id":`, `{"error":null,"id":`, 1)},
		{name: "trailing_document", body: valid + `{}`},
		{name: "malformed_json", body: `{` + secret},
		{name: "invalid_utf8", body: strings.Replace(valid, "selected-model", "\xff", 1)},
		{name: "outer_array", body: `[` + valid + `]`},
		{name: "outer_null", body: `null`},
		{name: "stream_chunk", body: strings.Replace(valid, `"chat.completion"`, `"chat.completion.chunk"`, 1)},
		{name: "delta", body: strings.Replace(valid, `"message":`, `"delta":`, 1)},
		{name: "multiple_choices", body: strings.Replace(valid, `"choices":[`, `"choices":[{},`, 1)},
		{name: "missing_choice", body: strings.Replace(valid, `"choices":`, `"other_choices":`, 1)},
		{name: "choice_duplicate_index", body: strings.Replace(valid, `"index":0`, `"index":1,"index":0`, 1)},
		{name: "null_index", body: strings.Replace(valid, `"index":0`, `"index":null`, 1)},
		{name: "wrong_index", body: strings.Replace(valid, `"index":0`, `"index":1`, 1)},
		{name: "nonassistant", body: strings.Replace(valid, `"assistant"`, `"user"`, 1)},
		{name: "null_content", body: strings.Replace(valid, `"hello\\nworld"`, `null`, 1)},
		{name: "image_content", body: strings.Replace(valid, `"hello\\nworld"`, `[{"type":"image_url","image_url":"private"}]`, 1)},
		{name: "escaped_duplicate_content", body: strings.Replace(valid, `"content":`, `"cont\u0065nt":"other","content":`, 1)},
		{name: "tool_finish", body: strings.Replace(valid, `"stop"`, `"tool_calls"`, 1)},
		{name: "unfinished", body: strings.Replace(valid, `"stop"`, `null`, 1)},
		{name: "filtered", body: strings.Replace(valid, `"stop"`, `"content_filter"`, 1)},
		{name: "refusal", body: strings.Replace(valid, `"refusal":null`, `"refusal":"no"`, 1)},
		{name: "annotation_payload", body: strings.Replace(valid, `"annotations":[]`, `"annotations":[{}]`, 1)},
		{name: "null_annotations", body: strings.Replace(valid, `"annotations":[]`, `"annotations":null`, 1)},
		{name: "logprob_payload", body: strings.Replace(valid, `"logprobs":null`, `"logprobs":{}`, 1)},
		{name: "null_created", body: strings.Replace(valid, `"created":1`, `"created":null`, 1)},
		{name: "missing_created", body: strings.Replace(valid, `"created":1,`, "", 1)},
		{name: "negative_created", body: strings.Replace(valid, `"created":1`, `"created":-1`, 1)},
		{name: "fractional_created", body: strings.Replace(valid, `"created":1`, `"created":1.5`, 1)},
		{name: "null_model", body: strings.Replace(valid, `"selected-model"`, `null`, 1)},
		{name: "nonstring_metadata", body: strings.Replace(valid, `"system_fingerprint":null`, `"system_fingerprint":{}`, 1)},
		{name: "non200", body: valid, status: 201, noRead: true},
		{name: "sse", body: valid, contentType: "text/event-stream", noRead: true},
		{name: "missing_content_type", body: valid, contentType: "absent", noRead: true},
		{name: "malformed_content_type", body: valid, contentType: "application/json; charset", noRead: true},
		{name: "wrong_charset", body: valid, contentType: "application/json; charset=utf-16", noRead: true},
		{name: "unknown_media_parameter", body: valid, contentType: "application/json; stream=true", noRead: true},
		{name: "duplicate_content_type", body: valid, duplicateType: true, noRead: true},
		{name: "gzip", body: valid, encoding: []string{"gzip"}, noRead: true},
		{name: "multiple_encoding", body: valid, encoding: []string{"identity", "gzip"}, noRead: true},
		{name: "combined_encoding", body: valid, encoding: []string{"identity, gzip"}, noRead: true},
		{name: "already_decompressed", body: valid, uncompressed: true, noRead: true},
		{name: "nil_response", nilResponse: true, noRead: true},
		{name: "nil_body", nilBody: true, noRead: true},
	}
	for _, field := range []string{"tool_calls", "function_call", "audio", "images", "reasoning_content", "unknown"} {
		cases = append(cases, responseCase{name: "unsupported_message_" + field, body: strings.Replace(valid, `"role":`, `"`+field+`":null,"role":`, 1)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := &oauthDerivedResponseBody{reader: strings.NewReader(tc.body), readError: tc.readError, closeError: tc.closeError}
			resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: -1, Uncompressed: tc.uncompressed}
			if tc.status != 0 {
				resp.StatusCode = tc.status
			}
			if tc.declared {
				resp.ContentLength = tc.length
			}
			if tc.contentType != "" {
				resp.Header.Set("Content-Type", tc.contentType)
			}
			if tc.contentType == "absent" {
				resp.Header.Del("Content-Type")
			}
			if tc.duplicateType {
				resp.Header.Add("Content-Type", "application/json")
			}
			if tc.encoding != nil {
				resp.Header["Content-Encoding"] = tc.encoding
			}
			if tc.nilBody {
				resp.Body = nil
			}
			if tc.nilResponse {
				resp = nil
			}
			got, usage, err := ReadOAuthDerivedTextResponse(resp)
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, tc.body, string(got))
				wantUsage := tc.usage
				if wantUsage == "" {
					wantUsage = rawUsage
				}
				assert.Equal(t, wantUsage, string(usage))
			} else {
				require.EqualError(t, err, "invalid OAuth derived text response")
				assert.NotContains(t, err.Error(), secret)
				assert.Nil(t, got)
				assert.Nil(t, usage)
			}
			wantCloses := 1
			if tc.nilBody || tc.nilResponse {
				wantCloses = 0
			}
			assert.Equal(t, wantCloses, body.closeCount)
			assert.LessOrEqual(t, body.bytesRead, limit+1)
			if tc.noRead {
				assert.Zero(t, body.bytesRead)
			}
		})
	}
}
