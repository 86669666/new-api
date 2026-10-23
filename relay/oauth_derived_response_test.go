package relay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const oauthConsumerRawUsage = `{ "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12, "prompt_tokens_details": { "cached_tokens": 4 } }`
const oauthConsumerResponse = `{"id":"chatcmpl-consumer","object":"chat.completion","created":1,"model":"observed-model","choices":[{"index":0,"message":{"role":"assistant","content":"private-body-canary"},"finish_reason":"stop"}],"usage":` + oauthConsumerRawUsage + `}`

type oauthConsumerBody struct {
	io.Reader
	closes   int
	closeErr error
}

func (b *oauthConsumerBody) Close() error {
	b.closes++
	return b.closeErr
}

type oauthConsumerWriter struct {
	recorder *httptest.ResponseRecorder
	events   []string
	writeErr error
	short    bool
}

func (w *oauthConsumerWriter) Header() http.Header {
	w.events = append(w.events, "headers")
	return w.recorder.Header()
}

func (w *oauthConsumerWriter) WriteHeader(status int) {
	w.events = append(w.events, "status")
	w.recorder.WriteHeader(status)
}

func (w *oauthConsumerWriter) Write(body []byte) (int, error) {
	w.events = append(w.events, "body")
	if w.writeErr != nil || w.short {
		n, _ := w.recorder.Write(body[:1])
		return n, w.writeErr
	}
	return w.recorder.Write(body)
}

func TestConsumeOAuthDerivedTextResponse(t *testing.T) {
	const ref = "server-receipt-ref"
	const failure = "OAuth derived text response could not be completed"
	privateErr := errors.New("private-finalizer-writer-canary")
	positive, zero, negative := 13, 0, -1
	settled := &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &positive}
	for _, tc := range []struct {
		name          string
		receipt       *model.OAuthDerivedTextCharge
		finalizeErr   error
		response      string
		closeErr      error
		cancelled     bool
		writeErr      error
		shortWrite    bool
		readerRejects bool
		publishes     bool
	}{
		{name: "settled_before_exact_output", receipt: settled, publishes: true},
		{name: "nil_receipt"},
		{name: "wrong_ref", receipt: &model.OAuthDerivedTextCharge{Ref: "other-ref", State: "settled", Actual: &positive}},
		{name: "held", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "held", Actual: &positive}},
		{name: "send_claimed", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "send_claimed", Actual: &positive}},
		{name: "unknown", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "unknown", Actual: &positive}},
		{name: "refunded_zero", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "refunded", Actual: &zero}},
		{name: "refunded_positive", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "refunded", Actual: &positive}},
		{name: "actual_missing", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "settled"}},
		{name: "actual_zero", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &zero}},
		{name: "actual_negative", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &negative}},
		{name: "commit_error_despite_receipt", receipt: settled, finalizeErr: privateErr},
		{name: "cancelled_client_finalize_error", cancelled: true, finalizeErr: privateErr},
		{name: "cancelled_client_still_settles_without_output", cancelled: true, receipt: settled},
		{name: "partial_write_error_terminal", receipt: settled, publishes: true, writeErr: privateErr},
		{name: "short_write_terminal", receipt: settled, publishes: true, shortWrite: true},
		{name: "truncated_body", response: oauthConsumerResponse[:len(oauthConsumerResponse)-1], readerRejects: true},
		{name: "unsupported_shape", response: strings.Replace(oauthConsumerResponse, `"chat.completion"`, `"chat.completion.chunk"`, 1), readerRejects: true},
		{name: "missing_usage", response: strings.Replace(oauthConsumerResponse, `,"usage":`+oauthConsumerRawUsage, "", 1), readerRejects: true},
		{name: "body_close_error", closeErr: privateErr, readerRejects: true},
		{name: "raw_usage_rejected_by_finalizer", response: strings.Replace(oauthConsumerResponse, oauthConsumerRawUsage, `{}`, 1), finalizeErr: model.ErrOAuthTextCharge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.response
			if original == "" {
				original = oauthConsumerResponse
			}
			body := &oauthConsumerBody{Reader: strings.NewReader(original), closeErr: tc.closeErr}
			resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: -1}
			writer := &oauthConsumerWriter{recorder: httptest.NewRecorder(), writeErr: tc.writeErr, short: tc.shortWrite}
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "request-context-value"))
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			calls := 0
			var finalizedContext context.Context
			err := consumeOAuthDerivedTextResponseWithFinalizer(ctx, ref, resp, writer, func(settleCtx context.Context, gotRef string, rawUsage []byte) (*model.OAuthDerivedTextCharge, error) {
				calls++
				finalizedContext = settleCtx
				require.Empty(t, writer.events, "no success headers/status/body before finalization returns")
				assert.Empty(t, writer.recorder.Header())
				assert.Empty(t, writer.recorder.Body.String())
				assert.Equal(t, 1, body.closes)
				assert.Equal(t, ref, gotRef)
				wantUsage := oauthConsumerRawUsage
				if tc.name == "raw_usage_rejected_by_finalizer" {
					wantUsage = `{}`
				}
				assert.Equal(t, wantUsage, string(rawUsage))
				assert.NoError(t, settleCtx.Err(), "client cancellation must not cancel settlement")
				assert.Equal(t, "request-context-value", settleCtx.Value(contextKey{}))
				_, bounded := settleCtx.Deadline()
				assert.True(t, bounded)
				writer.events = append(writer.events, "finalize")
				return tc.receipt, tc.finalizeErr
			})
			assert.Equal(t, 1, body.closes)
			if tc.readerRejects {
				assert.Zero(t, calls)
				assert.Empty(t, writer.events)
			} else {
				assert.Equal(t, 1, calls)
				require.NotNil(t, finalizedContext)
				assert.ErrorIs(t, finalizedContext.Err(), context.Canceled, "settlement timer must be released on return")
			}
			if tc.publishes {
				assert.Equal(t, []string{"finalize", "headers", "status", "body"}, writer.events)
				assert.Equal(t, http.StatusOK, writer.recorder.Code)
				assert.Equal(t, "application/json", writer.recorder.Header().Get("Content-Type"))
				assert.Equal(t, strconv.Itoa(len(original)), writer.recorder.Header().Get("Content-Length"))
				if tc.writeErr == nil && !tc.shortWrite {
					require.NoError(t, err)
					assert.Equal(t, original, writer.recorder.Body.String())
					return
				}
				assert.Equal(t, original[:1], writer.recorder.Body.String())
			} else {
				assert.Empty(t, writer.recorder.Header())
				assert.Empty(t, writer.recorder.Body.String())
				if !tc.readerRejects {
					assert.Equal(t, []string{"finalize"}, writer.events)
				}
			}
			require.EqualError(t, err, failure)
			assert.NotContains(t, err.Error(), ref)
			assert.NotContains(t, err.Error(), original)
			assert.NotContains(t, err.Error(), privateErr.Error())
			assert.NotContains(t, err.Error(), "private-body-canary")
		})
	}
}

func TestConsumeOAuthDerivedTextResponseFinalizerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		body := &oauthConsumerBody{Reader: strings.NewReader(oauthConsumerResponse)}
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: -1}
		writer := &oauthConsumerWriter{recorder: httptest.NewRecorder()}
		calls := 0
		err := consumeOAuthDerivedTextResponseWithFinalizer(context.Background(), "receipt", resp, writer, func(ctx context.Context, ref string, _ []byte) (*model.OAuthDerivedTextCharge, error) {
			calls++
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			assert.Equal(t, 5*time.Second, deadline.Sub(time.Now()))
			<-ctx.Done() // Virtual time: no wall-clock wait or real database.
			require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
			actual := 13
			return &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &actual}, nil
		})
		require.EqualError(t, err, "OAuth derived text response could not be completed")
		assert.Equal(t, 1, calls)
		assert.Equal(t, 1, body.closes)
		assert.Empty(t, writer.events, "late success cannot publish after the settlement deadline")
	})
}
