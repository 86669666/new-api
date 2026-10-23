package relay

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/channel/openai"
	"github.com/QuantumNous/new-api/service"
)

// consumeOAuthDerivedTextResponse is terminal for an already-sent request with
// a server-owned receipt ref. The caller must supply an uncommitted writer and
// must not retry, refund, run legacy billing, or append another response after
// this call, even on error: settlement may have committed and output may be
// partial. This boundary does not authorize a send or enable derived spending.
func consumeOAuthDerivedTextResponse(ctx context.Context, ref string, resp *http.Response, writer http.ResponseWriter) error {
	return consumeOAuthDerivedTextResponseWithFinalizer(ctx, ref, resp, writer, service.FinalizeOAuthDerivedText)
}

// The per-call seam stays private; the production entry always binds the real
// finalizer, which loads historical billing facts from the durable receipt.
func consumeOAuthDerivedTextResponseWithFinalizer(ctx context.Context, ref string, resp *http.Response, writer http.ResponseWriter, finalize func(context.Context, string, []byte) (*model.OAuthDerivedTextCharge, error)) error {
	failed := errors.New("OAuth derived text response could not be completed")
	body, rawUsage, err := openai.ReadOAuthDerivedTextResponse(resp)
	if err != nil {
		return failed
	}

	// Client cancellation must not cancel settlement of an already-sent debt.
	// The finalizer must honor this bounded context; there is no retry or refund.
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	receipt, err := finalize(settleCtx, ref, rawUsage)
	settleErr := settleCtx.Err()
	cancel()
	if err != nil || settleErr != nil || receipt == nil || receipt.Ref != ref || receipt.State != "settled" || receipt.Actual == nil || *receipt.Actual <= 0 {
		return failed
	}
	if ctx.Err() != nil || writer == nil {
		return failed
	}

	header := writer.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(http.StatusOK)
	n, err := writer.Write(body)
	if err != nil || n != len(body) {
		return failed
	}
	return nil
}
