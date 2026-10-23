package service

import (
	"context"
	"errors"
	"github.com/QuantumNous/new-api/model"
)

var ErrOAuthDerivedTextClosed = errors.New("OAuth derived text spending is not enabled")

// No boolean, configuration or client field opens this boundary. Root must
// integrate the selected producer/transport and SQL-only writer cutover first.
func ReserveOAuthDerivedText(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthDerivedTextCharge, error) {
	return nil, ErrOAuthDerivedTextClosed
}
func ClaimOAuthDerivedText(context.Context, string, model.OAuthTextFacts, int) (bool, error) {
	return false, ErrOAuthDerivedTextClosed
}

// Historical obligations survive admission closure. Caller must be the bounded
// raw-usage consumer with a charge computed from the immutable legacy snapshot.
func FinalizeOAuthDerivedText(ctx context.Context, ref string, actual int, usage model.OAuthTextUsage) (*model.OAuthDerivedTextCharge, error) {
	return model.FinalizeOAuthDerivedText(ctx, ref, actual, usage)
}
