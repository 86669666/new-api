package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"gorm.io/gorm"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const VerificationScopeOAuthDerivedIssue = "oauth.derived_token.issue"

// This exact context is shown by the consent client and bound by the existing
// step-up ceremony before the provider assigns a new grant identifier.
type OAuthDerivedConsentContext struct {
	Issuer     string   `json:"issuer"`
	ConsentRef string   `json:"consent_ref"`
	ClientID   string   `json:"client_id"`
	Scopes     []string `json:"scopes"`
	PolicyHash string   `json:"policy_hash"`
	QuotaLimit int64    `json:"quota_limit"`
	ExpiresAt  int64    `json:"expires_at"`
}

type OAuthDerivedConsentInput struct {
	ProofToken string `json:"proof_token"`
	QuotaLimit int64  `json:"quota_limit"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (c *OAuthDerivedConsentContext) normalize() bool {
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || issuer.Opaque != "" ||
		len(c.Issuer) > 2048 || !oauthIssueDigest(c.ConsentRef) || !oauthIssueDigest(c.PolicyHash) ||
		!validOAuthClientIDProof(c.ClientID) || c.QuotaLimit < 1 || c.QuotaLimit > 10000000 ||
		c.ExpiresAt <= 0 || c.ExpiresAt > model.OAuthUsageMaxInteger ||
		len(c.Scopes) == 0 || len(c.Scopes) > len(oauthPublicScopes) || !slices.Contains(c.Scopes, "tokens:write") {
		return false
	}
	slices.Sort(c.Scopes)
	for i, scope := range c.Scopes {
		if !slices.Contains(oauthPublicScopes, scope) || i > 0 && c.Scopes[i-1] == scope {
			return false
		}
	}
	return true
}

func oauthIssueDigest(text string) bool {
	if len(text) != 64 {
		return false
	}
	for _, ch := range text {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// Consume the existing proof only after comparing it against the server's
// actual provider request. Mutable AuthFlow payload supplies no authority.
func authorizeOAuthDerivedConsent(ctx context.Context, actor AuthIdentity, consent OAuthDerivedConsentContext, raw string) (*model.OAuthIssueAttestation, error) {
	now := time.Now().Unix()
	if consent.ExpiresAt < now+300 || consent.ExpiresAt > now+604800 || len(raw) > 4096 ||
		actor.SessionID == "" || strings.HasPrefix(actor.SessionID, "pat:") || strings.HasPrefix(actor.SessionID, "legacy") {
		return nil, ErrOAuthProviderDenied
	}
	body, err := common.Marshal(consent)
	if err != nil {
		return nil, ErrOAuthProviderDenied
	}
	binding, err := BindVerificationOperation(VerificationOperation{Scope: VerificationScopeOAuthDerivedIssue, Context: body})
	if err != nil {
		return nil, ErrOAuthProviderDenied
	}
	claims, err := verifySecurityProof(raw, actor, binding)
	if err != nil {
		return nil, ErrOAuthProviderDenied
	}
	verifiedAt, deadline := claims.IssuedAt.Unix(), claims.ExpiresAt.Unix()
	if verifiedAt <= 0 || verifiedAt > now || deadline <= now || deadline > verifiedAt+60 ||
		!slices.Contains([]string{VerificationMethodPassword, VerificationMethodPasskey, VerificationMethodTwoFA}, claims.Method) {
		return nil, ErrOAuthProviderDenied
	}
	if _, err := RequireVerificationMethod(actor, binding.Scope, claims.Method); err != nil {
		return nil, ErrOAuthProviderDenied
	}
	flow, err := model.ConsumeAuthFlowWithActionWithContext(ctx, claims.ID, model.AuthFlowMatch{
		Purpose: model.AuthFlowPurposeSecurityProof, UserId: actor.UserID, SessionId: actor.SessionID,
	}, func(tx *gorm.DB, _ *model.AuthFlow) error {
		return model.ValidateAuthSessionWithTx(tx, actor)
	})
	if err != nil {
		return nil, ErrOAuthProviderDenied
	}
	scopes := slices.Clone(consent.Scopes)
	slices.Sort(scopes)
	encoded, err := common.Marshal(scopes)
	if err != nil {
		return nil, ErrOAuthProviderDenied
	}
	digest := sha256.Sum256([]byte("newapi.oauth.issue-proof.v1\x00" + claims.Issuer + "\x00" + claims.TokenUse + "\x00" + claims.ID))
	return &model.OAuthIssueAttestation{
		ConsentRef: consent.ConsentRef, ProofDigest: fmt.Sprintf("%x", digest), ProofFlowID: flow.Id,
		UserID: actor.UserID, OriginSID: actor.SessionID, SessionVersion: actor.SessionVersion, UserAuthVersion: actor.UserAuthVersion,
		Issuer: consent.Issuer, ClientID: consent.ClientID, Scopes: string(encoded), PolicyHash: consent.PolicyHash, BindingHash: binding.ContextHash,
		VerifiedMethod: claims.Method, VerifiedAt: verifiedAt, ProofExpiresAt: deadline, QuotaLimit: consent.QuotaLimit, ExpiresAt: consent.ExpiresAt,
	}, nil
}

func oauthDerivedConsentGrantMatches(grant *model.OAuthGrant, proof *model.OAuthIssueAttestation) bool {
	return grant.GrantRef == proof.GrantRef && grant.ConsentRef == proof.ConsentRef &&
		grant.Subject == strconv.Itoa(proof.UserID) && grant.UserID == proof.UserID && grant.OriginSID == proof.OriginSID &&
		grant.SessionVersion == proof.SessionVersion && grant.UserAuthVersion == proof.UserAuthVersion &&
		grant.Issuer == proof.Issuer && grant.ClientID == proof.ClientID && grant.PolicyHash == proof.PolicyHash &&
		grant.Scopes == proof.Scopes && grant.CreatedAt >= proof.VerifiedAt && grant.ExpiresAt >= proof.ExpiresAt
}
