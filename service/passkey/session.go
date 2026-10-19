package passkey

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	webauthn "github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
)

const passkeyFlowTTL = 5 * time.Minute

type flowPayload struct {
	SessionData webauthn.SessionData `json:"session_data"`
	Security    FlowSecurity         `json:"security"`
}

type FlowSecurity struct {
	OrganizationContext   common.RawMessage `json:"organization_context,omitempty"`
	OrganizationAttemptID int64             `json:"organization_attempt_id,omitempty"`
	OrganizationExpiresAt int64             `json:"organization_expires_at,omitempty"`

	model.AuthSessionIdentity
	Scope          string                       `json:"scope"`
	ContextHash    string                       `json:"context_hash"`
	Authorization  *model.AuthFlowAuthorization `json:"authorization,omitempty"`
	LoginFlowID    int64                        `json:"login_flow_id,omitempty"`
	LoginExpiresAt int64                        `json:"login_expires_at,omitempty"`
}

func CreateSessionDataFlow(purpose string, security FlowSecurity, data *webauthn.SessionData) (string, int64, error) {
	return CreateSessionDataFlowWithContext(context.Background(), purpose, security, data)
}

func CreateSessionDataFlowWithContext(ctx context.Context, purpose string, security FlowSecurity, data *webauthn.SessionData) (string, int64, error) {
	if data == nil {
		return "", 0, errors.New("passkey session data is empty")
	}
	if purpose == model.AuthFlowPurposeLoginPasskey {
		if security.UserID <= 0 || security.UserAuthVersion <= 0 || security.LoginFlowID <= 0 || security.LoginExpiresAt <= time.Now().Unix() || security.SessionID != "" || security.SessionVersion != 0 {
			return "", 0, model.ErrAuthFlowInvalid
		}
	} else if purpose != model.AuthFlowPurposePasskeyLogin && (security.UserID <= 0 || security.SessionID == "" || security.Scope == "" || security.ContextHash == "" || security.UserAuthVersion <= 0 || security.SessionVersion <= 0) {
		return "", 0, model.ErrAuthFlowInvalid
	}
	if purpose == model.AuthFlowPurposePasskeyRegister && (security.Authorization == nil || security.Authorization.ProofID <= 0 || security.Authorization.AuthSessionIdentity != security.AuthSessionIdentity) {
		return "", 0, model.ErrAuthFlowInvalid
	}
	payload, err := common.Marshal(flowPayload{SessionData: *data, Security: security})
	if err != nil {
		return "", 0, err
	}
	expiresAt := time.Now().Add(passkeyFlowTTL)
	if purpose == model.AuthFlowPurposeLoginPasskey && security.LoginExpiresAt < expiresAt.Unix() {
		expiresAt = time.Unix(security.LoginExpiresAt, 0)
	}
	if security.OrganizationAttemptID > 0 {
		if purpose != model.AuthFlowPurposePasskeyStepUp || len(security.OrganizationContext) == 0 || security.OrganizationExpiresAt <= time.Now().Unix() {
			return "", 0, model.ErrAuthFlowInvalid
		}
		expiresAt = time.Unix(min(expiresAt.Unix(), security.OrganizationExpiresAt, data.Expires.Unix()), 0)
	}
	token, _, err := model.CreateAuthFlowWithContext(ctx, model.AuthFlowCreate{
		Purpose:   purpose,
		UserId:    security.UserID,
		SessionId: security.SessionID,
		Payload:   string(payload),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", 0, err
	}
	return token, expiresAt.Unix(), nil
}

func PopSessionDataFlow(token, purpose string, identity model.AuthSessionIdentity) (*webauthn.SessionData, *FlowSecurity, error) {
	return PopSessionDataFlowWithContext(context.Background(), token, purpose, identity)
}

func PopSessionDataFlowWithContext(ctx context.Context, token, purpose string, identity model.AuthSessionIdentity) (*webauthn.SessionData, *FlowSecurity, error) {
	var payload flowPayload
	_, err := model.ConsumeAuthFlowWithActionWithContext(ctx, token, model.AuthFlowMatch{
		Purpose:   purpose,
		UserId:    identity.UserID,
		SessionId: identity.SessionID,
	}, func(tx *gorm.DB, flow *model.AuthFlow) error {
		if err := common.UnmarshalJsonStr(flow.Payload, &payload); err != nil {
			return err
		}
		if payload.SessionData.RelyingPartyID == "" || payload.SessionData.Expires.IsZero() {
			return model.ErrAuthFlowInvalid
		}
		if !time.Now().Before(payload.SessionData.Expires) {
			return model.ErrAuthFlowExpired
		}
		if purpose == model.AuthFlowPurposePasskeyLogin {
			return nil
		}
		security := payload.Security
		if purpose == model.AuthFlowPurposeLoginPasskey {
			if security.AuthSessionIdentity != identity || identity.UserID <= 0 || identity.UserAuthVersion <= 0 || identity.SessionID != "" || identity.SessionVersion != 0 || security.LoginFlowID <= 0 || security.LoginExpiresAt <= time.Now().Unix() {
				return model.ErrAuthFlowInvalid
			}
			return nil
		}
		if security.AuthSessionIdentity != identity || security.Scope == "" || security.ContextHash == "" {
			return model.ErrAuthFlowInvalid
		}
		if purpose == model.AuthFlowPurposePasskeyRegister && (security.Authorization == nil || security.Authorization.ProofID <= 0 || security.Authorization.AuthSessionIdentity != identity) {
			return model.ErrAuthFlowInvalid
		}
		if err := model.ValidateAuthSessionWithTx(tx, identity); err != nil {
			return err
		}
		if strings.HasPrefix(security.Scope, "organization.") || strings.HasPrefix(security.Scope, "platform.organization.") {
			if security.OrganizationAttemptID <= 0 || len(security.OrganizationContext) == 0 {
				return model.ErrAuthFlowInvalid
			}
			if err := model.ValidateOrganizationAttemptWithTx(tx, identity, security.OrganizationAttemptID); err != nil {
				return err
			}
			_, session, err := model.OrganizationVerificationStateWithTx(tx, identity)
			if err != nil {
				return err
			}
			now := time.Now()
			if now.Unix() >= min(flow.ExpiresAt.Unix(), security.OrganizationExpiresAt, session.ExpiresAt, payload.SessionData.Expires.Unix()) {
				return model.ErrAuthFlowExpired
			}
			if err := tx.Model(flow).Update("consumed_at", now).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &payload.SessionData, &payload.Security, nil
}

// Inspection selects the server-owned protocol branch only; PopSessionDataFlow
// remains the sole atomic consumer and repeats the identity and deadline checks.
func InspectStepUpSecurity(token string, identity model.AuthSessionIdentity) (*FlowSecurity, error) {
	return InspectStepUpSecurityWithContext(context.Background(), token, identity)
}

func InspectStepUpSecurityWithContext(ctx context.Context, token string, identity model.AuthSessionIdentity) (*FlowSecurity, error) {
	flow, err := model.InspectAuthFlowRouteWithContext(ctx, token, model.AuthFlowMatch{Purpose: model.AuthFlowPurposePasskeyStepUp, UserId: identity.UserID, SessionId: identity.SessionID})
	if err != nil {
		return nil, err
	}
	var payload flowPayload
	if common.UnmarshalJsonStr(flow.Payload, &payload) != nil || payload.Security.AuthSessionIdentity != identity {
		return nil, model.ErrAuthFlowInvalid
	}
	return &payload.Security, nil
}
