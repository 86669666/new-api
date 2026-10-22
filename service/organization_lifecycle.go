package service

import (
	"context"
	"crypto/hmac"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"gorm.io/gorm"
)

// OrganizationCommandDTO is a wire command, not an authorization. Presence is
// checked against the action's exact field set before any conversion to int64.
type OrganizationCommandDTO struct {
	OrganizationID     string  `json:"organization_id,omitempty"`
	Revision           string  `json:"revision,omitempty"`
	Name               string  `json:"name,omitempty"`
	TargetUserID       string  `json:"target_user_id,omitempty"`
	Username           string  `json:"username,omitempty"`
	Role               string  `json:"role,omitempty"`
	Disabled           *bool   `json:"disabled,omitempty"`
	Reason             *string `json:"reason,omitempty"`
	InvitationID       string  `json:"invitation_id,omitempty"`
	TransferID         string  `json:"transfer_id,omitempty"`
	Generation         string  `json:"generation,omitempty"`
	PreviousID         string  `json:"previous_id,omitempty"`
	PreviousGeneration string  `json:"previous_generation,omitempty"`
	Replace            *bool   `json:"replace,omitempty"`
	RequestID          string  `json:"request_id,omitempty"`
	Amount             string  `json:"amount,omitempty"`
	Reference          string  `json:"reference,omitempty"`
	CreditID           string  `json:"credit_id,omitempty"`
}
type OrganizationSnapshot struct {
	TargetRole         string `json:"target_role,omitempty"`
	Generation         string `json:"generation,omitempty"`
	FromUserID         string `json:"from_user_id,omitempty"`
	ToUserID           string `json:"to_user_id,omitempty"`
	OwnershipVersion   string `json:"ownership_version,omitempty"`
	FromMemberRevision string `json:"from_member_revision,omitempty"`
	ToMemberRevision   string `json:"to_member_revision,omitempty"`
	WalletAmount       string `json:"wallet_amount,omitempty"`
}
type OrganizationContext struct {
	SchemaVersion int                    `json:"schema_version"`
	Command       OrganizationCommandDTO `json:"command"`
	Snapshot      OrganizationSnapshot   `json:"snapshot"`
}
type OrganizationProofResult struct {
	ProofToken string      `json:"proof_token"`
	ExpiresAt  int64       `json:"expires_at"`
	Method     string      `json:"method"`
	Scope      string      `json:"scope"`
	AuthBundle *AuthBundle `json:"auth_bundle"`
}
type organizationProofPayload struct {
	SchemaVersion int               `json:"schema_version"`
	Identity      AuthIdentity      `json:"identity"`
	Scope         string            `json:"scope"`
	Method        string            `json:"method"`
	Context       common.RawMessage `json:"context"`
}

func OrganizationScope(action string) string {
	switch action {
	case "platform_disable":
		return "platform.organization.disable"
	case "wallet_credit", "wallet_reverse":
		return "platform.organization." + action
	case "self_disable", "dissolve", "change_role", "remove", "invite", "reissue", "transfer_initiate", "transfer_accept":
		return "organization." + action
	default:
		return ""
	}
}
func OrganizationAction(scope string) string {
	if scope == "platform.organization.disable" {
		return "platform_disable"
	}
	if scope == "platform.organization.wallet_credit" || scope == "platform.organization.wallet_reverse" {
		return strings.TrimPrefix(scope, "platform.organization.")
	}
	action := strings.TrimPrefix(scope, "organization.")
	if OrganizationScope(action) == scope {
		return action
	}
	return ""
}
func IsOrganizationScope(scope string) bool { return OrganizationAction(scope) != "" }

func OrganizationDecimal(value string, zero bool) (int64, error) {
	if value == "" || len(value) > 19 || len(value) > 1 && value[0] == '0' {
		return 0, model.ErrOrganizationInvalidInput
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, model.ErrOrganizationInvalidInput
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 || !zero && n == 0 {
		return 0, model.ErrOrganizationInvalidInput
	}
	return n, nil
}
func organizationCommandFields(action string, full bool) []string {
	fields := []string{"revision"}
	switch action {
	case "create":
		return []string{"name"}
	case "rename":
		fields = append(fields, "name")
	case "self_disable", "platform_disable":
		fields = append(fields, "disabled", "reason")
	case "dissolve", "leave":
	case "wallet_credit":
		fields = append(fields, "request_id", "amount", "reference", "reason")
	case "wallet_reverse":
		fields = append(fields, "request_id", "reason")
		if full {
			fields = append(fields, "credit_id")
		}
	case "change_role":
		fields = append(fields, "role")
		if full {
			fields = append(fields, "target_user_id")
		}
	case "remove":
		if full {
			fields = append(fields, "target_user_id")
		}
	case "invite":
		fields = append(fields, "target_user_id", "role")
	case "reissue":
		fields = append(fields, "target_user_id", "role", "generation")
		if full {
			fields = append(fields, "invitation_id")
		}
	case "invite_accept", "invite_decline", "invite_revoke":
		fields = append(fields, "generation")
		if full {
			fields = append(fields, "invitation_id")
		}
	case "transfer_initiate":
		fields = append(fields, "target_user_id", "previous_id", "previous_generation", "replace")
	case "transfer_accept", "transfer_decline", "transfer_cancel":
		fields = append(fields, "generation")
		if full {
			fields = append(fields, "transfer_id")
		}
	default:
		return nil
	}
	if full {
		fields = append(fields, "organization_id")
	}
	return fields
}
func exactOrganizationFields(data []byte, fields []string) error {
	if fields == nil {
		return model.ErrOrganizationInvalidInput
	}
	if err := common.ValidateStrictJSONObject(data); err != nil {
		return model.ErrOrganizationInvalidInput
	}
	var object map[string]common.RawMessage
	if common.Unmarshal(data, &object) != nil || len(object) != len(fields) {
		return model.ErrOrganizationInvalidInput
	}
	for _, key := range fields {
		if _, ok := object[key]; !ok {
			return model.ErrOrganizationInvalidInput
		}
	}
	return nil
}

// DecodeOrganizationCommand is shared by preview, producer and consumer.
func DecodeOrganizationCommand(action string, data []byte, full bool, orgID, targetID, objectID string) (OrganizationCommandDTO, model.OrganizationCommand, error) {
	var wire OrganizationCommandDTO
	var cmd model.OrganizationCommand
	fields := organizationCommandFields(action, full)
	var rawFields map[string]common.RawMessage
	if common.Unmarshal(data, &rawFields) != nil {
		return wire, cmd, model.ErrOrganizationInvalidInput
	}
	_, emailPresent := rawFields["email"]
	emailInvite := action == "invite" && emailPresent
	if _, present := rawFields["username"]; action == "invite" && (present || emailInvite) {
		for index, field := range fields {
			if field == "target_user_id" {
				fields[index] = "username"
				if emailInvite {
					fields[index] = "email"
				}
			}
		}
	}
	if err := exactOrganizationFields(data, fields); err != nil {
		return wire, cmd, err
	}
	if emailInvite {
		var input struct {
			OrganizationCommandDTO
			Email string `json:"email"`
		}
		if common.UnmarshalStrictObject(data, &input) != nil || input.Email == "" {
			return wire, cmd, model.ErrOrganizationInvalidInput
		}
		wire = input.OrganizationCommandDTO
	} else if common.UnmarshalStrictObject(data, &wire) != nil {
		return wire, cmd, model.ErrOrganizationInvalidInput
	}
	if _, present := rawFields["username"]; present {
		if wire.Username == "" || !utf8.ValidString(wire.Username) || utf8.RuneCountInString(wire.Username) > 20 {
			return wire, cmd, model.ErrOrganizationInvalidInput
		}
		for _, r := range wire.Username {
			if unicode.IsControl(r) {
				return wire, cmd, model.ErrOrganizationInvalidInput
			}
		}
		cmd.Username = wire.Username
	}
	for _, field := range []string{"organization_id", "revision", "target_user_id", "invitation_id", "transfer_id", "generation", "previous_id", "previous_generation", "amount", "credit_id"} {
		if raw, present := rawFields[field]; present {
			var value string
			if common.Unmarshal(raw, &value) != nil {
				return wire, cmd, model.ErrOrganizationInvalidInput
			}
			if _, err := OrganizationDecimal(value, field == "previous_id" || field == "previous_generation"); err != nil {
				return wire, cmd, err
			}
		}
	}
	if !full && action != "create" {
		wire.OrganizationID = orgID
		if action == "change_role" || action == "remove" {
			wire.TargetUserID = targetID
		}
		if action == "reissue" || strings.HasPrefix(action, "invite_") {
			wire.InvitationID = objectID
		}
		if action == "transfer_accept" || action == "transfer_decline" || action == "transfer_cancel" {
			wire.TransferID = objectID
		}
		if action == "wallet_reverse" {
			wire.CreditID = objectID
		}
	}
	var err error
	if action != "create" {
		cmd.OrganizationID, err = OrganizationDecimal(wire.OrganizationID, false)
		if err != nil {
			return wire, cmd, err
		}
		cmd.Revision, err = OrganizationDecimal(wire.Revision, false)
		if err != nil {
			return wire, cmd, err
		}
	}
	if wire.TargetUserID != "" {
		n, e := OrganizationDecimal(wire.TargetUserID, false)
		if e != nil || int64(int(n)) != n {
			return wire, cmd, model.ErrOrganizationInvalidInput
		}
		cmd.TargetUserID = int(n)
	}
	for _, p := range []struct {
		value string
		dest  *int64
		zero  bool
	}{{wire.InvitationID, &cmd.ObjectID, false}, {wire.TransferID, &cmd.ObjectID, false}, {wire.Generation, &cmd.Generation, false}, {wire.PreviousID, &cmd.ObjectID, true}, {wire.PreviousGeneration, &cmd.Generation, true}, {wire.Amount, &cmd.WalletAmount, false}, {wire.CreditID, &cmd.WalletCreditID, false}} {
		if p.value != "" {
			*p.dest, err = OrganizationDecimal(p.value, p.zero)
			if err != nil {
				return wire, cmd, err
			}
		}
	}
	if wire.Role != "" && wire.Role != model.OrganizationRoleAdmin && wire.Role != model.OrganizationRoleMember {
		return wire, cmd, model.ErrOrganizationInvalidInput
	}
	cmd.Name = strings.TrimSpace(wire.Name)
	wire.Name = cmd.Name
	cmd.Role = wire.Role
	cmd.WalletRequestID, cmd.WalletReference = wire.RequestID, wire.Reference
	if wire.Disabled != nil {
		cmd.Disabled = *wire.Disabled
	}
	if wire.Reason != nil {
		cmd.Reason = *wire.Reason
	}
	if wire.Replace != nil {
		cmd.Replace = *wire.Replace
	}
	if emailInvite {
		if cmd.Role != model.OrganizationRoleMember && cmd.Role != model.OrganizationRoleAdmin {
			return wire, cmd, model.ErrOrganizationInvalidInput
		}
		return wire, cmd, ErrOrganizationEmailInviteUnsupported
	}
	return wire, cmd, nil
}
func organizationSnapshot(action string, b *model.OrganizationAuthorizationBinding) OrganizationSnapshot {
	s := OrganizationSnapshot{}
	if action == "wallet_credit" || action == "wallet_reverse" {
		s.WalletAmount = strconv.FormatInt(b.WalletAmount, 10)
	}
	if action == "remove" {
		s.TargetRole = b.Role
	}
	if action == "invite" || action == "reissue" || action == "transfer_initiate" {
		s.Generation = strconv.FormatInt(b.Generation, 10)
	}
	if action == "transfer_initiate" || action == "transfer_accept" {
		s.FromUserID = strconv.Itoa(b.FromUserID)
		s.ToUserID = strconv.Itoa(b.ToUserID)
		s.OwnershipVersion = strconv.FormatInt(b.OwnershipVersion, 10)
		s.FromMemberRevision = strconv.FormatInt(b.FromMemberRevision, 10)
		s.ToMemberRevision = strconv.FormatInt(b.ToMemberRevision, 10)
	}
	return s
}
func PreviewOrganizationOperation(identity AuthIdentity, action string, wire OrganizationCommandDTO, cmd model.OrganizationCommand) (VerificationOperation, *model.OrganizationAuthorizationBinding, string, error) {
	return PreviewOrganizationOperationWithContext(context.Background(), identity, action, wire, cmd)
}

func PreviewOrganizationOperationWithContext(ctx context.Context, identity AuthIdentity, action string, wire OrganizationCommandDTO, cmd model.OrganizationCommand) (VerificationOperation, *model.OrganizationAuthorizationBinding, string, error) {
	var err error
	wire, cmd, err = canonicalOrganizationInvitationCommand(ctx, identity, action, wire, cmd)
	if err != nil {
		return VerificationOperation{}, nil, "", err
	}
	b, name, err := model.PreviewOrganizationCommandWithContext(ctx, identity, action, cmd)
	if err != nil {
		return VerificationOperation{}, nil, "", err
	}
	if b == nil || OrganizationScope(action) == "" {
		return VerificationOperation{}, nil, "", model.ErrOrganizationInvalidInput
	}
	context, err := common.Marshal(OrganizationContext{SchemaVersion: 1, Command: wire, Snapshot: organizationSnapshot(action, b)})
	return VerificationOperation{Scope: OrganizationScope(action), Context: context}, b, name, err
}

// RebuildOrganizationOperation validates every semantic field against live state.
func RebuildOrganizationOperation(identity AuthIdentity, op VerificationOperation) (VerificationOperation, model.OrganizationCommand, *model.OrganizationAuthorizationBinding, error) {
	return RebuildOrganizationOperationWithContext(context.Background(), identity, op)
}

func RebuildOrganizationOperationWithContext(ctx context.Context, identity AuthIdentity, op VerificationOperation) (VerificationOperation, model.OrganizationCommand, *model.OrganizationAuthorizationBinding, error) {
	var cmd model.OrganizationCommand
	action := OrganizationAction(op.Scope)
	if action == "" {
		return op, cmd, nil, ErrProofScope
	}
	if err := exactOrganizationFields(op.Context, []string{"schema_version", "command", "snapshot"}); err != nil {
		return op, cmd, nil, ErrVerificationContextInvalid
	}
	var context struct {
		SchemaVersion int               `json:"schema_version"`
		Command       common.RawMessage `json:"command"`
		Snapshot      common.RawMessage `json:"snapshot"`
	}
	if common.UnmarshalStrictObject(op.Context, &context) != nil || context.SchemaVersion != 1 {
		return op, cmd, nil, ErrVerificationContextInvalid
	}
	// Proof producers and rebuilds accept only the original ID command shape.
	// The HTTP username selector is resolved before constructing this context.
	if action == "invite" && exactOrganizationFields(context.Command, organizationCommandFields(action, true)) != nil {
		return op, cmd, nil, ErrVerificationContextInvalid
	}
	wire, cmd, err := DecodeOrganizationCommand(action, context.Command, true, "", "", "")
	if err != nil {
		return op, cmd, nil, ErrVerificationContextInvalid
	}
	expected, b, _, err := PreviewOrganizationOperationWithContext(ctx, identity, action, wire, cmd)
	if err != nil {
		return op, cmd, nil, err
	}
	var supplied OrganizationContext
	if common.UnmarshalStrictObject(op.Context, &supplied) != nil {
		return op, cmd, nil, ErrVerificationContextInvalid
	}
	normalized, err := common.Marshal(supplied)
	if err != nil || !hmac.Equal(normalized, expected.Context) {
		return op, cmd, nil, ErrProofContext
	}
	// Zero-valued optional fields cannot disappear and bypass exact snapshot shape.
	expectedContext := OrganizationContext{}
	_ = common.Unmarshal(expected.Context, &expectedContext)
	snapshotBytes, _ := common.Marshal(expectedContext.Snapshot)
	var fields map[string]common.RawMessage
	_ = common.Unmarshal(snapshotBytes, &fields)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	if exactOrganizationFields(context.Snapshot, keys) != nil {
		return op, cmd, nil, ErrVerificationContextInvalid
	}
	return expected, cmd, b, nil
}

func organizationPolicy(state *model.UserVerificationState, method string, passwordEnabled, passkeyEnabled bool) error {
	if state == nil || state.Status != common.UserStatusEnabled {
		return ErrAuthTokenInvalid
	}
	switch method {
	case VerificationMethodPassword:
		if !passwordEnabled || !state.HasPassword || state.HasTwoFA || state.HasPasskey {
			return ErrVerificationUnavailable
		}
	case VerificationMethodTwoFA:
		if !state.HasTwoFA {
			return ErrVerificationUnavailable
		}
		if state.TwoFALocked {
			return ErrVerificationLocked
		}
	case VerificationMethodPasskey:
		if !state.HasPasskey || !passkeyEnabled {
			return ErrVerificationUnavailable
		}
	default:
		return ErrVerificationUnavailable
	}
	return nil
}
func OrganizationVerificationRequirements(identity AuthIdentity, scope string) (*VerificationRequirements, error) {
	return OrganizationVerificationRequirementsWithContext(context.Background(), identity, scope)
}

func OrganizationVerificationRequirementsWithContext(ctx context.Context, identity AuthIdentity, scope string) (*VerificationRequirements, error) {
	if !IsOrganizationScope(scope) {
		return nil, ErrProofScope
	}
	var state *model.UserVerificationState
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		state, _, err = model.OrganizationVerificationStateWithTx(tx, identity)
		return err
	})
	if err != nil {
		return nil, err
	}
	methods := []VerificationMethodOption{}
	choices := []string{}
	if state.HasTwoFA {
		choices = append(choices, VerificationMethodTwoFA)
	}
	if state.HasPasskey {
		choices = append(choices, VerificationMethodPasskey)
	}
	if len(choices) == 0 && state.HasPassword {
		choices = append(choices, VerificationMethodPassword)
	}
	for _, method := range choices {
		err := organizationPolicy(state, method, common.PasswordLoginEnabled, system_setting.PasskeySettingsSnapshot().Enabled)
		option := VerificationMethodOption{Method: method, Available: err == nil}
		if err != nil {
			option.Reason = err.Error()
		}
		methods = append(methods, option)
	}
	return &VerificationRequirements{Scope: scope, Methods: methods, OAuthProviders: []VerificationOAuthProvider{}, PasswordEncryptionEnabled: common.PasswordLoginEncryptionEnabled}, nil
}
func OrganizationVerificationBinding(op VerificationOperation) VerificationBinding {
	return VerificationBinding{Scope: op.Scope, ContextHash: common.GenerateHMACWithKey(authSigningKey("verification-context"), op.Scope+":"+string(op.Context))}
}
func VerifyOrganizationInput(identity AuthIdentity, input VerificationInput) (*OrganizationProofResult, error) {
	return VerifyOrganizationInputWithContext(context.Background(), identity, input)
}

func VerifyOrganizationInputWithContext(ctx context.Context, identity AuthIdentity, input VerificationInput) (*OrganizationProofResult, error) {
	op, _, _, err := RebuildOrganizationOperationWithContext(ctx, identity, VerificationOperation{Scope: input.Scope, Context: input.Context})
	if err != nil {
		return nil, err
	}
	if input.Method != VerificationMethodPassword && input.Method != VerificationMethodTwoFA {
		return nil, ErrVerificationUnavailable
	}
	if _, err := model.ReserveOrganizationVerificationAttemptWithContext(ctx, identity); err != nil {
		return nil, err
	}
	requirements, err := OrganizationVerificationRequirementsWithContext(ctx, identity, input.Scope)
	if err != nil {
		return nil, err
	}
	available := false
	for _, method := range requirements.Methods {
		if method.Method == input.Method && method.Available {
			available = true
		}
	}
	if !available {
		return nil, ErrVerificationUnavailable
	}
	if input.Method == VerificationMethodPassword {
		password := input.Password
		if common.PasswordLoginEncryptionEnabled {
			if password != "" || input.PasswordEncrypted == "" || input.EncryptionKeyID == "" {
				return nil, ErrVerificationContextInvalid
			}
			password, err = common.DecryptPassword(input.PasswordEncrypted, input.EncryptionKeyID)
			if err != nil {
				return nil, ErrVerificationFailed
			}
		} else if password == "" || input.PasswordEncrypted != "" || input.EncryptionKeyID != "" {
			return nil, ErrVerificationContextInvalid
		}
		user := &model.User{}
		err := model.DB.WithContext(ctx).First(user, identity.UserID).Error
		if err != nil {
			return nil, err
		}
		if !common.ValidatePasswordAndHash(password, user.Password) {
			return nil, ErrVerificationFailed
		}
	} else {
		if len(input.Code) != 6 {
			return nil, ErrVerificationFailed
		}
		for _, c := range input.Code {
			if c < '0' || c > '9' {
				return nil, ErrVerificationFailed
			}
		}
		factor := &model.TwoFA{}
		err := model.DB.WithContext(ctx).Where("user_id = ?", identity.UserID).First(factor).Error
		if err != nil {
			return nil, err
		}
		if factor == nil || !factor.IsEnabled {
			return nil, ErrVerificationUnavailable
		}
		valid, err := factor.ValidateTOTPAndUpdateUsageWithContext(ctx, input.Code)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, ErrVerificationFailed
		}
	}
	return CompleteOrganizationVerificationWithContext(ctx, identity, op, input.Method)
}

// This entry is called only after the real password/TOTP/WebAuthn producer has
// succeeded. Generic security completion deliberately rejects these scopes.
func CompleteOrganizationVerification(identity AuthIdentity, op VerificationOperation, method string) (*OrganizationProofResult, error) {
	return CompleteOrganizationVerificationWithContext(context.Background(), identity, op, method)
}

func CompleteOrganizationVerificationWithContext(ctx context.Context, identity AuthIdentity, op VerificationOperation, method string) (*OrganizationProofResult, error) {
	op, _, _, err := RebuildOrganizationOperationWithContext(ctx, identity, op)
	if err != nil {
		return nil, err
	}
	next, refresh, err := newLoginSession(identity.UserID, identity.UserAuthVersion, method, "", "")
	if err != nil {
		return nil, err
	}
	passwordEnabled, passkeyEnabled := common.PasswordLoginEnabled, system_setting.PasskeySettingsSnapshot().Enabled
	err = model.RotateOrganizationSessionWithContext(ctx, identity, next, func(tx *gorm.DB, state *model.UserVerificationState) error {
		return organizationPolicy(state, method, passwordEnabled, passkeyEnabled)
	})
	if err != nil {
		return nil, err
	}
	newIdentity := AuthIdentity{UserID: identity.UserID, SessionID: next.SID, SessionVersion: next.Version, UserAuthVersion: next.UserAuthVersion}
	if err := ctx.Err(); err != nil {
		return nil, model.CleanupOrganizationSession(next, err)
	}
	bundle, err := issueAuthBundle(next, next.SID+"."+refresh, true)
	if err != nil {
		return nil, model.CleanupOrganizationSession(next, err)
	}
	token, expiry, err := issueOrganizationSecurityProofWithContext(ctx, newIdentity, method, op, next.ExpiresAt)
	if err != nil {
		return nil, model.CleanupOrganizationSession(next, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, model.CleanupOrganizationSession(next, err)
	}
	return &OrganizationProofResult{ProofToken: token, ExpiresAt: expiry, Method: method, Scope: op.Scope, AuthBundle: bundle}, nil
}

func ConsumeOrganizationProof(raw string, identity AuthIdentity, op VerificationOperation, cmd model.OrganizationCommand, b *model.OrganizationAuthorizationBinding) (*model.OrganizationAuthorization, error) {
	return ConsumeOrganizationProofWithContext(context.Background(), raw, identity, op, cmd, b)
}

func ConsumeOrganizationProofWithContext(ctx context.Context, raw string, identity AuthIdentity, op VerificationOperation, cmd model.OrganizationCommand, b *model.OrganizationAuthorizationBinding) (*model.OrganizationAuthorization, error) {
	binding := OrganizationVerificationBinding(op)
	claims, err := verifySecurityProof(raw, identity, binding)
	if err != nil {
		return nil, err
	}
	if claims.Method != VerificationMethodPassword && claims.Method != VerificationMethodTwoFA && claims.Method != VerificationMethodPasskey {
		return nil, ErrProofMethod
	}
	if claims.ExpiresAt == nil || time.Now().Unix() >= claims.ExpiresAt.Unix() {
		return nil, ErrAuthTokenExpired
	}
	passwordEnabled, passkeyEnabled := common.PasswordLoginEnabled, system_setting.PasskeySettingsSnapshot().Enabled
	var validUntil int64
	flow, err := model.ConsumeAuthFlowWithActionWithContext(ctx, claims.ID, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeSecurityProof, UserId: identity.UserID, SessionId: identity.SessionID}, func(tx *gorm.DB, flow *model.AuthFlow) error {
		var payload organizationProofPayload
		if common.UnmarshalJsonStr(flow.Payload, &payload) != nil || payload.SchemaVersion != 1 || payload.Identity != identity || payload.Scope != op.Scope || payload.Method != claims.Method || !hmac.Equal(payload.Context, op.Context) {
			return ErrProofContext
		}
		state, session, err := model.OrganizationVerificationStateWithTx(tx, identity)
		if err != nil {
			return err
		}
		if err := organizationPolicy(state, claims.Method, passwordEnabled, passkeyEnabled); err != nil {
			return err
		}
		now := time.Now()
		validUntil = min(claims.ExpiresAt.Unix(), flow.ExpiresAt.Unix(), session.ExpiresAt)
		if now.Unix() >= validUntil {
			return ErrAuthTokenExpired
		}
		if err := tx.Model(flow).Update("consumed_at", now).Error; err != nil {
			return err
		}
		flow.ConsumedAt = &now
		return nil
	})
	if errors.Is(err, model.ErrAuthFlowConsumed) {
		return nil, ErrProofConsumed
	}
	if errors.Is(err, model.ErrAuthFlowExpired) {
		return nil, ErrAuthTokenExpired
	}
	if errors.Is(err, model.ErrAuthFlowInvalid) {
		return nil, ErrAuthTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	return &model.OrganizationAuthorization{Identity: identity, ProofID: flow.Id, Action: OrganizationAction(op.Scope), Method: claims.Method, ConsumedAt: flow.ConsumedAt.Unix(), ValidUntil: validUntil, Binding: *b, Command: cmd}, nil
}
func ExecuteOrganizationLifecycle(identity AuthIdentity, action string, wire OrganizationCommandDTO, cmd model.OrganizationCommand, rawProof string) (*model.OrganizationMutationReceipt, error) {
	return ExecuteOrganizationLifecycleWithContext(context.Background(), identity, action, wire, cmd, rawProof)
}

func canonicalOrganizationInvitationCommand(ctx context.Context, identity AuthIdentity, action string, wire OrganizationCommandDTO, cmd model.OrganizationCommand) (OrganizationCommandDTO, model.OrganizationCommand, error) {
	if action != "invite" || wire.Username == "" {
		return wire, cmd, nil
	}
	resolved, err := model.ResolveOrganizationInvitationTargetWithContext(ctx, identity, action, cmd)
	if err != nil {
		return wire, cmd, err
	}
	wire.TargetUserID, wire.Username = strconv.Itoa(resolved.TargetUserID), ""
	return wire, resolved, nil
}

func ExecuteOrganizationLifecycleWithContext(ctx context.Context, identity AuthIdentity, action string, wire OrganizationCommandDTO, cmd model.OrganizationCommand, rawProof string) (*model.OrganizationMutationReceipt, error) {
	var err error
	wire, cmd, err = canonicalOrganizationInvitationCommand(ctx, identity, action, wire, cmd)
	if err != nil {
		return nil, err
	}
	if action == "create" {
		if rawProof != "" {
			return nil, model.ErrOrganizationInvalidInput
		}
		return model.ExecuteOrganizationCommandWithContext(ctx, identity, action, cmd)
	}
	binding, _, err := model.PreviewOrganizationCommandWithContext(ctx, identity, action, cmd)
	if err != nil {
		return nil, err
	}
	if binding == nil {
		if rawProof != "" {
			return nil, model.ErrOrganizationInvalidInput
		}
	} else {
		if rawProof == "" {
			return nil, ErrOrganizationProofRequired
		}
		context, err := common.Marshal(OrganizationContext{SchemaVersion: 1, Command: wire, Snapshot: organizationSnapshot(action, binding)})
		if err != nil {
			return nil, err
		}
		cmd.Authorization, err = ConsumeOrganizationProofWithContext(ctx, rawProof, identity, VerificationOperation{Scope: OrganizationScope(action), Context: context}, cmd, binding)
		if err != nil {
			return nil, err
		}
	}
	return model.ExecuteOrganizationCommandWithContext(ctx, identity, action, cmd)
}

var ErrOrganizationProofRequired = errors.New("Security proof is required.")
var ErrOrganizationEmailInviteUnsupported = errors.New("Email invitations are not supported. Use a user ID or username.")

// CreateOrganizationWithKeyWithContext is deliberately separate from the proof
// and command contracts used by all other lifecycle operations.
func CreateOrganizationWithKeyWithContext(ctx context.Context, identity AuthIdentity, name, key string) (*model.OrganizationMutationReceipt, error) {
	return model.CreateOrganizationWithKey(ctx, identity, name, key)
}
