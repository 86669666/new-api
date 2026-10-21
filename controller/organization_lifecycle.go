package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

type organizationHTTPError struct {
	status        int
	code, message string
}

func (e *organizationHTTPError) Error() string { return e.message }
func writeOrganizationLifecycleError(c *gin.Context, err error) {
	status, code, message := 500, "ORG_INTERNAL_ERROR", "Unable to complete organization operation."
	var transport *organizationHTTPError
	var budget *model.OrganizationVerificationBudgetError
	switch {
	case errors.As(err, &transport):
		status, code, message = transport.status, transport.code, transport.message
	case errors.As(err, &budget):
		status, code, message = 429, "SECURITY_VERIFICATION_RATE_LIMITED", budget.Error()
		c.Header("Retry-After", strconv.Itoa(budget.RetryAfter))
	case errors.Is(err, model.ErrOrganizationInvalidInput):
		status, code, message = 400, "ORG_REQUEST_INVALID", "Invalid organization request."
	case errors.Is(err, model.ErrOrganizationSelfInvite):
		status, code, message = 400, "ORG_SELF_INVITE", "You cannot invite yourself to an organization."
	case errors.Is(err, service.ErrOrganizationEmailInviteUnsupported):
		status, code, message = 400, "ORG_EMAIL_INVITE_UNSUPPORTED", service.ErrOrganizationEmailInviteUnsupported.Error()
	case errors.Is(err, service.ErrVerificationContextInvalid):
		status, code, message = 400, "SECURITY_CONTEXT_INVALID", service.ErrVerificationContextInvalid.Error()
	case errors.Is(err, model.ErrOrganizationUnauthenticated), errors.Is(err, model.ErrUserSessionInactive), errors.Is(err, service.ErrLoginSessionRevoked):
		status, code, message = 401, "AUTH_SESSION_REVOKED", "The login session is no longer active."
	case errors.Is(err, model.ErrOrganizationNotFound):
		status, code, message = 404, "ORG_NOT_FOUND", "Organization is unavailable."
	case errors.Is(err, model.ErrOrganizationForbidden):
		status, code, message = 403, "ORG_FORBIDDEN", "Organization operation is forbidden."
	case errors.Is(err, model.ErrOrganizationConflict):
		status, code, message = 409, "ORG_STATE_CHANGED", "Organization state changed. Refresh the organization state before retrying."
	case errors.Is(err, model.ErrOrganizationNameTaken):
		status, code, message = 409, "ORG_NAME_TAKEN", "Organization name is already in use."
	case errors.Is(err, model.ErrOrganizationAlreadyMember):
		status, code, message = 409, "ORG_ALREADY_MEMBER", "This user is already a member of the organization."
	case errors.Is(err, model.ErrOrganizationInvitationExists):
		status, code, message = 409, "ORG_INVITATION_EXISTS", "An invitation already exists for this user. Use reissue to send another invitation."
	case errors.Is(err, model.ErrOrganizationWalletRequestConflict):
		status, code, message = 409, "ORG_WALLET_REQUEST_CONFLICT", model.ErrOrganizationWalletRequestConflict.Error()
	case errors.Is(err, model.ErrOrganizationWalletAlreadyReversed):
		status, code, message = 409, "ORG_WALLET_ALREADY_REVERSED", model.ErrOrganizationWalletAlreadyReversed.Error()
	case errors.Is(err, model.ErrOrganizationWalletInsufficient):
		status, code, message = 409, "ORG_WALLET_INSUFFICIENT_AVAILABLE", model.ErrOrganizationWalletInsufficient.Error()
	case errors.Is(err, model.ErrOrganizationWalletLimit):
		status, code, message = 409, "ORG_WALLET_LIMIT_EXCEEDED", model.ErrOrganizationWalletLimit.Error()
	case errors.Is(err, model.ErrOrganizationWalletNotEmpty):
		status, code, message = 409, "ORG_WALLET_NOT_EMPTY", model.ErrOrganizationWalletNotEmpty.Error()
	case errors.Is(err, model.ErrOrganizationDisabled):
		status, code, message = 409, "ORG_DISABLED", "Organization is disabled."
	case errors.Is(err, model.ErrOrganizationTerminal):
		status, code, message = 409, "ORG_REQUEST_RESOLVED", "Organization request is already resolved."
	case errors.Is(err, model.ErrOrganizationExpired):
		status, code, message = 410, "ORG_REQUEST_EXPIRED", "Organization request has expired."
	case errors.Is(err, service.ErrOrganizationProofRequired):
		status, code, message = 403, "SECURITY_PROOF_REQUIRED", service.ErrOrganizationProofRequired.Error()
	case errors.Is(err, service.ErrProofConsumed), errors.Is(err, model.ErrAuthFlowConsumed):
		status, code, message = 403, "SECURITY_PROOF_CONSUMED", "Security proof was already consumed."
	case errors.Is(err, service.ErrAuthTokenExpired), errors.Is(err, model.ErrAuthFlowExpired):
		status, code, message = 403, "SECURITY_PROOF_EXPIRED", "Security proof has expired."
	case errors.Is(err, service.ErrProofScope):
		status, code, message = 403, "SECURITY_PROOF_SCOPE_MISMATCH", "Verification does not match this action."
	case errors.Is(err, service.ErrProofContext):
		status, code, message = 403, "SECURITY_PROOF_CONTEXT_MISMATCH", "Verification does not match these action details."
	case errors.Is(err, service.ErrProofMethod):
		status, code, message = 403, "SECURITY_PROOF_METHOD_MISMATCH", "This verification method is not allowed for this action."
	case errors.Is(err, service.ErrVerificationUnavailable), errors.Is(err, model.ErrTwoFANotEnabled):
		status, code, message = 403, "SECURITY_METHOD_UNAVAILABLE", service.ErrVerificationUnavailable.Error()
	case errors.Is(err, service.ErrVerificationLocked):
		status, code, message = 403, "SECURITY_VERIFICATION_LOCKED", service.ErrVerificationLocked.Error()
	case errors.Is(err, service.ErrVerificationFailed):
		status, code, message = 403, "SECURITY_VERIFICATION_FAILED", service.ErrVerificationFailed.Error()
	case errors.Is(err, service.ErrAuthTokenInvalid), errors.Is(err, model.ErrAuthFlowInvalid):
		status, code, message = 403, "SECURITY_PROOF_INVALID", "Security proof is invalid."
	}
	c.Header("Cache-Control", "private, no-store")
	fields := gin.H{"code": code}
	var revisionConflict *model.OrganizationRevisionConflictError
	if errors.As(err, &revisionConflict) {
		fields["data"] = gin.H{"revision": strconv.FormatInt(revisionConflict.Revision, 10)}
	}
	common.ApiErrorStatus(c, status, common.NewMessage(message), fields)
	c.Abort()
}

// This check occurs before parsing proof, context or free text. It retains only
// the registered route and fixed decisions in request state.
func organizationRequest(c *gin.Context, allowProof, paged bool, bodyLimit int64, scopeQuery bool) (service.AuthIdentity, []byte, model.OrganizationPage, error) {
	if err := c.Request.Context().Err(); err != nil {
		return service.AuthIdentity{}, nil, model.OrganizationPage{}, err
	}
	c.Header("Cache-Control", "private, no-store")
	page := model.OrganizationPage{Limit: 20}
	var identity service.AuthIdentity
	for _, name := range []string{"Authorization", "X-Security-Proof", "Origin", "Referer", "Content-Type", "X-Organization-Id", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
		count := 0
		for key, values := range c.Request.Header {
			if strings.EqualFold(key, name) {
				count += len(values)
			}
		}
		if count > 1 {
			return identity, nil, page, model.ErrOrganizationInvalidInput
		}
	}
	for key := range c.Request.Header {
		if strings.EqualFold(key, "Idempotency-Key") || strings.EqualFold(key, "X-HTTP-Method-Override") || strings.EqualFold(key, "X-Method-Override") || strings.EqualFold(key, "X-HTTP-Method") || !allowProof && strings.EqualFold(key, "X-Security-Proof") {
			return identity, nil, page, model.ErrOrganizationInvalidInput
		}
	}
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		return identity, nil, page, model.ErrOrganizationInvalidInput
	}
	for key, values := range query {
		if len(values) != 1 {
			return identity, nil, page, model.ErrOrganizationInvalidInput
		}
		switch key {
		case "org_id":
		case "scope":
			if !scopeQuery {
				return identity, nil, page, model.ErrOrganizationInvalidInput
			}
		case "after_id", "limit":
			if !paged {
				return identity, nil, page, model.ErrOrganizationInvalidInput
			}
			n, ok := middleware.ParseOrganizationDecimal(values[0])
			if !ok {
				return identity, nil, page, model.ErrOrganizationInvalidInput
			}
			if key == "after_id" {
				page.AfterID = n
			} else {
				if n < 1 || n > 100 {
					return identity, nil, page, model.ErrOrganizationInvalidInput
				}
				page.Limit = int(n)
			}
		default:
			return identity, nil, page, model.ErrOrganizationInvalidInput
		}
	}
	var ok bool
	identity, ok = middleware.GetAuthIdentity(c)
	if !ok || identity.SessionID == "" || strings.HasPrefix(identity.SessionID, "pat:") || strings.HasPrefix(identity.SessionID, "legacy") {
		return identity, nil, page, &organizationHTTPError{403, "AUTH_SESSION_REQUIRED", "A dashboard session is required."}
	}
	if !middleware.OrganizationOriginAllowed(c.Request) {
		message := "Fetch metadata is not allowed without an Origin or Referer header."
		for key := range c.Request.Header {
			if strings.EqualFold(key, "Origin") || strings.EqualFold(key, "Referer") {
				message = "request origin is not allowed"
				break
			}
		}
		return identity, nil, page, &organizationHTTPError{403, "AUTH_ORIGIN_FORBIDDEN", message}
	}
	if c.Request.Method == http.MethodGet {
		if c.Request.Body != nil {
			data, err := io.ReadAll(io.LimitReader(c.Request.Body, 1))
			if err != nil || len(data) > 0 {
				return identity, nil, page, model.ErrOrganizationInvalidInput
			}
		}
		return identity, nil, page, nil
	}
	media, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || media != "application/json" || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") {
		return identity, nil, page, &organizationHTTPError{415, "UNSUPPORTED_MEDIA_TYPE", "JSON content type is required."}
	}
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, bodyLimit+1))
	if err != nil {
		if err := c.Request.Context().Err(); err != nil {
			return identity, nil, page, err
		}
		return identity, nil, page, model.ErrOrganizationInvalidInput
	}
	if int64(len(data)) > bodyLimit {
		return identity, nil, page, &organizationHTTPError{413, "REQUEST_TOO_LARGE", "Request body is too large."}
	}
	validate := common.ValidateStrictJSONObject
	if c.FullPath() == "/api/user/passkey/verify/finish" {
		validate = common.ValidateWebAuthnFinishJSONObject
	}
	if validate(data) != nil {
		return identity, nil, page, model.ErrOrganizationInvalidInput
	}
	return identity, data, page, nil
}
func OrganizationLifecycleHandler(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		identity, data, _, err := organizationRequest(c, service.OrganizationScope(action) != "", false, 16*1024, false)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		objectID := c.Param("invitation_id")
		if objectID == "" {
			objectID = c.Param("transfer_id")
		}
		if action == "wallet_reverse" {
			objectID = c.Param("credit_id")
		}
		wire, cmd, err := service.DecodeOrganizationCommand(action, data, false, c.Param("org_id"), c.Param("user_id"), objectID)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		if _, present := c.Request.Header["X-Security-Proof"]; present && c.GetHeader("X-Security-Proof") == "" {
			writeOrganizationLifecycleError(c, model.ErrOrganizationInvalidInput)
			return
		}
		receipt, err := service.ExecuteOrganizationLifecycleWithContext(c.Request.Context(), identity, action, wire, cmd, c.GetHeader("X-Security-Proof"))
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		if entry := receipt.WalletEntry; entry != nil {
			var creditID any
			if entry.ReversalOfID != nil {
				creditID = strconv.FormatInt(*entry.ReversalOfID, 10)
			}
			common.ApiSuccess(c, gin.H{"organization_id": strconv.FormatInt(entry.OrganizationID, 10), "entry_id": strconv.FormatInt(entry.ID, 10),
				"request_id": entry.RequestID, "kind": entry.Kind, "amount": strconv.FormatInt(entry.Amount, 10), "credit_id": creditID,
				"balance_after": strconv.FormatInt(entry.BalanceAfter, 10), "actor_user_id": strconv.Itoa(entry.ActorUserID), "created_at": entry.CreatedAt,
				"reference": entry.Reference, "reason": entry.Reason})
			// The immutable main-database ledger and event are the authoritative audit.
			// Do not copy free-text financial details into generic security logs.
			return
		}
		var generation, status any
		if receipt.Generation > 0 {
			generation = strconv.FormatInt(receipt.Generation, 10)
			status = receipt.Status
		}
		result := gin.H{"organization_id": strconv.FormatInt(receipt.OrganizationID, 10), "revision": strconv.FormatInt(receipt.Revision, 10), "action": strings.Replace(receipt.Action, "invite_", "invitation_", 1), "event_id": strconv.FormatInt(receipt.EventID, 10), "object_kind": receipt.ObjectKind, "object_id": strconv.FormatInt(receipt.ObjectID, 10), "generation": generation, "status": status}
		code := 200
		if action == "create" {
			code = 201
		}
		c.JSON(code, gin.H{"success": true, "message": "", "data": result})
		// Nil sink context prevents automatic request metadata/free-text capture.
		model.RecordAuditLog(nil, model.AuditLog{UserId: identity.UserID, Category: model.AuditCategorySecurity, ActorRole: c.GetInt("role"), Action: "organization." + action, AuthMethod: "session", Method: c.Request.Method, Route: c.FullPath(), Status: code, Success: true, Other: model.AuditOther{Op: &model.AuditOperation{Action: action, Params: model.AuditFields{"org_id": strconv.FormatInt(receipt.OrganizationID, 10), "event_id": strconv.FormatInt(receipt.EventID, 10)}}}})
	}
}
func OrganizationPreviewHandler(platform bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, data, _, err := organizationRequest(c, false, false, 16*1024, false)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		var request struct {
			Action  string            `json:"action"`
			Command common.RawMessage `json:"command"`
		}
		if common.ValidateJSONObjectFields(data, []string{"action", "command"}, nil) != nil || common.UnmarshalStrictObject(data, &request) != nil || request.Action == "" ||
			platform != (request.Action == "platform_disable" || request.Action == "wallet_credit" || request.Action == "wallet_reverse") {
			writeOrganizationLifecycleError(c, model.ErrOrganizationInvalidInput)
			return
		}
		wire, cmd, err := service.DecodeOrganizationCommand(request.Action, request.Command, true, "", "", "")
		if err != nil || wire.OrganizationID != c.Param("org_id") {
			if wire.OrganizationID != c.Param("org_id") || !errors.Is(err, service.ErrOrganizationEmailInviteUnsupported) {
				err = model.ErrOrganizationInvalidInput
			}
			writeOrganizationLifecycleError(c, err)
			return
		}
		op, b, name, err := service.PreviewOrganizationOperationWithContext(c.Request.Context(), identity, request.Action, wire, cmd)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		methods, err := service.OrganizationVerificationRequirementsWithContext(c.Request.Context(), identity, op.Scope)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		var target, role, disabled, replace any
		if b.TargetUserID > 0 {
			target = strconv.Itoa(b.TargetUserID)
		}
		if b.Role != "" {
			role = b.Role
		}
		if wire.Disabled != nil {
			disabled = *wire.Disabled
		}
		if wire.Replace != nil {
			replace = *wire.Replace
		}
		display := gin.H{"organization_name": name, "target_user_id": target, "target_role": role, "disabled": disabled, "replace": replace}
		if request.Action == "wallet_credit" || request.Action == "wallet_reverse" {
			display["amount"], display["request_id"], display["credit_id"] = strconv.FormatInt(b.WalletAmount, 10), wire.RequestID, wire.CreditID
			display["reference"], display["reason"] = wire.Reference, cmd.Reason
		}
		common.ApiSuccess(c, gin.H{"operation": op, "methods": methods.Methods, "password_encryption_enabled": methods.PasswordEncryptionEnabled, "display": display})
	}
}

func OrganizationWalletReadHandler(platform bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, _, _, err := organizationRequest(c, false, false, 0, false)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		orgID, err := service.OrganizationDecimal(c.Param("org_id"), false)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		wallet, err := model.ReadOrganizationWalletWithContext(c.Request.Context(), identity, orgID, platform)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		data := gin.H{"organization_id": strconv.FormatInt(orgID, 10), "opened": wallet.ID != 0,
			"balance": strconv.FormatInt(wallet.Balance, 10), "reserved": strconv.FormatInt(wallet.Reserved, 10),
			"available": strconv.FormatInt(wallet.Balance-wallet.Reserved, 10)}
		// Protect the prepared financial snapshot from committed role/session changes.
		if _, err := model.ReadOrganizationWalletWithContext(c.Request.Context(), identity, orgID, platform); err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		common.ApiSuccess(c, data)
	}
}
func organizationRequestView(v *model.OrganizationRequestResult) any {
	if v == nil {
		return nil
	}
	var revision, role, resolved any
	if v.OrganizationRevision != nil {
		revision = strconv.FormatInt(*v.OrganizationRevision, 10)
	}
	if v.Role != "" {
		role = v.Role
	}
	if v.ResolvedAt != 0 {
		resolved = v.ResolvedAt
	}
	result := gin.H{"organization_id": strconv.FormatInt(v.OrganizationID, 10), "organization_name": v.OrganizationName, "organization_revision": revision, "object_id": strconv.FormatInt(v.ObjectID, 10), "generation": strconv.FormatInt(v.Generation, 10), "kind": v.Kind, "from_user_id": strconv.Itoa(v.FromUserID), "target_user_id": strconv.Itoa(v.TargetUserID), "role": role, "status": v.Status, "expires_at": v.ExpiresAt, "resolved_at": resolved, "reason_code": v.ReasonCode}
	if v.Kind == "invitation" {
		result["from_username"], result["target_username"] = v.FromUsername, v.TargetUsername
	}
	return result
}
func OrganizationLifecycleQuery(kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		paged := kind == "invitation_inbox" || kind == "transfer_inbox" || kind == "invitation_slots"
		identity, _, page, err := organizationRequest(c, false, paged, 0, false)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		var orgID int64
		if c.Param("org_id") != "" {
			orgID, err = service.OrganizationDecimal(c.Param("org_id"), false)
			if err != nil {
				writeOrganizationLifecycleError(c, err)
				return
			}
		}
		if kind == "self_state" || kind == "platform_state" {
			v, err := model.GetOrganizationLifecycleStateWithContext(c.Request.Context(), identity, orgID, kind == "platform_state")
			if err != nil {
				writeOrganizationLifecycleError(c, err)
				return
			}
			data := gin.H{"organization_id": strconv.FormatInt(v.ID, 10), "name": v.Name, "revision": strconv.FormatInt(v.Revision, 10), "self_disabled": v.SelfDisabled, "platform_disabled": v.PlatformDisabled, "dissolved": v.Dissolved}
			if kind == "self_state" {
				data["my_role"] = v.MyRole
			}
			common.ApiSuccess(c, data)
			return
		}
		var rows []model.OrganizationRequestResult
		var single *model.OrganizationRequestResult
		switch kind {
		case "invitation_inbox":
			rows, err = model.ListPendingOrganizationInvitationsForActorWithContext(c.Request.Context(), identity, page)
		case "transfer_inbox":
			rows, err = model.ListPendingOrganizationOwnershipTransfersForActorWithContext(c.Request.Context(), identity, page)
		case "invitation_slots":
			rows, err = model.ListOrganizationInvitationSlotsWithContext(c.Request.Context(), identity, orgID, page)
		case "transfer_slot":
			single, err = model.GetOrganizationOwnershipTransferSlotWithContext(c.Request.Context(), identity, orgID)
		case "invitation_result", "transfer_result":
			id := c.Param("invitation_id")
			if kind == "transfer_result" {
				id = c.Param("transfer_id")
			}
			objectID, e := service.OrganizationDecimal(id, false)
			if e != nil {
				writeOrganizationLifecycleError(c, e)
				return
			}
			generation, e := service.OrganizationDecimal(c.Param("generation"), false)
			if e != nil {
				writeOrganizationLifecycleError(c, e)
				return
			}
			if kind == "invitation_result" {
				single, err = model.GetOrganizationInvitationResultWithContext(c.Request.Context(), identity, orgID, objectID, generation)
			} else {
				single, err = model.GetOrganizationOwnershipTransferResultWithContext(c.Request.Context(), identity, orgID, objectID, generation)
			}
		default:
			err = model.ErrOrganizationInvalidInput
		}
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		if !paged {
			common.ApiSuccess(c, organizationRequestView(single))
			return
		}
		items := make([]any, 0, len(rows))
		for i := range rows {
			items = append(items, organizationRequestView(&rows[i]))
		}
		var cursor any
		if len(rows) == page.Limit {
			cursor = strconv.FormatInt(rows[len(rows)-1].ObjectID, 10)
		}
		common.ApiSuccess(c, gin.H{"items": items, "limit": page.Limit, "next_after_id": cursor})
	}
}

// Shared producer routes retain a replayable bounded body for the organization
// branch. Shared producer routing and consumption use the same decoded envelope.
func readSecurityProducerBody(c *gin.Context) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, 64*1024+1))
	if err != nil {
		return nil, model.ErrOrganizationInvalidInput
	}
	if len(data) > 64*1024 {
		return nil, &organizationHTTPError{413, "REQUEST_TOO_LARGE", "Request body is too large."}
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}
func organizationVerificationSuccess(c *gin.Context, identity service.AuthIdentity, proof *service.OrganizationProofResult) {
	service.WriteRefreshCookie(c, proof.AuthBundle.RefreshToken)
	common.ApiSuccess(c, proof)
	model.RecordAuditLog(nil, model.AuditLog{UserId: identity.UserID, Category: model.AuditCategorySecurity, ActorRole: c.GetInt("role"), Action: "user.security_verify", AuthMethod: proof.Method, Method: c.Request.Method, Route: c.FullPath(), Status: 200, Success: true})
}
