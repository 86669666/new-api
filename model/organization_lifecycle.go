package model

import (
	"context"
	"errors"
	"math"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

func (s *organizationState) advance(c OrganizationCommand) error {
	if s.org.Revision != c.Revision {
		return ErrOrganizationConflict
	}
	if s.execution != nil && s.execution.preview {
		return errOrganizationPreviewComplete
	}
	next, err := organizationNextVersion(s.org.Revision)
	if err != nil {
		return err
	}
	result := s.tx.Model(&Organization{}).Where("id = ? AND revision = ? AND owner_user_id = ? AND ownership_version = ?", s.org.ID, c.Revision, s.org.OwnerUserID, s.org.OwnershipVersion).Updates(map[string]any{"revision": next, "updated_at": s.now})
	if err = organizationCAS(result); err != nil {
		return err
	}
	s.org.Revision = next
	s.org.UpdatedAt = s.now
	return nil
}
func (s *organizationState) event(action string, subject int, kind string, id, generation int64, before, after, reason, role string, expires int64) error {
	event := OrganizationEvent{OrganizationID: s.org.ID, OrganizationRevision: s.org.Revision, ActorUserID: s.identity.UserID, Action: action, SubjectUserID: subject, ObjectKind: kind, ObjectID: id, ObjectGeneration: generation, BeforeState: before, AfterState: after, ReasonCode: reason, Role: role, ExpiresAt: expires, CreatedAt: s.now}
	if err := s.tx.Create(&event).Error; err != nil {
		return err
	}
	if s.execution != nil && s.execution.receipt != nil && action == organizationPrimaryEvent(s.execution.action) && s.execution.receipt.EventID == 0 {
		r := s.execution.receipt
		r.OrganizationID = s.org.ID
		r.Revision = s.org.Revision
		r.Action = s.execution.action
		r.EventID = event.ID
		r.ObjectKind = kind
		r.ObjectID = id
		if kind == "invitation" || kind == "transfer" {
			r.Generation = generation
			r.Status = after
		}
	}
	return nil
}
func (s *organizationState) changeMember(m *OrganizationMember, role string, removed int64, reason string) error {
	next, err := organizationNextVersion(m.Revision)
	if err != nil {
		return err
	}
	if err = organizationCAS(s.tx.Model(&OrganizationMember{}).Where("id = ? AND organization_id = ? AND revision = ?", m.ID, s.org.ID, m.Revision).Updates(map[string]any{"role": role, "removed_at": removed, "removal_reason": reason, "revision": next, "updated_at": s.now})); err != nil {
		return err
	}
	m.Role = role
	m.RemovedAt = removed
	m.RemovalReason = reason
	m.Revision = next
	m.UpdatedAt = s.now
	return nil
}
func (s *organizationState) resolveInvitation(v *OrganizationInvitation, status, reason string) error {
	query := s.tx.Model(&OrganizationInvitation{}).Where("id = ? AND organization_id = ? AND generation = ? AND status = ?", v.ID, s.org.ID, v.Generation, OrganizationPending)
	if status == OrganizationAccepted {
		query = query.Where("expires_at > ?", s.now)
	}
	if status == OrganizationExpired {
		query = query.Where("expires_at <= ?", s.now)
	}
	if err := organizationCAS(query.Updates(map[string]any{"status": status, "resolved_at": s.now, "updated_at": s.now, "resolution_reason": reason})); err != nil {
		return err
	}
	v.Status = status
	v.ResolvedAt = s.now
	v.ResolutionReason = reason
	return s.event("invitation."+status, v.TargetUserID, "invitation", v.ID, v.Generation, OrganizationPending, status, reason, v.Role, v.ExpiresAt)
}
func (s *organizationState) resolveTransfer(status, reason string) error {
	v := &s.transfer
	query := s.tx.Model(&OrganizationOwnershipTransfer{}).Where("id = ? AND organization_id = ? AND generation = ? AND status = ?", v.ID, s.org.ID, v.Generation, OrganizationPending)
	if status == OrganizationAccepted {
		query = query.Where("expires_at > ?", s.now)
	}
	if status == OrganizationExpired {
		query = query.Where("expires_at <= ?", s.now)
	}
	if err := organizationCAS(query.Updates(map[string]any{"status": status, "resolved_at": s.now, "updated_at": s.now, "resolution_reason": reason})); err != nil {
		return err
	}
	v.Status = status
	v.ResolvedAt = s.now
	v.ResolutionReason = reason
	return s.event("transfer."+status, v.ToUserID, "transfer", v.ID, v.Generation, OrganizationPending, status, reason, "", v.ExpiresAt)
}

// Every invalidated slot gets its own terminal history in the same transaction.
func (s *organizationState) revokeDependentRequests(userID int, reason string) error {
	for i := range s.invitations {
		v := &s.invitations[i]
		if v.Status == OrganizationPending && (userID == 0 || v.InviterUserID == userID || v.TargetUserID == userID) {
			if err := s.resolveInvitation(v, OrganizationRevoked, reason); err != nil {
				return err
			}
		}
	}
	if s.transfer.Status == OrganizationPending && (userID == 0 || s.transfer.FromUserID == userID || s.transfer.ToUserID == userID) {
		return s.resolveTransfer(OrganizationCancelled, reason)
	}
	return nil
}

func validateOrganizationCommand(action string, c OrganizationCommand) error {
	if c.OrganizationID <= 0 || c.Revision <= 0 || c.TargetUserID < 0 || c.ObjectID < 0 || c.Generation < 0 {
		return ErrOrganizationInvalidInput
	}
	rest := c
	rest.OrganizationID = 0
	rest.Revision = 0
	rest.Authorization = nil
	switch action {
	case "rename":
		rest.Name = ""
	case "self_disable", "platform_disable":
		rest.Disabled = false
		rest.Reason = ""
	case "change_role":
		rest.TargetUserID = 0
		rest.Role = ""
	case "remove":
		rest.TargetUserID = 0
	case "invite", "reissue":
		rest.TargetUserID = 0
		rest.Username = ""
		rest.ExpectedUsername = ""
		rest.Role = ""
		rest.ObjectID = 0
		rest.Generation = 0
	case "invite_accept", "invite_decline", "invite_revoke":
		rest.ObjectID = 0
		rest.Generation = 0
	case "transfer_initiate":
		rest.TargetUserID = 0
		rest.ObjectID = 0
		rest.Generation = 0
		rest.Replace = false
	case "transfer_accept", "transfer_decline", "transfer_cancel":
		rest.ObjectID = 0
		rest.Generation = 0
	case "wallet_credit", "wallet_reverse":
		rest.WalletRequestID = ""
		rest.WalletAmount = 0
		rest.WalletCreditID = 0
		rest.WalletReference = ""
		rest.Reason = ""
	case "leave", "dissolve", "invite_expire", "transfer_expire":
	default:
		return ErrOrganizationInvalidInput
	}
	if rest != (OrganizationCommand{}) {
		return ErrOrganizationInvalidInput
	}
	if action == "wallet_credit" || action == "wallet_reverse" {
		return validateOrganizationWalletCommand(action, c)
	}
	if c.Username != "" || c.ExpectedUsername != "" {
		username := c.Username
		if username == "" {
			username = c.ExpectedUsername
		}
		if c.Username != "" && (c.TargetUserID != 0 || c.ExpectedUsername != "") || !utf8.ValidString(username) || utf8.RuneCountInString(username) > 20 {
			return ErrOrganizationInvalidInput
		}
		for _, r := range username {
			if unicode.IsControl(r) {
				return ErrOrganizationInvalidInput
			}
		}
	}
	if action == "self_disable" || action == "platform_disable" {
		if utf8.RuneCountInString(c.Reason) > 128 || !utf8.ValidString(c.Reason) || !c.Disabled && c.Reason != "" {
			return ErrOrganizationInvalidInput
		}
		for _, r := range c.Reason {
			if unicode.IsControl(r) {
				return ErrOrganizationInvalidInput
			}
		}
	}
	return nil
}

func CreateOrganization(identity AuthSessionIdentity, name string) (*Organization, error) {
	return createOrganizationWithReceipt(context.Background(), identity, name, nil, "")
}
func createOrganizationWithReceipt(ctx context.Context, identity AuthSessionIdentity, name string, receipt *OrganizationMutationReceipt, key string) (*Organization, error) {
	name, err := organizationName(name)
	if err != nil {
		return nil, err
	}
	var request *OrganizationCreationRequest
	if key != "" {
		request, err = newOrganizationCreationRequest(identity.UserID, name, key)
		if err != nil {
			return nil, err
		}
	}
	var org Organization
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("id = ?", identity.UserID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
			return err
		}
		now := organizationNow().Unix()
		if _, err := validateOrganizationIdentity(tx, identity, now); err != nil {
			return err
		}
		if request != nil {
			var previous OrganizationCreationRequest
			err := tx.Where("user_id = ? AND key_hash = ?", identity.UserID, request.KeyHash).First(&previous).Error
			if err == nil {
				if previous.RequestHash != request.RequestHash {
					return ErrOrganizationIdempotencyConflict
				}
				replay, err := replayOrganizationCreation(tx, identity, &previous, receipt)
				if err != nil {
					return err
				}
				org = *replay
				return nil
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}
		if err := requireOrganizationNameAvailable(tx, identity.UserID, 0, name); err != nil {
			return err
		}
		if err := requireOrganizationCapacity(tx, identity.UserID, true, true); err != nil {
			return err
		}
		now = organizationNow().Unix()
		if _, err := validateOrganizationIdentity(tx, identity, now); err != nil {
			return err
		}
		org = Organization{Name: name, CreatedByUserID: identity.UserID, OwnerUserID: identity.UserID, Revision: 1, OwnershipVersion: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		if err := tx.Create(&OrganizationMember{OrganizationID: org.ID, UserID: identity.UserID, Role: OrganizationRoleMember, Revision: 1, JoinedAt: now, UpdatedAt: now}).Error; err != nil {
			return err
		}
		s := organizationState{tx: tx, identity: identity, org: org, now: now, execution: &organizationExecution{action: "create", receipt: receipt}}
		if err := s.event("organization.created", identity.UserID, "organization", org.ID, 0, "", "active", "", "", 0); err != nil {
			return err
		}
		if request != nil {
			request.OrganizationID, request.EventID, request.CreatedAt = org.ID, receipt.EventID, now
			// Any insert/unique failure aborts the entire transaction. Never
			// attempt a read-back inside an aborted PostgreSQL transaction.
			return tx.Create(request).Error
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &org, nil
}

func RenameOrganization(i AuthSessionIdentity, c OrganizationCommand) error {
	return mutateOrganization(i, c, "rename")
}
func SetOrganizationSelfDisabled(i AuthSessionIdentity, c OrganizationCommand) error {
	return mutateOrganization(i, c, "self_disable")
}
func SetOrganizationPlatformDisabled(i AuthSessionIdentity, c OrganizationCommand) error {
	return mutateOrganization(i, c, "platform_disable")
}
func DissolveOrganization(i AuthSessionIdentity, c OrganizationCommand) error {
	return mutateOrganization(i, c, "dissolve")
}
func ChangeOrganizationMemberRole(i AuthSessionIdentity, c OrganizationCommand) error {
	return mutateOrganization(i, c, "change_role")
}
func RemoveOrganizationMember(i AuthSessionIdentity, c OrganizationCommand) error {
	return mutateOrganization(i, c, "remove")
}
func LeaveOrganization(i AuthSessionIdentity, c OrganizationCommand) error {
	return mutateOrganization(i, c, "leave")
}

func mutateOrganization(i AuthSessionIdentity, c OrganizationCommand, action string, options ...*organizationExecution) error {
	if err := validateOrganizationCommand(action, c); err != nil {
		return err
	}
	return withOrganization(i, c, true, func(s *organizationState) error {
		if s.org.DissolvedAt != 0 {
			return ErrOrganizationTerminal
		}
		role := s.role(i.UserID)
		b := s.binding(c)
		switch action {
		case "rename":
			if c.Authorization != nil {
				return ErrOrganizationInvalidInput
			}
			if role != OrganizationRoleOwner && role != OrganizationRoleAdmin {
				return ErrOrganizationForbidden
			}
			if err := s.requireEnabled(); err != nil {
				return err
			}
			name, err := organizationName(c.Name)
			if err != nil {
				return err
			}
			if name == s.org.Name {
				return ErrOrganizationConflict
			}
			if err = requireOrganizationNameAvailable(s.tx, s.org.OwnerUserID, s.org.ID, name); err != nil {
				return err
			}
			if err = s.advance(c); err != nil {
				return err
			}
			if err = s.tx.Model(&Organization{}).Where("id = ?", s.org.ID).Update("name", name).Error; err != nil {
				return err
			}
		case "self_disable", "platform_disable":
			if action == "self_disable" {
				if err := s.requireOwner(); err != nil {
					return err
				}
				if s.org.PlatformDisabledAt != 0 {
					return ErrOrganizationDisabled
				}
			} else if s.users[i.UserID].Role != common.RoleRootUser {
				return ErrOrganizationForbidden
			}
			b.Disabled = c.Disabled
			b.Reason = c.Reason
			if err := s.authorize(action, c, b); err != nil {
				return err
			}
			at := s.org.SelfDisabledAt
			if action == "platform_disable" {
				at = s.org.PlatformDisabledAt
			}
			if (at != 0) == c.Disabled {
				return ErrOrganizationConflict
			}
			if err := s.advance(c); err != nil {
				return err
			}
			prefix := "self"
			if action == "platform_disable" {
				prefix = "platform"
			}
			at = 0
			if c.Disabled {
				at = s.now
			}
			if err := s.tx.Model(&Organization{}).Where("id = ?", s.org.ID).Updates(map[string]any{prefix + "_disabled_at": at, prefix + "_disabled_reason": c.Reason}).Error; err != nil {
				return err
			}
			if c.Disabled {
				if err := s.revokeDependentRequests(0, action); err != nil {
					return err
				}
			}
		case "dissolve":
			if err := s.requireOwner(); err != nil {
				return err
			}
			if s.org.PlatformDisabledAt != 0 {
				return ErrOrganizationDisabled
			}
			var wallet OrganizationWallet
			if err := lockForUpdate(s.tx).Where("organization_id = ?", s.org.ID).Find(&wallet).Error; err != nil {
				return err
			}
			s.now = organizationNow().Unix()
			if _, err := validateOrganizationIdentity(s.tx, i, s.now); err != nil {
				return err
			}
			if err := s.authorize(action, c, b); err != nil {
				return err
			}
			if wallet.Balance != 0 || wallet.Reserved != 0 {
				return ErrOrganizationWalletNotEmpty
			}
			if err := s.advance(c); err != nil {
				return err
			}
			if err := s.tx.Model(&Organization{}).Where("id = ?", s.org.ID).Update("dissolved_at", s.now).Error; err != nil {
				return err
			}
			for j := range s.members {
				m := &s.members[j]
				if m.RemovedAt == 0 {
					if err := s.changeMember(m, OrganizationRoleMember, s.now, "dissolved"); err != nil {
						return err
					}
				}
			}
			if err := s.revokeDependentRequests(0, "dissolved"); err != nil {
				return err
			}
		case "change_role", "remove", "leave":
			target := c.TargetUserID
			if action == "leave" {
				target = i.UserID
			}
			m := s.member(target)
			if m == nil {
				return ErrOrganizationNotFound
			}
			if target == s.org.OwnerUserID {
				return ErrOrganizationForbidden
			}
			if action != "leave" {
				if err := s.requireEnabled(); err != nil {
					return err
				}
			}
			if action == "change_role" {
				if err := s.requireOwner(); err != nil {
					return err
				}
				if c.Role != OrganizationRoleMember && c.Role != OrganizationRoleAdmin {
					return ErrOrganizationInvalidInput
				}
				if c.Role == m.Role {
					return ErrOrganizationConflict
				}
				b.TargetUserID = target
				b.Role = c.Role
				if err := s.authorize(action, c, b); err != nil {
					return err
				}
			} else if action == "remove" {
				if target == i.UserID {
					return ErrOrganizationForbidden
				}
				if role != OrganizationRoleOwner && !(role == OrganizationRoleAdmin && m.Role == OrganizationRoleMember) {
					return ErrOrganizationForbidden
				}
				if m.Role == OrganizationRoleAdmin {
					b.TargetUserID = target
					b.Role = m.Role
					if err := s.authorize(action, c, b); err != nil {
						return err
					}
				} else if c.Authorization != nil {
					return ErrOrganizationInvalidInput
				}
			} else if c.Authorization != nil {
				return ErrOrganizationInvalidInput
			}
			if err := s.advance(c); err != nil {
				return err
			}
			before := m.Role
			if action == "change_role" {
				if err := s.changeMember(m, c.Role, 0, ""); err != nil {
					return err
				}
			} else {
				if err := s.changeMember(m, OrganizationRoleMember, s.now, action); err != nil {
					return err
				}
			}
			if err := s.revokeDependentRequests(target, action); err != nil {
				return err
			}
			return s.event("member."+action, target, "member", m.ID, m.Revision, before, m.Role, action, m.Role, 0)
		}
		after := "active"
		if action == "dissolve" {
			after = "dissolved"
		}
		if c.Disabled {
			after = "disabled"
		}
		return s.event("organization."+action, 0, "organization", s.org.ID, 0, "", after, "", "", 0)
	}, options...)
}

func InviteOrganizationMember(i AuthSessionIdentity, c OrganizationCommand) error {
	return issueOrganizationInvitation(i, c, false)
}
func ReissueOrganizationInvitation(i AuthSessionIdentity, c OrganizationCommand) error {
	return issueOrganizationInvitation(i, c, true)
}

var errOrganizationInvitationTargetResolved = errors.New("organization invitation target resolved")

// ResolveOrganizationInvitationTargetWithContext resolves a selector only after
// the same invitation authority and revision checks as the write. Its dedicated
// sentinel is usable only after an explicitly successful rollback, including the
// SQLite actor reservation. Target user locks belong to the subsequent command.
func ResolveOrganizationInvitationTargetWithContext(ctx context.Context, i AuthSessionIdentity, action string, c OrganizationCommand) (OrganizationCommand, error) {
	if action != "invite" && action != "reissue" || c.Username == "" || c.TargetUserID != 0 || c.ExpectedUsername != "" || c.Authorization != nil || c.Role != OrganizationRoleMember && c.Role != OrganizationRoleAdmin {
		return OrganizationCommand{}, ErrOrganizationInvalidInput
	}
	if err := validateOrganizationCommand(action, c); err != nil {
		return OrganizationCommand{}, err
	}
	var resolved OrganizationCommand
	err := withOrganizationWithContext(ctx, i, c, true, func(s *organizationState) error {
		if err := s.requireEnabled(); err != nil {
			return err
		}
		if !s.canInvite(c.Role) {
			return ErrOrganizationForbidden
		}
		var user User
		if err := s.tx.Select("id", "username").Where("username = ?", c.Username).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrOrganizationNotFound
			}
			return err
		}
		// SQL collations may ignore case, accents or trailing spaces.
		if user.Username != c.Username {
			return ErrOrganizationNotFound
		}
		if err := s.tx.Rollback().Error; err != nil {
			return err
		}
		resolved = c
		resolved.TargetUserID, resolved.ExpectedUsername, resolved.Username = user.Id, c.Username, ""
		return errOrganizationInvitationTargetResolved
	}, &organizationExecution{ctx: ctx, action: action, preview: true})
	if !errors.Is(err, errOrganizationInvitationTargetResolved) {
		if err == nil {
			err = ErrOrganizationInvalidInput
		}
		return OrganizationCommand{}, err
	}
	return resolved, nil
}

func issueOrganizationInvitation(i AuthSessionIdentity, c OrganizationCommand, reissue bool, options ...*organizationExecution) error {
	action := "invite"
	if reissue {
		action = "reissue"
	}
	if err := validateOrganizationCommand(action, c); err != nil {
		return err
	}
	if c.Username != "" {
		ctx := context.Background()
		if len(options) > 0 && options[0] != nil && options[0].ctx != nil {
			ctx = options[0].ctx
		}
		var err error
		c, err = ResolveOrganizationInvitationTargetWithContext(ctx, i, action, c)
		if err != nil {
			return err
		}
	}
	if c.TargetUserID <= 0 || c.Role != OrganizationRoleMember && c.Role != OrganizationRoleAdmin {
		return ErrOrganizationInvalidInput
	}
	if c.TargetUserID == i.UserID {
		return ErrOrganizationSelfInvite
	}
	return withOrganization(i, c, true, func(s *organizationState) error {
		if err := s.requireEnabled(); err != nil {
			return err
		}
		if !s.canInvite(c.Role) {
			return ErrOrganizationForbidden
		}
		if !s.activeUser(c.TargetUserID) {
			return ErrOrganizationNotFound
		}
		if c.ExpectedUsername != "" && s.users[c.TargetUserID].Username != c.ExpectedUsername {
			return ErrOrganizationConflict
		}
		if s.member(c.TargetUserID) != nil {
			return ErrOrganizationAlreadyMember
		}
		var old *OrganizationInvitation
		for j := range s.invitations {
			if s.invitations[j].TargetUserID == c.TargetUserID {
				old = &s.invitations[j]
			}
		}
		generation := int64(1)
		if old != nil {
			if !reissue {
				return ErrOrganizationInvitationExists
			}
			if old.ID != c.ObjectID || old.Generation != c.Generation {
				return ErrOrganizationConflict
			}
			var err error
			generation, err = organizationNextVersion(old.Generation)
			if err != nil {
				return err
			}
		} else if reissue || c.ObjectID != 0 || c.Generation != 0 {
			return ErrOrganizationNotFound
		}
		if c.Role == OrganizationRoleAdmin {
			b := s.binding(c)
			b.TargetUserID = c.TargetUserID
			b.Role = c.Role
			b.Generation = generation
			if old != nil {
				b.ObjectID = old.ID
			}
			if err := s.authorize(action, c, b); err != nil {
				return err
			}
		} else if c.Authorization != nil {
			return ErrOrganizationInvalidInput
		}
		if s.now > math.MaxInt64-7*24*3600 {
			return ErrOrganizationConflict
		}
		if err := s.advance(c); err != nil {
			return err
		}
		if old != nil && old.Status == OrganizationPending {
			if err := s.resolveInvitation(old, OrganizationRevoked, "reissued"); err != nil {
				return err
			}
		}
		v := OrganizationInvitation{OrganizationID: s.org.ID, TargetUserID: c.TargetUserID, InviterUserID: i.UserID, InviterMemberRevision: s.member(i.UserID).Revision, Role: c.Role, Generation: generation, Status: OrganizationPending, ExpiresAt: s.now + 7*24*3600, CreatedAt: s.now, UpdatedAt: s.now}
		if old == nil {
			if err := s.tx.Create(&v).Error; err != nil {
				return err
			}
		} else {
			v.ID = old.ID
			if err := organizationCAS(s.tx.Model(&OrganizationInvitation{}).Where("id = ? AND organization_id = ? AND generation = ?", old.ID, s.org.ID, old.Generation).Select("inviter_user_id", "inviter_member_revision", "role", "generation", "status", "expires_at", "resolved_at", "created_at", "updated_at", "resolution_reason").Updates(&v)); err != nil {
				return err
			}
		}
		return s.event("invitation.issued", v.TargetUserID, "invitation", v.ID, v.Generation, "", v.Status, "", v.Role, v.ExpiresAt)
	}, options...)
}

func AcceptOrganizationInvitation(i AuthSessionIdentity, c OrganizationCommand) error {
	return resolveOrganizationInvitation(i, c, OrganizationAccepted)
}
func DeclineOrganizationInvitation(i AuthSessionIdentity, c OrganizationCommand) error {
	return resolveOrganizationInvitation(i, c, OrganizationDeclined)
}
func RevokeOrganizationInvitation(i AuthSessionIdentity, c OrganizationCommand) error {
	return resolveOrganizationInvitation(i, c, OrganizationRevoked)
}
func resolveOrganizationInvitation(i AuthSessionIdentity, c OrganizationCommand, status string, options ...*organizationExecution) error {
	action := map[string]string{OrganizationAccepted: "invite_accept", OrganizationDeclined: "invite_decline", OrganizationRevoked: "invite_revoke"}[status]
	if err := validateOrganizationCommand(action, c); err != nil {
		return err
	}
	if c.ObjectID <= 0 || c.Generation <= 0 || c.Authorization != nil {
		return ErrOrganizationInvalidInput
	}
	return withOrganization(i, c, true, func(s *organizationState) error {
		var v *OrganizationInvitation
		for j := range s.invitations {
			if s.invitations[j].ID == c.ObjectID {
				v = &s.invitations[j]
			}
		}
		if v == nil {
			return ErrOrganizationNotFound
		}
		if status == OrganizationRevoked {
			if !s.canInvite(v.Role) {
				return ErrOrganizationForbidden
			}
		} else if i.UserID != v.TargetUserID {
			return ErrOrganizationNotFound
		}
		if v.Generation != c.Generation {
			return ErrOrganizationConflict
		}
		if v.Status != OrganizationPending {
			return ErrOrganizationTerminal
		}
		if v.ExpiresAt <= s.now {
			return ErrOrganizationExpired
		}
		if err := s.requireEnabled(); err != nil {
			return err
		}
		if status == OrganizationAccepted {
			inviter := s.member(v.InviterUserID)
			r := s.role(v.InviterUserID)
			if !s.activeUser(v.InviterUserID) || !s.activeUser(v.TargetUserID) || inviter == nil || inviter.Revision != v.InviterMemberRevision || !(r == OrganizationRoleOwner || r == OrganizationRoleAdmin && v.Role == OrganizationRoleMember) {
				return ErrOrganizationForbidden
			}
			if s.member(i.UserID) != nil {
				return ErrOrganizationConflict
			}
			if err := requireOrganizationCapacity(s.tx, i.UserID, false, true); err != nil {
				return err
			}
		}
		if err := s.advance(c); err != nil {
			return err
		}
		if status == OrganizationAccepted {
			var old *OrganizationMember
			for j := range s.members {
				if s.members[j].UserID == i.UserID {
					old = &s.members[j]
				}
			}
			if old == nil {
				if err := s.tx.Create(&OrganizationMember{OrganizationID: s.org.ID, UserID: i.UserID, Role: v.Role, Revision: 1, JoinedAt: s.now, UpdatedAt: s.now}).Error; err != nil {
					return err
				}
			} else {
				if err := s.changeMember(old, v.Role, 0, ""); err != nil {
					return err
				}
				if err := s.tx.Model(old).Update("joined_at", s.now).Error; err != nil {
					return err
				}
			}
		}
		return s.resolveInvitation(v, status, status)
	}, options...)
}

// Expiry is an explicit trusted-host operation, not a scheduled actor privilege.
func ExpireOrganizationInvitations(orgID int64) error {
	return expireOrganizationRequests(orgID, false)
}
func ExpireOrganizationOwnershipTransfer(orgID int64) error {
	return expireOrganizationRequests(orgID, true)
}
func expireOrganizationRequests(orgID int64, transfer bool) error {
	if orgID <= 0 {
		return ErrOrganizationInvalidInput
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		s := &organizationState{tx: tx}
		if err := lockForUpdate(tx).First(&s.org, orgID).Error; err != nil {
			return err
		}
		if transfer {
			if err := lockForUpdate(tx).Where("organization_id = ?", orgID).Find(&s.transfer).Error; err != nil {
				return err
			}
		} else if err := lockForUpdate(tx).Where("organization_id = ? AND status = ?", orgID, OrganizationPending).Order("id").Find(&s.invitations).Error; err != nil {
			return err
		}
		s.now = organizationNow().Unix()
		needed := false
		if transfer {
			needed = s.transfer.Status == OrganizationPending && s.transfer.ExpiresAt <= s.now
		} else {
			for _, v := range s.invitations {
				needed = needed || v.ExpiresAt <= s.now
			}
		}
		if !needed {
			return nil
		}
		if err := s.advance(OrganizationCommand{Revision: s.org.Revision}); err != nil {
			return err
		}
		if transfer {
			return s.resolveTransfer(OrganizationExpired, "expired")
		}
		for j := range s.invitations {
			v := &s.invitations[j]
			if v.ExpiresAt <= s.now {
				if err := s.resolveInvitation(v, OrganizationExpired, "expired"); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func InitiateOrganizationOwnershipTransfer(i AuthSessionIdentity, c OrganizationCommand, options ...*organizationExecution) error {
	if err := validateOrganizationCommand("transfer_initiate", c); err != nil {
		return err
	}
	if c.TargetUserID <= 0 || c.TargetUserID == i.UserID {
		return ErrOrganizationInvalidInput
	}
	return withOrganization(i, c, true, func(s *organizationState) error {
		if err := s.requireEnabled(); err != nil {
			return err
		}
		if err := s.requireOwner(); err != nil {
			return err
		}
		from, to := s.member(i.UserID), s.member(c.TargetUserID)
		if to == nil || !s.activeUser(c.TargetUserID) {
			return ErrOrganizationNotFound
		}
		old := s.transfer
		generation := int64(1)
		if old.ID != 0 {
			if old.ID != c.ObjectID || old.Generation != c.Generation {
				return ErrOrganizationConflict
			}
			var err error
			generation, err = organizationNextVersion(old.Generation)
			if err != nil {
				return err
			}
			if old.Status == OrganizationPending && !c.Replace {
				return ErrOrganizationConflict
			}
		} else if c.ObjectID != 0 || c.Generation != 0 || c.Replace {
			return ErrOrganizationInvalidInput
		}
		b := s.binding(c)
		b.TargetUserID = c.TargetUserID
		b.ObjectID = old.ID
		b.Generation = generation
		b.Replace = c.Replace
		b.FromUserID = i.UserID
		b.ToUserID = c.TargetUserID
		b.OwnershipVersion = s.org.OwnershipVersion
		b.FromMemberRevision = from.Revision
		b.ToMemberRevision = to.Revision
		if err := s.authorize("transfer_initiate", c, b); err != nil {
			return err
		}
		if s.now > math.MaxInt64-24*3600 {
			return ErrOrganizationConflict
		}
		if err := s.advance(c); err != nil {
			return err
		}
		if old.Status == OrganizationPending {
			if err := s.resolveTransfer(OrganizationCancelled, "replaced"); err != nil {
				return err
			}
		}
		v := OrganizationOwnershipTransfer{OrganizationID: s.org.ID, FromUserID: i.UserID, ToUserID: c.TargetUserID, Generation: generation, OwnerVersion: s.org.OwnershipVersion, FromMemberRevision: from.Revision, ToMemberRevision: to.Revision, Status: OrganizationPending, ExpiresAt: s.now + 24*3600, CreatedAt: s.now, UpdatedAt: s.now}
		if old.ID == 0 {
			if err := s.tx.Create(&v).Error; err != nil {
				return err
			}
		} else {
			v.ID = old.ID
			if err := organizationCAS(s.tx.Model(&OrganizationOwnershipTransfer{}).Where("id = ? AND organization_id = ? AND generation = ?", old.ID, s.org.ID, old.Generation).Select("from_user_id", "to_user_id", "generation", "owner_version", "from_member_revision", "to_member_revision", "status", "expires_at", "resolved_at", "created_at", "updated_at", "resolution_reason").Updates(&v)); err != nil {
				return err
			}
		}
		return s.event("transfer.initiated", v.ToUserID, "transfer", v.ID, v.Generation, "", v.Status, "", "", v.ExpiresAt)
	}, options...)
}
func AcceptOrganizationOwnershipTransfer(i AuthSessionIdentity, c OrganizationCommand) error {
	return resolveOrganizationTransfer(i, c, OrganizationAccepted)
}
func DeclineOrganizationOwnershipTransfer(i AuthSessionIdentity, c OrganizationCommand) error {
	return resolveOrganizationTransfer(i, c, OrganizationDeclined)
}
func CancelOrganizationOwnershipTransfer(i AuthSessionIdentity, c OrganizationCommand) error {
	return resolveOrganizationTransfer(i, c, OrganizationCancelled)
}
func resolveOrganizationTransfer(i AuthSessionIdentity, c OrganizationCommand, status string, options ...*organizationExecution) error {
	action := map[string]string{OrganizationAccepted: "transfer_accept", OrganizationDeclined: "transfer_decline", OrganizationCancelled: "transfer_cancel"}[status]
	if err := validateOrganizationCommand(action, c); err != nil {
		return err
	}
	if c.ObjectID <= 0 || c.Generation <= 0 {
		return ErrOrganizationInvalidInput
	}
	return withOrganization(i, c, true, func(s *organizationState) error {
		v := s.transfer
		if v.ID == 0 || v.ID != c.ObjectID {
			return ErrOrganizationNotFound
		}
		if status == OrganizationCancelled {
			if i.UserID != v.FromUserID || s.org.OwnerUserID != i.UserID {
				return ErrOrganizationForbidden
			}
		} else if i.UserID != v.ToUserID {
			return ErrOrganizationNotFound
		}
		if v.Generation != c.Generation {
			return ErrOrganizationConflict
		}
		if v.Status != OrganizationPending {
			return ErrOrganizationTerminal
		}
		if v.ExpiresAt <= s.now {
			return ErrOrganizationExpired
		}
		if err := s.requireEnabled(); err != nil {
			return err
		}
		from, to := s.member(v.FromUserID), s.member(v.ToUserID)
		if status == OrganizationAccepted {
			if !s.activeUser(v.FromUserID) || !s.activeUser(v.ToUserID) || from == nil || to == nil || from.Revision != v.FromMemberRevision || to.Revision != v.ToMemberRevision || s.org.OwnerUserID != v.FromUserID || s.org.OwnershipVersion != v.OwnerVersion {
				return ErrOrganizationForbidden
			}
			b := s.binding(c)
			b.TargetUserID = v.ToUserID
			b.ObjectID = v.ID
			b.Generation = v.Generation
			b.FromUserID = v.FromUserID
			b.ToUserID = v.ToUserID
			b.OwnershipVersion = v.OwnerVersion
			b.FromMemberRevision = from.Revision
			b.ToMemberRevision = to.Revision
			if err := s.authorize(action, c, b); err != nil {
				return err
			}
			if err := requireOrganizationNameAvailable(s.tx, v.ToUserID, s.org.ID, s.org.Name); err != nil {
				return err
			}
			if err := requireOrganizationCapacity(s.tx, v.ToUserID, true, false); err != nil {
				return err
			}
		} else if c.Authorization != nil {
			return ErrOrganizationInvalidInput
		}
		if err := s.advance(c); err != nil {
			return err
		}
		if status == OrganizationAccepted {
			next, err := organizationNextVersion(s.org.OwnershipVersion)
			if err != nil {
				return err
			}
			if err = organizationCAS(s.tx.Model(&Organization{}).Where("id = ? AND revision = ? AND owner_user_id = ? AND ownership_version = ?", s.org.ID, s.org.Revision, v.FromUserID, v.OwnerVersion).Updates(map[string]any{"owner_user_id": v.ToUserID, "ownership_version": next})); err != nil {
				return err
			}
			if err = s.changeMember(from, OrganizationRoleAdmin, 0, ""); err != nil {
				return err
			}
			if err = s.changeMember(to, OrganizationRoleMember, 0, ""); err != nil {
				return err
			}
			if err = s.resolveTransfer(status, status); err != nil {
				return err
			}
			if err = s.revokeDependentRequests(v.FromUserID, "owner_changed"); err != nil {
				return err
			}
			return s.revokeDependentRequests(v.ToUserID, "owner_changed")
		}
		return s.resolveTransfer(status, status)
	}, options...)
}

// OrganizationMutationReceipt is captured alongside the primary event, never
// reconstructed from a later query or an independently visible organization.
type OrganizationMutationReceipt struct {
	Replayed       bool // Internal only: replay is not a new mutation or creation audit.
	OrganizationID int64
	Revision       int64
	Action         string
	EventID        int64
	ObjectKind     string
	ObjectID       int64
	Generation     int64
	Status         string
	WalletEntry    *OrganizationWalletEntry
}
type organizationExecution struct {
	ctx     context.Context
	action  string
	preview bool
	binding *OrganizationAuthorizationBinding
	receipt *OrganizationMutationReceipt
	orgName string
}

var errOrganizationPreviewComplete = errors.New("organization preflight complete")

func organizationPrimaryEvent(action string) string {
	switch action {
	case "create":
		return "organization.created"
	case "change_role", "remove", "leave":
		return "member." + action
	case "invite", "reissue":
		return "invitation.issued"
	case "invite_accept":
		return "invitation.accepted"
	case "invite_decline":
		return "invitation.declined"
	case "invite_revoke":
		return "invitation.revoked"
	case "transfer_initiate":
		return "transfer.initiated"
	case "transfer_accept":
		return "transfer.accepted"
	case "transfer_decline":
		return "transfer.declined"
	case "transfer_cancel":
		return "transfer.cancelled"
	default:
		return "organization." + action
	}
}
func executeOrganizationCommand(i AuthSessionIdentity, c OrganizationCommand, op *organizationExecution) error {
	switch op.action {
	case "create":
		_, err := createOrganizationWithReceipt(op.ctx, i, c.Name, op.receipt, "")
		return err
	case "rename", "self_disable", "platform_disable", "dissolve", "change_role", "remove", "leave":
		return mutateOrganization(i, c, op.action, op)
	case "invite", "reissue":
		return issueOrganizationInvitation(i, c, op.action == "reissue", op)
	case "invite_accept":
		return resolveOrganizationInvitation(i, c, OrganizationAccepted, op)
	case "invite_decline":
		return resolveOrganizationInvitation(i, c, OrganizationDeclined, op)
	case "invite_revoke":
		return resolveOrganizationInvitation(i, c, OrganizationRevoked, op)
	case "transfer_initiate":
		return InitiateOrganizationOwnershipTransfer(i, c, op)
	case "transfer_accept":
		return resolveOrganizationTransfer(i, c, OrganizationAccepted, op)
	case "transfer_decline":
		return resolveOrganizationTransfer(i, c, OrganizationDeclined, op)
	case "transfer_cancel":
		return resolveOrganizationTransfer(i, c, OrganizationCancelled, op)
	case "wallet_credit", "wallet_reverse":
		return mutateOrganizationWallet(i, c, op.action, op)
	default:
		return ErrOrganizationInvalidInput
	}
}
func ExecuteOrganizationCommand(i AuthSessionIdentity, action string, c OrganizationCommand) (*OrganizationMutationReceipt, error) {
	return ExecuteOrganizationCommandWithContext(context.Background(), i, action, c)
}

func ExecuteOrganizationCommandWithContext(ctx context.Context, i AuthSessionIdentity, action string, c OrganizationCommand) (*OrganizationMutationReceipt, error) {
	r := &OrganizationMutationReceipt{}
	err := executeOrganizationCommand(i, c, &organizationExecution{ctx: ctx, action: action, receipt: r})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Preview shares every pre-mutation branch and stops before the first domain
// write. The no-op SQLite actor reservation is rolled back with this sentinel.
func PreviewOrganizationCommand(i AuthSessionIdentity, action string, c OrganizationCommand) (*OrganizationAuthorizationBinding, string, error) {
	return PreviewOrganizationCommandWithContext(context.Background(), i, action, c)
}

func PreviewOrganizationCommandWithContext(ctx context.Context, i AuthSessionIdentity, action string, c OrganizationCommand) (*OrganizationAuthorizationBinding, string, error) {
	if action == "create" || c.Authorization != nil {
		return nil, "", ErrOrganizationInvalidInput
	}
	op := &organizationExecution{ctx: ctx, action: action, preview: true}
	err := executeOrganizationCommand(i, c, op)
	if !errors.Is(err, errOrganizationPreviewComplete) {
		if err == nil {
			err = ErrOrganizationInvalidInput
		}
		return nil, "", err
	}
	return op.binding, op.orgName, nil
}
