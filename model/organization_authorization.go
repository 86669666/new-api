package model

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"gorm.io/gorm"
)

// OrganizationAuthorization is trusted, ephemeral service-to-model state. It is
// not a signed credential and must never be decoded from a client or persisted.
// The service consumes a real proof and caps ValidUntil at its expiry.
// A failed business transaction does not restore that consumed proof.
type OrganizationAuthorization struct {
	Identity   AuthSessionIdentity
	ProofID    int64
	Action     string
	Method     string
	ConsumedAt int64
	ValidUntil int64
	Binding    OrganizationAuthorizationBinding
	Command    OrganizationCommand
}

type OrganizationAuthorizationBinding struct {
	Reason             string
	Replace            bool
	OrganizationID     int64
	Revision           int64
	TargetUserID       int
	Role               string
	Disabled           bool
	ObjectID           int64
	Generation         int64
	FromUserID         int
	ToUserID           int
	OwnershipVersion   int64
	FromMemberRevision int64
	ToMemberRevision   int64
}

// Server clock dependency is private; tests advance it only in serial fixtures.
var organizationNow = time.Now

type organizationState struct {
	tx          *gorm.DB
	identity    AuthSessionIdentity
	org         Organization
	members     []OrganizationMember
	invitations []OrganizationInvitation
	transfer    OrganizationOwnershipTransfer
	users       map[int]User
	session     UserSession
	execution   *organizationExecution
	now         int64
}

func (s *organizationState) member(userID int) *OrganizationMember {
	for i := range s.members {
		if s.members[i].UserID == userID && s.members[i].RemovedAt == 0 {
			return &s.members[i]
		}
	}
	return nil
}
func (s *organizationState) role(userID int) string {
	m := s.member(userID)
	if m == nil {
		return ""
	}
	if s.org.OwnerUserID == userID {
		return OrganizationRoleOwner
	}
	return m.Role
}
func (s *organizationState) activeUser(userID int) bool {
	u, ok := s.users[userID]
	return ok && !u.DeletedAt.Valid && u.Status == common.UserStatusEnabled
}
func (s *organizationState) requireOwner() error {
	if s.role(s.identity.UserID) != OrganizationRoleOwner {
		return ErrOrganizationForbidden
	}
	return nil
}
func (s *organizationState) canInvite(role string) bool {
	actor := s.role(s.identity.UserID)
	return actor == OrganizationRoleOwner || actor == OrganizationRoleAdmin && role == OrganizationRoleMember
}
func (s *organizationState) requireEnabled() error {
	if s.org.DissolvedAt != 0 {
		return ErrOrganizationTerminal
	}
	if s.org.SelfDisabledAt != 0 || s.org.PlatformDisabledAt != 0 {
		return ErrOrganizationDisabled
	}
	return nil
}
func (s *organizationState) authorize(action string, c OrganizationCommand, b OrganizationAuthorizationBinding) error {
	if s.org.Revision != c.Revision {
		return ErrOrganizationConflict
	}
	if s.execution != nil && s.execution.preview {
		s.execution.binding = &b
		return nil
	}
	a := c.Authorization
	if s.execution != nil && a != nil && a.Identity == s.identity && organizationNow().Unix() >= a.ValidUntil {
		return ErrAuthFlowExpired
	}
	if a == nil || a.Identity != s.identity || a.ProofID <= 0 || a.Action != action || !slices.Contains([]string{"password", "2fa", "passkey"}, a.Method) || a.ConsumedAt <= 0 || a.ConsumedAt > s.now || s.now >= a.ValidUntil || a.Binding != b {
		return ErrOrganizationForbidden
	}
	if s.execution != nil {
		command := c
		command.Authorization = nil
		if a.Command != command {
			return ErrOrganizationForbidden
		}
	}
	state, err := getUserVerificationState(s.tx, s.identity.UserID, false)
	if err != nil {
		return err
	}
	switch a.Method {
	case "password":
		if !common.PasswordLoginEnabled || !state.HasPassword || state.HasTwoFA || state.HasPasskey {
			return ErrOrganizationForbidden
		}
	case "2fa":
		if !state.HasTwoFA || state.TwoFALocked {
			return ErrOrganizationForbidden
		}
	case "passkey":
		if !state.HasPasskey || !system_setting.PasskeySettingsSnapshot().Enabled {
			return ErrOrganizationForbidden
		}
	}
	if organizationNow().Unix() >= a.ValidUntil {
		if s.execution != nil {
			return ErrAuthFlowExpired
		}
		return ErrOrganizationForbidden
	}
	return nil
}
func (s *organizationState) binding(c OrganizationCommand) OrganizationAuthorizationBinding {
	return OrganizationAuthorizationBinding{OrganizationID: s.org.ID, Revision: c.Revision}
}

func validateOrganizationIdentity(tx *gorm.DB, identity AuthSessionIdentity, now int64) (UserSession, error) {
	var session UserSession
	if identity.UserID <= 0 || identity.UserAuthVersion <= 0 || identity.SessionVersion <= 0 || identity.SessionID == "" || strings.HasPrefix(identity.SessionID, "pat:") || strings.HasPrefix(identity.SessionID, "legacy") {
		return session, ErrOrganizationUnauthenticated
	}
	if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, ErrUserSessionInactive) {
			return session, ErrOrganizationUnauthenticated
		}
		return session, err
	}
	if err := lockForUpdate(tx).Where("sid = ? AND user_id = ?", identity.SessionID, identity.UserID).First(&session).Error; err != nil {
		return session, err
	}
	if session.ExpiresAt <= now {
		return session, ErrOrganizationUnauthenticated
	}
	return session, nil
}

// Lock plans are speculative. No new user locks may be acquired after the org
// lock; a changed participant set returns conflict instead of reversing order.
func withOrganization(identity AuthSessionIdentity, c OrganizationCommand, mutate bool, operation func(*organizationState) error, options ...*organizationExecution) error {
	parent := context.Background()
	if len(options) > 0 && options[0] != nil && options[0].ctx != nil {
		parent = options[0].ctx
	}
	return withOrganizationWithContext(parent, identity, c, mutate, operation, options...)
}

// Context propagation alone must not opt a read into command visibility rules.
// Read callbacks retain their route-specific participant/member/root checks.
func withOrganizationWithContext(parent context.Context, identity AuthSessionIdentity, c OrganizationCommand, mutate bool, operation func(*organizationState) error, options ...*organizationExecution) error {
	if c.OrganizationID <= 0 || mutate && c.Revision <= 0 {
		return ErrOrganizationInvalidInput
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	db := DB.WithContext(ctx)
	ids := []int{identity.UserID}
	if c.TargetUserID > 0 {
		ids = append(ids, c.TargetUserID)
	}
	var before Organization
	if err := db.First(&before, c.OrganizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOrganizationNotFound
		}
		return err
	}
	ids = append(ids, before.OwnerUserID)
	var invite OrganizationInvitation
	if c.ObjectID > 0 {
		if err := db.Where("id = ? AND organization_id = ?", c.ObjectID, c.OrganizationID).Find(&invite).Error; err != nil {
			return err
		}
		if invite.ID != 0 {
			ids = append(ids, invite.InviterUserID, invite.TargetUserID)
		}
	}
	var transfer OrganizationOwnershipTransfer
	if err := db.Where("organization_id = ?", c.OrganizationID).Find(&transfer).Error; err != nil {
		return err
	}
	if transfer.ID != 0 {
		ids = append(ids, transfer.FromUserID, transfer.ToUserID)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	return db.Transaction(func(tx *gorm.DB) error {
		if mutate && common.UsingMainDatabase(common.DatabaseTypeSQLite) {
			if err := tx.Model(&User{}).Where("id = ?", identity.UserID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
				return err
			}
		}
		s := &organizationState{tx: tx, identity: identity, users: map[int]User{}}
		if len(options) > 0 {
			s.execution = options[0]
		}
		for _, id := range ids {
			if id <= 0 {
				return ErrOrganizationUnauthenticated
			}
			var u User
			err := lockForUpdate(tx.Unscoped()).First(&u, id).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if err == nil {
				s.users[id] = u
			}
		}
		var err error
		s.session, err = validateOrganizationIdentity(tx, identity, organizationNow().Unix())
		if err != nil {
			return err
		}
		if err = lockForUpdate(tx).First(&s.org, c.OrganizationID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrOrganizationNotFound
			}
			return err
		}
		if err = lockForUpdate(tx).Where("organization_id = ?", s.org.ID).Order("user_id").Find(&s.members).Error; err != nil {
			return err
		}
		if err = lockForUpdate(tx).Where("organization_id = ?", s.org.ID).Order("id").Find(&s.invitations).Error; err != nil {
			return err
		}
		if err = lockForUpdate(tx).Where("organization_id = ?", s.org.ID).Find(&s.transfer).Error; err != nil {
			return err
		}
		if s.execution != nil {
			a := s.execution.action
			visible := s.member(identity.UserID) != nil
			if a == "platform_disable" {
				if s.users[identity.UserID].Role != common.RoleRootUser {
					return ErrOrganizationForbidden
				}
				visible = true
			}
			if a == "invite_accept" || a == "invite_decline" {
				visible = false
				for _, v := range s.invitations {
					if v.ID == c.ObjectID && v.TargetUserID == identity.UserID {
						visible = true
					}
				}
			}
			if a == "transfer_accept" || a == "transfer_decline" {
				visible = s.transfer.ID == c.ObjectID && s.transfer.ToUserID == identity.UserID
			}
			if a == "reissue" || a == "invite_revoke" {
				visible = false
				for _, v := range s.invitations {
					if v.ID == c.ObjectID && s.canInvite(v.Role) {
						visible = true
					}
				}
			}
			if a == "transfer_cancel" {
				visible = s.transfer.ID == c.ObjectID && s.transfer.FromUserID == identity.UserID && s.org.OwnerUserID == identity.UserID
			}
			if a == "change_role" || a == "remove" {
				visible = visible && s.member(c.TargetUserID) != nil
			}
			if !visible {
				return ErrOrganizationNotFound
			}
		}
		if !slices.Contains(ids, s.org.OwnerUserID) {
			return ErrOrganizationConflict
		}
		if mutate && s.org.Revision != c.Revision {
			return ErrOrganizationConflict
		}
		for _, v := range s.invitations {
			if v.ID == c.ObjectID && (!slices.Contains(ids, v.InviterUserID) || !slices.Contains(ids, v.TargetUserID)) {
				return ErrOrganizationConflict
			}
		}
		if s.transfer.ID != 0 && (!slices.Contains(ids, s.transfer.FromUserID) || !slices.Contains(ids, s.transfer.ToUserID)) {
			return ErrOrganizationConflict
		}
		// Recheck the already locked identity after all lock waits; never reuse the
		// request-start timestamp for expiry or proof authorization decisions.
		s.now = organizationNow().Unix()
		s.session, err = validateOrganizationIdentity(tx, identity, s.now)
		if err != nil {
			return err
		}
		if s.execution != nil {
			s.execution.orgName = s.org.Name
		}
		return operation(s)
	})
}
