package model

import (
	"context"
	"errors"
	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
)

// These projections deliberately exclude users, credentials, proof records and
// private platform reasons. Cursor pagination is keyset based with bounded size.
type OrganizationView struct {
	ID               int64
	Name             string
	Revision         int64
	OwnershipVersion int64
	SelfDisabled     bool
	PlatformDisabled bool
	Dissolved        bool
	MyRole           string
	MyMemberRevision int64
}
type OrganizationMemberView struct {
	ID       int64
	UserID   int
	Username string
	Role     string
	Revision int64
	JoinedAt int64
}
type OrganizationRequestResult struct {
	OrganizationName     *string
	OrganizationRevision *int64
	OrganizationID       int64
	ObjectID             int64
	Generation           int64
	Kind                 string
	FromUserID           int
	TargetUserID         int
	FromUsername         string
	TargetUsername       string
	Role                 string
	Status               string
	ExpiresAt            int64
	ResolvedAt           int64
	ReasonCode           string
}
type OrganizationPage struct {
	AfterID int64
	Limit   int
}

func (p OrganizationPage) valid() bool { return p.AfterID >= 0 && p.Limit > 0 && p.Limit <= 100 }
func (s *organizationState) view() OrganizationView {
	v := OrganizationView{ID: s.org.ID, Name: s.org.Name, Revision: s.org.Revision, OwnershipVersion: s.org.OwnershipVersion, SelfDisabled: s.org.SelfDisabledAt != 0, PlatformDisabled: s.org.PlatformDisabledAt != 0, Dissolved: s.org.DissolvedAt != 0, MyRole: s.role(s.identity.UserID)}
	if m := s.member(s.identity.UserID); m != nil {
		v.MyMemberRevision = m.Revision
	}
	return v
}
func GetOrganizationForActor(i AuthSessionIdentity, orgID int64) (*OrganizationView, error) {
	var result OrganizationView
	err := withOrganization(i, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		if s.role(i.UserID) == "" {
			return ErrOrganizationNotFound
		}
		result = s.view()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
func ListOrganizationsForActor(i AuthSessionIdentity, p OrganizationPage) ([]OrganizationView, error) {
	if !p.valid() {
		return nil, ErrOrganizationInvalidInput
	}
	result := []OrganizationView{}
	err := DB.Transaction(func(tx *gorm.DB) error {
		if _, err := validateOrganizationIdentity(tx, i, organizationNow().Unix()); err != nil {
			return err
		}
		var rows []struct {
			Organization
			Role           string
			MemberRevision int64
		}
		err := tx.Model(&Organization{}).Select("organizations.*, organization_members.role, organization_members.revision AS member_revision").Joins("JOIN organization_members ON organization_members.organization_id = organizations.id").Where("organization_members.user_id = ? AND organization_members.removed_at = 0 AND organizations.id > ?", i.UserID, p.AfterID).Order("organizations.id").Limit(p.Limit).Scan(&rows).Error
		if err != nil {
			return err
		}
		for _, r := range rows {
			role := r.Role
			if r.OwnerUserID == i.UserID {
				role = OrganizationRoleOwner
			}
			result = append(result, OrganizationView{ID: r.ID, Name: r.Name, Revision: r.Revision, OwnershipVersion: r.OwnershipVersion, SelfDisabled: r.SelfDisabledAt != 0, PlatformDisabled: r.PlatformDisabledAt != 0, Dissolved: r.DissolvedAt != 0, MyRole: role, MyMemberRevision: r.MemberRevision})
		}
		_, err = validateOrganizationIdentity(tx, i, organizationNow().Unix())
		return err
	})
	return result, err
}
func ListOrganizationMembersForActor(i AuthSessionIdentity, orgID int64, p OrganizationPage) ([]OrganizationMemberView, error) {
	if !p.valid() {
		return nil, ErrOrganizationInvalidInput
	}
	result := []OrganizationMemberView{}
	err := withOrganization(i, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		if s.role(i.UserID) == "" {
			return ErrOrganizationNotFound
		}
		if err := s.requireEnabled(); err != nil {
			return err
		}
		var members []OrganizationMember
		if err := s.tx.Where("organization_id = ? AND removed_at = 0 AND id > ?", orgID, p.AfterID).Order("id").Limit(p.Limit).Find(&members).Error; err != nil {
			return err
		}
		var err error
		result, err = s.memberViews(members)
		return err
	})
	return result, err
}

// memberViews reads names only for the authorized page, without acquiring user
// locks after organization locks. Missing or soft-deleted users retain their
// membership entry and cursor with an empty username.
func (s *organizationState) memberViews(members []OrganizationMember) ([]OrganizationMemberView, error) {
	result := make([]OrganizationMemberView, 0, len(members))
	if len(members) == 0 {
		return result, nil
	}
	ids := make([]int, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.UserID)
	}
	var users []User
	if err := s.tx.Select("id", "username").Where("id IN ?", ids).Find(&users).Error; err != nil {
		return nil, err
	}
	names := make(map[int]string, len(users))
	for _, user := range users {
		names[user.Id] = user.Username
	}
	for _, member := range members {
		role := member.Role
		if member.UserID == s.org.OwnerUserID {
			role = OrganizationRoleOwner
		}
		result = append(result, OrganizationMemberView{ID: member.ID, UserID: member.UserID, Username: names[member.UserID], Role: role, Revision: member.Revision, JoinedAt: member.JoinedAt})
	}
	return result, nil
}

func ListOrganizationEventsForActor(i AuthSessionIdentity, orgID int64, p OrganizationPage) ([]OrganizationEvent, error) {
	if !p.valid() {
		return nil, ErrOrganizationInvalidInput
	}
	result := []OrganizationEvent{}
	err := withOrganization(i, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		role := s.role(i.UserID)
		if role != OrganizationRoleOwner && role != OrganizationRoleAdmin {
			return ErrOrganizationForbidden
		}
		if err := s.requireEnabled(); err != nil {
			return err
		}
		return s.tx.Where("organization_id = ? AND id > ?", orgID, p.AfterID).Order("id").Limit(p.Limit).Find(&result).Error
	})
	return result, err
}
func ListPendingOrganizationInvitationsForActor(i AuthSessionIdentity, p OrganizationPage) ([]OrganizationRequestResult, error) {
	return ListPendingOrganizationInvitationsForActorWithContext(context.Background(), i, p)
}

func ListPendingOrganizationInvitationsForActorWithContext(ctx context.Context, i AuthSessionIdentity, p OrganizationPage) ([]OrganizationRequestResult, error) {
	return organizationInboxWithContext(ctx, i, p, false)
}
func ListPendingOrganizationOwnershipTransfersForActor(i AuthSessionIdentity, p OrganizationPage) ([]OrganizationRequestResult, error) {
	return ListPendingOrganizationOwnershipTransfersForActorWithContext(context.Background(), i, p)
}

func ListPendingOrganizationOwnershipTransfersForActorWithContext(ctx context.Context, i AuthSessionIdentity, p OrganizationPage) ([]OrganizationRequestResult, error) {
	return organizationInboxWithContext(ctx, i, p, true)
}
func organizationInboxWithContext(ctx context.Context, i AuthSessionIdentity, p OrganizationPage, transfer bool) ([]OrganizationRequestResult, error) {
	if !p.valid() {
		return nil, ErrOrganizationInvalidInput
	}
	if _, err := validateOrganizationIdentity(DB.WithContext(ctx), i, organizationNow().Unix()); err != nil {
		return nil, err
	}
	result := []OrganizationRequestResult{}
	cursor := p.AfterID
	for len(result) < p.Limit {
		var rows []struct {
			ID             int64
			OrganizationID int64
			Generation     int64
		}
		query := DB.WithContext(ctx).Model(&OrganizationInvitation{}).Where("target_user_id = ?", i.UserID)
		kind := "invitation"
		if transfer {
			query = DB.WithContext(ctx).Model(&OrganizationOwnershipTransfer{}).Where("to_user_id = ?", i.UserID)
			kind = "transfer"
		}
		if err := query.Select("id,organization_id,generation").Where("status = ? AND expires_at > ? AND id > ?", OrganizationPending, organizationNow().Unix(), cursor).Order("id").Limit(100).Scan(&rows).Error; err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		for _, v := range rows {
			cursor = v.ID
			view, err := organizationRequestResultWithContext(ctx, i, v.OrganizationID, v.ID, v.Generation, kind)
			if errors.Is(err, ErrOrganizationNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if view.OrganizationRevision != nil && view.Status == OrganizationPending {
				result = append(result, *view)
			}
			if len(result) == p.Limit {
				break
			}
		}
		if len(rows) < 100 {
			break
		}
	}
	return result, nil
}

func GetOrganizationInvitationResult(i AuthSessionIdentity, orgID, id, generation int64) (*OrganizationRequestResult, error) {
	return GetOrganizationInvitationResultWithContext(context.Background(), i, orgID, id, generation)
}

func GetOrganizationInvitationResultWithContext(ctx context.Context, i AuthSessionIdentity, orgID, id, generation int64) (*OrganizationRequestResult, error) {
	return organizationRequestResultWithContext(ctx, i, orgID, id, generation, "invitation")
}
func GetOrganizationOwnershipTransferResult(i AuthSessionIdentity, orgID, id, generation int64) (*OrganizationRequestResult, error) {
	return GetOrganizationOwnershipTransferResultWithContext(context.Background(), i, orgID, id, generation)
}

func GetOrganizationOwnershipTransferResultWithContext(ctx context.Context, i AuthSessionIdentity, orgID, id, generation int64) (*OrganizationRequestResult, error) {
	return organizationRequestResultWithContext(ctx, i, orgID, id, generation, "transfer")
}
func organizationRequestResultWithContext(ctx context.Context, i AuthSessionIdentity, orgID, id, generation int64, kind string) (*OrganizationRequestResult, error) {
	if id <= 0 || generation <= 0 {
		return nil, ErrOrganizationInvalidInput
	}
	var result OrganizationRequestResult
	err := withOrganizationWithContext(ctx, i, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		var first, last OrganizationEvent
		q := s.tx.Where("organization_id = ? AND object_kind = ? AND object_id = ? AND object_generation = ?", orgID, kind, id, generation)
		if err := q.Order("id").First(&first).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrOrganizationNotFound
			}
			return err
		}
		if err := s.tx.Where("organization_id = ? AND object_kind = ? AND object_id = ? AND object_generation = ?", orgID, kind, id, generation).Order("id DESC").First(&last).Error; err != nil {
			return err
		}
		own := i.UserID == first.SubjectUserID || kind == "transfer" && i.UserID == first.ActorUserID
		govern := s.org.DissolvedAt == 0 && s.org.SelfDisabledAt == 0 && s.org.PlatformDisabledAt == 0 && (s.role(i.UserID) == OrganizationRoleOwner || kind == "invitation" && first.Role == OrganizationRoleMember && s.role(i.UserID) == OrganizationRoleAdmin)
		if !own && !govern {
			return ErrOrganizationNotFound
		}
		result = OrganizationRequestResult{OrganizationID: orgID, ObjectID: id, Generation: generation, Kind: kind, FromUserID: first.ActorUserID, TargetUserID: first.SubjectUserID, Role: first.Role, Status: last.AfterState, ExpiresAt: first.ExpiresAt, ReasonCode: last.ReasonCode}
		if kind == "invitation" {
			var users []User
			if err := s.tx.Select("id", "username").Where("id IN ?", []int{first.ActorUserID, first.SubjectUserID}).Find(&users).Error; err != nil {
				return err
			}
			for _, user := range users {
				if user.Id == first.ActorUserID {
					result.FromUsername = user.Username
				}
				if user.Id == first.SubjectUserID {
					result.TargetUsername = user.Username
				}
			}
		}
		if result.Status == OrganizationPending {
			if s.now >= result.ExpiresAt {
				result.Status = OrganizationExpired
			}
		} else {
			result.ResolvedAt = last.CreatedAt
		}
		if result.Status == OrganizationPending && s.org.DissolvedAt == 0 && s.org.SelfDisabledAt == 0 && s.org.PlatformDisabledAt == 0 {
			actionable := false
			if kind == "invitation" {
				for _, v := range s.invitations {
					if v.ID == id && v.Generation == generation && v.Status == OrganizationPending {
						// Decline remains available to the exact target even if
						// inviter changes have made acceptance unavailable.
						actionable = govern || i.UserID == v.TargetUserID
					}
				}
			} else {
				v := s.transfer
				if v.ID == id && v.Generation == generation && v.Status == OrganizationPending {
					actionable = i.UserID == v.ToUserID || i.UserID == v.FromUserID && s.org.OwnerUserID == i.UserID
				}
			}
			if actionable {
				name, revision := s.org.Name, s.org.Revision
				result.OrganizationName = &name
				result.OrganizationRevision = &revision
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func GetOrganizationLifecycleState(i AuthSessionIdentity, orgID int64, platform bool) (*OrganizationView, error) {
	return GetOrganizationLifecycleStateWithContext(context.Background(), i, orgID, platform)
}

func GetOrganizationLifecycleStateWithContext(ctx context.Context, i AuthSessionIdentity, orgID int64, platform bool) (*OrganizationView, error) {
	var view OrganizationView
	err := withOrganizationWithContext(ctx, i, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		if platform {
			if s.users[i.UserID].Role != common.RoleRootUser {
				return ErrOrganizationForbidden
			}
		} else if s.member(i.UserID) == nil {
			return ErrOrganizationNotFound
		}
		view = s.view()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &view, nil
}
func ListOrganizationInvitationSlots(i AuthSessionIdentity, orgID int64, p OrganizationPage) ([]OrganizationRequestResult, error) {
	return ListOrganizationInvitationSlotsWithContext(context.Background(), i, orgID, p)
}

func ListOrganizationInvitationSlotsWithContext(ctx context.Context, i AuthSessionIdentity, orgID int64, p OrganizationPage) ([]OrganizationRequestResult, error) {
	if !p.valid() {
		return nil, ErrOrganizationInvalidInput
	}
	var slots []OrganizationInvitation
	err := withOrganizationWithContext(ctx, i, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		role := s.role(i.UserID)
		if role == "" {
			return ErrOrganizationNotFound
		}
		if role != OrganizationRoleOwner && role != OrganizationRoleAdmin {
			return ErrOrganizationForbidden
		}
		if err := s.requireEnabled(); err != nil {
			return err
		}
		q := s.tx.Where("organization_id = ? AND id > ?", orgID, p.AfterID)
		if role == OrganizationRoleAdmin {
			q = q.Where("role = ?", OrganizationRoleMember)
		}
		return q.Order("id").Limit(p.Limit).Find(&slots).Error
	})
	if err != nil {
		return nil, err
	}
	result := []OrganizationRequestResult{}
	for _, v := range slots {
		r, err := organizationRequestResultWithContext(ctx, i, orgID, v.ID, v.Generation, "invitation")
		if err != nil {
			return nil, err
		}
		result = append(result, *r)
	}
	return result, nil
}
func GetOrganizationOwnershipTransferSlot(i AuthSessionIdentity, orgID int64) (*OrganizationRequestResult, error) {
	return GetOrganizationOwnershipTransferSlotWithContext(context.Background(), i, orgID)
}

func GetOrganizationOwnershipTransferSlotWithContext(ctx context.Context, i AuthSessionIdentity, orgID int64) (*OrganizationRequestResult, error) {
	var slot OrganizationOwnershipTransfer
	err := withOrganizationWithContext(ctx, i, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		if s.member(i.UserID) == nil {
			return ErrOrganizationNotFound
		}
		if err := s.requireOwner(); err != nil {
			return err
		}
		if err := s.requireEnabled(); err != nil {
			return err
		}
		slot = s.transfer
		return nil
	})
	if err != nil {
		return nil, err
	}
	if slot.ID == 0 {
		return nil, nil
	}
	return organizationRequestResultWithContext(ctx, i, orgID, slot.ID, slot.Generation, "transfer")
}
