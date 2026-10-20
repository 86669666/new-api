package model

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// OrganizationAccessKind identifies the bounded, read-only access projections.
// Lifecycle queries intentionally retain their separate recovery semantics.
type OrganizationAccessKind int

const (
	OrganizationAccessDiscovery OrganizationAccessKind = iota
	OrganizationAccessContext
	OrganizationAccessDetail
	OrganizationAccessMembers
	OrganizationAccessEvents
)

// OrganizationAccessResult stays internal. Only the service's explicit wire
// projections may leave the host. ActorRole comes from the authoritative user.
type OrganizationAccessResult struct {
	ActorRole     int
	Organizations []OrganizationView
	Organization  *OrganizationView
	Members       []OrganizationMemberView
	Events        []OrganizationEvent
}

// ReadOrganizationTasks lists organization-owned tasks under the same locked
// membership read as the other organization projections, so a committed
// removal or disable is observed by every later read. Owners and admins see
// every organization task; members see only their own submissions.
func ReadOrganizationTasks(identity AuthSessionIdentity, orgID int64, queryParams SyncTaskQueryParams, startIdx, num int) ([]*Task, int64, int, error) {
	var tasks []*Task
	var total int64
	if orgID <= 0 || startIdx < 0 || num < 1 || num > 100 {
		return nil, 0, 0, ErrOrganizationInvalidInput
	}
	actorRole, err := organizationActorRole(identity)
	if err != nil {
		return nil, 0, actorRole, err
	}
	err = withOrganization(identity, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		actorRole = s.users[identity.UserID].Role
		if s.member(identity.UserID) == nil || s.requireEnabled() != nil {
			return ErrOrganizationNotFound
		}
		query := applyTaskQueryFilters(s.tx.Model(&Task{}).Where("organization_id = ?", orgID), queryParams)
		if role := s.role(identity.UserID); role != OrganizationRoleOwner && role != OrganizationRoleAdmin {
			query = query.Where("user_id = ?", identity.UserID)
		}
		query = query.Session(&gorm.Session{})
		if err := query.Count(&total).Error; err != nil {
			return err
		}
		if err := query.Omit("channel_id", "data").Order("id desc").Limit(num).Offset(startIdx).Find(&tasks).Error; err != nil {
			return err
		}
		_, err := validateOrganizationIdentity(s.tx, identity, organizationNow().Unix())
		return err
	})
	if err != nil {
		return nil, 0, actorRole, err
	}
	return tasks, total, actorRole, nil
}

// ReadOrganizationTaskWithContext binds every lookup to an internal row ID and
// current organization authority. Repeated delivery checks use this same path;
// neither public task IDs nor cached membership can authorize a response.
func ReadOrganizationTaskWithContext(ctx context.Context, identity AuthSessionIdentity, orgID, taskRowID int64) (*Task, int, error) {
	if orgID <= 0 || taskRowID <= 0 {
		return nil, 0, ErrOrganizationInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	actorRole, err := organizationActorRole(identity)
	if err != nil {
		return nil, actorRole, err
	}
	var task Task
	err = withOrganizationWithContext(ctx, identity, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		actorRole = s.users[identity.UserID].Role
		if s.member(identity.UserID) == nil || s.requireEnabled() != nil {
			return ErrOrganizationNotFound
		}
		query := s.tx.Where("id = ? AND organization_id = ?", taskRowID, orgID)
		if role := s.role(identity.UserID); role != OrganizationRoleOwner && role != OrganizationRoleAdmin {
			query = query.Where("user_id = ?", identity.UserID)
		}
		if err := query.First(&task).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrOrganizationNotFound
			}
			return err
		}
		if !task.ResultRetrievable() {
			return ErrOrganizationNotFound
		}
		_, err := validateOrganizationIdentity(s.tx, identity, organizationNow().Unix())
		return err
	})
	if err != nil {
		return nil, actorRole, err
	}
	return &task, actorRole, nil
}

// organizationActorRole is the preliminary session check that precedes S1's
// out-of-transaction lock planning: session failures answer 401 before any
// organization lookup can answer 404. The role is for audit only, never the
// data grant.
func organizationActorRole(identity AuthSessionIdentity) (int, error) {
	var actor User
	err := DB.Transaction(func(tx *gorm.DB) error {
		if _, err := validateOrganizationIdentity(tx, identity, organizationNow().Unix()); err != nil {
			return err
		}
		return tx.Select("role").First(&actor, identity.UserID).Error
	})
	return actor.Role, err
}

// ReadOrganizationAccess keeps authorization and projection in one transaction.
// The preliminary session check covers S1's out-of-transaction lock planning
// (including unknown organizations); it is never used as the data grant.
func ReadOrganizationAccess(identity AuthSessionIdentity, kind OrganizationAccessKind, orgID int64, page OrganizationPage) (OrganizationAccessResult, error) {
	result := OrganizationAccessResult{}
	if kind < OrganizationAccessDiscovery || kind > OrganizationAccessEvents || orgID < 0 || kind == OrganizationAccessDiscovery && orgID != 0 || !page.valid() {
		return result, ErrOrganizationInvalidInput
	}
	if kind == OrganizationAccessDiscovery || kind == OrganizationAccessContext && orgID == 0 {
		err := DB.Transaction(func(tx *gorm.DB) error {
			if _, err := validateOrganizationIdentity(tx, identity, organizationNow().Unix()); err != nil {
				return err
			}
			var actor User
			// The actor is already locked; keep this a current read so MySQL does not
			// establish a repeatable-read snapshot before the active organization query.
			if err := lockForUpdate(tx).Select("role").First(&actor, identity.UserID).Error; err != nil {
				return err
			}
			result.ActorRole = actor.Role
			if kind == OrganizationAccessDiscovery {
				var rows []struct {
					ID             int64
					Name           string
					Revision       int64
					OwnerUserID    int
					Role           string
					MemberRevision int64
				}
				err := tx.Model(&Organization{}).
					Select("organizations.id, organizations.name, organizations.revision, organizations.owner_user_id, organization_members.role, organization_members.revision AS member_revision").
					Joins("JOIN organization_members ON organization_members.organization_id = organizations.id").
					Where("organization_members.user_id = ? AND organization_members.removed_at = 0 AND organizations.self_disabled_at = 0 AND organizations.platform_disabled_at = 0 AND organizations.dissolved_at = 0 AND organizations.id > ?", identity.UserID, page.AfterID).
					Order("organizations.id").Limit(page.Limit).Scan(&rows).Error
				if err != nil {
					return err
				}
				result.Organizations = make([]OrganizationView, 0, len(rows))
				for _, row := range rows {
					role := row.Role
					if row.OwnerUserID == identity.UserID {
						role = OrganizationRoleOwner
					}
					result.Organizations = append(result.Organizations, OrganizationView{ID: row.ID, Name: row.Name, Revision: row.Revision, MyRole: role, MyMemberRevision: row.MemberRevision})
				}
			}
			_, err := validateOrganizationIdentity(tx, identity, organizationNow().Unix())
			return err
		})
		return result, err
	}
	if orgID == 0 {
		return result, ErrOrganizationInvalidInput
	}
	actorRole, err := organizationActorRole(identity)
	result.ActorRole = actorRole
	if err != nil {
		return result, err
	}
	err = withOrganization(identity, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		result.ActorRole = s.users[identity.UserID].Role
		// Availability precedes role checks; outsiders and disabled organizations
		// have the same 404, including on the restricted events view.
		if s.member(identity.UserID) == nil || s.requireEnabled() != nil {
			return ErrOrganizationNotFound
		}
		view := s.view()
		result.Organization = &view
		switch kind {
		case OrganizationAccessMembers:
			var members []OrganizationMember
			if err := s.tx.Where("organization_id = ? AND removed_at = 0 AND id > ?", orgID, page.AfterID).Order("id").Limit(page.Limit).Find(&members).Error; err != nil {
				return err
			}
			result.Members, err = s.memberViews(members)
			if err != nil {
				return err
			}
		case OrganizationAccessEvents:
			if view.MyRole != OrganizationRoleOwner && view.MyRole != OrganizationRoleAdmin {
				return ErrOrganizationForbidden
			}
			if err := s.tx.Where("organization_id = ? AND id > ?", orgID, page.AfterID).Order("id").Limit(page.Limit).Find(&result.Events).Error; err != nil {
				return err
			}
		}
		// Expiry is checked after all waits and once more before delivery.
		_, err := validateOrganizationIdentity(s.tx, identity, organizationNow().Unix())
		return err
	})
	return result, err
}
