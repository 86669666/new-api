package model

import "gorm.io/gorm"

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
	if err := DB.Transaction(func(tx *gorm.DB) error {
		if _, err := validateOrganizationIdentity(tx, identity, organizationNow().Unix()); err != nil {
			return err
		}
		var actor User
		if err := tx.Select("role").First(&actor, identity.UserID).Error; err != nil {
			return err
		}
		result.ActorRole = actor.Role
		return nil
	}); err != nil {
		return result, err
	}
	err := withOrganization(identity, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
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
			result.Members = make([]OrganizationMemberView, 0, len(members))
			for _, member := range members {
				role := member.Role
				if member.UserID == s.org.OwnerUserID {
					role = OrganizationRoleOwner
				}
				result.Members = append(result.Members, OrganizationMemberView{ID: member.ID, UserID: member.UserID, Role: role, Revision: member.Revision, JoinedAt: member.JoinedAt})
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
