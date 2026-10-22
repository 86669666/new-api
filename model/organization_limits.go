package model

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"gorm.io/gorm"
)

var (
	ErrOrganizationCreatedLimit = errors.New("The maximum number of owned organizations has been reached.")
	ErrOrganizationJoinedLimit  = errors.New("The maximum number of joined organizations has been reached.")
)

// OrganizationLimits is the complete global policy; explicit zero means unlimited.
type OrganizationLimits struct {
	MaxOrganizationsCreated int64 `json:"max_organizations_created"`
	MaxOrganizationsJoined  int64 `json:"max_organizations_joined"`
}

// ReadOrganizationLimits reads one authoritative snapshot. Only absent rows
// default to zero; corrupt values and collation aliases fail closed.
func ReadOrganizationLimits(tx *gorm.DB) (OrganizationLimits, error) {
	var limits OrganizationLimits
	var options []Option
	keys := []string{operation_setting.OrganizationCreatedLimitOptionKey, operation_setting.OrganizationJoinedLimitOptionKey}
	// Read both limits in one statement so PostgreSQL READ COMMITTED cannot
	// combine settings from different committed policy versions.
	if err := tx.Where(map[string]any{"key": keys}).Find(&options).Error; err != nil {
		return limits, err
	}
	for _, option := range options {
		index := 0
		switch option.Key {
		case operation_setting.OrganizationCreatedLimitOptionKey:
		case operation_setting.OrganizationJoinedLimitOptionKey:
			index = 1
		default:
			return limits, errors.New("invalid organization limit option identity")
		}
		limit, err := operation_setting.ParseOrganizationLimit(option.Value)
		if err != nil {
			return limits, err
		}
		if index == 0 {
			limits.MaxOrganizationsCreated = limit
		} else {
			limits.MaxOrganizationsJoined = limit
		}
	}
	return limits, nil
}

// ValidateOrganizationLimitsIdentity rechecks the live dashboard identity and,
// for a settings write, the current root role. It does not grant other scopes.
func ValidateOrganizationLimitsIdentity(ctx context.Context, identity AuthSessionIdentity, root bool) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := validateOrganizationIdentity(tx, identity, organizationNow().Unix()); err != nil {
			return err
		}
		if root {
			var user User
			if err := tx.Select("role").First(&user, identity.UserID).Error; err != nil {
				return err
			}
			if user.Role != common.RoleRootUser {
				return ErrOrganizationForbidden
			}
		}
		// The first session read may have waited on a user/session lock.
		_, err := validateOrganizationIdentity(tx, identity, organizationNow().Unix())
		return err
	})
}

// requireOrganizationCapacity runs after participant User locks, before the
// net increase. Preserve this snapshot position, including under MySQL RR.
func requireOrganizationCapacity(tx *gorm.DB, userID int, owned, joined bool) error {
	limits, err := ReadOrganizationLimits(tx)
	if err != nil {
		return err
	}
	if owned && limits.MaxOrganizationsCreated > 0 {
		var count int64
		if err := tx.Model(&Organization{}).Where("owner_user_id = ? AND dissolved_at = 0", userID).Count(&count).Error; err != nil {
			return err
		}
		if count >= limits.MaxOrganizationsCreated {
			return ErrOrganizationCreatedLimit
		}
	}
	if joined && limits.MaxOrganizationsJoined > 0 {
		var count int64
		if err := tx.Model(&OrganizationMember{}).
			Joins("JOIN organizations ON organizations.id = organization_members.organization_id").
			Where("organization_members.user_id = ? AND organization_members.removed_at = 0 AND organizations.dissolved_at = 0", userID).
			Distinct("organization_members.organization_id").Count(&count).Error; err != nil {
			return err
		}
		if count >= limits.MaxOrganizationsJoined {
			return ErrOrganizationJoinedLimit
		}
	}
	return nil
}
