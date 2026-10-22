package model

import (
	"errors"

	"github.com/QuantumNous/new-api/setting/operation_setting"
	"gorm.io/gorm"
)

var (
	ErrOrganizationCreatedLimit = errors.New("The maximum number of owned organizations has been reached.")
	ErrOrganizationJoinedLimit  = errors.New("The maximum number of joined organizations has been reached.")
)

// requireOrganizationCapacity runs after the participant User locks and before
// any net increase. User locks serialize admissions across organizations and
// sessions; the first ordinary read must follow those locks for MySQL RR.
// Missing options mean unlimited, while malformed or unreadable policy fails closed.
func requireOrganizationCapacity(tx *gorm.DB, userID int, owned, joined bool) error {
	var limits [2]int64
	var options []Option
	keys := []string{operation_setting.OrganizationCreatedLimitOptionKey, operation_setting.OrganizationJoinedLimitOptionKey}
	// Read both limits in one statement so PostgreSQL READ COMMITTED cannot
	// combine settings from different committed policy versions.
	if err := tx.Where(map[string]any{"key": keys}).Find(&options).Error; err != nil {
		return err
	}
	for _, option := range options {
		index := 0
		switch option.Key {
		case operation_setting.OrganizationCreatedLimitOptionKey:
		case operation_setting.OrganizationJoinedLimitOptionKey:
			index = 1
		default:
			return errors.New("invalid organization limit option identity")
		}
		limit, err := operation_setting.ParseOrganizationLimit(option.Value)
		if err != nil {
			return err
		}
		limits[index] = limit
	}
	if owned && limits[0] > 0 {
		var count int64
		if err := tx.Model(&Organization{}).Where("owner_user_id = ? AND dissolved_at = 0", userID).Count(&count).Error; err != nil {
			return err
		}
		if count >= limits[0] {
			return ErrOrganizationCreatedLimit
		}
	}
	if joined && limits[1] > 0 {
		var count int64
		if err := tx.Model(&OrganizationMember{}).
			Joins("JOIN organizations ON organizations.id = organization_members.organization_id").
			Where("organization_members.user_id = ? AND organization_members.removed_at = 0 AND organizations.dissolved_at = 0", userID).
			Distinct("organization_members.organization_id").Count(&count).Error; err != nil {
			return err
		}
		if count >= limits[1] {
			return ErrOrganizationJoinedLimit
		}
	}
	return nil
}
