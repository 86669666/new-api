package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

var ErrOrganizationIdempotencyConflict = errors.New("The idempotency key was already used for a different organization request.")

// OrganizationCreationRequest is a permanent success receipt in the primary
// database. Its dedicated table scopes keys to organization.create/v1. Neither
// dissolution nor session rotation releases a key for another creation.
type OrganizationCreationRequest struct {
	ID             int64  `gorm:"primaryKey"`
	UserID         int    `gorm:"not null;uniqueIndex:uq_org_creation_user_key,priority:1"`
	KeyHash        string `gorm:"type:varchar(64);not null;uniqueIndex:uq_org_creation_user_key,priority:2"`
	RequestHash    string `gorm:"type:varchar(64);not null"`
	OrganizationID int64  `gorm:"not null"`
	EventID        int64  `gorm:"not null"`
	ReceiptVersion int    `gorm:"not null"`
	CreatedAt      int64  `gorm:"not null;autoCreateTime:false"`
}

func ValidateOrganizationCreationKey(key string) error {
	if len(key) == 0 || len(key) > 128 {
		return ErrOrganizationInvalidInput
	}
	for i := range len(key) {
		b := key[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if i > 0 && (b == '.' || b == '_' || b == ':' || b == '-') {
			continue
		}
		return ErrOrganizationInvalidInput
	}
	return nil
}

// CreateOrganizationWithKey keeps the key out of the command/proof contracts of
// all other organization operations. Empty keys are rejected by this entry.
func CreateOrganizationWithKey(ctx context.Context, identity AuthSessionIdentity, name, key string) (*OrganizationMutationReceipt, error) {
	if err := ValidateOrganizationCreationKey(key); err != nil {
		return nil, err
	}
	receipt := &OrganizationMutationReceipt{}
	_, err := createOrganizationWithReceipt(ctx, identity, name, receipt, key)
	if err != nil {
		return nil, err
	}
	return receipt, nil
}

func newOrganizationCreationRequest(userID int, name, key string) (*OrganizationCreationRequest, error) {
	if err := ValidateOrganizationCreationKey(key); err != nil {
		return nil, err
	}
	payload, err := common.Marshal(struct {
		Version   int    `json:"version"`
		Operation string `json:"operation"`
		Name      string `json:"name"`
	}{1, "organization.create", name})
	if err != nil {
		return nil, err
	}
	keyHash, requestHash := sha256.Sum256([]byte(key)), sha256.Sum256(payload)
	return &OrganizationCreationRequest{UserID: userID, KeyHash: hex.EncodeToString(keyHash[:]), RequestHash: hex.EncodeToString(requestHash[:]), ReceiptVersion: 1}, nil
}

// replayOrganizationCreation holds User -> Organization -> Member locks. The
// final session validation must use a new clock reading after lock waits.
func replayOrganizationCreation(tx *gorm.DB, identity AuthSessionIdentity, request *OrganizationCreationRequest, receipt *OrganizationMutationReceipt) (*Organization, error) {
	if request.ReceiptVersion != 1 || request.OrganizationID <= 0 || request.EventID <= 0 || receipt == nil {
		return nil, errors.New("invalid organization creation receipt")
	}
	var org Organization
	if err := lockForUpdate(tx).First(&org, request.OrganizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, err
	}
	var member OrganizationMember
	err := lockForUpdate(tx).Where("organization_id = ? AND user_id = ?", org.ID, identity.UserID).First(&member).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if _, err := validateOrganizationIdentity(tx, identity, organizationNow().Unix()); err != nil {
		return nil, err
	}
	if org.DissolvedAt != 0 || member.ID == 0 || member.RemovedAt != 0 {
		return nil, ErrOrganizationNotFound
	}
	if org.SelfDisabledAt != 0 || org.PlatformDisabledAt != 0 {
		return nil, ErrOrganizationDisabled
	}
	*receipt = OrganizationMutationReceipt{OrganizationID: org.ID, Revision: 1, Action: "create", EventID: request.EventID, ObjectKind: "organization", ObjectID: org.ID, Replayed: true}
	return &org, nil
}
