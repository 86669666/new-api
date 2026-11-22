package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const (
	PersonalMidjourneyShareTTL         int64 = 15 * 60
	PersonalMidjourneyShareRetention   int64 = 24 * 60 * 60
	PersonalMidjourneyShareActiveLimit       = 8
)

var ErrMidjourneyShareLimit = errors.New("personal media share limit exceeded")

// MidjourneyImageShare stores only a digest of the bearer capability. The
// capability itself is returned once by the create endpoint and is never
// persisted or included in management responses.
type MidjourneyImageShare struct {
	ID           int64  `json:"id" gorm:"primaryKey"`
	MidjourneyID int    `json:"-" gorm:"not null;index"`
	UserID       int    `json:"-" gorm:"not null;index"`
	Version      int    `json:"version" gorm:"not null;index"`
	VersionRowID int64  `json:"-" gorm:"not null;index"`
	AccessHash   string `json:"-" gorm:"type:char(64);not null;uniqueIndex"`
	ExpiresAt    int64  `json:"expires_at" gorm:"not null;index"`
	RevokedAt    int64  `json:"revoked_at" gorm:"not null;index"`
	CreatedAt    int64  `json:"created_at" gorm:"not null;index"`
}

func validShareHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

func CreatePersonalMidjourneyShare(ctx context.Context, identity AuthSessionIdentity, rowID, version int64, accessHash string, now int64) (*MidjourneyImageShare, error) {
	if rowID <= 0 || version != PersonalMidjourneyImageVersion || !validShareHash(accessHash) {
		return nil, gorm.ErrRecordNotFound
	}
	result := &MidjourneyImageShare{}
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
			return err
		}
		var task Midjourney
		if err := lockForUpdate(tx).Where("id = ? AND user_id = ?", rowID, identity.UserID).First(&task).Error; err != nil {
			return err
		}
		var snapshot MidjourneyImageVersion
		if err := tx.Where("midjourney_id = ? AND user_id = ? AND version = ?", rowID, identity.UserID, version).First(&snapshot).Error; err != nil {
			return err
		}
		if snapshot.MjID != task.MjId || snapshot.SubmitTime != task.SubmitTime {
			return gorm.ErrRecordNotFound
		}
		cutoff := now - PersonalMidjourneyShareRetention
		if err := tx.Where("user_id = ? AND ((revoked_at > 0 AND revoked_at <= ?) OR expires_at <= ?)", identity.UserID, cutoff, cutoff).Delete(&MidjourneyImageShare{}).Error; err != nil {
			return err
		}
		var active int64
		if err := tx.Model(&MidjourneyImageShare{}).Where("user_id = ? AND revoked_at = 0 AND expires_at > ?", identity.UserID, now).Count(&active).Error; err != nil {
			return err
		}
		if active >= PersonalMidjourneyShareActiveLimit {
			return ErrMidjourneyShareLimit
		}
		*result = MidjourneyImageShare{MidjourneyID: task.Id, UserID: identity.UserID, Version: int(version), VersionRowID: snapshot.ID, AccessHash: accessHash, ExpiresAt: now + PersonalMidjourneyShareTTL, CreatedAt: now}
		return tx.Create(result).Error
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func ListPersonalMidjourneyShares(ctx context.Context, identity AuthSessionIdentity, rowID, version, now int64) ([]MidjourneyImageShare, error) {
	if rowID <= 0 || version != PersonalMidjourneyImageVersion {
		return nil, gorm.ErrRecordNotFound
	}
	db := DB.WithContext(ctx)
	task := db.Model(&Midjourney{}).Select("1").Where(
		"midjourneys.id = midjourney_image_versions.midjourney_id AND midjourneys.user_id = midjourney_image_versions.user_id AND midjourneys.mj_id = midjourney_image_versions.mj_id AND midjourneys.submit_time = midjourney_image_versions.submit_time")
	ownedVersion := personalMediaOwnerWithDB(db, identity).Model(&MidjourneyImageVersion{}).Select("id").
		Where("midjourney_id = ? AND version = ? AND EXISTS (?)", rowID, version, task)
	var snapshot MidjourneyImageVersion
	if err := ownedVersion.Session(&gorm.Session{}).Take(&snapshot).Error; err != nil {
		return nil, err
	}
	shares := make([]MidjourneyImageShare, 0)
	err := db.Where("version_row_id IN (?) AND midjourney_id = ? AND user_id = ? AND version = ? AND revoked_at = 0 AND expires_at > ?", ownedVersion, rowID, identity.UserID, version, now).
		Order("id asc").Limit(PersonalMidjourneyShareActiveLimit).Find(&shares).Error
	return shares, err
}

func RevokePersonalMidjourneyShare(ctx context.Context, identity AuthSessionIdentity, rowID, version, shareID int64, now int64) error {
	if rowID <= 0 || version != PersonalMidjourneyImageVersion || shareID <= 0 {
		return gorm.ErrRecordNotFound
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
			return err
		}
		var task Midjourney
		if err := lockForUpdate(tx).Where("id = ? AND user_id = ?", rowID, identity.UserID).First(&task).Error; err != nil {
			return err
		}
		var snapshot MidjourneyImageVersion
		if err := tx.Where("midjourney_id = ? AND user_id = ? AND version = ? AND mj_id = ? AND submit_time = ?", rowID, identity.UserID, version, task.MjId, task.SubmitTime).First(&snapshot).Error; err != nil {
			return err
		}
		var share MidjourneyImageShare
		if err := lockForUpdate(tx).Where("id = ? AND midjourney_id = ? AND user_id = ? AND version = ? AND version_row_id = ?", shareID, rowID, identity.UserID, version, snapshot.ID).First(&share).Error; err != nil {
			return err
		}
		if share.RevokedAt == 0 {
			return tx.Model(&share).Update("revoked_at", now).Error
		}
		return nil
	})
}

// ReadPublicPersonalMidjourneyShare performs a fresh owner/task/version check
// before returning immutable bytes. It deliberately has no provider fallback.
func ReadPublicPersonalMidjourneyShare(ctx context.Context, accessHash string, now int64) (*MidjourneyImageVersion, error) {
	if !validShareHash(accessHash) {
		return nil, gorm.ErrRecordNotFound
	}
	var result MidjourneyImageVersion
	err := DB.WithContext(ctx).Table("midjourney_image_versions AS versions").Select("versions.*").
		Joins("JOIN midjourney_image_shares AS shares ON shares.version_row_id = versions.id").
		Joins("JOIN midjourneys AS tasks ON tasks.id = shares.midjourney_id AND tasks.user_id = shares.user_id AND tasks.mj_id = versions.mj_id AND tasks.submit_time = versions.submit_time").
		Joins("JOIN users AS owners ON owners.id = shares.user_id AND owners.status = ? AND owners.deleted_at IS NULL", common.UserStatusEnabled).
		Where("shares.access_hash = ? AND shares.revoked_at = 0 AND shares.expires_at > ? AND shares.midjourney_id = versions.midjourney_id AND shares.user_id = versions.user_id AND shares.version = versions.version", accessHash, now).
		First(&result).Error
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(result.Data)
	if result.Length <= 0 || result.Length > PersonalMidjourneyImageMaxBytes || result.Length != int64(len(result.Data)) || hex.EncodeToString(digest[:]) != result.Digest {
		return nil, ErrMidjourneyImageIntegrity
	}
	return &result, nil
}
