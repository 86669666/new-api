package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

const (
	// One completed personal image is enough for the first immutable snapshot
	// contract. The per-owner budget keeps an account from filling the primary
	// database with pinned media while remaining deterministic under the user
	// lock held by PinPersonalMidjourneyImage.
	PersonalMidjourneyImageVersion           = 1
	PersonalMidjourneyImageMaxBytes    int64 = 2 << 20
	PersonalMidjourneyImageOwnerBudget int64 = 16 << 20
)

var (
	ErrMidjourneyImageNotReady       = errors.New("midjourney image is not complete")
	ErrMidjourneyImageBudgetExceeded = errors.New("personal media storage budget exceeded")
	ErrMidjourneyImageChanged        = errors.New("midjourney image changed while it was being pinned")
	ErrMidjourneyImageIntegrity      = errors.New("immutable midjourney image integrity check failed")
)

// MidjourneyImageVersion is immutable media copied into the primary database.
// Version 1 is deliberately unique per Midjourney row; sharing, expiry and
// revocation are separate contracts and are not represented here.
type MidjourneyImageVersion struct {
	ID           int64  `json:"-" gorm:"primaryKey"`
	MidjourneyID int    `json:"-" gorm:"not null;uniqueIndex:uq_mj_image_version;index"`
	UserID       int    `json:"-" gorm:"not null;index"`
	MjID         string `json:"-" gorm:"type:varchar(191);not null"`
	SubmitTime   int64  `json:"-" gorm:"not null;index"`
	Version      int    `json:"version" gorm:"not null;uniqueIndex:uq_mj_image_version"`
	Data         []byte `json:"-" gorm:"not null"`
	Digest       string `json:"digest" gorm:"type:char(64);not null"`
	Length       int64  `json:"length" gorm:"not null"`
	MIME         string `json:"mime" gorm:"type:varchar(128);not null"`
	CreatedAt    int64  `json:"created_at" gorm:"not null;index"`
}

func PinPersonalMidjourneyImage(ctx context.Context, identity AuthSessionIdentity, observed *Midjourney, data []byte, mime string) (*MidjourneyImageVersion, bool, error) {
	if observed == nil || len(data) == 0 || int64(len(data)) > PersonalMidjourneyImageMaxBytes {
		return nil, false, ErrMidjourneyImageNotReady
	}
	digest := sha256.Sum256(data)
	var version MidjourneyImageVersion
	created := false
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
			return err
		}
		var task Midjourney
		if err := lockForUpdate(tx).Where("id = ? AND user_id = ?", observed.Id, identity.UserID).First(&task).Error; err != nil {
			return err
		}
		if task.Status != "SUCCESS" || task.ImageUrl == "" || task.Progress != "" && task.Progress != "100%" {
			return ErrMidjourneyImageNotReady
		}
		if task.MjId != observed.MjId || task.SubmitTime != observed.SubmitTime {
			return ErrMidjourneyImageChanged
		}
		var existing MidjourneyImageVersion
		err := tx.Where("midjourney_id = ? AND version = ?", observed.Id, PersonalMidjourneyImageVersion).First(&existing).Error
		if err == nil {
			if existing.UserID != identity.UserID || existing.MidjourneyID != task.Id || existing.MjID != task.MjId || existing.SubmitTime != task.SubmitTime {
				return ErrMidjourneyImageChanged
			}
			version = existing
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if task.ImageUrl != observed.ImageUrl || task.ChannelId != observed.ChannelId {
			return ErrMidjourneyImageChanged
		}
		var used int64
		if err := tx.Model(&MidjourneyImageVersion{}).Where("user_id = ?", identity.UserID).Select("COALESCE(SUM(length), 0)").Scan(&used).Error; err != nil {
			return err
		}
		if used > PersonalMidjourneyImageOwnerBudget-int64(len(data)) {
			return ErrMidjourneyImageBudgetExceeded
		}
		version = MidjourneyImageVersion{
			MidjourneyID: task.Id, UserID: identity.UserID, MjID: task.MjId, SubmitTime: task.SubmitTime,
			Version: PersonalMidjourneyImageVersion, Data: data, Digest: hex.EncodeToString(digest[:]),
			Length: int64(len(data)), MIME: mime, CreatedAt: time.Now().Unix(),
		}
		created = true
		return tx.Create(&version).Error
	})
	if err != nil {
		return nil, false, err
	}
	return &version, created, nil
}

func ReadPersonalMidjourneyImageVersion(ctx context.Context, identity AuthSessionIdentity, rowID, version int) (*MidjourneyImageVersion, error) {
	if rowID <= 0 || version <= 0 {
		return nil, gorm.ErrRecordNotFound
	}
	var result MidjourneyImageVersion
	db := DB.WithContext(ctx)
	ownerTask := db.Model(&Midjourney{}).Select("1").
		Where("id = midjourney_image_versions.midjourney_id AND user_id = midjourney_image_versions.user_id").
		Where("mj_id = midjourney_image_versions.mj_id AND submit_time = midjourney_image_versions.submit_time")
	if err := personalMediaOwnerWithDB(db, identity).
		Where("midjourney_id = ? AND version = ? AND EXISTS (?)", rowID, version, ownerTask).
		First(&result).Error; err != nil {
		return nil, err
	}
	digest := sha256.Sum256(result.Data)
	if result.Length <= 0 || result.Length > PersonalMidjourneyImageMaxBytes ||
		result.Length != int64(len(result.Data)) || hex.EncodeToString(digest[:]) != result.Digest {
		return nil, ErrMidjourneyImageIntegrity
	}
	return &result, nil
}
