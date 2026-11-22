package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

const (
	PersonalTaskImageKey               = "image-1"
	PersonalTaskImageVersion           = 1
	PersonalTaskImageMaxBytes    int64 = 2 << 20
	PersonalTaskImageOwnerBudget int64 = 16 << 20
)

var (
	ErrPersonalTaskImageChanged   = errors.New("task image source changed while it was being pinned")
	ErrPersonalTaskImageBudget    = errors.New("personal task image storage budget exceeded")
	ErrPersonalTaskImageIntegrity = errors.New("immutable task image integrity check failed")
)

// PersonalTaskImage stores the first immutable image by task row and artifact key.
type PersonalTaskImage struct {
	ID          int64  `json:"-" gorm:"primaryKey"`
	TaskRowID   int64  `json:"-" gorm:"not null;uniqueIndex:uq_personal_task_image"`
	ArtifactKey string `json:"-" gorm:"type:varchar(128);not null;uniqueIndex:uq_personal_task_image"`
	Version     int    `json:"version" gorm:"not null;uniqueIndex:uq_personal_task_image"`
	UserID      int    `json:"-" gorm:"not null;index"`
	TaskID      string `json:"-" gorm:"type:varchar(191);not null"`
	SubmitTime  int64  `json:"-" gorm:"not null"`
	Data        []byte `json:"-" gorm:"not null"`
	Digest      string `json:"digest" gorm:"type:char(64);not null"`
	Length      int64  `json:"length" gorm:"not null"`
	MIME        string `json:"mime" gorm:"type:varchar(64);not null"`
	CreatedAt   int64  `json:"created_at" gorm:"not null"`
}

func (image *PersonalTaskImage) checkIntegrity() error {
	digest := sha256.Sum256(image.Data)
	if image.Length <= 0 || image.Length > PersonalTaskImageMaxBytes ||
		image.Length != int64(len(image.Data)) || hex.EncodeToString(digest[:]) != image.Digest ||
		(image.MIME != "image/png" && image.MIME != "image/jpeg") {
		return ErrPersonalTaskImageIntegrity
	}
	return nil
}

func ReadPersonalTaskImage(ctx context.Context, identity AuthSessionIdentity, rowID int64) (*PersonalTaskImage, error) {
	db := DB.WithContext(ctx)
	ownedImage := personalMediaOwnerWithDB(db, identity).Model(&PersonalTaskImage{}).Select("id").
		Where("task_row_id = ? AND artifact_key = ? AND version = ?", rowID, PersonalTaskImageKey, PersonalTaskImageVersion)
	var result struct {
		PersonalTaskImage
		Current Task `gorm:"embedded;embeddedPrefix:current_"`
	}
	// Read the version and the current task's retrieval eligibility in one
	// statement, including the session and owner predicates in ownedImage.
	err := db.Table("personal_task_images AS image_versions").
		Select("image_versions.*, tasks.task_id AS current_task_id, tasks.submit_time AS current_submit_time, tasks.billing_protocol AS current_billing_protocol, tasks.billing_state AS current_billing_state, tasks.private_data AS current_private_data").
		Joins("JOIN tasks ON tasks.id = image_versions.task_row_id AND tasks.user_id = image_versions.user_id AND tasks.organization_id = 0 AND tasks.task_id = image_versions.task_id AND tasks.submit_time = image_versions.submit_time AND tasks.status = ?", TaskStatusSuccess).
		Where("image_versions.id IN (?)", ownedImage).Take(&result).Error
	if err != nil {
		return nil, err
	}
	if !result.Current.ResultRetrievable() || result.Current.TaskID != result.TaskID || result.Current.SubmitTime != result.SubmitTime {
		return nil, gorm.ErrRecordNotFound
	}
	return &result.PersonalTaskImage, result.PersonalTaskImage.checkIntegrity()
}

func PinPersonalTaskImage(ctx context.Context, identity AuthSessionIdentity, observed *Task, data []byte, mime string) (*PersonalTaskImage, bool, error) {
	if len(data) == 0 || int64(len(data)) > PersonalTaskImageMaxBytes || (mime != "image/png" && mime != "image/jpeg") {
		return nil, false, ErrPersonalTaskImageIntegrity
	}
	var image PersonalTaskImage
	created := false
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
			return err
		}
		var current Task
		if err := lockForUpdate(tx).Where("id = ? AND user_id = ? AND organization_id = 0", observed.ID, identity.UserID).Take(&current).Error; err != nil {
			return err
		}
		if !current.ResultRetrievable() || current.Status != TaskStatusSuccess ||
			current.TaskID != observed.TaskID || current.SubmitTime != observed.SubmitTime ||
			current.Platform != observed.Platform || current.PrivateData.Execution == nil ||
			observed.PrivateData.Execution == nil || current.PrivateData.Execution.TaskPlugin == nil ||
			observed.PrivateData.Execution.TaskPlugin == nil ||
			current.PrivateData.Execution.TaskPlugin.Key != observed.PrivateData.Execution.TaskPlugin.Key ||
			current.PrivateData.Execution.TaskPlugin.Version != observed.PrivateData.Execution.TaskPlugin.Version {
			return ErrPersonalTaskImageChanged
		}
		err := tx.Where("task_row_id = ? AND artifact_key = ? AND version = ?", observed.ID, PersonalTaskImageKey, PersonalTaskImageVersion).Take(&image).Error
		if err == nil {
			if image.UserID != identity.UserID || image.TaskID != current.TaskID || image.SubmitTime != current.SubmitTime {
				return ErrPersonalTaskImageChanged
			}
			return image.checkIntegrity()
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if current.ChannelId != observed.ChannelId || current.Action != observed.Action ||
			current.UpdatedAt != observed.UpdatedAt || current.Properties != observed.Properties ||
			current.PrivateData.UpstreamTaskID != observed.PrivateData.UpstreamTaskID ||
			!bytes.Equal(current.Data, observed.Data) {
			return ErrPersonalTaskImageChanged
		}
		var used int64
		if err := tx.Model(&PersonalTaskImage{}).Where("user_id = ?", identity.UserID).Select("COALESCE(SUM(length), 0)").Scan(&used).Error; err != nil {
			return err
		}
		if used > PersonalTaskImageOwnerBudget-int64(len(data)) {
			return ErrPersonalTaskImageBudget
		}
		digest := sha256.Sum256(data)
		image = PersonalTaskImage{TaskRowID: current.ID, ArtifactKey: PersonalTaskImageKey,
			Version: PersonalTaskImageVersion, UserID: current.UserId, TaskID: current.TaskID, SubmitTime: current.SubmitTime,
			Data: data, Digest: hex.EncodeToString(digest[:]), Length: int64(len(data)), MIME: mime, CreatedAt: time.Now().Unix()}
		if err := tx.Create(&image).Error; err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return &image, created, nil
}
