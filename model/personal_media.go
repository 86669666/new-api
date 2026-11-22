package model

import (
	"context"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// personalMediaOwner binds the resource query to the owner's current session
// in the same database statement, including when serving a response after an upstream wait.
func personalMediaOwnerWithDB(db *gorm.DB, identity AuthSessionIdentity) *gorm.DB {
	owner := db.Model(&User{}).Select("1").
		Where("id = ? AND status = ? AND auth_version = ?", identity.UserID, common.UserStatusEnabled, identity.UserAuthVersion)
	session := db.Model(&UserSession{}).Select("1").
		Where("sid = ? AND user_id = ? AND status = ? AND version = ? AND user_auth_version = ? AND revoked_at = 0 AND expires_at > ?",
			identity.SessionID, identity.UserID, UserSessionStatusActive, identity.SessionVersion, identity.UserAuthVersion, time.Now().Unix())
	return db.Where("user_id = ? AND EXISTS (?) AND EXISTS (?)", identity.UserID, owner, session)
}

func personalMediaOwner(ctx context.Context, identity AuthSessionIdentity) *gorm.DB {
	return personalMediaOwnerWithDB(DB.WithContext(ctx), identity)
}

func ReadPersonalTaskArtifact(ctx context.Context, identity AuthSessionIdentity, rowID int64) (*Task, error) {
	var task Task
	err := personalMediaOwner(ctx, identity).Where("id = ? AND organization_id = ?", rowID, 0).First(&task).Error
	return &task, err
}

// TaskMediaResultFingerprint binds a native-media ticket to the exact
// retrievable result observed when the ticket was minted.
func TaskMediaResultFingerprint(task *Task) string {
	if task == nil {
		return ""
	}
	payload, err := common.Marshal(struct {
		TaskID     string
		Status     TaskStatus
		Platform   any
		ChannelID  int
		UserID     int
		Action     string
		CreatedAt  int64
		UpdatedAt  int64
		ResultURL  string
		Properties Properties
		Data       any
		Private    TaskPrivateData
	}{
		TaskID: task.TaskID, Status: task.Status, Platform: task.Platform, ChannelID: task.ChannelId,
		UserID: task.UserId, Action: task.Action, CreatedAt: task.CreatedAt, UpdatedAt: task.UpdatedAt,
		ResultURL: task.GetResultURL(), Properties: task.Properties, Data: task.Data, Private: task.PrivateData,
	})
	if err != nil {
		return ""
	}
	return common.GenerateHMACWithKey([]byte("task-media-result-v1:"+common.CryptoSecret), string(payload))
}

func ReadPersonalMidjourneyImage(ctx context.Context, identity AuthSessionIdentity, rowID int64) (*Midjourney, error) {
	var task Midjourney
	err := personalMediaOwner(ctx, identity).Where("id = ?", rowID).First(&task).Error
	return &task, err
}
