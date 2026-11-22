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

func ReadPersonalMidjourneyImage(ctx context.Context, identity AuthSessionIdentity, rowID int64) (*Midjourney, error) {
	var task Midjourney
	err := personalMediaOwner(ctx, identity).Where("id = ?", rowID).First(&task).Error
	return &task, err
}
