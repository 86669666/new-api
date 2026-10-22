package model

import (
	"errors"
	"os"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// OAuthRevocationJob is a pending Hydra revoke for one user. An empty ClientID
// revokes the login session and every client. The row holds no token.
type OAuthRevocationJob struct {
	ID        int    `json:"-" gorm:"primaryKey"`
	UserID    int    `json:"-" gorm:"not null;uniqueIndex:idx_oauth_revoke_user_client"`
	ClientID  string `json:"-" gorm:"type:varchar(255);not null;uniqueIndex:idx_oauth_revoke_user_client"`
	Attempts  int    `json:"-"`
	NextAt    int64  `json:"-" gorm:"bigint;index"`
	LastError string `json:"-" gorm:"type:varchar(160)"`
	CreatedAt int64  `json:"-" gorm:"bigint"`
}

func (OAuthRevocationJob) TableName() string {
	return "oauth_revocation_jobs"
}

func MigrateOAuthRevocationJobsIfEnabled(db *gorm.DB) error {
	if os.Getenv("OAUTH_USERINFO_ENABLED") != "true" || db == nil {
		return nil
	}
	return db.AutoMigrate(&OAuthRevocationJob{})
}

var wakeOAuthRevocation func()

// SetOAuthRevocationWaker registers the process retry loop. A nil waker leaves
// queued jobs stored until a later flush.
func SetOAuthRevocationWaker(fn func()) { wakeOAuthRevocation = fn }

func WakeOAuthRevocation() {
	if wakeOAuthRevocation != nil {
		wakeOAuthRevocation()
	}
}

// ScheduleOAuthRevocation disables this user's issued relay keys and queues a
// Hydra revoke in the caller's transaction. A missing job table skips the queue.
// Issued keys are still disabled when that association table exists.
func ScheduleOAuthRevocation(tx *gorm.DB, userID int, clientID string) error {
	if userID <= 0 || tx == nil {
		return nil
	}
	if err := disableOAuthIssuedTokensTx(tx, userID, clientID); err != nil {
		return err
	}
	if !tx.Migrator().HasTable(&OAuthRevocationJob{}) {
		return nil
	}
	now := common.GetTimestamp()
	// A duplicate job is already queued. ON CONFLICT avoids aborting the caller's
	// transaction, which PostgreSQL does after a unique violation.
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&OAuthRevocationJob{
		UserID: userID, ClientID: clientID, NextAt: now, CreatedAt: now,
	}).Error
}

func disableOAuthIssuedTokensTx(tx *gorm.DB, userID int, clientID string) error {
	if userID <= 0 || tx == nil || !tx.Migrator().HasTable(&OAuthIssuedToken{}) {
		return nil
	}
	query := tx.Where("user_id = ?", userID)
	if clientID != "" {
		query = query.Where("client_id = ?", clientID)
	}
	var rows []OAuthIssuedToken
	if err := query.Find(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		var token Token
		err := tx.Where("id = ? AND user_id = ?", row.TokenID, userID).First(&token).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err = invalidateTokenCacheForMutation(token.Key); err != nil {
			return err
		}
		if err = tx.Model(&Token{}).Where("id = ? AND user_id = ?", token.Id, userID).Update("status", common.TokenStatusDisabled).Error; err != nil {
			return err
		}
	}
	return nil
}

func ListDueOAuthRevocations(limit int) ([]OAuthRevocationJob, error) {
	if DB == nil || !DB.Migrator().HasTable(&OAuthRevocationJob{}) {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}
	var rows []OAuthRevocationJob
	err := DB.Where("next_at <= ?", common.GetTimestamp()).Order("id asc").Limit(limit).Find(&rows).Error
	return rows, err
}

func CompleteOAuthRevocation(id int) error {
	if DB == nil || id <= 0 {
		return nil
	}
	return DB.Delete(&OAuthRevocationJob{}, id).Error
}

func DeferOAuthRevocation(id, attempts int, nextAt int64) error {
	if DB == nil || id <= 0 {
		return nil
	}
	return DB.Model(&OAuthRevocationJob{}).Where("id = ?", id).Updates(map[string]any{
		"attempts": attempts, "next_at": nextAt, "last_error": "oauth revocation unavailable",
	}).Error
}

// QueueOAuthUserRevocation disables this user's issued relay keys and stores a
// Hydra revoke for every client. The HTTP call happens after commit.
func QueueOAuthUserRevocation(userID int) error {
	if userID <= 0 || DB == nil {
		return nil
	}
	err := DB.Transaction(func(tx *gorm.DB) error {
		return ScheduleOAuthRevocation(tx, userID, "")
	})
	if err != nil {
		return err
	}
	WakeOAuthRevocation()
	return nil
}
