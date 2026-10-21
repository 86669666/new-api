package model

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	ErrClientEventUnauthorized = errors.New("client event credential rejected")
	ErrClientEventForbidden    = errors.New("client event access denied")
)

// ClientEvent is an authenticated client self-report, never a billing record.
// ReceivedAt bounds retention; removing a row also removes its deduplication key.
type ClientEvent struct {
	ID           int64 `gorm:"primaryKey"`
	UserID       int   `gorm:"index"`
	TokenID      int
	ClientID     string `gorm:"type:varchar(36)"`
	Channel      string `gorm:"type:varchar(64)"`
	EventType    string `gorm:"type:varchar(16)"`
	EventTimeMS  int64
	ReceivedAt   int64  `gorm:"index"`
	Fingerprint  string `gorm:"type:char(64);uniqueIndex"`
	AppVersion   string `gorm:"type:varchar(32)"`
	OS           string `gorm:"type:varchar(16)"`
	Provider     string `gorm:"type:varchar(128)"`
	Model        string `gorm:"type:varchar(255)"`
	Source       string `gorm:"type:varchar(8)"`
	InputTokens  *int64
	OutputTokens *int64
}

// Unexported fields keep the exact key request-local and nonserializable.
type ClientEventCredential struct {
	userID  int
	tokenID int
	key     string
}

func (c ClientEventCredential) TokenID() int { return c.tokenID }

func checkClientEventAuthority(user User, token Token, key, ip string, now int64) error {
	if token.Key != key || token.UserId != user.Id || token.DeletedAt.Valid ||
		(token.Status != common.TokenStatusEnabled && token.Status != common.TokenStatusExhausted) ||
		(token.ExpiredTime != -1 && token.ExpiredTime <= now) {
		return ErrClientEventUnauthorized
	}
	if user.DeletedAt.Valid || user.Status != common.UserStatusEnabled {
		return ErrClientEventForbidden
	}
	if allowed := token.GetIpLimits(); len(allowed) > 0 {
		address := net.ParseIP(ip)
		if address == nil || !common.IsIpInCIDRList(address, allowed) {
			return ErrClientEventForbidden
		}
	}
	return nil
}

// AuthenticateClientEvent bypasses caches and suppresses credential SQL traces.
// This preliminary observation authorizes the limiter, not the eventual write.
func AuthenticateClientEvent(ctx context.Context, key, ip string) (ClientEventCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db := DB.WithContext(ctx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})
	var token Token
	err := db.Select("id", "user_id", "key", "status", "expired_time", "allow_ips").Where(commonKeyCol+" = ?", key).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ClientEventCredential{}, ErrClientEventUnauthorized
	}
	if err != nil {
		return ClientEventCredential{}, err
	}
	// SQL collations may consider a case/accent/padding variant equal.
	if token.Key != key {
		return ClientEventCredential{}, ErrClientEventUnauthorized
	}
	var user User
	err = db.Select("id", "status").First(&user, token.UserId).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ClientEventCredential{}, ErrClientEventForbidden
	}
	if err != nil {
		return ClientEventCredential{}, err
	}
	if err := checkClientEventAuthority(user, token, key, ip, time.Now().Unix()); err != nil {
		return ClientEventCredential{}, err
	}
	return ClientEventCredential{userID: user.Id, tokenID: token.Id, key: key}, nil
}

func ReceiveClientEvents(ctx context.Context, credential ClientEventCredential, ip string, events []ClientEvent) (int, error) {
	if credential.userID <= 0 || credential.tokenID <= 0 || credential.key == "" || len(events) > 10 {
		return 0, ErrClientEventUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	count := 0
	err := DB.WithContext(ctx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Transaction(func(tx *gorm.DB) error {
		// SQLite must reserve its writer before any transactional read.
		if tx.Dialector.Name() == "sqlite" {
			if err := tx.Model(&User{}).Where("id = ?", credential.userID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
				return err
			}
		}
		var user User
		if err := lockForUpdate(tx).Select("id", "status").First(&user, credential.userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrClientEventForbidden
			}
			return err
		}
		var token Token
		if err := lockForUpdate(tx).Select("id", "user_id", "key", "status", "expired_time", "allow_ips").First(&token, credential.tokenID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrClientEventUnauthorized
			}
			return err
		}
		if err := checkClientEventAuthority(user, token, credential.key, ip, time.Now().Unix()); err != nil {
			return err
		}
		unique := make(map[string]ClientEvent, len(events))
		fingerprints := make([]string, 0, len(events))
		for _, event := range events {
			event.UserID, event.TokenID, event.ID = user.Id, token.Id, 0
			// Token rotation, receive time and unknown fields do not split identity.
			encoded, err := common.Marshal([]any{"client-event-v1", user.Id, event.ClientID, event.Channel, event.EventType,
				event.EventTimeMS, event.AppVersion, event.OS, event.Provider, event.Model, event.Source, event.InputTokens, event.OutputTokens})
			if err != nil {
				return err
			}
			event.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(encoded))
			if _, exists := unique[event.Fingerprint]; !exists {
				fingerprints = append(fingerprints, event.Fingerprint)
				unique[event.Fingerprint] = event
			}
		}
		// First ordinary consistent read is after the owner lock, including on
		// MySQL RR. The owner serializes other tokens belonging to this user.
		existing := []string{}
		if len(fingerprints) > 0 {
			if err := tx.Model(&ClientEvent{}).Where("user_id = ? AND fingerprint IN ?", user.Id, fingerprints).Pluck("fingerprint", &existing).Error; err != nil {
				return err
			}
		}
		for _, fingerprint := range existing {
			delete(unique, fingerprint)
		}
		for _, fingerprint := range fingerprints {
			if event, ok := unique[fingerprint]; ok {
				if err := tx.Create(&event).Error; err != nil {
					return err
				}
				count++
			}
		}
		// Inserts can wait too. An expired admission must roll back, not return200.
		return checkClientEventAuthority(user, token, credential.key, ip, time.Now().Unix())
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// DeleteClientEventBatch rechecks the cutoff at deletion, without DELETE LIMIT.
func DeleteClientEventBatch(ctx context.Context, before int64) (int64, error) {
	ids := []int64{}
	if err := DB.WithContext(ctx).Model(&ClientEvent{}).Where("received_at < ?", before).Order("id").Limit(1000).Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result := DB.WithContext(ctx).Where("id IN ? AND received_at < ?", ids, before).Delete(&ClientEvent{})
	return result.RowsAffected, result.Error
}
