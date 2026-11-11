package model

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var ErrClientEventDisabled = errors.New("client event collection disabled")

const anonymousClientEventCapacity = 100000

// Shared by anonymous writes and Option updates. SQLite reserves its writer
// before any read; other engines use the project's canonical row lock helper.
// No process publication mutex may be acquired from an ingestion transaction.
func lockClientEventsOption(tx *gorm.DB) (Option, error) {
	var option Option
	if tx.Dialector.Name() == "sqlite" {
		if err := tx.Model(&Option{}).Where(map[string]any{"key": operation_setting.ClientEventsConfigKey}).UpdateColumn("value", gorm.Expr("value")).Error; err != nil {
			return option, err
		}
	}
	if err := lockForUpdate(tx).Where(map[string]any{"key": operation_setting.ClientEventsConfigKey}).First(&option).Error; err != nil {
		return option, err
	}
	var matches []Option
	if err := tx.Where("LOWER(TRIM("+commonKeyCol+")) = LOWER(?)", operation_setting.ClientEventsConfigKey).Find(&matches).Error; err != nil {
		return option, err
	}
	if len(matches) != 1 || option.Key != operation_setting.ClientEventsConfigKey || matches[0].Key != option.Key {
		return option, operation_setting.ErrClientEventsConfig
	}
	return option, nil
}

func anonymousClientEventFingerprint(event ClientEvent) (string, error) {
	data, err := common.Marshal([]any{"client-event-anonymous-v1", event.ClientID, event.Channel, event.EventType, event.EventTimeMS, event.AppVersion, event.OS, event.Provider, event.Model, event.Source, event.InputTokens, event.OutputTokens})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

// Enabling is fail closed on unknown reserved-zero history or constraints.
// A savepoint probe checks the actual deployed zero-ID insert constraints;
// it always rolls back, never creates user0 or persists a synthetic report.
func validateAnonymousClientEventStore(tx *gorm.DB) error {
	var rows []ClientEvent
	if err := tx.Where("user_id <= 0 OR token_id <= 0").Limit(anonymousClientEventCapacity + 1).Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) > anonymousClientEventCapacity {
		return errors.New("anonymous event capacity exceeded")
	}
	for _, row := range rows {
		fp, err := anonymousClientEventFingerprint(row)
		if err != nil || row.UserID != 0 || row.TokenID != 0 || row.Fingerprint != fp {
			return errors.New("unrecognized reserved-zero client event history")
		}
	}
	if err := tx.SavePoint("client_event_zero_probe").Error; err != nil {
		return err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	event := ClientEvent{ClientID: id.String(), Channel: "constraint-probe", EventType: "app_launch", OS: "linux", ReceivedAt: time.Now().Unix(), EventTimeMS: time.Now().UnixMilli()}
	fp, err := anonymousClientEventFingerprint(event)
	if err != nil {
		return err
	}
	event.Fingerprint = fp
	if err := tx.Create(&event).Error; err != nil {
		return err
	}
	return tx.RollbackTo("client_event_zero_probe").Error
}

// This is an unauthenticated writer, not a weaker ClientEventCredential. The
// Option lock is held through the whole batch commit, capacity and dedup reads.
func ReceiveAnonymousClientEvents(ctx context.Context, events []ClientEvent) (int, error) {
	if len(events) > 10 {
		return 0, errors.New("client event batch too large")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	count := 0
	err := DB.WithContext(ctx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Transaction(func(tx *gorm.DB) error {
		option, err := lockClientEventsOption(tx)
		if err != nil {
			return err
		}
		config, err := operation_setting.ParseClientEventsConfig(option.Value)
		if err != nil {
			return err
		}
		if !config.Enabled || !config.AllowAnonymous {
			return ErrClientEventDisabled
		}
		unique := make(map[string]ClientEvent, len(events))
		fingerprints := make([]string, 0, len(events))
		for _, event := range events {
			event.ID, event.UserID, event.TokenID = 0, 0, 0
			fp, err := anonymousClientEventFingerprint(event)
			if err != nil {
				return err
			}
			event.Fingerprint = fp
			if _, found := unique[fp]; !found {
				unique[fp] = event
				fingerprints = append(fingerprints, fp)
			}
		}
		existing := []string{}
		if len(fingerprints) > 0 {
			if err := tx.Model(&ClientEvent{}).Where("user_id = 0 AND token_id = 0 AND fingerprint IN ?", fingerprints).Pluck("fingerprint", &existing).Error; err != nil {
				return err
			}
		}
		for _, fp := range existing {
			delete(unique, fp)
		}
		// Bounded candidate scan; no full-table count or unbounded in-memory queue.
		var ids []int64
		if err := tx.Model(&ClientEvent{}).Where("user_id = 0 AND token_id = 0").Limit(anonymousClientEventCapacity+1).Pluck("id", &ids).Error; err != nil {
			return err
		}
		if len(ids)+len(unique) > anonymousClientEventCapacity {
			return errors.New("anonymous event capacity exceeded")
		}
		for _, fp := range fingerprints {
			if event, ok := unique[fp]; ok {
				if err := tx.Create(&event).Error; err != nil {
					return err
				}
				count++
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
