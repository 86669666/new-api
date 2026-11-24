package model

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

// LegacyMediaCutover is the single shared transition record. Preparation
// does not create it. Both deadlines derive from the same UTC Unix timestamp.
type LegacyMediaCutover struct {
	ID         int    `gorm:"primaryKey;autoIncrement:false"`
	SnapshotID string `gorm:"type:char(64);not null"`
	StartedAt  int64  `gorm:"not null"`
}

const legacyMediaCutoverID = 1

// ReadLegacyMediaContent returns nil when there is no transition record, so
// the caller can continue its compatibility read. Once the record exists,
// all errors deny legacy delivery and the caller must not fetch live content.
func ReadLegacyMediaContent(ctx context.Context, route LegacyMediaRoute, now time.Time) (*LegacyMediaContent, error) {
	var content *LegacyMediaContent
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var cutover LegacyMediaCutover
		err := tx.Take(&cutover, "id = ?", legacyMediaCutoverID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		days := 30
		if route.Family == LegacyTaskArtifactV1 {
			days = 90
		}
		start := time.Unix(cutover.StartedAt, 0)
		deadline := start.Add(time.Duration(days) * 24 * time.Hour)
		if !route.valid() || cutover.StartedAt <= 0 || now.Before(start) || !now.Before(deadline) {
			return ErrLegacyMediaUnproven
		}
		var snapshot LegacyMediaSnapshot
		err = tx.Select("id").Take(&snapshot, "id = ?", cutover.SnapshotID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrLegacyMediaUnproven
		}
		if err != nil {
			return err
		}
		_, content, err = readFrozenLegacyMedia(tx, cutover.SnapshotID, route)
		if err != nil {
			return err
		}
		content.ExpiresAt = deadline
		return nil
	})
	if err != nil {
		return nil, err
	}
	return content, nil
}

// CheckLegacyMediaCompatibility rechecks the primary database before any
// live legacy fetch and again before publication after an upstream wait.
func CheckLegacyMediaCompatibility(ctx context.Context, subject LegacyMediaSubject) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var cutover LegacyMediaCutover
		err := tx.Select("id").Take(&cutover, "id = ?", legacyMediaCutoverID).Error
		if err == nil {
			return ErrLegacyMediaUnproven
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		// Preparation and revocation currently cover MJ images and V1 image-1.
		if subject.Family == LegacyTaskArtifactV1 && subject.ArtifactKey != PersonalTaskImageKey {
			return nil
		}
		var first LegacyMediaRouteObservation
		err = tx.Select("route_digest").Take(&first, "family = ?", subject.Family).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// An empty inventory cannot constrain previously valid route IDs
			// or require equal source and observation collations.
			return checkLegacyMediaRevocation(tx, subject)
		}
		if err != nil {
			return err
		}
		if err := verifyLegacyMediaComparison(tx, subject.Family); err != nil {
			return err
		}
		var observed []LegacyMediaRouteObservation
		if err := legacyRouteObservations(tx, subject.LegacyMediaRoute).Limit(2).Find(&observed).Error; err != nil {
			return err
		}
		if len(observed) > 0 {
			// A previously observed address must not inherit another object's
			// eligibility or escape the revocation of its original subject.
			if len(observed) != 1 || observed[0].Ambiguous || observed[0].LegacyMediaRoute != subject.LegacyMediaRoute ||
				observed[0].SubjectDigest != legacySnapshotDigest(subject) {
				return ErrLegacyMediaUnproven
			}
			if err := lockLegacyMediaSubject(tx, subject); err != nil {
				return err
			}
		}
		return checkLegacyMediaRevocation(tx, subject)
	})
}
