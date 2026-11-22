package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	LegacyMidjourneyImage = "mj_image"
	LegacyTaskArtifactV1  = "task_v1"
)

var (
	ErrLegacyMediaUnproven = errors.New("legacy media identity or version could not be verified")
	ErrLegacyMediaRevoked  = errors.New("legacy media links for this artifact were revoked")
)

// LegacyMediaSnapshot is an immutable preparation manifest. Its ID identifies
// its entire membership. CreatedAt is an audit timestamp, not a cutover time.
type LegacyMediaSnapshot struct {
	ID        string `gorm:"type:char(64);primaryKey"`
	CreatedAt int64  `gorm:"not null"`
}

type LegacyMediaRoute struct {
	Family      string `gorm:"type:varchar(16);not null"`
	PublicID    string `gorm:"type:varchar(191);not null;index"`
	ArtifactKey string `gorm:"type:varchar(128);not null"`
}

// LegacyMediaSubject binds a legacy route identity to the personal resource
// that existed when it was inventoried.
type LegacyMediaSubject struct {
	LegacyMediaRoute `gorm:"embedded"`
	RowID            int64 `gorm:"not null"`
	OwnerID          int   `gorm:"not null"`
	SubmitTime       int64 `gorm:"not null"`
}

// LegacyMediaBinding is supplied by an internal, trusted inventory caller.
// EvidenceDigest identifies the inventory evidence. Matching the database can
// prove the retained version, but does not prove when an old link was issued.
type LegacyMediaBinding struct {
	LegacyMediaSubject `gorm:"embedded"`
	VersionID          int64  `gorm:"not null"`
	Version            int    `gorm:"not null"`
	ContentDigest      string `gorm:"type:char(64);not null"`
	ContentLength      int64  `gorm:"not null"`
	EvidenceDigest     string `gorm:"type:char(64);not null"`
}

type LegacyMediaSnapshotEntry struct {
	SnapshotID         string `gorm:"type:char(64);primaryKey"`
	RouteDigest        string `gorm:"type:char(64);primaryKey"`
	LegacyMediaBinding `gorm:"embedded"`
}

// LegacyMediaRouteObservation remembers the first subject seen for a legacy
// address. Rebinding an address cannot make an old link select a new object.
type LegacyMediaRouteObservation struct {
	RouteDigest      string `gorm:"type:char(64);primaryKey"`
	LegacyMediaRoute `gorm:"embedded"`
	SubjectDigest    string `gorm:"type:char(64);not null"`
	Ambiguous        bool   `gorm:"not null"`
}

// LegacyMediaRevocation contains no copy of a URL or bearer credential. Its
// identity does not depend on the version or snapshot that recorded it.
type LegacyMediaRevocation struct {
	SubjectDigest string `gorm:"type:char(64);primaryKey"`
	CreatedAt     int64  `gorm:"not null"`
}

func (route LegacyMediaRoute) valid() bool {
	if route.PublicID == "" || len(route.PublicID) > 191 || !utf8.ValidString(route.PublicID) ||
		strings.ContainsRune(route.PublicID, 0) {
		return false
	}
	switch route.Family {
	case LegacyMidjourneyImage:
		return route.ArtifactKey == "image"
	case LegacyTaskArtifactV1:
		return route.PublicID == strings.TrimSpace(route.PublicID) && route.ArtifactKey == PersonalTaskImageKey
	default:
		return false
	}
}

func validLegacyDigest(digest string) bool {
	if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func legacySnapshotDigest(value any) string {
	// The only inputs are ordered slices and structs of primitive fields.
	data, err := common.Marshal(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (subject LegacyMediaSubject) revocationDigest() string {
	return legacySnapshotDigest(struct {
		Family      string
		RowID       int64
		ArtifactKey string
	}{subject.Family, subject.RowID, subject.ArtifactKey})
}

func legacyRouteObservations(tx *gorm.DB, route LegacyMediaRoute) *gorm.DB {
	// Match live lookup collation, then compare raw route bytes on read.
	return tx.Model(&LegacyMediaRouteObservation{}).Where(
		"family = ? AND public_id = ? AND artifact_key = ?", route.Family, route.PublicID, route.ArtifactKey)
}

// A legacy MySQL column can retain a different collation after an upgrade.
// A preparation lookup only compares observations under the same equality
// rules as the live route. A mismatched schema needs separate inventory review.
func verifyLegacyMediaComparison(tx *gorm.DB, family string) error {
	if !common.UsingMainDatabase(common.DatabaseTypeMySQL) {
		return nil
	}
	table, column := "tasks", "task_id"
	if family == LegacyMidjourneyImage {
		table, column = "midjourneys", "mj_id"
	}
	var columns []struct {
		Charset   string
		Collation string
	}
	err := tx.Raw(`SELECT character_set_name AS charset, collation_name AS collation
		FROM information_schema.columns WHERE table_schema = DATABASE()
		AND ((table_name = ? AND column_name = ?) OR
			(table_name = 'legacy_media_route_observations' AND column_name = 'public_id'))`,
		table, column).Scan(&columns).Error
	if err != nil {
		return err
	}
	if len(columns) != 2 || columns[0].Collation == "" || columns[0] != columns[1] {
		return ErrLegacyMediaUnproven
	}
	return nil
}

// lockLegacyMediaSubject checks all global candidates before selecting a
// personal owner. A database collation match alone cannot prove exact identity.
func lockLegacyMediaSubject(tx *gorm.DB, subject LegacyMediaSubject) error {
	switch subject.Family {
	case LegacyMidjourneyImage:
		var rows []Midjourney
		if err := lockForUpdate(tx).Where("mj_id = ?", subject.PublicID).Order("id").Limit(2).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) != 1 || int64(rows[0].Id) != subject.RowID || rows[0].UserId != subject.OwnerID ||
			rows[0].MjId != subject.PublicID || rows[0].SubmitTime != subject.SubmitTime ||
			rows[0].Status != "SUCCESS" || rows[0].ImageUrl == "" ||
			rows[0].Progress != "" && rows[0].Progress != "100%" {
			return ErrLegacyMediaUnproven
		}
	case LegacyTaskArtifactV1:
		var rows []Task
		if err := lockForUpdate(tx).Where("task_id = ?", subject.PublicID).Order("id").Limit(2).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].ID != subject.RowID || rows[0].UserId != subject.OwnerID ||
			rows[0].TaskID != subject.PublicID || rows[0].SubmitTime != subject.SubmitTime ||
			rows[0].OrganizationID != 0 || rows[0].Status != TaskStatusSuccess || !rows[0].ResultRetrievable() {
			return ErrLegacyMediaUnproven
		}
	default:
		return ErrLegacyMediaUnproven
	}
	var count int64
	if err := tx.Model(&User{}).Where("id = ? AND status = ?", subject.OwnerID, common.UserStatusEnabled).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return ErrLegacyMediaUnproven
	}
	return nil
}

func verifyLegacyMediaVersion(tx *gorm.DB, binding LegacyMediaBinding) error {
	if binding.Family == LegacyMidjourneyImage {
		var row MidjourneyImageVersion
		err := lockForUpdate(tx).Where("id = ? AND midjourney_id = ? AND user_id = ? AND version = ?",
			binding.VersionID, binding.RowID, binding.OwnerID, binding.Version).Take(&row).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		sum := sha256.Sum256(row.Data)
		if err != nil || row.MjID != binding.PublicID || row.SubmitTime != binding.SubmitTime ||
			row.Length != binding.ContentLength || row.Length != int64(len(row.Data)) ||
			row.Length <= 0 || row.Length > PersonalMidjourneyImageMaxBytes ||
			row.Digest != binding.ContentDigest || hex.EncodeToString(sum[:]) != row.Digest ||
			(row.MIME != "image/png" && row.MIME != "image/jpeg") {
			return ErrLegacyMediaUnproven
		}
		return nil
	}

	var row PersonalTaskImage
	err := lockForUpdate(tx).Where("id = ? AND task_row_id = ? AND user_id = ? AND version = ?",
		binding.VersionID, binding.RowID, binding.OwnerID, binding.Version).Take(&row).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if err != nil || row.TaskID != binding.PublicID || row.SubmitTime != binding.SubmitTime ||
		row.ArtifactKey != binding.ArtifactKey || row.Length != binding.ContentLength ||
		row.Digest != binding.ContentDigest || row.checkIntegrity() != nil {
		return ErrLegacyMediaUnproven
	}
	return nil
}

// PrepareLegacyMediaSnapshot freezes exactly the supplied inventory batch in
// the main database. It neither enables a migration nor grants legacy access.
func PrepareLegacyMediaSnapshot(ctx context.Context, proposed []LegacyMediaBinding) (string, error) {
	if len(proposed) == 0 {
		return "", ErrLegacyMediaUnproven
	}
	entries := make([]LegacyMediaSnapshotEntry, 0, len(proposed))
	for _, binding := range proposed {
		if !binding.LegacyMediaRoute.valid() || binding.RowID <= 0 || binding.OwnerID <= 0 ||
			binding.SubmitTime <= 0 || binding.VersionID <= 0 || binding.Version <= 0 || binding.ContentLength <= 0 ||
			!validLegacyDigest(binding.ContentDigest) || !validLegacyDigest(binding.EvidenceDigest) {
			return "", ErrLegacyMediaUnproven
		}
		entries = append(entries, LegacyMediaSnapshotEntry{
			RouteDigest: legacySnapshotDigest(binding.LegacyMediaRoute), LegacyMediaBinding: binding,
		})
	}
	slices.SortFunc(entries, func(a, b LegacyMediaSnapshotEntry) int {
		return strings.Compare(a.RouteDigest, b.RouteDigest)
	})
	for i := 1; i < len(entries); i++ {
		if entries[i-1].RouteDigest == entries[i].RouteDigest {
			return "", ErrLegacyMediaUnproven
		}
	}
	id := legacySnapshotDigest(entries)
	rebound := false
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing LegacyMediaSnapshot
		err := tx.First(&existing, "id = ?", id).Error
		if err == nil {
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		checkedFamilies := make(map[string]bool, 2)
		for i := range entries {
			entry := &entries[i]
			if !checkedFamilies[entry.Family] {
				if err := verifyLegacyMediaComparison(tx, entry.Family); err != nil {
					return err
				}
				checkedFamilies[entry.Family] = true
			}
			if err := lockLegacyMediaSubject(tx, entry.LegacyMediaSubject); err != nil {
				return err
			}
			if err := verifyLegacyMediaVersion(tx, entry.LegacyMediaBinding); err != nil {
				return err
			}
			entry.SnapshotID = id
		}
		for _, entry := range entries {
			subjectDigest := legacySnapshotDigest(entry.LegacyMediaSubject)
			var observed []LegacyMediaRouteObservation
			if err := lockForUpdate(legacyRouteObservations(tx, entry.LegacyMediaRoute)).
				Limit(2).Find(&observed).Error; err != nil {
				return err
			}
			if len(observed) == 0 {
				observation := LegacyMediaRouteObservation{RouteDigest: entry.RouteDigest,
					LegacyMediaRoute: entry.LegacyMediaRoute, SubjectDigest: subjectDigest}
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&observation).Error; err != nil {
					return err
				}
				if err := lockForUpdate(legacyRouteObservations(tx, entry.LegacyMediaRoute)).
					Limit(2).Find(&observed).Error; err != nil {
					return err
				}
			}
			if len(observed) != 1 || observed[0].LegacyMediaRoute != entry.LegacyMediaRoute ||
				observed[0].SubjectDigest != subjectDigest || observed[0].Ambiguous {
				rebound = true
				if err := legacyRouteObservations(tx, entry.LegacyMediaRoute).Update("ambiguous", true).Error; err != nil {
					return err
				}
			}
		}
		// Keep the observed ambiguity, but publish no snapshot for this batch.
		if rebound {
			return nil
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&LegacyMediaSnapshot{ID: id}).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(&entries, 50).Error
	})
	if err != nil {
		return "", err
	}
	if rebound {
		return "", ErrLegacyMediaUnproven
	}
	return id, nil
}

func legacySnapshotEntry(tx *gorm.DB, snapshotID string, route LegacyMediaRoute) (*LegacyMediaSnapshotEntry, error) {
	if !validLegacyDigest(snapshotID) || !route.valid() {
		return nil, ErrLegacyMediaUnproven
	}
	var entry LegacyMediaSnapshotEntry
	err := tx.Where("snapshot_id = ? AND route_digest = ?", snapshotID, legacySnapshotDigest(route)).Take(&entry).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if err != nil || entry.LegacyMediaRoute != route {
		return nil, ErrLegacyMediaUnproven
	}
	return &entry, nil
}

// ReadPreparedLegacyMedia checks a preparation snapshot against current primary
// data. It returns binding metadata for verification, never a content response.
func ReadPreparedLegacyMedia(ctx context.Context, snapshotID string, route LegacyMediaRoute) (*LegacyMediaBinding, error) {
	var binding LegacyMediaBinding
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		entry, err := legacySnapshotEntry(tx, snapshotID, route)
		if err != nil {
			return err
		}
		binding = entry.LegacyMediaBinding
		if err := verifyLegacyMediaComparison(tx, route.Family); err != nil {
			return err
		}
		if err := lockLegacyMediaSubject(tx, binding.LegacyMediaSubject); err != nil {
			return err
		}
		if err := verifyLegacyMediaVersion(tx, binding); err != nil {
			return err
		}
		var observed []LegacyMediaRouteObservation
		if err := lockForUpdate(legacyRouteObservations(tx, route)).Limit(2).Find(&observed).Error; err != nil {
			return err
		}
		if len(observed) != 1 || observed[0].Ambiguous || observed[0].LegacyMediaRoute != route ||
			observed[0].SubjectDigest != legacySnapshotDigest(binding.LegacyMediaSubject) {
			return ErrLegacyMediaUnproven
		}
		var revoked LegacyMediaRevocation
		err = lockForUpdate(tx).Take(&revoked, "subject_digest = ?", binding.revocationDigest()).Error
		if err == nil {
			return ErrLegacyMediaRevoked
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &binding, nil
}

// RevokePreparedLegacyMedia saves an irreversible, object- and artifact-level
// revocation. It applies across prepared manifests and is independent of new
// short-lived shares. Existing anonymous routes do not yet consult it.
func RevokePreparedLegacyMedia(ctx context.Context, identity AuthSessionIdentity, snapshotID string, route LegacyMediaRoute) error {
	if _, isAccessToken := ParseAccessTokenSessionID(identity.SessionID); isAccessToken || identity.UserID <= 0 {
		return ErrUserSessionInactive
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
			return err
		}
		entry, err := legacySnapshotEntry(tx, snapshotID, route)
		if err != nil {
			return err
		}
		subject := entry.LegacyMediaSubject
		if subject.OwnerID != identity.UserID {
			return ErrLegacyMediaUnproven
		}
		owned := lockForUpdate(tx).Where("id = ? AND user_id = ?", subject.RowID, identity.UserID)
		// Revocation must work even while the same resource is temporarily
		// unavailable, ambiguous, or lacks retrievable bytes.
		if subject.Family == LegacyMidjourneyImage {
			err = owned.Select("id").Take(&Midjourney{}).Error
		} else {
			err = owned.Where("organization_id = 0").Select("id").Take(&Task{}).Error
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrLegacyMediaUnproven
		}
		if err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&LegacyMediaRevocation{SubjectDigest: subject.revocationDigest(), CreatedAt: time.Now().Unix()}).Error
	})
}
