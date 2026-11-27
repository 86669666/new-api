package model

import (
	"context"
	"regexp"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

type oauthTextCancellationApproval struct {
	Action         string `json:"action"`
	DatabaseSeal   string `json:"database_seal"`
	Ref            string `json:"ref"`
	Fingerprint    string `json:"fingerprint"`
	Version        int64  `json:"version"`
	Reserve        int    `json:"reserve"`
	EvidenceDigest string `json:"evidence_sha256"`
	ApprovedBy     string `json:"approved_by"`
	ExecutedBy     string `json:"executed_by"`
}

type oauthTextCancellation struct {
	Ref             string `gorm:"type:char(64);primaryKey" json:"ref"`
	Fingerprint     string `gorm:"type:char(64);not null" json:"fingerprint"`
	OriginalVersion int64  `gorm:"not null" json:"original_version"`
	Returned        int    `gorm:"not null" json:"returned"`
	EvidenceDigest  string `gorm:"type:char(64);not null" json:"evidence_sha256"`
	ApprovedBy      string `gorm:"size:64;not null" json:"approved_by"`
	ExecutedBy      string `gorm:"size:64;not null" json:"executed_by"`
	CreatedAt       int64  `gorm:"not null" json:"created_at"`
}

func (oauthTextCancellation) TableName() string { return "oauth_text_cancellations" }

var oauthTextOperator = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func (a oauthTextCancellationApproval) valid() bool {
	return a.Action == "cancel_reserved" && oauthDerivedDigest(a.DatabaseSeal) &&
		oauthDerivedDigest(a.Ref) && oauthDerivedDigest(a.Fingerprint) && oauthDerivedDigest(a.EvidenceDigest) &&
		a.Version == 1 && a.Reserve > 0 && a.Reserve <= common.MaxQuota &&
		oauthTextOperator.MatchString(a.ApprovedBy) && oauthTextOperator.MatchString(a.ExecutedBy) && a.ApprovedBy != a.ExecutedBy
}

// Cancellation and send recognition share the original payer row as the
// serialization point. Authorization to cancel comes from the offline caller.
func cancelReservedOAuthText(ctx context.Context, db *gorm.DB, a oauthTextCancellationApproval) (*oauthTextCancellation, error) {
	if !a.valid() {
		return nil, ErrOAuthTextCharge
	}
	seed, err := readOAuthDerivedTextCharge(ctx, db, a.Ref)
	if err != nil {
		return nil, err
	}
	if seed.PayerID != seed.UserID || seed.PayerID <= 0 || seed.TokenID <= 0 ||
		seed.Fingerprint != a.Fingerprint || seed.Reserve != a.Reserve {
		return nil, ErrOAuthTextCharge
	}
	proof := oauthTextCancellation{Ref: a.Ref, Fingerprint: a.Fingerprint, OriginalVersion: a.Version,
		Returned: a.Reserve, EvidenceDigest: a.EvidenceDigest, ApprovedBy: a.ApprovedBy, ExecutedBy: a.ExecutedBy}
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, seed.PayerID); err != nil {
			return err
		}
		var user User
		if err := lockForUpdate(tx).First(&user, seed.PayerID).Error; err != nil {
			return err
		}
		var token Token
		if err := lockForUpdate(tx).Unscoped().First(&token, seed.TokenID).Error; err != nil {
			return err
		}
		var charge OAuthDerivedTextCharge
		if err := lockForUpdate(tx).First(&charge, "ref = ?", a.Ref).Error; err != nil {
			return err
		}
		if charge.PayerID != seed.PayerID || charge.UserID != seed.UserID || charge.TokenID != seed.TokenID || charge.GrantRef != seed.GrantRef ||
			charge.Fingerprint != a.Fingerprint || charge.Reserve != a.Reserve || charge.Facts != seed.Facts ||
			charge.QuotaLimit != seed.QuotaLimit || charge.TokenKeyRef != seed.TokenKeyRef ||
			charge.SourceBindingHash != seed.SourceBindingHash || charge.SourceSnapshotHash != seed.SourceSnapshotHash ||
			charge.ClaimAt != 0 || charge.SendDeadline != 0 || charge.Attempt != 0 || charge.Actual != nil || charge.Usage != "" {
			return ErrOAuthTextCharge
		}
		if charge.State == "cancelled" && charge.Version == a.Version+1 &&
			charge.HeldReason == "never_claimed" && charge.Publication == "suppressed" {
			var previous oauthTextCancellation
			if err := tx.First(&previous, "ref = ?", a.Ref).Error; err != nil {
				return err
			}
			proof.CreatedAt = previous.CreatedAt
			if proof != previous {
				return ErrOAuthTextCharge
			}
			return nil
		}
		if charge.State != "reserved" || charge.Version != a.Version || charge.Publication != "pending" ||
			charge.HeldReason != "" || token.UserId != user.Id || token.UnlimitedQuota ||
			OAuthDerivedTokenKeyRef(token.Key) != charge.TokenKeyRef ||
			charge.QuotaLimit < 1 || charge.QuotaLimit > 10_000_000 ||
			token.RemainQuota < 0 || int64(token.RemainQuota) > charge.QuotaLimit ||
			token.UsedQuota < a.Reserve || int64(token.UsedQuota) > charge.QuotaLimit ||
			int64(token.RemainQuota)+int64(token.UsedQuota) != charge.QuotaLimit ||
			user.Quota < 0 || user.Quota > common.MaxWalletQuota-a.Reserve {
			return ErrOAuthTextCharge
		}
		change := tx.Model(&OAuthDerivedTextCharge{}).
			Where("ref = ? AND state = ? AND version = ? AND fingerprint = ?", a.Ref, "reserved", a.Version, a.Fingerprint).
			Updates(map[string]any{"state": "cancelled", "version": a.Version + 1, "held_reason": "never_claimed", "publication": "suppressed"})
		if change.Error != nil || change.RowsAffected != 1 {
			return ErrOAuthTextCharge
		}
		change = tx.Model(&User{}).Where("id = ?", user.Id).UpdateColumn("quota", user.Quota+a.Reserve)
		if change.Error != nil || change.RowsAffected != 1 {
			return ErrOAuthTextCharge
		}
		change = tx.Unscoped().Model(&Token{}).Where("id = ?", token.Id).Updates(map[string]any{
			"remain_quota": token.RemainQuota + a.Reserve, "used_quota": token.UsedQuota - a.Reserve,
		})
		if change.Error != nil || change.RowsAffected != 1 {
			return ErrOAuthTextCharge
		}
		proof.CreatedAt = common.GetTimestamp()
		return tx.Create(&proof).Error
	})
	if err != nil {
		return nil, err
	}
	return &proof, nil
}
