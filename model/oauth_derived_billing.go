package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

var ErrOAuthTextCharge = errors.New("OAuth derived text charge conflict or unavailable")

// OAuthTextFacts is server-selected input, never an HTTP binding. Ratios retain
// enough facts for the existing legacy text calculator to reproduce the price.
// The shared selected-request producer and raw-usage consumer are not wired yet.
type OAuthTextFacts struct {
	GrantRef        string
	UserID          int
	TokenID         int
	Model           string
	ChannelID       int
	RouteHash       string
	BodyHash        string
	PolicyHash      string
	ModelRatio      float64
	CompletionRatio float64
	GroupRatio      float64
	PromptEstimate  int
	MaxCompletion   int
}

type OAuthDerivedTextCharge struct {
	Ref               string `gorm:"type:char(64);primaryKey"`
	Fingerprint       string `gorm:"type:char(64);not null"`
	GrantRef          string `gorm:"type:char(64);not null"`
	UserID            int    `gorm:"not null;index:idx_oauth_text_user_state,priority:1"`
	TokenID           int    `gorm:"not null"`
	PayerID           int    `gorm:"not null"`
	SourceBindingHash string `gorm:"type:char(64);not null"`
	TokenKeyRef       string `gorm:"type:char(64);not null"`
	QuotaLimit        int64  `gorm:"not null"`
	Facts             string `gorm:"type:text;not null"`
	Reserve           int    `gorm:"not null"`
	Actual            *int
	Usage             string `gorm:"type:text;not null"`
	State             string `gorm:"type:varchar(24);not null;index:idx_oauth_text_user_state,priority:2"`
	Version           int64  `gorm:"not null"`
	Attempt           int    `gorm:"not null"`
	ClaimAt           int64
	HeldReason        string `gorm:"type:varchar(32)"`
	Publication       string `gorm:"type:varchar(24);not null"`
}

// No automatic migration or production issuance registers this candidate.
func (OAuthDerivedTextCharge) TableName() string { return "oauth_derived_text_charges" }

func (f OAuthTextFacts) fingerprint(reserve int) (string, string, error) {
	if !oauthDerivedDigest(f.GrantRef) || f.UserID <= 0 || f.TokenID <= 0 || f.ChannelID <= 0 || f.Model == "" || len(f.Model) > 256 || !oauthDerivedDigest(f.RouteHash) || !oauthDerivedDigest(f.BodyHash) || !oauthDerivedDigest(f.PolicyHash) || reserve < 0 || reserve > common.MaxQuota || f.PromptEstimate <= 0 || f.PromptEstimate > common.MaxQuota || f.MaxCompletion <= 0 || f.MaxCompletion > common.MaxQuota {
		return "", "", ErrOAuthTextCharge
	}
	for _, v := range []float64{f.ModelRatio, f.CompletionRatio, f.GroupRatio} {
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return "", "", ErrOAuthTextCharge
		}
	}
	b, err := common.Marshal(f)
	if err != nil {
		return "", "", err
	}
	payload, err := common.Marshal(struct {
		Facts   OAuthTextFacts
		Reserve int
	}{f, reserve})
	if err != nil {
		return "", "", err
	}
	h := sha256.Sum256(payload)
	return string(b), hex.EncodeToString(h[:]), nil
}

// withOAuthTextAdmission reuses the complete current User/session/grant/cleanup
// prefix. Source, finite Token and charge operations all use that same tx.
func withOAuthTextAdmission(ctx context.Context, f OAuthTextFacts, action func(*gorm.DB, *User, *Token, *OAuthDerivedTokenSource) error) error {
	return withCurrentOAuthGrant(ctx, f.GrantRef, f.UserID, func(tx *gorm.DB, u *User, _ *UserSession, g *OAuthGrant) error {
		now := time.Now().Unix()
		if g.State != "active" {
			return ErrOAuthTextCharge
		}
		if err := validateOAuthDerivedTokenStore(tx, now); err != nil {
			return err
		}
		var source OAuthDerivedTokenSource
		if err := lockForUpdate(tx).Where("grant_ref = ?", f.GrantRef).First(&source).Error; err != nil {
			return err
		}
		var token Token
		if err := lockForUpdate(tx).First(&token, f.TokenID).Error; err != nil {
			return err
		}
		if err := validateOAuthDerivedTokenBinding(&source, g, &token, now); err != nil {
			return err
		}
		if source.TerminalAt != nil || source.ExpiresAt <= now || token.ExpiredTime <= now || token.Status != common.TokenStatusEnabled || source.PolicyHash != f.PolicyHash {
			return ErrOAuthTextCharge
		}
		return action(tx, u, &token, &source)
	})
}

func oauthTextUnresolved(tx *gorm.DB, userID int, except string) error {
	var n int64
	if err := tx.Model(&OAuthDerivedTextCharge{}).Where("user_id = ? AND ref <> ? AND state IN ?", userID, except, []string{"send_claimed", "held"}).Count(&n).Error; err != nil {
		return err
	}
	if n != 0 {
		return ErrOAuthTextCharge
	}
	return nil
}

// ReserveOAuthDerivedText is a domain boundary, not production permission. Its
// only service producer is closed until the shared SQL writer cutover is proven.
func ReserveOAuthDerivedText(ctx context.Context, ref string, f OAuthTextFacts, reserve int) (*OAuthDerivedTextCharge, error) {
	facts, fp, err := f.fingerprint(reserve)
	if err != nil || !oauthDerivedDigest(ref) {
		return nil, ErrOAuthTextCharge
	}
	var out OAuthDerivedTextCharge
	err = withOAuthTextAdmission(ctx, f, func(tx *gorm.DB, u *User, t *Token, source *OAuthDerivedTokenSource) error {
		err := lockForUpdate(tx).Where("ref = ?", ref).First(&out).Error
		if err == nil {
			if out.Fingerprint != fp {
				return ErrOAuthTextCharge
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := oauthTextUnresolved(tx, u.Id, ref); err != nil {
			return err
		}
		if u.Quota < reserve || u.Quota > common.MaxWalletQuota || t.RemainQuota < reserve || t.UsedQuota > common.MaxWalletQuota-reserve {
			return ErrOAuthTextCharge
		}
		if err := tx.Model(&User{}).Where("id = ?", u.Id).UpdateColumn("quota", u.Quota-reserve).Error; err != nil {
			return err
		}
		if err := tx.Model(&Token{}).Where("id = ?", t.Id).Updates(map[string]any{"remain_quota": t.RemainQuota - reserve, "used_quota": t.UsedQuota + reserve}).Error; err != nil {
			return err
		}
		out = OAuthDerivedTextCharge{Ref: ref, Fingerprint: fp, GrantRef: f.GrantRef, UserID: u.Id, PayerID: u.Id, TokenID: t.Id, SourceBindingHash: source.BindingHash, TokenKeyRef: *source.KeyRef, QuotaLimit: source.QuotaLimit, Facts: facts, Reserve: reserve, State: "reserved", Version: 1, Publication: "pending"}
		return tx.Create(&out).Error
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Claim returns true only for the committed transition winner. It does not
// promise network atomicity; a lost acknowledgement must never be resent.
func ClaimOAuthDerivedText(ctx context.Context, ref string, f OAuthTextFacts, reserve int) (bool, error) {
	_, fp, err := f.fingerprint(reserve)
	if err != nil {
		return false, err
	}
	won := false
	err = withOAuthTextAdmission(ctx, f, func(tx *gorm.DB, u *User, _ *Token, _ *OAuthDerivedTokenSource) error {
		if err := oauthTextUnresolved(tx, u.Id, ref); err != nil {
			return err
		}
		var c OAuthDerivedTextCharge
		if err := lockForUpdate(tx).Where("ref = ?", ref).First(&c).Error; err != nil {
			return err
		}
		if c.Fingerprint != fp {
			return ErrOAuthTextCharge
		}
		if c.State != "reserved" {
			return nil
		}
		result := tx.Model(&OAuthDerivedTextCharge{}).Where("ref = ? AND state = ? AND version = ?", ref, "reserved", c.Version).Updates(map[string]any{"state": "send_claimed", "claim_at": time.Now().Unix(), "version": c.Version + 1})
		won = result.RowsAffected == 1
		return result.Error
	})
	return won && err == nil, err
}

type OAuthTextUsage struct {
	Prompt     int
	Completion int
	Total      int
}

// Finalize requires bounded raw usage and an amount from the existing legacy
// calculator using persisted Facts. It never estimates missing usage or chooses
// a new payer, and deliberately does not require a currently active grant.
func FinalizeOAuthDerivedText(ctx context.Context, ref string, actual int, usage OAuthTextUsage) (*OAuthDerivedTextCharge, error) {
	if DB == nil || !oauthDerivedDigest(ref) || actual < 0 || actual > common.MaxQuota || usage.Prompt <= 0 || usage.Completion < 0 || usage.Prompt > common.MaxQuota || usage.Completion > common.MaxQuota-usage.Prompt || usage.Total != usage.Prompt+usage.Completion {
		return nil, ErrOAuthTextCharge
	}
	b, err := common.Marshal(usage)
	if err != nil {
		return nil, err
	}
	var seed OAuthDerivedTextCharge
	if err := DB.WithContext(ctx).Where("ref = ?", ref).First(&seed).Error; err != nil {
		return nil, err
	}
	var out OAuthDerivedTextCharge
	err = DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if common.UsingMainDatabase(common.DatabaseTypeSQLite) {
			if err := tx.Model(&User{}).Where("id = ?", seed.PayerID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
				return err
			}
		}
		var u User
		ue := lockForUpdate(tx).First(&u, seed.PayerID).Error
		if ue != nil && !errors.Is(ue, gorm.ErrRecordNotFound) {
			return ue
		}
		var t Token
		te := lockForUpdate(tx).Unscoped().First(&t, seed.TokenID).Error
		if te != nil && !errors.Is(te, gorm.ErrRecordNotFound) {
			return te
		}
		if err := lockForUpdate(tx).Where("ref = ?", ref).First(&out).Error; err != nil {
			return err
		}
		if out.PayerID != seed.PayerID || out.TokenID != seed.TokenID || out.PayerID != out.UserID {
			return ErrOAuthTextCharge
		}
		if out.Actual != nil {
			if *out.Actual != actual || out.Usage != string(b) {
				return ErrOAuthTextCharge
			}
			return nil
		}
		if out.State != "send_claimed" || out.Reserve < 0 || out.Reserve > common.MaxQuota {
			return ErrOAuthTextCharge
		}
		delta := actual - out.Reserve
		reason := ""
		switch {
		case ue != nil || te != nil || t.UserId != out.UserID:
			reason = "payer_or_token_missing"
		case t.UnlimitedQuota || OAuthDerivedTokenKeyRef(t.Key) != out.TokenKeyRef || out.QuotaLimit < 1 || out.QuotaLimit > 10000000 || int64(t.RemainQuota) > out.QuotaLimit || int64(t.UsedQuota) > out.QuotaLimit || int64(t.RemainQuota)+int64(t.UsedQuota) != out.QuotaLimit:
			reason = "token_binding_changed"
		case u.Quota < 0 || u.Quota > common.MaxWalletQuota || t.UsedQuota < out.Reserve || t.RemainQuota < 0:
			reason = "balance_invalid"
		case delta > 0 && (u.Quota < delta || t.RemainQuota < delta || t.UsedQuota > common.MaxWalletQuota-delta):
			reason = "insufficient_delta"
		case delta < 0 && (u.Quota > common.MaxWalletQuota+delta || t.RemainQuota > common.MaxWalletQuota+delta):
			reason = "refund_capacity"
		}
		out.Actual = &actual
		out.Usage = string(b)
		out.Version++
		out.HeldReason = reason
		if reason != "" {
			out.State = "held"
		} else {
			if err := tx.Model(&User{}).Where("id = ?", out.PayerID).UpdateColumn("quota", u.Quota-delta).Error; err != nil {
				return err
			}
			if err := tx.Unscoped().Model(&Token{}).Where("id = ?", out.TokenID).Updates(map[string]any{"remain_quota": t.RemainQuota - delta, "used_quota": t.UsedQuota + delta}).Error; err != nil {
				return err
			}
			out.State = "settled"
			if actual == 0 {
				out.State = "refunded"
			}
		}
		return tx.Save(&out).Error
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}
