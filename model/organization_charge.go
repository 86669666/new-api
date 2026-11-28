package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	OrganizationChargeReserved   = "reserved"
	OrganizationChargeDispatched = "dispatched"
	OrganizationChargeSettled    = "settled"
	OrganizationChargeReleased   = "released"
	OrganizationChargeRefunded   = "refunded"
)

var ErrOrganizationChargeFunds = errors.New("Insufficient available organization wallet balance.")

// OrganizationCharge retains the original payment binding and monetary facts.
// The main database is the authority even when the separate log store is down.
type OrganizationCharge struct {
	ID             int64  `gorm:"primaryKey"`
	OrganizationID int64  `gorm:"not null;index"`
	WalletID       int64  `gorm:"not null"`
	ActorUserID    int    `gorm:"not null;uniqueIndex:uq_org_charge_actor_key,priority:1"`
	RequestKeyHash string `gorm:"type:varchar(64);not null;uniqueIndex:uq_org_charge_actor_key,priority:2"`
	BindingHash    string `gorm:"type:varchar(64);not null"`
	PolicyHash     string `gorm:"type:varchar(64);not null"`
	QuotaPerUnit   int64  `gorm:"not null"`
	State          string `gorm:"type:varchar(16);not null"`
	Reserved       int64  `gorm:"not null"`
	Actual         int64  `gorm:"not null"`
	CreatedAt      int64  `gorm:"not null;autoCreateTime:false"`
	DispatchedAt   int64  `gorm:"not null"`
	SettledAt      int64  `gorm:"not null"`
	ReleasedAt     int64  `gorm:"not null"`
	RefundedAt     int64  `gorm:"not null"`
}

type OrganizationChargeRequest struct {
	OrganizationID int64
	RequestKey     string
	PolicyHash     string
	RequestHash    string
	QuotaPerUnit   int64
	Reserve        int64
}

func withOrganizationChargeAdmission(ctx context.Context, actor AuthSessionIdentity, req OrganizationChargeRequest, run func(*organizationState, *OrganizationWallet, *OrganizationCharge) error) error {
	key, err := uuid.Parse(req.RequestKey)
	if err != nil || key == uuid.Nil || key.String() != req.RequestKey || req.Reserve <= 0 || req.Reserve > common.MaxWalletQuota ||
		req.QuotaPerUnit <= 0 || req.Reserve%req.QuotaPerUnit != 0 || len(req.PolicyHash) != 64 || len(req.RequestHash) != 64 {
		return ErrOrganizationInvalidInput
	}
	keyDigest := sha256.Sum256([]byte(req.RequestKey))
	keyHash := hex.EncodeToString(keyDigest[:])
	binding, err := common.Marshal([]any{req.OrganizationID, actor.UserID, actor.SessionID, actor.UserAuthVersion, actor.SessionVersion, keyHash, req.PolicyHash, req.RequestHash, req.QuotaPerUnit, req.Reserve})
	if err != nil {
		return err
	}
	bindingHash := sha256.Sum256(binding)
	return withOrganizationWithContext(ctx, actor, OrganizationCommand{OrganizationID: req.OrganizationID}, false, func(s *organizationState) error {
		if !s.activeUser(actor.UserID) || s.member(actor.UserID) == nil {
			return ErrOrganizationNotFound
		}
		if err := s.requireEnabled(); err != nil {
			return err
		}
		wallet, err := lockOrganizationChargeWallet(s.tx, s.org.ID)
		if err != nil {
			return err
		}
		if _, err := validateOrganizationIdentity(s.tx, actor, organizationNow().Unix()); err != nil {
			return err
		}
		var charge OrganizationCharge
		if err := lockForUpdate(s.tx).Where("actor_user_id = ? AND request_key_hash = ?", actor.UserID, keyHash).Find(&charge).Error; err != nil {
			return err
		}
		hash := hex.EncodeToString(bindingHash[:])
		if charge.ID != 0 && (charge.OrganizationID != s.org.ID || charge.WalletID != wallet.ID || charge.BindingHash != hash || charge.QuotaPerUnit != req.QuotaPerUnit || charge.PolicyHash != req.PolicyHash || charge.Reserved != req.Reserve) {
			return ErrOrganizationIdempotencyConflict
		}
		if charge.ID == 0 {
			charge = OrganizationCharge{OrganizationID: s.org.ID, WalletID: wallet.ID, ActorUserID: actor.UserID,
				RequestKeyHash: keyHash, BindingHash: hash, PolicyHash: req.PolicyHash, QuotaPerUnit: req.QuotaPerUnit, Reserved: req.Reserve}
		}
		return run(s, wallet, &charge)
	})
}

func ReserveOrganizationCharge(ctx context.Context, actor AuthSessionIdentity, req OrganizationChargeRequest) (OrganizationCharge, error) {
	var result OrganizationCharge
	err := withOrganizationChargeAdmission(ctx, actor, req, func(s *organizationState, wallet *OrganizationWallet, charge *OrganizationCharge) error {
		if err := requireStandaloneOrganizationCharge(s.tx, charge.ID); err != nil {
			return err
		}
		if err := reserveOrganizationCharge(s, wallet, charge); err != nil {
			return err
		}
		result = *charge
		return nil
	})
	return result, err
}

func reserveOrganizationCharge(s *organizationState, wallet *OrganizationWallet, charge *OrganizationCharge) error {
	if charge.ID == 0 {
		if wallet.ID == 0 || wallet.Balance-wallet.Reserved < charge.Reserved {
			return ErrOrganizationChargeFunds
		}
		now := organizationNow().Unix()
		if err := writeOrganizationChargeWallet(s.tx, wallet, wallet.Balance, wallet.Reserved+charge.Reserved, now); err != nil {
			return err
		}
		charge.State, charge.CreatedAt = OrganizationChargeReserved, now
		if err := s.tx.Create(charge).Error; err != nil {
			return err
		}
	}
	return nil
}

// DispatchOrganizationCharge returns a one-use permission only after commit.
// A lost/unknown commit cannot produce an upstream call.
func DispatchOrganizationCharge(ctx context.Context, actor AuthSessionIdentity, req OrganizationChargeRequest) (OrganizationCharge, bool, error) {
	var result OrganizationCharge
	var granted bool
	err := withOrganizationChargeAdmission(ctx, actor, req, func(s *organizationState, wallet *OrganizationWallet, charge *OrganizationCharge) error {
		if err := requireStandaloneOrganizationCharge(s.tx, charge.ID); err != nil {
			return err
		}
		var err error
		granted, err = dispatchOrganizationCharge(s.tx, wallet, charge)
		if err != nil {
			return err
		}
		result = *charge
		return nil
	})
	return result, granted && err == nil, err
}

func dispatchOrganizationCharge(tx *gorm.DB, wallet *OrganizationWallet, charge *OrganizationCharge) (bool, error) {
	if charge.ID == 0 {
		return false, ErrOrganizationNotFound
	}
	if charge.State != OrganizationChargeReserved {
		return false, nil
	}
	if wallet.Reserved < charge.Reserved {
		return false, ErrOrganizationConflict
	}
	now := organizationNow().Unix()
	if err := organizationCAS(tx.Model(&OrganizationCharge{}).Where("id = ? AND state = ?", charge.ID, charge.State).
		Updates(map[string]any{"state": OrganizationChargeDispatched, "dispatched_at": now})); err != nil {
		return false, err
	}
	charge.State, charge.DispatchedAt = OrganizationChargeDispatched, now
	return true, nil
}

func lockOrganizationChargeWallet(tx *gorm.DB, orgID int64) (*OrganizationWallet, error) {
	var wallet OrganizationWallet
	if err := lockForUpdate(tx).Where("organization_id = ?", orgID).Find(&wallet).Error; err != nil {
		return nil, err
	}
	if wallet.Balance < 0 || wallet.Balance > common.MaxWalletQuota || wallet.Reserved < 0 || wallet.Reserved > wallet.Balance {
		return nil, ErrOrganizationConflict
	}
	return &wallet, nil
}

func writeOrganizationChargeWallet(tx *gorm.DB, wallet *OrganizationWallet, balance, reserved, now int64) error {
	if balance < 0 || balance > common.MaxWalletQuota || reserved < 0 || reserved > balance {
		return ErrOrganizationConflict
	}
	return organizationCAS(tx.Model(&OrganizationWallet{}).Where("id = ? AND balance = ? AND reserved = ?", wallet.ID, wallet.Balance, wallet.Reserved).
		Updates(map[string]any{"balance": balance, "reserved": reserved, "updated_at": now}))
}

// CancelReservedOrganizationCharge releases only a charge still guaranteed
// unsent. FinishOrganizationCharge is reserved for the trusted execution path.
func CancelReservedOrganizationCharge(ctx context.Context, binding OrganizationCharge) (OrganizationCharge, error) {
	return transitionOrganizationCharge(ctx, binding, OrganizationChargeReserved, OrganizationChargeReleased, 0)
}

func FinishOrganizationCharge(ctx context.Context, binding OrganizationCharge, actual int64, noCharge bool) (OrganizationCharge, error) {
	if noCharge {
		if actual != 0 {
			return OrganizationCharge{}, ErrOrganizationInvalidInput
		}
		return transitionOrganizationCharge(ctx, binding, OrganizationChargeDispatched, OrganizationChargeReleased, 0)
	}
	return transitionOrganizationCharge(ctx, binding, OrganizationChargeDispatched, OrganizationChargeSettled, actual)
}

// RefundSettledOrganizationCharge is an internal full reversal. A settled
// charge can be reversed once; callers have no ability to choose a credit.
func RefundSettledOrganizationCharge(ctx context.Context, binding OrganizationCharge) (OrganizationCharge, error) {
	return transitionOrganizationCharge(ctx, binding, OrganizationChargeSettled, OrganizationChargeRefunded, 0)
}

func transitionOrganizationCharge(ctx context.Context, binding OrganizationCharge, from, to string, actual int64) (OrganizationCharge, error) {
	var result OrganizationCharge
	err := withLockedOrganizationCharge(ctx, binding, func(tx *gorm.DB, org Organization, wallet *OrganizationWallet, charge *OrganizationCharge) error {
		if err := requireStandaloneOrganizationCharge(tx, charge.ID); err != nil {
			return err
		}
		if err := applyOrganizationChargeTransition(tx, org, wallet, charge, from, to, actual); err != nil {
			return err
		}
		result = *charge
		return nil
	})
	return result, err
}

// Task-linked charges must transition only with their task row.
func requireStandaloneOrganizationCharge(tx *gorm.DB, chargeID int64) error {
	if chargeID == 0 {
		return nil
	}
	var count int64
	if err := tx.Model(&Task{}).Where("billing_ref = ?", organizationTaskBillingRef(chargeID)).Count(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return ErrOrganizationConflict
	}
	return nil
}

func withLockedOrganizationCharge(ctx context.Context, binding OrganizationCharge, run func(*gorm.DB, Organization, *OrganizationWallet, *OrganizationCharge) error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if binding.ID <= 0 || binding.OrganizationID <= 0 || binding.WalletID <= 0 || binding.Reserved <= 0 || binding.Reserved > common.MaxWalletQuota {
		return ErrOrganizationInvalidInput
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The primary SQLite writer must take its write lock before any read.
		if common.UsingMainDatabase(common.DatabaseTypeSQLite) {
			if err := tx.Model(&Organization{}).Where("id = ?", binding.OrganizationID).UpdateColumn("revision", gorm.Expr("revision")).Error; err != nil {
				return err
			}
		}
		var org Organization
		if err := lockForUpdate(tx).First(&org, binding.OrganizationID).Error; err != nil {
			return err
		}
		wallet, err := lockOrganizationChargeWallet(tx, org.ID)
		if err != nil {
			return err
		}
		var charge OrganizationCharge
		if err := lockForUpdate(tx).Where("id = ? AND organization_id = ?", binding.ID, org.ID).First(&charge).Error; err != nil {
			return err
		}
		if wallet.ID == 0 || charge.WalletID != wallet.ID || charge.WalletID != binding.WalletID ||
			charge.ActorUserID != binding.ActorUserID || charge.RequestKeyHash != binding.RequestKeyHash || charge.BindingHash != binding.BindingHash || charge.PolicyHash != binding.PolicyHash ||
			charge.QuotaPerUnit != binding.QuotaPerUnit || charge.Reserved != binding.Reserved {
			return ErrOrganizationConflict
		}
		return run(tx, org, wallet, &charge)
	})
}

func applyOrganizationChargeTransition(tx *gorm.DB, org Organization, wallet *OrganizationWallet, charge *OrganizationCharge, from, to string, actual int64) error {
	if actual < 0 || actual > charge.Reserved {
		return ErrOrganizationInvalidInput
	}
	if to == OrganizationChargeSettled && (charge.QuotaPerUnit <= 0 || actual%charge.QuotaPerUnit != 0) {
		return ErrOrganizationInvalidInput
	}
	if charge.State == to || to == OrganizationChargeSettled && charge.State == OrganizationChargeRefunded {
		if to == OrganizationChargeSettled && charge.Actual != actual ||
			to == OrganizationChargeReleased && (from == OrganizationChargeReserved) != (charge.DispatchedAt == 0) {
			return ErrOrganizationConflict
		}
		return nil
	}
	if charge.State != from {
		return ErrOrganizationConflict
	}
	if org.DissolvedAt != 0 {
		return ErrOrganizationTerminal
	}

	now := organizationNow().Unix()
	balance, reserved := wallet.Balance, wallet.Reserved
	updates := map[string]any{"state": to}
	switch to {
	case OrganizationChargeSettled:
		balance, reserved = balance-actual, reserved-charge.Reserved
		charge.Actual, charge.SettledAt = actual, now
		updates["actual"], updates["settled_at"] = actual, now
	case OrganizationChargeReleased:
		reserved -= charge.Reserved
		charge.ReleasedAt, updates["released_at"] = now, now
	case OrganizationChargeRefunded:
		if charge.Actual < 0 || charge.Actual > charge.Reserved || balance > common.MaxWalletQuota-charge.Actual {
			return ErrOrganizationConflict
		}
		balance += charge.Actual
		charge.RefundedAt, updates["refunded_at"] = now, now
	}
	if balance != wallet.Balance || reserved != wallet.Reserved {
		if err := writeOrganizationChargeWallet(tx, wallet, balance, reserved, now); err != nil {
			return err
		}
	}
	if err := organizationCAS(tx.Model(&OrganizationCharge{}).Where("id = ? AND state = ?", charge.ID, from).Updates(updates)); err != nil {
		return err
	}
	charge.State = to
	return nil
}
