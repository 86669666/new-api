package model

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
)

var (
	ErrOrganizationWalletRequestConflict = errors.New("This wallet request ID was already used with different details.")
	ErrOrganizationWalletAlreadyReversed = errors.New("This wallet credit was already reversed.")
	ErrOrganizationWalletInsufficient    = errors.New("The organization wallet has insufficient available quota for this reversal.")
	ErrOrganizationWalletLimit           = errors.New("The organization wallet quota limit would be exceeded.")
	ErrOrganizationWalletNotEmpty        = errors.New("Empty the organization wallet and release all reserved quota before dissolving the organization.")
)

// Balance includes Reserved. No reservation or consumption writer is enabled.
type OrganizationWallet struct {
	ID             int64 `gorm:"primaryKey"`
	OrganizationID int64 `gorm:"not null;uniqueIndex:uq_org_wallet"`
	Balance        int64 `gorm:"not null"`
	Reserved       int64 `gorm:"not null"`
	CreatedAt      int64 `gorm:"not null;autoCreateTime:false"`
	UpdatedAt      int64 `gorm:"not null;autoUpdateTime:false"`
}

// Entries are append-only. NULL on credits permits multiple credits while the
// unique reversal target allows exactly one full reversal of each credit.
type OrganizationWalletEntry struct {
	ID                   int64  `gorm:"primaryKey"`
	OrganizationID       int64  `gorm:"not null;uniqueIndex:uq_org_wallet_request,priority:1"`
	RequestID            string `gorm:"type:varchar(36);not null;uniqueIndex:uq_org_wallet_request,priority:2"`
	Kind                 string `gorm:"type:varchar(16);not null"`
	Amount               int64  `gorm:"not null"`
	ReversalOfID         *int64 `gorm:"uniqueIndex:uq_org_wallet_reversal"`
	ActorUserID          int    `gorm:"not null"`
	OrganizationRevision int64  `gorm:"not null"`
	Reference            string `gorm:"type:varchar(128);not null"`
	Reason               string `gorm:"type:varchar(128);not null"`
	BalanceAfter         int64  `gorm:"not null"`
	CreatedAt            int64  `gorm:"not null;autoCreateTime:false"`
}

func validateOrganizationWalletCommand(action string, c OrganizationCommand) error {
	if len(c.WalletRequestID) != 36 {
		return ErrOrganizationInvalidInput
	}
	for index, value := range c.WalletRequestID {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value != '-' {
				return ErrOrganizationInvalidInput
			}
		} else if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return ErrOrganizationInvalidInput
		}
	}
	for _, value := range []string{c.Reason, c.WalletReference} {
		if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 || strings.TrimSpace(value) != value {
			return ErrOrganizationInvalidInput
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return ErrOrganizationInvalidInput
			}
		}
	}
	if c.Reason == "" || action == "wallet_credit" && (c.WalletAmount <= 0 || c.WalletAmount > common.MaxWalletQuota || c.WalletReference == "" || c.WalletCreditID != 0) ||
		action == "wallet_reverse" && (c.WalletCreditID <= 0 || c.WalletAmount != 0 || c.WalletReference != "") {
		return ErrOrganizationInvalidInput
	}
	return nil
}

func mutateOrganizationWallet(identity AuthSessionIdentity, c OrganizationCommand, action string, op *organizationExecution) error {
	if err := validateOrganizationCommand(action, c); err != nil {
		return err
	}
	return withOrganization(identity, c, true, func(s *organizationState) error {
		if s.users[identity.UserID].Role != common.RoleRootUser {
			return ErrOrganizationForbidden
		}
		if s.org.DissolvedAt != 0 {
			return ErrOrganizationTerminal
		}
		if action == "wallet_credit" {
			if err := s.requireEnabled(); err != nil {
				return err
			}
		}
		var wallet OrganizationWallet
		if err := lockForUpdate(s.tx).Where("organization_id = ?", s.org.ID).Find(&wallet).Error; err != nil {
			return err
		}
		// The wallet may have waited on another transaction after the org locks.
		s.now = organizationNow().Unix()
		var err error
		s.session, err = validateOrganizationIdentity(s.tx, identity, s.now)
		if err != nil {
			return err
		}
		var entry OrganizationWalletEntry
		if err := s.tx.Where("organization_id = ? AND request_id = ?", s.org.ID, c.WalletRequestID).Find(&entry).Error; err != nil {
			return err
		}
		existing := entry.ID != 0
		kind := strings.TrimPrefix(action, "wallet_")
		if existing {
			creditID := int64(0)
			if entry.ReversalOfID != nil {
				creditID = *entry.ReversalOfID
			}
			if entry.Kind != kind || entry.Reason != c.Reason || entry.Reference != c.WalletReference || creditID != c.WalletCreditID || action == "wallet_credit" && entry.Amount != c.WalletAmount {
				return ErrOrganizationWalletRequestConflict
			}
		} else {
			if wallet.Balance < 0 || wallet.Reserved < 0 || wallet.Reserved > wallet.Balance || wallet.Balance > common.MaxWalletQuota {
				return ErrOrganizationConflict
			}
			entry = OrganizationWalletEntry{OrganizationID: s.org.ID, RequestID: c.WalletRequestID, Kind: kind, Amount: c.WalletAmount,
				ActorUserID: identity.UserID, OrganizationRevision: s.org.Revision, Reference: c.WalletReference, Reason: c.Reason, CreatedAt: s.now}
			if action == "wallet_credit" {
				if wallet.Balance > common.MaxWalletQuota-c.WalletAmount {
					return ErrOrganizationWalletLimit
				}
				entry.BalanceAfter = wallet.Balance + c.WalletAmount
			} else {
				var credit OrganizationWalletEntry
				if err := s.tx.Where("id = ? AND organization_id = ? AND kind = ?", c.WalletCreditID, s.org.ID, "credit").Find(&credit).Error; err != nil {
					return err
				}
				if credit.ID == 0 {
					return ErrOrganizationNotFound
				}
				var reversed int64
				if err := s.tx.Model(&OrganizationWalletEntry{}).Where("reversal_of_id = ?", credit.ID).Count(&reversed).Error; err != nil {
					return err
				}
				if reversed != 0 {
					return ErrOrganizationWalletAlreadyReversed
				}
				if credit.Amount <= 0 || credit.Amount > common.MaxWalletQuota || wallet.Balance-wallet.Reserved < credit.Amount {
					return ErrOrganizationWalletInsufficient
				}
				entry.Amount = credit.Amount
				entry.ReversalOfID = &credit.ID
				entry.BalanceAfter = wallet.Balance - credit.Amount
			}
		}
		binding := s.binding(c)
		binding.WalletAmount = entry.Amount // Reverse proof binds the immutable original credit amount.
		if err := s.authorize(action, c, binding); err != nil {
			return err
		}
		if op.preview {
			// Unlike lifecycle mutations, wallet writes do not call advance.
			// Roll back even the SQLite actor reservation and never open a wallet.
			return errOrganizationPreviewComplete
		}
		if !existing {
			if wallet.ID == 0 {
				wallet = OrganizationWallet{OrganizationID: s.org.ID, CreatedAt: s.now, UpdatedAt: s.now}
				if err := s.tx.Create(&wallet).Error; err != nil {
					return err
				}
			}
			if err := organizationCAS(s.tx.Model(&OrganizationWallet{}).Where("id = ? AND balance = ? AND reserved = ?", wallet.ID, wallet.Balance, wallet.Reserved).
				Updates(map[string]any{"balance": entry.BalanceAfter, "updated_at": s.now})); err != nil {
				return err
			}
			if err := s.tx.Create(&entry).Error; err != nil {
				return err
			}
			if err := s.event("organization."+action, 0, "wallet_entry", entry.ID, 0, "", kind, action, "", 0); err != nil {
				return err
			}
		}
		*op.receipt = OrganizationMutationReceipt{OrganizationID: entry.OrganizationID, Revision: entry.OrganizationRevision,
			Action: action, ObjectKind: "wallet_entry", ObjectID: entry.ID, WalletEntry: &entry}
		return nil
	}, op)
}

// Wallet reads have a narrow financial recovery policy: current governance
// members may read while disabled; only platform root may read after dissolution.
func ReadOrganizationWalletWithContext(ctx context.Context, identity AuthSessionIdentity, orgID int64, platform bool) (*OrganizationWallet, error) {
	var wallet OrganizationWallet
	err := withOrganizationWithContext(ctx, identity, OrganizationCommand{OrganizationID: orgID}, false, func(s *organizationState) error {
		if platform {
			if s.users[identity.UserID].Role != common.RoleRootUser {
				return ErrOrganizationForbidden
			}
		} else if role := s.role(identity.UserID); s.org.DissolvedAt != 0 || role != OrganizationRoleOwner && role != OrganizationRoleAdmin {
			return ErrOrganizationNotFound
		}
		if err := s.tx.Where("organization_id = ?", orgID).Find(&wallet).Error; err != nil {
			return err
		}
		if wallet.Balance < 0 || wallet.Reserved < 0 || wallet.Reserved > wallet.Balance || wallet.Balance > common.MaxWalletQuota {
			return ErrOrganizationConflict
		}
		_, err := validateOrganizationIdentity(s.tx, identity, organizationNow().Unix())
		return err
	})
	if err != nil {
		return nil, err
	}
	wallet.OrganizationID = orgID
	return &wallet, nil
}
