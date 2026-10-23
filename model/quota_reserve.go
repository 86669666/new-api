package model

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// CheckUserBillingAdmission serializes a new admission with durable unresolved
// obligations. It neither reserves money nor chooses a payer: free requests and
// subscription/organization preferences keep their existing funding semantics.
// Historical settlement and refunds must not call this admission-only check.
func CheckUserBillingAdmission(ctx context.Context, userID int) error {
	if DB == nil {
		return errors.New("wallet database unavailable")
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, userID); err != nil {
			return err
		}
		var user User
		if err := lockForUpdate(tx).Select("id").First(&user, userID).Error; err != nil {
			return err
		}
		if err := oauthTextUnresolved(tx, userID, ""); err != nil {
			return err
		}
		return taskWalletUnresolved(tx, userID, 0)
	})
}

// TryReserveUserQuota admits and reserves against committed SQL money only.
// A missing or unreadable charge store is an error, never evidence of no debt.
// This requires the charge store and old-writer cutover before deployment.
func TryReserveUserQuota(id int, quota int) (bool, error) {
	return reserveUserQuota(id, quota, false)
}

// TryReserveAdditionalUserQuota preserves ordinary pre-send top-up arrears.
// It is still admission: unresolved charges and store errors reject atomically.
func TryReserveAdditionalUserQuota(id int, quota int) (bool, error) {
	return reserveUserQuota(id, quota, true)
}

func reserveUserQuota(id int, quota int, allowArrears bool) (bool, error) {
	if quota < 0 {
		return false, errors.New("quota cannot be negative")
	}
	if err := common.ValidateWalletQuota(quota); err != nil {
		return false, err
	}
	if DB == nil {
		return false, errors.New("wallet database unavailable")
	}
	reserved := false
	err := DB.Transaction(func(tx *gorm.DB) error {
		// Same User-first serialization as derived Reserve/Claim, including
		// SQLite's writer reservation before any snapshot read.
		if err := LockOAuthUser(tx, id); err != nil {
			return err
		}
		var user User
		if err := lockForUpdate(tx).Select("id", "quota").First(&user, id).Error; err != nil {
			return err
		}
		if err := oauthTextUnresolved(tx, id, ""); err != nil {
			return err
		}
		if err := taskWalletUnresolved(tx, id, 0); err != nil {
			return err
		}
		if !allowArrears && user.Quota < quota {
			return nil
		}
		if user.Quota > common.MaxWalletQuota || user.Quota < -common.MaxWalletQuota+quota {
			return ErrWalletQuotaLimitExceeded
		}
		if quota > 0 {
			result := tx.Model(&User{}).Where("id = ?", id).
				UpdateColumn("quota", gorm.Expr("quota - ?", quota))
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return gorm.ErrRecordNotFound
			}
		}
		reserved = true
		return nil
	})
	if err != nil {
		return false, err
	}
	if reserved && quota > 0 {
		if err := cacheDecrUserQuota(id, int64(quota)); err != nil {
			common.SysLog(common.LogText("failed to invalidate user quota projection: %s", err.Error()))
		}
	}
	return reserved, nil
}

// TryReserveTokenQuota atomically checks and deducts a token quota. Unlimited
// tokens skip the balance check but still update remain/used accounting.
func TryReserveTokenQuota(id int, key string, quota int, unlimited bool) (bool, error) {
	if quota < 0 || quota > common.MaxWalletQuota {
		return false, ErrWalletQuotaLimitExceeded
	}
	if quota == 0 {
		var token Token
		err := DB.Where("id = ? AND "+commonKeyCol+" = ?", id, key).First(&token).Error
		return err == nil, err
	}
	// Unlimited is a current SQL fact, never a cache/caller assertion.
	result := DB.Model(&Token{}).Where("id = ? AND "+commonKeyCol+" = ?", id, key).
		Where("unlimited_quota = ? OR remain_quota >= ?", true, quota).
		Where("remain_quota >= ? AND remain_quota <= ? AND used_quota >= ? AND used_quota <= ?", -common.MaxWalletQuota+quota, common.MaxWalletQuota, -common.MaxWalletQuota, common.MaxWalletQuota-quota).
		Updates(map[string]any{"remain_quota": gorm.Expr("remain_quota - ?", quota), "used_quota": gorm.Expr("used_quota + ?", quota), "accessed_time": common.GetTimestamp()})
	if result.Error != nil {
		return false, result.Error
	}
	if result.RowsAffected == 1 {
		_ = invalidateTokenCacheForMutation(key)
		return true, nil
	}
	var existing Token
	if err := DB.Select("id").Where("id = ? AND "+commonKeyCol+" = ?", id, key).First(&existing).Error; err != nil {
		return false, err
	}
	return false, nil
}
