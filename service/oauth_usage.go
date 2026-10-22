package service

import (
	"context"
	"errors"
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"math"
	"slices"
	"time"
)

var (
	ErrUsageLogsDisabled    = errors.New("Usage log collection is disabled.")
	ErrUsageStatUnavailable = errors.New("Usage statistics are unavailable.")
	ErrUsageQueryFailed     = errors.New("Failed to query usage records.")
)

func (a *OAuthUserInfoAccess) RequireUsageScope() error {
	if a == nil || a.resource == nil || !a.resource.grantsRequired || a.credential == "" || a.identity.userID <= 0 || a.identity.grantID == "" {
		return ErrOAuthInvalidToken
	}
	if !slices.Contains(a.identity.scopes, "usage:read") {
		return ErrOAuthInsufficientScope
	}
	return nil
}

// finalizeUsage runs after JSON encoding and before publication. It reuses the
// uncached issuer, active local grant/source SID/current user and cleanup fence
// checks. Neither the bearer nor the privately bound userID escapes this service.
func (a *OAuthUserInfoAccess) finalizeUsage(ctx context.Context, data []byte) ([]byte, error) {
	if err := a.RequireUsageScope(); err != nil {
		return nil, err
	}
	identity, _, err := a.resource.readCurrentIdentity(ctx, a.credential)
	if err != nil {
		return nil, err
	}
	initialScopes, currentScopes := slices.Clone(a.identity.scopes), slices.Clone(identity.scopes)
	slices.Sort(initialScopes)
	slices.Sort(currentScopes)
	if identity.userID != a.identity.userID || identity.authVersion != a.identity.authVersion || identity.issuer != a.identity.issuer || identity.clientID != a.identity.clientID || identity.grantID != a.identity.grantID || identity.grantExpiresAt != a.identity.grantExpiresAt || identity.grantRevision != a.identity.grantRevision || identity.expiresAt != a.identity.expiresAt || identity.notBefore != a.identity.notBefore || !slices.Equal(initialScopes, currentScopes) {
		return nil, ErrOAuthInvalidToken
	}
	if !slices.Contains(identity.scopes, "usage:read") {
		return nil, ErrOAuthInsufficientScope
	}
	now := time.Now().Unix()
	if identity.expiresAt <= now || identity.grantExpiresAt <= now || identity.notBefore > now {
		return nil, ErrOAuthInvalidToken
	}
	if ctx.Err() != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	return data, nil
}

func (a *OAuthUserInfoAccess) PrepareUsageLogs(ctx context.Context, start, end int64, modelName string, page, size int) ([]byte, error) {
	if err := a.RequireUsageScope(); err != nil {
		return nil, err
	}
	if page < 1 || page > 100001 || size < 1 || size > 100 || (page-1)*size > 100000 {
		return nil, ErrUsageQueryFailed
	}
	if !common.LogConsumeEnabled {
		return nil, ErrUsageLogsDisabled
	}
	unit := common.QuotaPerUnit
	if unit <= 0 || math.IsNaN(unit) || math.IsInf(unit, 0) {
		return nil, ErrUsageQueryFailed
	}
	items, total, err := model.GetOAuthUsageLogs(ctx, a.identity.userID, start, end, modelName, (page-1)*size, size)
	if err != nil {
		return nil, ErrUsageQueryFailed
	}
	data, err := common.Marshal(map[string]any{"success": true, "message": "", "data": map[string]any{"items": items, "total": total, "page": page, "page_size": size}, "quota_per_unit": unit, "data_complete": false})
	if err != nil {
		return nil, ErrUsageQueryFailed
	}
	return a.finalizeUsage(ctx, data)
}

func (a *OAuthUserInfoAccess) PrepareUsageStat(ctx context.Context, start, end int64, granularity string) ([]byte, error) {
	if err := a.RequireUsageScope(); err != nil {
		return nil, err
	}
	if !common.LogConsumeEnabled || !common.DataExportEnabled {
		return nil, ErrUsageStatUnavailable
	}
	unit := common.QuotaPerUnit
	if unit <= 0 || math.IsNaN(unit) || math.IsInf(unit, 0) {
		return nil, ErrUsageQueryFailed
	}
	buckets, err := model.GetOAuthUsageStat(ctx, a.identity.userID, start, end, granularity)
	if err != nil {
		return nil, ErrUsageQueryFailed
	}
	data, err := common.Marshal(map[string]any{"success": true, "message": "", "data": buckets, "granularity": granularity, "quota_per_unit": unit, "data_complete": false})
	if err != nil {
		return nil, ErrUsageQueryFailed
	}
	return a.finalizeUsage(ctx, data)
}
