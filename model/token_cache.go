package model

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
)

func getTokenCacheKey(key string) string {
	return fmt.Sprintf("token:%s", common.GenerateHMAC(key))
}

func getTokenCacheFenceKey(key string) string {
	return fmt.Sprintf("token:fence:%s", common.GenerateHMAC(key))
}

func tokenCacheTTLSeconds() int {
	ttl := common.RedisKeyCacheSeconds()
	if ttl <= 0 {
		return 60
	}
	return ttl
}

// tokenCacheFenceSeconds must outlive a token mutation's database write plus
// any in-flight reader's DB-read-to-cache-init gap. The fence is not deleted
// after commit; it expires naturally so a reader holding a pre-mutation
// snapshot cannot publish it right after the mutation cleared the cache.
// While the fence exists readers simply serve the database without caching.
const tokenCacheFenceSeconds = 10

// invalidateTokenCacheForMutation is called before a token metadata mutation
// writes to the database: it raises the fence and drops the cached hash so no
// reader can act on (or re-publish) the pre-mutation state.
func invalidateTokenCacheForMutation(key string) error {
	if !common.RedisEnabled || key == "" {
		return nil
	}
	ctx := context.Background()
	err := common.RDB.Set(ctx, getTokenCacheFenceKey(key), 1, time.Duration(tokenCacheFenceSeconds)*time.Second).Err()
	if err != nil {
		return err
	}
	return common.RDB.Del(ctx, getTokenCacheKey(key)).Err()
}

// cacheInitToken publishes a database snapshot only when no mutation fence is
// active and the hash is cold. An existing hash only gets its TTL refreshed:
// a live low observation may conservatively veto new admission. SQL alone
// owns money; refreshing a projection must not erase that observation.
// 返回值：0=被 fence 拦截，1=完成初始化，2=哈希已存在，仅刷新 TTL。
func cacheInitToken(token Token) (int, error) {
	if !common.RedisEnabled {
		return 0, nil
	}
	allowIps := ""
	if token.AllowIps != nil {
		allowIps = *token.AllowIps
	}
	const script = `
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
if redis.call('EXISTS', KEYS[1]) == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[18])
  return 2
end
redis.call('HSET', KEYS[1],
  'Id', ARGV[1], 'UserId', ARGV[2], 'Status', ARGV[3], 'Name', ARGV[4],
  'CreatedTime', ARGV[5], 'AccessedTime', ARGV[6], 'ExpiredTime', ARGV[7],
  'UnlimitedQuota', ARGV[8], 'ModelLimitsEnabled', ARGV[9], 'ModelLimits', ARGV[10],
  'AllowIps', ARGV[11], 'Group', ARGV[12], 'CrossGroupRetry', ARGV[13],
  'AutoGroups', ARGV[14], 'RemainQuota', ARGV[15], 'UsedQuota', ARGV[16],
  'AllowUserQuotaQuery', ARGV[17])
redis.call('EXPIRE', KEYS[1], ARGV[18])
return 1`

	return common.RDB.Eval(context.Background(), script, []string{
		getTokenCacheKey(token.Key), getTokenCacheFenceKey(token.Key),
	},
		token.Id, token.UserId, token.Status, token.Name,
		token.CreatedTime, token.AccessedTime, token.ExpiredTime,
		strconv.FormatBool(token.UnlimitedQuota), strconv.FormatBool(token.ModelLimitsEnabled),
		token.ModelLimits, allowIps, token.Group, strconv.FormatBool(token.CrossGroupRetry),
		token.AutoGroups, token.RemainQuota, token.UsedQuota,
		strconv.FormatBool(token.AllowUserQuotaQuery),
		tokenCacheTTLSeconds(),
	).Int()
}

// ErrTokenCacheIdentity denotes an observed cache hit contradicting SQL identity.
// It must never be treated as a miss and repaired by admitting this request.
var ErrTokenCacheIdentity = errors.New("token cache identity conflict")
var errTokenCacheUnavailable = errors.New("token cache observation unavailable")

// TokenCacheAdmissionObservation is negative-only, nonpersistent evidence.
// Only a SQL-bound cache read can populate it; the zero value grants nothing.
type TokenCacheAdmissionObservation struct {
	finite    bool
	remaining int
}

func (o TokenCacheAdmissionObservation) Rejects(quota int) bool {
	return quota > 0 && o.finite && o.remaining < quota
}

func (o TokenCacheAdmissionObservation) BlocksTrust(threshold float64) bool {
	return o.finite && float64(o.remaining) <= threshold
}

func validatedTokenCache(key string) (*Token, TokenCacheAdmissionObservation, error) {
	var observation TokenCacheAdmissionObservation
	if !common.RedisEnabled {
		return nil, observation, errTokenCacheUnavailable
	}
	fields, err := common.RDB.HGetAll(context.Background(), getTokenCacheKey(key)).Result()
	if err != nil || len(fields) == 0 {
		return nil, observation, errTokenCacheUnavailable
	}
	id, idErr := strconv.Atoi(fields["Id"])
	owner, ownerErr := strconv.Atoi(fields["UserId"])
	if idErr != nil || ownerErr != nil || id <= 0 || owner <= 0 {
		return nil, observation, ErrTokenCacheIdentity
	}
	var token Token
	if err := DB.Where("id = ?", id).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, observation, ErrTokenCacheIdentity
		}
		return nil, observation, fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	if token.UserId != owner || subtle.ConstantTimeCompare([]byte(token.Key), []byte(key)) != 1 {
		return nil, observation, ErrTokenCacheIdentity
	}
	// Never accept a stored raw key in a mismatched slot, even though normal
	// projections deliberately omit that credential.
	if cachedKey, present := fields["Key"]; present && cachedKey != key {
		return nil, observation, ErrTokenCacheIdentity
	}
	if remaining, err := strconv.Atoi(fields["RemainQuota"]); err == nil && !token.UnlimitedQuota {
		observation = TokenCacheAdmissionObservation{finite: true, remaining: remaining}
	}
	return &token, observation, nil
}

func cacheGetTokenByKey(key string) (*Token, error) {
	token, _, err := validatedTokenCache(key)
	return token, err
}

// ReadTokenCacheAdmissionObservation does not reserve, refund, or publish money.
// Misses/Redis outages contribute no veto. SQL errors and observed identity
// conflicts remain errors, never an invented zero balance or a positive grant.
func ReadTokenCacheAdmissionObservation(tokenID int, key string) (TokenCacheAdmissionObservation, error) {
	token, observation, err := validatedTokenCache(key)
	if errors.Is(err, errTokenCacheUnavailable) {
		return TokenCacheAdmissionObservation{}, nil
	}
	if err != nil {
		return TokenCacheAdmissionObservation{}, err
	}
	if token.Id != tokenID {
		return TokenCacheAdmissionObservation{}, ErrTokenCacheIdentity
	}
	return observation, nil
}
