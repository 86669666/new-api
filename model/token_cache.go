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

func (token Token) cacheMAC() (string, error) {
	key := getTokenCacheKey(token.Key)
	token.Key = ""
	token.RemainQuota = 0
	token.UsedQuota = 0
	token.AccessedTime = 0
	if token.AllowIps != nil && *token.AllowIps == "" {
		token.AllowIps = nil
	}
	return authCacheMAC(key, struct {
		Token          Token
		AutoGroups     string
		CacheExpiresAt int64
	}{token, token.AutoGroups, token.CacheExpiresAt})
}

func getTokenCacheKey(key string) string {
	return fmt.Sprintf("token:%s", common.GenerateHMAC(key))
}

// The fence uses the cache key as its hash tag so cacheInitToken's script
// reads both keys from one slot on sharded Redis.
func getTokenCacheFenceKey(key string) string {
	return fmt.Sprintf("token:fence:{%s}", getTokenCacheKey(key))
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

func cacheInitToken(token Token) (int, error) {
	if !common.RedisEnabled {
		return 0, nil
	}
	allowIps := ""
	if token.AllowIps != nil {
		allowIps = *token.AllowIps
	}
	cacheKey := getTokenCacheKey(token.Key)
	var existing Token
	readErr := common.RedisHGetObj(cacheKey, &existing)
	if readErr != nil {
		// Decoding stops at the first unreadable field, before CacheMAC.
		existing.CacheMAC, _ = common.RDB.HGet(context.Background(), cacheKey, "CacheMAC").Result()
	}
	existing.Key = token.Key
	existingMAC, macErr := existing.cacheMAC()
	repair := readErr != nil || macErr != nil || !validAuthCacheMAC(existingMAC, existing.CacheMAC, existing.CacheExpiresAt)
	token.CacheExpiresAt = time.Now().Add(time.Duration(tokenCacheTTLSeconds()) * time.Second).UnixMilli()
	mac, err := token.cacheMAC()
	if err != nil {
		return 0, err
	}
	const script = `
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
local exists = redis.call('EXISTS', KEYS[1])
if exists == 1 and (ARGV[21] ~= 'true' or (redis.call('HGET', KEYS[1], 'CacheMAC') or '') ~= ARGV[22]) then
  redis.call('EXPIRE', KEYS[1], ARGV[18])
  return 2
end
redis.call('HDEL', KEYS[1], 'DeletedAt')
redis.call('HSET', KEYS[1],
  'Id', ARGV[1], 'UserId', ARGV[2], 'Status', ARGV[3], 'Name', ARGV[4],
  'CreatedTime', ARGV[5], 'ExpiredTime', ARGV[7],
  'UnlimitedQuota', ARGV[8], 'ModelLimitsEnabled', ARGV[9], 'ModelLimits', ARGV[10],
  'AllowIps', ARGV[11], 'Group', ARGV[12], 'CrossGroupRetry', ARGV[13],
  'AutoGroups', ARGV[14], 'AllowUserQuotaQuery', ARGV[17],
  'CacheExpiresAt', ARGV[19], 'CacheMAC', ARGV[20])
for _, counter in ipairs({{'AccessedTime', ARGV[6]}, {'RemainQuota', ARGV[15]}, {'UsedQuota', ARGV[16]}}) do
  if not string.match(redis.call('HGET', KEYS[1], counter[1]) or '', '^-?%d+$') then
    redis.call('HSET', KEYS[1], counter[1], counter[2])
  end
end
redis.call('EXPIRE', KEYS[1], ARGV[18])
if exists == 1 then
  return 2
end
return 1`

	return common.RDB.Eval(context.Background(), script, []string{
		cacheKey, getTokenCacheFenceKey(token.Key),
	},
		token.Id, token.UserId, token.Status, token.Name,
		token.CreatedTime, token.AccessedTime, token.ExpiredTime,
		strconv.FormatBool(token.UnlimitedQuota), strconv.FormatBool(token.ModelLimitsEnabled),
		token.ModelLimits, allowIps, token.Group, strconv.FormatBool(token.CrossGroupRetry),
		token.AutoGroups, token.RemainQuota, token.UsedQuota,
		strconv.FormatBool(token.AllowUserQuotaQuery),
		tokenCacheTTLSeconds(),
		token.CacheExpiresAt, mac, strconv.FormatBool(repair), existing.CacheMAC,
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

// Exhausted only vetoes strict admission; it never establishes an available balance.
func (o TokenCacheAdmissionObservation) Exhausted() bool {
	return o.finite && o.remaining <= 0
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
	var cached Token
	if err := common.RedisHGetObj(getTokenCacheKey(key), &cached); err != nil {
		return nil, observation, errTokenCacheUnavailable
	}
	if cached.Id != id || cached.UserId != owner || (cached.Key != "" && cached.Key != key) {
		return nil, observation, ErrTokenCacheIdentity
	}
	cached.Key = key
	mac, err := cached.cacheMAC()
	if err != nil || !validAuthCacheMAC(mac, cached.CacheMAC, cached.CacheExpiresAt) {
		return nil, observation, errTokenCacheUnavailable
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
