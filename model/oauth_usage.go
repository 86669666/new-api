package model

import (
	"context"
	"errors"
)

// OAuthUsageMaxInteger bounds every integer published by this numeric protocol.
const OAuthUsageMaxInteger int64 = 1<<53 - 1

var ErrOAuthUsageNumeric = errors.New("unsafe usage integer")

// GetOAuthUsageLogs reads account-attributed records, including token-zero and
// deleted-token history. It does not describe a personal funding ledger.
func GetOAuthUsageLogs(ctx context.Context, userID int, start, end int64, modelName string, offset, limit int) ([]TokenUsageLog, int64, error) {
	if userID <= 0 || start < 0 || end < start || offset < 0 || offset > 100000 || limit < 1 || limit > 100 || len(modelName) > 256 {
		return nil, 0, errors.New("invalid usage query")
	}
	if LOG_DB == nil {
		return nil, 0, errors.New("usage database unavailable")
	}
	items, total, err := queryUsageLogs(LOG_DB.WithContext(ctx).Model(&Log{}).
		Where("user_id = ? AND type = ? AND created_at >= ? AND created_at <= ?", userID, LogTypeConsume, start, end), modelName, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	if total < 0 || total > OAuthUsageMaxInteger {
		return nil, 0, ErrOAuthUsageNumeric
	}
	for _, item := range items {
		for _, value := range []int64{item.CreatedAt, int64(item.PromptTokens), int64(item.CompletionTokens), int64(item.Quota), int64(item.UseTime)} {
			if value < -OAuthUsageMaxInteger || value > OAuthUsageMaxInteger {
				return nil, 0, ErrOAuthUsageNumeric
			}
		}
	}
	return items, total, nil
}

// GetOAuthUsageStat sums persisted source hours. SQL SUM/scan errors are failures,
// never empty data; each selected hour and each daily addition must be JS-safe.
func GetOAuthUsageStat(ctx context.Context, userID int, start, end int64, granularity string) ([]TokenUsageBucket, error) {
	if userID <= 0 || start < 0 || end < start || granularity != "hour" && granularity != "day" {
		return nil, errors.New("invalid usage query")
	}
	if DB == nil {
		return nil, errors.New("usage database unavailable")
	}
	hours := make([]TokenUsageBucket, 0)
	err := DB.WithContext(ctx).Model(&QuotaData{}).
		Select("created_at AS ts, SUM(quota) AS quota, SUM(count) AS requests, SUM(token_used) AS tokens").
		Where("user_id = ? AND created_at >= ? AND created_at <= ?", userID, start-start%3600, end-end%3600).
		Group("created_at").Order("created_at ASC").Scan(&hours).Error
	if err != nil {
		return nil, err
	}
	return FoldOAuthUsageHours(hours, granularity)
}

// FoldOAuthUsageHours preserves signed recorded values and sparse UTC buckets.
// Bounds are checked before addition, so neither int64 wrap nor unsafe numeric
// JSON can be hidden by a later negative correction.
func FoldOAuthUsageHours(hours []TokenUsageBucket, granularity string) ([]TokenUsageBucket, error) {
	if granularity != "hour" && granularity != "day" {
		return nil, errors.New("invalid usage granularity")
	}
	result := make([]TokenUsageBucket, 0, len(hours))
	var previous int64 = -1
	for _, hour := range hours {
		if hour.TS < 0 || hour.TS > OAuthUsageMaxInteger || hour.TS%3600 != 0 || hour.TS <= previous {
			return nil, ErrOAuthUsageNumeric
		}
		previous = hour.TS
		for _, value := range []int64{hour.Quota, hour.Requests, hour.Tokens} {
			if value < -OAuthUsageMaxInteger || value > OAuthUsageMaxInteger {
				return nil, ErrOAuthUsageNumeric
			}
		}
		if granularity == "hour" {
			result = append(result, hour)
			continue
		}
		ts := hour.TS - hour.TS%86400
		if len(result) == 0 || result[len(result)-1].TS != ts {
			result = append(result, TokenUsageBucket{TS: ts})
		}
		day := &result[len(result)-1]
		for _, pair := range [][2]*int64{{&day.Quota, &hour.Quota}, {&day.Requests, &hour.Requests}, {&day.Tokens, &hour.Tokens}} {
			a, b := *pair[0], *pair[1]
			if b > 0 && a > OAuthUsageMaxInteger-b || b < 0 && a < -OAuthUsageMaxInteger-b {
				return nil, ErrOAuthUsageNumeric
			}
			*pair[0] = a + b
		}
	}
	return result, nil
}
