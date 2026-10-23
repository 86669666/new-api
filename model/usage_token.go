package model

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// TokenUsageLog is the public projection shared with read-only API-key clients.
// Keep operational metadata and credentials out of this type and its SELECT.
type TokenUsageLog struct {
	CreatedAt        int64  `json:"created_at"`
	ModelName        string `json:"model_name"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	Quota            int    `json:"quota"`
	UseTime          int    `json:"use_time"`
	IsStream         bool   `json:"is_stream"`
	Group            string `json:"group"`
}

type TokenUsageBucket struct {
	TS       int64 `json:"ts"`
	Quota    int64 `json:"quota"`
	Requests int64 `json:"requests"`
	Tokens   int64 `json:"tokens"`
}

func GetTokenUsageLogs(ctx context.Context, userID, tokenID int, start, end int64, modelName string, offset, limit int) ([]TokenUsageLog, int64, error) {
	if userID <= 0 || tokenID <= 0 {
		return nil, 0, errors.New("invalid token usage owner")
	}
	items, total, err := queryUsageLogs(LOG_DB.WithContext(ctx).Model(&Log{}).
		Where("user_id = ? AND token_id = ? AND type = ? AND created_at >= ? AND created_at <= ?", userID, tokenID, LogTypeConsume, start, end), modelName, offset, limit)
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

// queryUsageLogs shares only the bounded public projection and ordering. Each
// caller must first bind its positive owner and any required token predicate.
func queryUsageLogs(query *gorm.DB, modelName string, offset, limit int) ([]TokenUsageLog, int64, error) {
	items := make([]TokenUsageLog, 0)
	if modelName != "" {
		query = query.Where("model_name = ?", modelName)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if int64(offset) >= total {
		return items, total, nil
	}
	order := "created_at DESC, id DESC"
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		order = clickHouseLogOrder("")
	}
	err := query.Select("created_at", "model_name", "prompt_tokens", "completion_tokens", "quota", "use_time", "is_stream", "group").
		Order(order).Offset(offset).Limit(limit).Scan(&items).Error
	return items, total, err
}

// GetTokenUsageStat selects whole stored UTC hours containing [start,end].
// Daily buckets fold only those hours, without expanding to whole days. Historical
// token_id=0 rows and unflushed cache data cannot safely be assigned to this key.
func GetTokenUsageStat(ctx context.Context, userID, tokenID int, start, end int64, granularity string) ([]TokenUsageBucket, error) {
	if userID <= 0 || tokenID <= 0 {
		return nil, errors.New("invalid token usage owner")
	}
	hours := make([]TokenUsageBucket, 0)
	err := DB.WithContext(ctx).Model(&QuotaData{}).
		Select("created_at AS ts, SUM(quota) AS quota, SUM(count) AS requests, SUM(token_used) AS tokens").
		Where("user_id = ? AND token_id = ? AND created_at >= ? AND created_at <= ?", userID, tokenID, start-start%3600, end-end%3600).
		Group("created_at").Order("created_at ASC").Scan(&hours).Error
	if err != nil {
		return nil, err
	}
	return FoldOAuthUsageHours(hours, granularity)
}
