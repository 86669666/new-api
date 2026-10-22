package model

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	ErrClientEventUnauthorized = errors.New("client event credential rejected")
	ErrClientEventForbidden    = errors.New("client event access denied")
)

// ClientEvent is an authenticated client self-report, never a billing record.
// ReceivedAt bounds retention; removing a row also removes its deduplication key.
type ClientEvent struct {
	ID           int64 `gorm:"primaryKey"`
	UserID       int   `gorm:"index"`
	TokenID      int
	ClientID     string `gorm:"type:varchar(36)"`
	Channel      string `gorm:"type:varchar(64)"`
	EventType    string `gorm:"type:varchar(16)"`
	EventTimeMS  int64
	ReceivedAt   int64  `gorm:"index"`
	Fingerprint  string `gorm:"type:char(64);uniqueIndex"`
	AppVersion   string `gorm:"type:varchar(32)"`
	OS           string `gorm:"type:varchar(16)"`
	Provider     string `gorm:"type:varchar(128)"`
	Model        string `gorm:"type:varchar(255)"`
	Source       string `gorm:"type:varchar(8)"`
	InputTokens  *int64
	OutputTokens *int64
}

// Unexported fields keep the exact key request-local and nonserializable.
type ClientEventCredential struct {
	userID  int
	tokenID int
	key     string
}

func (c ClientEventCredential) TokenID() int { return c.tokenID }

func checkClientEventAuthority(user User, token Token, key, ip string, now int64) error {
	if token.Key != key || token.UserId != user.Id || token.DeletedAt.Valid ||
		(token.Status != common.TokenStatusEnabled && token.Status != common.TokenStatusExhausted) ||
		(token.ExpiredTime != -1 && token.ExpiredTime <= now) {
		return ErrClientEventUnauthorized
	}
	if user.DeletedAt.Valid || user.Status != common.UserStatusEnabled {
		return ErrClientEventForbidden
	}
	if allowed := token.GetIpLimits(); len(allowed) > 0 {
		address := net.ParseIP(ip)
		if address == nil || !common.IsIpInCIDRList(address, allowed) {
			return ErrClientEventForbidden
		}
	}
	return nil
}

// AuthenticateClientEvent bypasses caches and suppresses credential SQL traces.
// This preliminary observation authorizes the limiter, not the eventual write.
func AuthenticateClientEvent(ctx context.Context, key, ip string) (ClientEventCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db := DB.WithContext(ctx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})
	var token Token
	err := db.Select("id", "user_id", "key", "status", "expired_time", "allow_ips").Where(commonKeyCol+" = ?", key).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ClientEventCredential{}, ErrClientEventUnauthorized
	}
	if err != nil {
		return ClientEventCredential{}, err
	}
	// SQL collations may consider a case/accent/padding variant equal.
	if token.Key != key {
		return ClientEventCredential{}, ErrClientEventUnauthorized
	}
	var user User
	err = db.Select("id", "status").First(&user, token.UserId).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ClientEventCredential{}, ErrClientEventForbidden
	}
	if err != nil {
		return ClientEventCredential{}, err
	}
	if err := checkClientEventAuthority(user, token, key, ip, time.Now().Unix()); err != nil {
		return ClientEventCredential{}, err
	}
	return ClientEventCredential{userID: user.Id, tokenID: token.Id, key: key}, nil
}

func ReceiveClientEvents(ctx context.Context, credential ClientEventCredential, ip string, events []ClientEvent) (int, error) {
	if credential.userID <= 0 || credential.tokenID <= 0 || credential.key == "" || len(events) > 10 {
		return 0, ErrClientEventUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	count := 0
	err := DB.WithContext(ctx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Transaction(func(tx *gorm.DB) error {
		// SQLite must reserve its writer before any transactional read.
		if tx.Dialector.Name() == "sqlite" {
			if err := tx.Model(&User{}).Where("id = ?", credential.userID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
				return err
			}
		}
		var user User
		if err := lockForUpdate(tx).Select("id", "status").First(&user, credential.userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrClientEventForbidden
			}
			return err
		}
		var token Token
		if err := lockForUpdate(tx).Select("id", "user_id", "key", "status", "expired_time", "allow_ips").First(&token, credential.tokenID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrClientEventUnauthorized
			}
			return err
		}
		if err := checkClientEventAuthority(user, token, credential.key, ip, time.Now().Unix()); err != nil {
			return err
		}
		unique := make(map[string]ClientEvent, len(events))
		fingerprints := make([]string, 0, len(events))
		for _, event := range events {
			event.UserID, event.TokenID, event.ID = user.Id, token.Id, 0
			// Token rotation, receive time and unknown fields do not split identity.
			encoded, err := common.Marshal([]any{"client-event-v1", user.Id, event.ClientID, event.Channel, event.EventType,
				event.EventTimeMS, event.AppVersion, event.OS, event.Provider, event.Model, event.Source, event.InputTokens, event.OutputTokens})
			if err != nil {
				return err
			}
			event.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(encoded))
			if _, exists := unique[event.Fingerprint]; !exists {
				fingerprints = append(fingerprints, event.Fingerprint)
				unique[event.Fingerprint] = event
			}
		}
		// First ordinary consistent read is after the owner lock, including on
		// MySQL RR. The owner serializes other tokens belonging to this user.
		existing := []string{}
		if len(fingerprints) > 0 {
			if err := tx.Model(&ClientEvent{}).Where("user_id = ? AND fingerprint IN ?", user.Id, fingerprints).Pluck("fingerprint", &existing).Error; err != nil {
				return err
			}
		}
		for _, fingerprint := range existing {
			delete(unique, fingerprint)
		}
		for _, fingerprint := range fingerprints {
			if event, ok := unique[fingerprint]; ok {
				if err := tx.Create(&event).Error; err != nil {
					return err
				}
				count++
			}
		}
		// Inserts can wait too. An expired admission must roll back, not return200.
		return checkClientEventAuthority(user, token, credential.key, ip, time.Now().Unix())
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// DeleteClientEventBatch rechecks the cutoff at deletion, without DELETE LIMIT.
func DeleteClientEventBatch(ctx context.Context, before int64) (int64, error) {
	ids := []int64{}
	if err := DB.WithContext(ctx).Model(&ClientEvent{}).Where("received_at < ?", before).Order("id").Limit(1000).Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result := DB.WithContext(ctx).Where("id IN ? AND received_at < ?", ids, before).Delete(&ClientEvent{})
	return result.RowsAffected, result.Error
}

// ClientEventStatsQuery describes the two fixed, retained self-report views.
// String comparisons are deliberately performed in Go, independent of SQL collation.
type ClientEventStatsQuery struct {
	Kind      string  `json:"kind"`
	StartTime int64   `json:"start_time"`
	EndTime   int64   `json:"end_time"`
	Channel   string  `json:"channel"`
	Model     string  `json:"model"`
	Provider  string  `json:"provider"`
	Source    string  `json:"source"`
	Version   *string `json:"version"`
	OS        string  `json:"os"`
}

type ClientEventUsageStats struct {
	Day                 string  `json:"day"`
	Model               string  `json:"model"`
	Provider            string  `json:"provider"`
	Source              string  `json:"source"`
	Events              int     `json:"events"`
	InputTokens         *string `json:"input_tokens"`
	OutputTokens        *string `json:"output_tokens"`
	InputMissingEvents  int     `json:"input_missing_events"`
	OutputMissingEvents int     `json:"output_missing_events"`
	CounterDataComplete bool    `json:"counter_data_complete"`
}

type ClientEventClientStats struct {
	Version       string `json:"version"`
	OS            string `json:"os"`
	ActiveClients int    `json:"active_clients"`
}

type ClientEventStats struct {
	Usage   []ClientEventUsageStats
	Clients []ClientEventClientStats
}

var (
	ErrClientEventQueryTooLarge  = errors.New("client event query exceeds bounded input or groups")
	ErrClientEventCounterInvalid = errors.New("invalid stored client event counter")
)

// QueryClientEventStats reads one bounded statement's visible set. LIMIT is a
// candidate bound, not a promise about physical I/O or a cross-page snapshot.
func QueryClientEventStats(ctx context.Context, query ClientEventStatsQuery) (ClientEventStats, error) {
	result := ClientEventStats{Usage: []ClientEventUsageStats{}, Clients: []ClientEventClientStats{}}
	if query.Kind != "usage" && query.Kind != "clients" || query.StartTime < 0 || query.EndTime <= query.StartTime || query.EndTime > math.MaxInt64/1000 || query.EndTime-query.StartTime > 31*86400 {
		return result, errors.New("invalid client event query window")
	}
	var rows []ClientEvent
	err := DB.WithContext(ctx).Model(&ClientEvent{}).
		Select("user_id", "client_id", "channel", "event_type", "event_time_ms", "received_at", "app_version", "os", "provider", "model", "source", "input_tokens", "output_tokens").
		Where("received_at >= ? AND received_at < ?", max(int64(0), query.StartTime-3600), query.EndTime+7*86400).
		Order("received_at ASC").Limit(50001).Find(&rows).Error
	if err != nil {
		return result, err
	}
	if len(rows) > 50000 {
		return result, ErrClientEventQueryTooLarge
	}
	type usageKey struct{ day, model, provider, source string }
	type usageSum struct {
		item          ClientEventUsageStats
		input, output big.Int
	}
	type clientKey struct{ version, os string }
	type clientIdentity struct {
		userID            int
		channel, clientID string
	}
	usage := make(map[usageKey]*usageSum)
	clients := make(map[clientKey]map[clientIdentity]struct{})
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if row.EventTimeMS < query.StartTime*1000 || row.EventTimeMS >= query.EndTime*1000 || query.Channel != "" && row.Channel != query.Channel {
			continue
		}
		if query.Kind == "usage" {
			if row.EventType != "token_usage" || query.Model != "" && row.Model != query.Model || query.Provider != "" && row.Provider != query.Provider || query.Source != "" && row.Source != query.Source {
				continue
			}
			for _, n := range []*int64{row.InputTokens, row.OutputTokens} {
				if n != nil && (*n < 0 || *n > 9007199254740991) {
					return result, ErrClientEventCounterInvalid
				}
			}
			key := usageKey{time.UnixMilli(row.EventTimeMS).UTC().Format("2006-01-02"), row.Model, row.Provider, row.Source}
			sum := usage[key]
			if sum == nil {
				if len(usage) == 2000 {
					return result, ErrClientEventQueryTooLarge
				}
				sum = &usageSum{item: ClientEventUsageStats{Day: key.day, Model: key.model, Provider: key.provider, Source: key.source}}
				usage[key] = sum
			}
			sum.item.Events++
			if row.InputTokens == nil {
				sum.item.InputMissingEvents++
			} else {
				sum.input.Add(&sum.input, big.NewInt(*row.InputTokens))
			}
			if row.OutputTokens == nil {
				sum.item.OutputMissingEvents++
			} else {
				sum.output.Add(&sum.output, big.NewInt(*row.OutputTokens))
			}
		} else {
			if row.EventType != "app_launch" || query.Version != nil && row.AppVersion != *query.Version || query.OS != "" && row.OS != query.OS {
				continue
			}
			key := clientKey{row.AppVersion, row.OS}
			if clients[key] == nil {
				if len(clients) == 2000 {
					return result, ErrClientEventQueryTooLarge
				}
				clients[key] = make(map[clientIdentity]struct{})
			}
			clients[key][clientIdentity{row.UserID, row.Channel, row.ClientID}] = struct{}{}
		}
	}
	for _, sum := range usage {
		if sum.item.InputMissingEvents < sum.item.Events {
			value := sum.input.String()
			sum.item.InputTokens = &value
		}
		if sum.item.OutputMissingEvents < sum.item.Events {
			value := sum.output.String()
			sum.item.OutputTokens = &value
		}
		sum.item.CounterDataComplete = sum.item.InputMissingEvents == 0 && sum.item.OutputMissingEvents == 0
		result.Usage = append(result.Usage, sum.item)
	}
	for key, identities := range clients {
		result.Clients = append(result.Clients, ClientEventClientStats{Version: key.version, OS: key.os, ActiveClients: len(identities)})
	}
	slices.SortFunc(result.Usage, func(a, b ClientEventUsageStats) int {
		return cmp.Or(strings.Compare(a.Day, b.Day), strings.Compare(a.Model, b.Model), strings.Compare(a.Provider, b.Provider), strings.Compare(a.Source, b.Source))
	})
	slices.SortFunc(result.Clients, func(a, b ClientEventClientStats) int {
		return cmp.Or(strings.Compare(a.Version, b.Version), strings.Compare(a.OS, b.OS))
	})
	return result, ctx.Err()
}

// ClientEventQueryActor is captured solely from dashboard authentication context.
// It is not a request DTO and must never be serialized or logged.
type ClientEventQueryActor struct {
	Identity       AuthSessionIdentity
	UseAccessToken bool
	Legacy         bool
	TokenID        int
	TokenRef       string
}

// ReadClientEventQueryAuthority bypasses all identity caches. Its final call is
// the response's authorization observation point, not an atomic permission snapshot.
func ReadClientEventQueryAuthority(ctx context.Context, actor ClientEventQueryActor) ([]string, error) {
	identity := actor.Identity
	if identity.UserID <= 0 || identity.UserAuthVersion <= 0 {
		return nil, ErrClientEventUnauthorized
	}
	db := DB.WithContext(ctx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})
	var user User
	err := db.Select("id", "role", "status", "auth_version", "access_token").First(&user, identity.UserID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrClientEventUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if user.Status != common.UserStatusEnabled || user.AuthVersion != identity.UserAuthVersion {
		return nil, ErrClientEventUnauthorized
	}
	if user.Role < common.RoleAdminUser {
		return nil, ErrClientEventForbidden
	}
	if actor.UseAccessToken {
		if actor.TokenRef == "" {
			return nil, ErrClientEventUnauthorized
		}
		if actor.Legacy {
			if actor.TokenID != 0 || identity.SessionID != "" || LegacyAccessTokensRetired(time.Now().Unix()) || user.GetAccessToken() == "" || AccessTokenFingerprint(user.GetAccessToken()) != actor.TokenRef {
				return nil, ErrClientEventUnauthorized
			}
			return nil, ctx.Err()
		}
		if actor.TokenID <= 0 || identity.SessionID != AccessTokenSessionID(actor.TokenID) || identity.SessionVersion != AccessTokenSessionVersion {
			return nil, ErrClientEventUnauthorized
		}
		var token UserAccessToken
		err = db.Where("id = ? AND user_id = ?", actor.TokenID, identity.UserID).First(&token).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrClientEventUnauthorized
		}
		if err != nil {
			return nil, err
		}
		if token.TokenHash != actor.TokenRef || token.Expired(time.Now().Unix()) {
			return nil, ErrClientEventUnauthorized
		}
		return token.GetScopes(), ctx.Err()
	}
	if identity.SessionID == "" || identity.SessionVersion <= 0 || actor.Legacy || actor.TokenID != 0 || actor.TokenRef != "" {
		return nil, ErrClientEventUnauthorized
	}
	var session UserSession
	err = db.Select("sid", "user_id", "status", "revoked_at", "expires_at", "version", "user_auth_version").Where("sid = ? AND user_id = ?", identity.SessionID, identity.UserID).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrClientEventUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if session.SID != identity.SessionID || session.Status != UserSessionStatusActive || session.RevokedAt != 0 || session.ExpiresAt <= time.Now().Unix() || session.Version != identity.SessionVersion || session.UserAuthVersion != identity.UserAuthVersion {
		return nil, ErrClientEventUnauthorized
	}
	return nil, ctx.Err()
}
