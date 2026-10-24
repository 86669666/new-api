package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

var ErrOAuthDerivedTokenUnknown = errors.New("OAuth derived-token provenance is unavailable")

// OAuthDerivedTokenSource retains both an unused first-create permission and,
// once created, its immutable token provenance. It is never soft deleted.
// Fresh bootstrap establishes history; issuance remains unregistered and closed.
type OAuthDerivedTokenSource struct {
	GrantRef       string  `json:"-" gorm:"type:char(64);primaryKey;not null;uniqueIndex:uq_oauth_derived_grant_idem,priority:1"`
	UserID         int     `json:"-" gorm:"not null;index:idx_oauth_derived_user_created,priority:1"`
	SchemaVersion  int     `json:"-" gorm:"not null"`
	QuotaLimit     int64   `json:"-" gorm:"not null"`
	ExpiresAt      int64   `json:"-" gorm:"not null"`
	PolicyHash     string  `json:"-" gorm:"type:char(64);not null"`
	BindingHash    string  `json:"-" gorm:"type:char(64);not null"`
	VerifiedAt     int64   `json:"-" gorm:"not null"`
	ProofExpiresAt int64   `json:"-" gorm:"not null"`
	PermitDeadline int64   `json:"-" gorm:"not null"`
	VerifiedMethod string  `json:"-" gorm:"type:varchar(16);not null"`
	ProofFlowID    int64   `json:"-" gorm:"not null;uniqueIndex:uq_oauth_derived_proof"`
	TokenID        *int    `json:"-" gorm:"uniqueIndex:uq_oauth_derived_token"`
	KeyRef         *string `json:"-" gorm:"type:char(64);uniqueIndex:uq_oauth_derived_key"`
	IdemHash       *string `json:"-" gorm:"type:char(64);uniqueIndex:uq_oauth_derived_grant_idem,priority:2"`
	RequestHash    *string `json:"-" gorm:"type:char(64)"`
	CreatedAt      *int64  `json:"-" gorm:"autoCreateTime:false;index:idx_oauth_derived_user_created,priority:2"`
	TerminalAt     *int64  `json:"-"`
	TerminalReason *string `json:"-" gorm:"type:varchar(32)"`
}

func (OAuthDerivedTokenSource) TableName() string { return "oauth_derived_token_sources" }

// OAuthDerivedTokenHistory is an existing, independently established history
// assertion. Reading a syntactically valid seal does not bootstrap history or
// prove arbitrary imports/corruption safe. There is deliberately no ready setter.
type OAuthDerivedTokenHistory struct {
	ID            int    `json:"-" gorm:"primaryKey;autoIncrement:false"`
	SchemaVersion int    `json:"-" gorm:"not null"`
	HistorySeal   string `json:"-" gorm:"type:char(64);not null"`
	SealedAt      int64  `json:"-" gorm:"not null"`
}

func (OAuthDerivedTokenHistory) TableName() string { return "oauth_derived_token_history" }

func (source *OAuthDerivedTokenSource) BeforeSave(*gorm.DB) error {
	return source.Validate(time.Now().Unix())
}

// Validate checks the complete row, including nullable success and terminal
// tuples. Expired authentication facts remain valid historical facts.
func (source *OAuthDerivedTokenSource) Validate(now int64) error {
	if source == nil || !oauthDerivedDigest(source.GrantRef) || source.UserID <= 0 || source.SchemaVersion != 1 ||
		source.QuotaLimit < 1 || source.QuotaLimit > 10000000 || source.ExpiresAt <= 0 || source.ExpiresAt > OAuthUsageMaxInteger ||
		!oauthDerivedDigest(source.PolicyHash) || !oauthDerivedDigest(source.BindingHash) ||
		source.VerifiedAt <= 0 || source.VerifiedAt > now || source.VerifiedAt > OAuthUsageMaxInteger-60 ||
		source.ProofExpiresAt <= source.VerifiedAt || source.ProofExpiresAt > OAuthUsageMaxInteger ||
		source.PermitDeadline <= source.VerifiedAt || source.PermitDeadline > min(source.VerifiedAt+60, source.ProofExpiresAt) ||
		source.ProofFlowID <= 0 || source.ProofFlowID > OAuthUsageMaxInteger ||
		!slices.Contains([]string{"password", "2fa", "passkey"}, source.VerifiedMethod) {
		return ErrOAuthDerivedTokenUnknown
	}
	successFields := 0
	for _, present := range []bool{source.TokenID != nil, source.KeyRef != nil, source.IdemHash != nil, source.RequestHash != nil, source.CreatedAt != nil} {
		if present {
			successFields++
		}
	}
	if successFields != 0 && successFields != 5 {
		return ErrOAuthDerivedTokenUnknown
	}
	if successFields == 5 && (*source.TokenID <= 0 || int64(*source.TokenID) > OAuthUsageMaxInteger ||
		!oauthDerivedDigest(*source.KeyRef) || !oauthDerivedDigest(*source.IdemHash) || !oauthDerivedDigest(*source.RequestHash) ||
		*source.CreatedAt < source.VerifiedAt || *source.CreatedAt > now || *source.CreatedAt >= min(source.PermitDeadline, source.ExpiresAt)) {
		return ErrOAuthDerivedTokenUnknown
	}
	if (source.TerminalAt == nil) != (source.TerminalReason == nil) {
		return ErrOAuthDerivedTokenUnknown
	}
	if source.TerminalAt != nil {
		if *source.TerminalAt < source.VerifiedAt || *source.TerminalAt > now ||
			!slices.Contains([]string{"disabled", "deleted", "revoked"}, *source.TerminalReason) ||
			source.CreatedAt != nil && *source.TerminalAt < *source.CreatedAt {
			return ErrOAuthDerivedTokenUnknown
		}
	}
	return nil
}

func oauthDerivedDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

// OAuthDerivedTokenKeyRef is only a lookup digest of an already generated,
// high-entropy token. It is not a credential or a key-format classification rule.
func OAuthDerivedTokenKeyRef(key string) string {
	digest := sha256.Sum256([]byte("newapi.oauth.derived-key.v1\x00" + key))
	return hex.EncodeToString(digest[:])
}

// ValidateOAuthDerivedTokenStore validates existing state only. No absent table,
// empty query, disabled feature or configuration value creates a history seal.
func ValidateOAuthDerivedTokenStore(ctx context.Context) error {
	if DB == nil {
		return ErrOAuthDerivedTokenUnknown
	}
	return validateOAuthDerivedTokenStore(DB.WithContext(ctx), time.Now().Unix())
}

func validateOAuthDerivedTokenSchema(db *gorm.DB) error {
	for _, value := range []any{&OAuthDerivedTokenSource{}, &OAuthDerivedTokenHistory{}, &OAuthDerivedTokenBootstrapIdentity{}} {
		statement := &gorm.Statement{DB: db}
		if err := statement.Parse(value); err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		if err := db.Model(value).Select(statement.Schema.DBNames).Limit(0).Find(value).Error; err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		columns, err := db.Migrator().ColumnTypes(value)
		if err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		var primary []string
		for _, column := range columns {
			if yes, _ := column.PrimaryKey(); yes {
				primary = append(primary, column.Name())
				continue
			}
			field := statement.Schema.LookUpField(column.Name())
			nullable, known := column.Nullable()
			if field == nil || !known || nullable == field.NotNull {
				return ErrOAuthDerivedTokenUnknown
			}
		}
		if len(statement.Schema.PrimaryFieldDBNames) != 1 || !slices.Equal(primary, statement.Schema.PrimaryFieldDBNames) {
			return ErrOAuthDerivedTokenUnknown
		}
		if err := validateOAuthDerivedTokenIndex(db, statement.Table, "", primary, true); err != nil {
			return err
		}
		indexes, err := db.Migrator().GetIndexes(value)
		if err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		for _, expected := range statement.Schema.ParseIndexes() {
			var names []string
			for _, field := range expected.Fields {
				names = append(names, field.DBName)
			}
			matched := false
			for _, actual := range indexes {
				unique, known := actual.Unique()
				if actual.Name() == expected.Name && known && unique == (expected.Class == "UNIQUE") && slices.Equal(actual.Columns(), names) {
					matched = true
				}
			}
			if !matched || validateOAuthDerivedTokenIndex(db, statement.Table, expected.Name, names, expected.Class == "UNIQUE") != nil {
				return ErrOAuthDerivedTokenUnknown
			}
		}
	}
	return nil
}

func validateOAuthDerivedTokenStore(db *gorm.DB, now int64) error {
	if err := validateOAuthDerivedTokenSchema(db); err != nil {
		return err
	}
	if err := validateOAuthDerivedTokenAnchor(db); err != nil {
		return err
	}
	var history []OAuthDerivedTokenHistory
	if err := db.Limit(2).Find(&history).Error; err != nil || len(history) != 1 {
		return ErrOAuthDerivedTokenUnknown
	}
	seal := history[0]
	if seal.ID != 1 || seal.SchemaVersion != 1 || !oauthDerivedDigest(seal.HistorySeal) || seal.SealedAt <= 0 || seal.SealedAt > now {
		return ErrOAuthDerivedTokenUnknown
	}
	return nil
}

// GORM's Index omits predicates and prefix lengths. Verify the physical K1a
// constraint as well; a name/column match alone cannot establish provenance.
// An empty name selects the primary key. All queries only read existing state.
func validateOAuthDerivedTokenIndex(db *gorm.DB, table, name string, columns []string, unique bool) error {
	switch db.Dialector.Name() {
	case "sqlite":
		var indexes []struct {
			Name    *string
			Unique  *bool
			Partial *bool
		}
		if err := db.Raw(`SELECT name, "unique", partial FROM pragma_index_list(?) WHERE name = ? OR (? = '' AND origin = 'pk')`, table, name, name).Scan(&indexes).Error; err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		if name == "" && len(indexes) == 0 {
			// An INTEGER PRIMARY KEY aliases the rowid and has no separate
			// index. Other primary keys must have an origin='pk' index.
			var primary []struct {
				Name *string
				Type *string
				PK   *int
			}
			if err := db.Raw("SELECT name, type, pk FROM pragma_table_info(?) WHERE pk > 0", table).Scan(&primary).Error; err != nil ||
				len(primary) != 1 || len(columns) != 1 || primary[0].Name == nil || *primary[0].Name != columns[0] ||
				primary[0].Type == nil || *primary[0].Type != "INTEGER" || primary[0].PK == nil || *primary[0].PK != 1 {
				return ErrOAuthDerivedTokenUnknown
			}
			return nil
		}
		if len(indexes) != 1 || indexes[0].Name == nil || indexes[0].Unique == nil || *indexes[0].Unique != unique ||
			indexes[0].Partial == nil || *indexes[0].Partial {
			return ErrOAuthDerivedTokenUnknown
		}
		var keys []struct {
			Seqno *int
			Cid   *int
			Name  *string
		}
		if err := db.Raw(`SELECT seqno, cid, name FROM pragma_index_xinfo(?) WHERE "key" = 1 ORDER BY seqno`, *indexes[0].Name).Scan(&keys).Error; err != nil || len(keys) != len(columns) {
			return ErrOAuthDerivedTokenUnknown
		}
		for i, key := range keys {
			// Negative cid identifies an expression or rowid, not a full column.
			if key.Seqno == nil || *key.Seqno != i || key.Cid == nil || *key.Cid < 0 || key.Name == nil || *key.Name != columns[i] {
				return ErrOAuthDerivedTokenUnknown
			}
		}
	case "mysql":
		if name == "" {
			name = "PRIMARY"
		}
		var keys []struct {
			ColumnName   *string
			NonUnique    *bool
			SeqInIndex   *int
			PrefixLength *int
			IndexType    *string
			IndexState   *string
		}
		// These columns exist in MySQL 5.7.8. Functional keys on newer
		// versions have no COLUMN_NAME; SUB_PART detects truncated keys.
		if err := db.Raw("SELECT COLUMN_NAME AS column_name, NON_UNIQUE AS non_unique, SEQ_IN_INDEX AS seq_in_index, SUB_PART AS prefix_length, INDEX_TYPE AS index_type, `COMMENT` AS index_state FROM information_schema.statistics WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? ORDER BY SEQ_IN_INDEX", table, name).Scan(&keys).Error; err != nil || len(keys) != len(columns) {
			return ErrOAuthDerivedTokenUnknown
		}
		for i, key := range keys {
			if key.ColumnName == nil || *key.ColumnName != columns[i] || key.NonUnique == nil || *key.NonUnique == unique ||
				key.SeqInIndex == nil || *key.SeqInIndex != i+1 || key.PrefixLength != nil || key.IndexType == nil || *key.IndexType != "BTREE" ||
				key.IndexState == nil || *key.IndexState != "" {
				return ErrOAuthDerivedTokenUnknown
			}
		}
	case "postgres":
		var keys []struct {
			ColumnName *string
			Verified   *bool
		}
		// Use only PG 9.6 catalog fields. indclass counts key columns even
		// on newer PG with INCLUDE; indnatts alone would accept included
		// columns as part of a supposedly composite unique constraint.
		if err := db.Raw(`SELECT a.attname AS column_name,
			(i.indisunique = ? AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate
			AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts = ?
			AND pg_catalog.array_length(i.indclass::oid[], 1) = ?) AS verified
			FROM pg_catalog.pg_index AS i
			JOIN pg_catalog.pg_class AS c ON c.oid = i.indexrelid
			CROSS JOIN LATERAL pg_catalog.unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum, position)
			JOIN pg_catalog.pg_attribute AS a ON a.attrelid = i.indrelid AND a.attnum = k.attnum AND NOT a.attisdropped
			WHERE i.indrelid = pg_catalog.to_regclass(?) AND ((? = '' AND i.indisprimary) OR c.relname = ?)
			ORDER BY k.position`, unique, len(columns), len(columns), table, name, name).Scan(&keys).Error; err != nil || len(keys) != len(columns) {
			return ErrOAuthDerivedTokenUnknown
		}
		for i, key := range keys {
			if key.ColumnName == nil || *key.ColumnName != columns[i] || key.Verified == nil || !*key.Verified {
				return ErrOAuthDerivedTokenUnknown
			}
		}
	default:
		return ErrOAuthDerivedTokenUnknown
	}
	return nil
}

type OAuthDerivedTokenClass string

const (
	OAuthDerivedTokenUnknown      OAuthDerivedTokenClass = "unknown"
	OAuthDerivedTokenManualProven OAuthDerivedTokenClass = "manual_proven"
	OAuthDerivedTokenBound        OAuthDerivedTokenClass = "derived"
)

// ClassifyOAuthDerivedToken is authoritative SQL classification, never spending
// permission. A negative source lookup is meaningful only with a validated,
// already established history assertion and an existing authoritative Token.
func ClassifyOAuthDerivedToken(ctx context.Context, tokenID int) (OAuthDerivedTokenClass, error) {
	if tokenID <= 0 || int64(tokenID) > OAuthUsageMaxInteger || DB == nil {
		return OAuthDerivedTokenUnknown, ErrOAuthDerivedTokenUnknown
	}
	kind := OAuthDerivedTokenUnknown
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := validateOAuthDerivedTokenStore(tx, time.Now().Unix()); err != nil {
			return err
		}
		var token Token
		if err := tx.Unscoped().First(&token, tokenID).Error; err != nil || token.UserId <= 0 || token.Key == "" {
			return ErrOAuthDerivedTokenUnknown
		}
		var sources []OAuthDerivedTokenSource
		if err := tx.Where("token_id = ? OR key_ref = ?", token.Id, OAuthDerivedTokenKeyRef(token.Key)).Limit(2).Find(&sources).Error; err != nil || len(sources) > 1 {
			return ErrOAuthDerivedTokenUnknown
		}
		if len(sources) == 0 {
			// Losing both lookup members of a partial success tuple must not
			// turn that user's previously derived token into a manual token.
			var partial int64
			if err := tx.Model(&OAuthDerivedTokenSource{}).Where("user_id = ?", token.UserId).
				Where("(token_id IS NULL OR key_ref IS NULL OR idem_hash IS NULL OR request_hash IS NULL OR created_at IS NULL) AND (token_id IS NOT NULL OR key_ref IS NOT NULL OR idem_hash IS NOT NULL OR request_hash IS NOT NULL OR created_at IS NOT NULL)").
				Count(&partial).Error; err != nil || partial != 0 {
				return ErrOAuthDerivedTokenUnknown
			}
			kind = OAuthDerivedTokenManualProven
			return nil
		}
		source := &sources[0]
		var grant OAuthGrant
		if err := tx.Where("grant_ref = ?", source.GrantRef).First(&grant).Error; err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		if err := validateOAuthDerivedTokenBinding(source, &grant, &token, time.Now().Unix()); err != nil {
			return err
		}
		kind = OAuthDerivedTokenBound
		return nil
	})
	if err != nil {
		return OAuthDerivedTokenUnknown, ErrOAuthDerivedTokenUnknown
	}
	return kind, nil
}

func validateOAuthDerivedTokenBinding(source *OAuthDerivedTokenSource, grant *OAuthGrant, token *Token, now int64) error {
	if err := source.Validate(now); err != nil {
		return err
	}
	if grant.GrantRef != source.GrantRef || grant.GrantRef != OAuthGrantRef(grant.Issuer, grant.GrantID) ||
		grant.UserID != source.UserID || grant.Subject != strconv.Itoa(source.UserID) || grant.Issuer == "" || grant.ClientID == "" ||
		grant.OriginSID == "" || grant.UserAuthVersion <= 0 || grant.SessionVersion <= 0 ||
		grant.CreatedAt < source.VerifiedAt || grant.ExpiresAt < source.ExpiresAt {
		return ErrOAuthDerivedTokenUnknown
	}
	var scopes []string
	if common.UnmarshalJsonStr(grant.Scopes, &scopes) != nil || !slices.Contains(scopes, "tokens:write") ||
		source.TokenID != nil && grant.State != "active" && grant.State != "revoked" {
		return ErrOAuthDerivedTokenUnknown
	}
	if token == nil {
		if source.TokenID != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		return nil
	}
	if source.TokenID == nil || *source.TokenID != token.Id || token.UserId != source.UserID || token.Key == "" ||
		*source.KeyRef != OAuthDerivedTokenKeyRef(token.Key) || token.UnlimitedQuota || token.ExpiredTime <= 0 || token.ExpiredTime > OAuthUsageMaxInteger ||
		int64(token.RemainQuota) < -OAuthUsageMaxInteger || int64(token.RemainQuota) > OAuthUsageMaxInteger ||
		token.UsedQuota < 0 || int64(token.UsedQuota) > OAuthUsageMaxInteger ||
		int64(token.RemainQuota)+int64(token.UsedQuota) != source.QuotaLimit ||
		!slices.Contains([]int{common.TokenStatusEnabled, common.TokenStatusDisabled, common.TokenStatusExpired, common.TokenStatusExhausted}, token.Status) {
		return ErrOAuthDerivedTokenUnknown
	}
	return nil
}

type OAuthDerivedTokenMetadata struct {
	TokenID        string `json:"token_id"`
	Status         string `json:"status"`
	QuotaLimit     int64  `json:"quota_limit"`
	RemainingQuota *int64 `json:"remaining_quota"`
	UsedQuota      *int64 `json:"used_quota"`
	ExpiresAt      int64  `json:"expires_at"`
}

// Source is retained only for the service's post-encoding equality check.
type OAuthDerivedTokenMetadataSnapshot struct {
	Items  []OAuthDerivedTokenMetadata
	Source *OAuthDerivedTokenSource `json:"-"`
}

// ReadOAuthDerivedTokenMetadata reuses the current-grant user/session/cleanup
// boundary. It neither searches other grants nor produces a token or permit.
func ReadOAuthDerivedTokenMetadata(ctx context.Context, grantRef string, userID int) (*OAuthDerivedTokenMetadataSnapshot, error) {
	if !oauthDerivedDigest(grantRef) || userID <= 0 {
		return nil, ErrOAuthGrantInvalid
	}
	snapshot := &OAuthDerivedTokenMetadataSnapshot{Items: make([]OAuthDerivedTokenMetadata, 0)}
	err := withCurrentOAuthGrant(ctx, grantRef, userID, func(tx *gorm.DB, _ *User, _ *UserSession, grant *OAuthGrant) error {
		if grant.State != "active" {
			return ErrOAuthGrantInvalid
		}
		now := time.Now().Unix()
		if err := validateOAuthDerivedTokenStore(tx, now); err != nil {
			return err
		}
		var source OAuthDerivedTokenSource
		if err := tx.Where("grant_ref = ?", grantRef).First(&source).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return ErrOAuthDerivedTokenUnknown
		}
		var token *Token
		if source.TokenID != nil {
			token = &Token{}
			if err := tx.Unscoped().First(token, *source.TokenID).Error; err != nil {
				// A tombstone cannot recover owner-effective values of a missing row.
				return ErrOAuthDerivedTokenUnknown
			}
		}
		if err := validateOAuthDerivedTokenBinding(&source, grant, token, now); err != nil {
			return err
		}
		snapshot.Source = &source
		if token == nil {
			return nil
		}
		expires := min(source.ExpiresAt, token.ExpiredTime)
		remaining, used := int64(token.RemainQuota), int64(token.UsedQuota)
		item := OAuthDerivedTokenMetadata{TokenID: strconv.Itoa(token.Id), Status: "active", QuotaLimit: source.QuotaLimit, RemainingQuota: &remaining, UsedQuota: &used, ExpiresAt: expires}
		switch {
		case token.DeletedAt.Valid:
			item.Status, item.RemainingQuota, item.UsedQuota = "deleted", nil, nil
		case source.TerminalReason != nil:
			if *source.TerminalReason == "deleted" {
				return ErrOAuthDerivedTokenUnknown
			}
			item.Status = *source.TerminalReason
		case token.Status == common.TokenStatusDisabled:
			item.Status = "disabled"
		case expires <= now || token.Status == common.TokenStatusExpired:
			item.Status = "expired"
		case remaining <= 0 || token.Status == common.TokenStatusExhausted:
			item.Status = "exhausted"
		}
		snapshot.Items = append(snapshot.Items, item)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}
