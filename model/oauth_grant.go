package model

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

var ErrOAuthGrantInvalid = errors.New("invalid OAuth grant")

// OAuthGrant is local authorization state, not a credential store. Issuer IDs
// are retained verbatim; fixed hexadecimal indexes avoid URL lengths and
// case-insensitive identifier collisions on MySQL.
type OAuthGrant struct {
	GrantRef            string `gorm:"type:char(64);primaryKey"`
	ConsentRef          string `gorm:"type:char(64);not null;uniqueIndex:idx_oauth_grants_consent"`
	GrantID             string `gorm:"type:varchar(43);not null"`
	Issuer              string `gorm:"type:text;not null"`
	ClientID            string `gorm:"type:text;not null"`
	Subject             string `gorm:"type:text;not null"`
	UserID              int    `gorm:"not null;index:idx_oauth_grants_user"`
	ConsentRequestID    string `gorm:"type:text;not null"`
	HydraLoginSessionID string `gorm:"type:text;not null"`
	OriginSID           string `gorm:"type:varchar(64);not null;index:idx_oauth_grants_sid"`
	SessionVersion      int64  `gorm:"not null"`
	UserAuthVersion     int64  `gorm:"not null"`
	Scopes              string `gorm:"type:text;not null"`
	PolicyHash          string `gorm:"type:char(64);not null"`
	Revision            int64  `gorm:"not null"`
	State               string `gorm:"type:varchar(16);not null"`
	CreatedAt           int64  `gorm:"autoCreateTime:false;not null"`
	ApprovedAt          int64  `gorm:"not null"`
	ExpiresAt           int64  `gorm:"not null"`
	RevokedAt           int64  `gorm:"not null"`
	RevokedReason       string `gorm:"type:text;not null"`
}

func (OAuthGrant) TableName() string { return "oauth_grants" }

func OAuthGrantRef(issuer, grantID string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("newapi.oauth.grant.v1\x00"+issuer+"\x00"+grantID)))
}

// InitOAuthGrantStore is deliberately separate from the unconditional host
// migration. Disabled installations neither create nor delete grant tombstones.
func InitOAuthGrantStore(enabled bool) error {
	if !enabled {
		return nil
	}
	if DB == nil {
		return errors.New("OAuth grant database unavailable")
	}
	if common.IsMasterNode {
		if err := DB.AutoMigrate(&OAuthGrant{}); err != nil {
			return err
		}
	}
	// Query every required column, including on an empty table. Slave nodes must
	// not silently start against a partial or missing schema.
	stmt := &gorm.Statement{DB: DB}
	if err := stmt.Parse(&OAuthGrant{}); err != nil {
		return err
	}
	query := DB.Select(stmt.Schema.DBNames).Limit(1).Find(&[]OAuthGrant{})
	if query.Error != nil {
		return query.Error
	}
	if common.UsingMainDatabase(common.DatabaseTypePostgreSQL) {
		// ColumnTypes hides constraint keys from non-owners, while GetIndexes
		// omits constraint-backed indexes. Bind physical metadata to the same
		// relation selected above, accepting immediate whole-column uniqueness.
		relation := query.Statement.Quote(query.Statement.Table)
		if query.Statement.TableExpr != nil {
			if len(query.Statement.TableExpr.Vars) != 0 {
				return errors.New("OAuth grant uniqueness unavailable")
			}
			relation = query.Statement.TableExpr.SQL
		}
		for _, expected := range [][]string{{"grant_ref"}, {"consent_ref"}} {
			var columns []struct {
				IndexOID int64 `gorm:"column:index_oid"`
				Name     string
			}
			// On pre-INCLUDE catalogs the absent JSON field falls back to
			// indnatts; newer catalogs exclude payloads from the real key.
			if err := DB.Raw(`SELECT i.indexrelid::bigint AS index_oid,a.attname AS name
				FROM pg_catalog.pg_class r
				JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
				JOIN pg_catalog.pg_index i ON i.indrelid=r.oid
				JOIN pg_catalog.pg_class ix ON ix.oid=i.indexrelid AND ix.relnamespace=n.oid
				LEFT JOIN pg_catalog.pg_constraint c ON c.conrelid=r.oid AND c.conindid=i.indexrelid AND c.contype IN ('p','u')
				CROSS JOIN LATERAL (SELECT COALESCE((pg_catalog.to_jsonb(i)->>'indnkeyatts')::integer,i.indnatts) AS value) key_count
				CROSS JOIN LATERAL unnest(i.indkey::smallint[]) WITH ORDINALITY k(attnum,position)
				JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid AND a.attnum=k.attnum
					AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull
				WHERE r.oid=pg_catalog.to_regclass(?) AND r.relkind='r' AND ix.relkind='i'
				AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate
				AND i.indpred IS NULL AND i.indexprs IS NULL AND key_count.value=? AND k.position<=key_count.value
				AND (c.oid IS NULL OR (c.connamespace=n.oid AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
					AND array_length(c.conkey,1)=key_count.value AND c.conkey[k.position::integer]=k.attnum))
				ORDER BY i.indexrelid,k.position`, relation, len(expected)).Scan(&columns).Error; err != nil {
				return err
			}
			keys := make(map[int64][]string)
			for _, column := range columns {
				keys[column.IndexOID] = append(keys[column.IndexOID], column.Name)
			}
			unique := false
			for _, key := range keys {
				unique = unique || slices.Equal(key, expected)
			}
			if !unique {
				return errors.New("OAuth grant uniqueness unavailable")
			}
		}
	} else {
		indexes, err := DB.Migrator().GetIndexes(&OAuthGrant{})
		if err != nil {
			return err
		}
		columns, err := DB.Migrator().ColumnTypes(&OAuthGrant{})
		if err != nil {
			return err
		}
		var primaryColumns []string
		for _, column := range columns {
			if primary, _ := column.PrimaryKey(); primary {
				primaryColumns = append(primaryColumns, column.Name())
			}
		}
		grantUnique, consentUnique := slices.Equal(primaryColumns, []string{"grant_ref"}), false
		for _, index := range indexes {
			unique, _ := index.Unique()
			primary, _ := index.PrimaryKey()
			if unique || primary {
				grantUnique = grantUnique || slices.Equal(index.Columns(), []string{"grant_ref"})
				consentUnique = consentUnique || slices.Equal(index.Columns(), []string{"consent_ref"})
			}
		}
		if !grantUnique || !consentUnique {
			return errors.New("OAuth grant uniqueness unavailable")
		}
	}
	return InitOAuthCleanupStore(true)
}

// CreateOAuthGrantWithTx joins preview consumption and the issuer attempt claim.
// The caller must never perform HTTP while this transaction remains open.
func CreateOAuthGrantWithTx(tx *gorm.DB, grant *OAuthGrant) error {
	if err := LockOAuthUser(tx, grant.UserID); err != nil {
		return err
	}
	if err := CheckOAuthCleanupWithTx(tx, grant.Issuer, grant.UserID, grant.ClientID, grant.OriginSID, grant.GrantRef, grant.HydraLoginSessionID); err != nil {
		return err
	}
	actor := AuthSessionIdentity{UserID: grant.UserID, SessionID: grant.OriginSID, SessionVersion: grant.SessionVersion, UserAuthVersion: grant.UserAuthVersion}
	if err := ValidateAuthSessionWithTx(tx, actor); err != nil {
		return err
	}
	var session UserSession
	if err := lockForUpdate(tx).Where("sid = ?", grant.OriginSID).First(&session).Error; err != nil {
		return err
	}
	now := time.Now().Unix()
	grant.GrantRef = OAuthGrantRef(grant.Issuer, grant.GrantID)
	grant.ConsentRef = fmt.Sprintf("%x", sha256.Sum256([]byte("newapi.oauth.consent.v1\x00"+grant.Issuer+"\x00"+grant.ConsentRequestID)))
	grant.State, grant.Revision, grant.CreatedAt = "prepared", 1, now
	grant.ExpiresAt = min(now+7*24*60*60, session.ExpiresAt)
	if grant.ExpiresAt <= now {
		return ErrOAuthGrantInvalid
	}
	return tx.Create(grant).Error
}

// withCurrentOAuthGrant takes locks in user -> source session -> grant order.
// The preliminary row supplies only the session locator; all security fields
// are read again under locks. SQLite takes its writer reservation before reads
// so it cannot authorize from a stale snapshot after a concurrent logout.
func withCurrentOAuthGrant(ctx context.Context, ref string, userID int, action func(*gorm.DB, *User, *UserSession, *OAuthGrant) error) error {
	if DB == nil {
		return errors.New("OAuth grant database unavailable")
	}
	var seed OAuthGrant
	if err := DB.WithContext(ctx).Where("grant_ref = ?", ref).First(&seed).Error; err != nil {
		return err
	}
	if seed.UserID != userID {
		return ErrOAuthGrantInvalid
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if common.UsingMainDatabase(common.DatabaseTypeSQLite) {
			if err := tx.Model(&User{}).Where("id = ?", userID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
				return err
			}
		}
		var user User
		if err := lockForUpdate(tx).Select("id", "username", "display_name", "email", "group", "status", "auth_version", "quota", "used_quota").First(&user, userID).Error; err != nil {
			return err
		}
		var session UserSession
		if err := lockForUpdate(tx).Where("sid = ? AND user_id = ?", seed.OriginSID, userID).First(&session).Error; err != nil {
			return err
		}
		var grant OAuthGrant
		if err := lockForUpdate(tx).Where("grant_ref = ?", ref).First(&grant).Error; err != nil {
			return err
		}
		now := time.Now().Unix()
		if grant.UserID != userID || grant.OriginSID != session.SID || grant.UserAuthVersion != user.AuthVersion || grant.SessionVersion != session.Version || session.UserAuthVersion != user.AuthVersion || user.Status != common.UserStatusEnabled || session.Status != UserSessionStatusActive || session.RevokedAt != 0 || session.ExpiresAt <= now || grant.ExpiresAt <= now || grant.ExpiresAt > session.ExpiresAt || grant.RevokedAt != 0 {
			return ErrOAuthGrantInvalid
		}
		if err := CheckOAuthCleanupWithTx(tx, grant.Issuer, userID, grant.ClientID, grant.OriginSID, grant.GrantRef, grant.HydraLoginSessionID); err != nil {
			return err
		}
		return action(tx, &user, &session, &grant)
	})
}

// ApproveOAuthGrant atomically couples the final actor check to approval.
func ApproveOAuthGrant(ctx context.Context, prepared *OAuthGrant) error {
	return withCurrentOAuthGrant(ctx, prepared.GrantRef, prepared.UserID, func(tx *gorm.DB, _ *User, _ *UserSession, grant *OAuthGrant) error {
		if *grant != *prepared || grant.State != "prepared" {
			return ErrOAuthGrantInvalid
		}
		result := tx.Model(&OAuthGrant{}).Where("grant_ref = ? AND state = ? AND revision = ?", grant.GrantRef, "prepared", grant.Revision).
			Updates(map[string]any{"state": "approved", "approved_at": time.Now().Unix(), "revision": grant.Revision + 1})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrOAuthGrantInvalid
		}
		return nil
	})
}

// OAuthGrantAuthorization contains only already-introspected claims. It cannot
// supply or replace the source dashboard session stored during explicit consent.
type OAuthGrantAuthorization struct {
	Issuer, GrantID, ClientID, Subject                     string
	UserID                                                 int
	AuthVersion, GrantExpiresAt, TokenExpiresAt, NotBefore int64
	Scopes                                                 []string
	Activate                                               bool
}

// OAuthGrantSnapshot is the locked user projection and authorization revision.
// SourceSessionExpiresAt permits deadline checks after the transaction commits.
type OAuthGrantSnapshot struct {
	User                   *User
	Revision               int64
	SourceSessionExpiresAt int64
}

func AuthorizeOAuthGrant(ctx context.Context, claims OAuthGrantAuthorization) (*OAuthGrantSnapshot, error) {
	var snapshot *OAuthGrantSnapshot
	err := withCurrentOAuthGrant(ctx, OAuthGrantRef(claims.Issuer, claims.GrantID), claims.UserID, func(tx *gorm.DB, user *User, session *UserSession, grant *OAuthGrant) error {
		var scopes []string
		now := time.Now().Unix()
		if grant.Issuer != claims.Issuer || grant.GrantID != claims.GrantID || grant.ClientID != claims.ClientID || grant.Subject != claims.Subject || grant.UserAuthVersion != claims.AuthVersion || grant.ExpiresAt != claims.GrantExpiresAt || claims.TokenExpiresAt <= now || claims.NotBefore > now || common.UnmarshalJsonStr(grant.Scopes, &scopes) != nil {
			return ErrOAuthGrantInvalid
		}
		expected := slices.Clone(claims.Scopes)
		slices.Sort(expected)
		slices.Sort(scopes)
		if !slices.Equal(scopes, expected) {
			return ErrOAuthGrantInvalid
		}
		if claims.Activate {
			if grant.State != "approved" {
				return ErrOAuthGrantInvalid
			}
			result := tx.Model(&OAuthGrant{}).Where("grant_ref = ? AND state = ? AND revision = ?", grant.GrantRef, "approved", grant.Revision).
				Updates(map[string]any{"state": "active", "revision": grant.Revision + 1})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrOAuthGrantInvalid
			}
		} else if grant.State != "active" {
			return ErrOAuthGrantInvalid
		}
		revision := grant.Revision
		if claims.Activate {
			revision++
		}
		snapshot = &OAuthGrantSnapshot{User: user, Revision: revision, SourceSessionExpiresAt: session.ExpiresAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// COMMIT may itself wait. Do not publish a projection that expired while
	// the transaction was finishing, even though its locked reads were valid.
	now := time.Now().Unix()
	if claims.TokenExpiresAt <= now || claims.GrantExpiresAt <= now || snapshot.SourceSessionExpiresAt <= now || claims.NotBefore > now {
		return nil, ErrOAuthGrantInvalid
	}
	return snapshot, nil
}
