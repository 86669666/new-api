package model

import (
	"errors"
	"os"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// OAuthIssuedToken binds one relay key to the OAuth client that created it.
// The tokens table is unchanged. Plaintext is not stored here.
type OAuthIssuedToken struct {
	ID        int    `json:"-" gorm:"primaryKey"`
	TokenID   int    `json:"-" gorm:"uniqueIndex;not null"`
	UserID    int    `json:"-" gorm:"not null;uniqueIndex:idx_oauth_issued_user_client"`
	ClientID  string `json:"-" gorm:"type:varchar(255);not null;uniqueIndex:idx_oauth_issued_user_client"`
	Revealed  bool   `json:"-"`
	CreatedAt int64  `json:"-" gorm:"bigint"`
}

func (OAuthIssuedToken) TableName() string {
	return "oauth_issued_tokens"
}

// MigrateOAuthIssuedTokensIfEnabled creates the association table only while
// the userinfo resource is enabled, so a disabled startup keeps the old schema.
func MigrateOAuthIssuedTokensIfEnabled(db *gorm.DB) error {
	if os.Getenv("OAUTH_USERINFO_ENABLED") != "true" || db == nil {
		return nil
	}
	return db.AutoMigrate(&OAuthIssuedToken{})
}

func OAuthUserQuota(userID int) (int, int, error) {
	var row struct {
		Quota     int
		UsedQuota int
	}
	err := DB.Model(&User{}).Select("quota", "used_quota").Where("id = ?", userID).Take(&row).Error
	return row.Quota, row.UsedQuota, err
}

func ListOAuthIssuedTokens(userID int, clientID string) ([]Token, error) {
	var ids []int
	if err := DB.Model(&OAuthIssuedToken{}).Where("user_id = ? AND client_id = ?", userID, clientID).Pluck("token_id", &ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []Token{}, nil
	}
	var tokens []Token
	if err := DB.Where("user_id = ? AND id IN ?", userID, ids).Order("id desc").Find(&tokens).Error; err != nil {
		return nil, err
	}
	for i := range tokens {
		tokens[i].Key = ""
	}
	return tokens, nil
}

// IssueOAuthClientToken creates at most one relay key for this user and client.
// The plaintext is returned only on the first successful call.
func IssueOAuthClientToken(userID int, clientID string, quota, expireDays int) (string, bool, error) {
	if userID <= 0 || clientID == "" || quota < 0 || expireDays < 1 {
		return "", false, errors.New("invalid oauth issued token")
	}
	var plain string
	var first bool
	for range 2 {
		err := DB.Transaction(func(tx *gorm.DB) error {
			var row OAuthIssuedToken
			err := lockForUpdate(tx).Where("user_id = ? AND client_id = ?", userID, clientID).First(&row).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				key, keyErr := common.GenerateKey()
				if keyErr != nil {
					return keyErr
				}
				now := common.GetTimestamp()
				token := &Token{
					UserId: userID, Name: oauthIssuedTokenName(clientID), Key: key, Status: common.TokenStatusEnabled,
					CreatedTime: now, AccessedTime: now, ExpiredTime: now + int64(expireDays)*86400,
					RemainQuota: quota, UnlimitedQuota: false,
				}
				if err = tx.Create(token).Error; err != nil {
					return err
				}
				row = OAuthIssuedToken{TokenID: token.Id, UserID: userID, ClientID: clientID, Revealed: true, CreatedAt: now}
				if err = tx.Create(&row).Error; err != nil {
					return err
				}
				plain, first = "sk-"+key, true
				return nil
			}
			if err != nil {
				return err
			}
			plain, first = "", false
			return nil
		})
		if oauthIssuedConflict(err) {
			continue
		}
		return plain, first, err
	}
	return "", false, errors.New("oauth issued token conflict")
}

func DisableOAuthIssuedTokens(userID int, clientID string) error {
	if userID <= 0 || !DB.Migrator().HasTable(&OAuthIssuedToken{}) {
		return nil
	}
	query := DB.Where("user_id = ?", userID)
	if clientID != "" {
		query = query.Where("client_id = ?", clientID)
	}
	var rows []OAuthIssuedToken
	if err := query.Find(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		var token Token
		err := DB.Where("id = ? AND user_id = ?", row.TokenID, userID).First(&token).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		token.Status = common.TokenStatusDisabled
		if err = token.SelectUpdate(); err != nil {
			return err
		}
	}
	return nil
}

func DisableOAuthIssuedTokensForUser(userID int) error {
	return DisableOAuthIssuedTokens(userID, "")
}

func oauthIssuedTokenName(clientID string) string {
	name := "oauth-" + clientID
	if len(name) > 40 {
		return name[:40]
	}
	return name
}

func oauthIssuedConflict(err error) bool {
	return err != nil && (errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "UNIQUE"))
}
