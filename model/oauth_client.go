package model

import (
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// OAuthClient is a public OAuth client this server is willing to accept.
// It has no client secret. The tokens table is not changed.
type OAuthClient struct {
	ID           int    `json:"id" gorm:"primaryKey"`
	ClientID     string `json:"client_id" gorm:"type:varchar(64);uniqueIndex;not null"`
	Name         string `json:"name" gorm:"type:varchar(64);not null"`
	RedirectURIs string `json:"-" gorm:"type:text;not null"`
	Scopes       string `json:"scopes" gorm:"type:varchar(512);not null"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    int64  `json:"created_at" gorm:"bigint"`
	UpdatedAt    int64  `json:"updated_at" gorm:"bigint"`
}

func (OAuthClient) TableName() string { return "oauth_clients" }

// OAuthAuthorization is one user's consent for one OAuth client.
type OAuthAuthorization struct {
	ID        int    `json:"-" gorm:"primaryKey"`
	UserID    int    `json:"-" gorm:"not null;uniqueIndex:idx_oauth_auth_user_client"`
	ClientID  string `json:"client_id" gorm:"type:varchar(255);not null;uniqueIndex:idx_oauth_auth_user_client"`
	Name      string `json:"name" gorm:"type:varchar(64)"`
	Scopes    string `json:"scopes" gorm:"type:varchar(512)"`
	RevokedAt int64  `json:"revoked_at" gorm:"bigint"`
	CreatedAt int64  `json:"created_at" gorm:"bigint"`
	UpdatedAt int64  `json:"updated_at" gorm:"bigint"`
}

func (OAuthAuthorization) TableName() string { return "oauth_authorizations" }

// MigrateOAuthClientsIfEnabled creates the client registry only while userinfo
// is enabled, so a disabled startup keeps the previous schema.
func MigrateOAuthClientsIfEnabled(db *gorm.DB) error {
	if os.Getenv("OAUTH_USERINFO_ENABLED") != "true" || db == nil {
		return nil
	}
	return db.AutoMigrate(&OAuthClient{}, &OAuthAuthorization{})
}

func oauthClientTableReady() bool {
	return DB != nil && DB.Migrator().HasTable(&OAuthClient{})
}

// FirstEnabledOAuthClientID returns the oldest enabled client whose redirect
// set equals redirects. A missing table or database error yields an empty id.
func FirstEnabledOAuthClientID(redirects []string) string {
	if len(redirects) == 0 || !oauthClientTableReady() {
		return ""
	}
	want := slices.Clone(redirects)
	slices.Sort(want)
	var rows []OAuthClient
	if err := DB.Where("enabled = ?", true).Order("id asc").Find(&rows).Error; err != nil {
		return ""
	}
	for _, row := range rows {
		list, err := row.RedirectList()
		if err != nil {
			continue
		}
		got := slices.Clone(list)
		slices.Sort(got)
		if slices.Equal(got, want) {
			return row.ClientID
		}
	}
	return ""
}

func OAuthClientEnabled(clientID string) bool {
	if clientID == "" || !oauthClientTableReady() {
		return false
	}
	var count int64
	err := DB.Model(&OAuthClient{}).Where("client_id = ? AND enabled = ?", clientID, true).Count(&count).Error
	return err == nil && count == 1
}

func EnabledOAuthRedirects() []string {
	if !oauthClientTableReady() {
		return nil
	}
	var rows []OAuthClient
	if err := DB.Where("enabled = ?", true).Find(&rows).Error; err != nil {
		return nil
	}
	values := []string{}
	for _, row := range rows {
		list, err := row.RedirectList()
		if err != nil {
			continue
		}
		values = append(values, list...)
	}
	return values
}

func (row OAuthClient) RedirectList() ([]string, error) {
	var values []string
	if row.RedirectURIs == "" || common.UnmarshalJsonStr(row.RedirectURIs, &values) != nil || len(values) == 0 {
		return nil, errors.New("oauth client redirects are invalid")
	}
	return values, nil
}

func ListOAuthClients() ([]OAuthClient, error) {
	var rows []OAuthClient
	err := DB.Order("id desc").Find(&rows).Error
	return rows, err
}

func GetOAuthClientByID(id int) (OAuthClient, error) {
	var row OAuthClient
	err := DB.First(&row, id).Error
	return row, err
}

func CreateOAuthClient(row *OAuthClient) error {
	return DB.Create(row).Error
}

func UpdateOAuthClient(row *OAuthClient) error {
	return DB.Model(row).Select("name", "redirect_uris", "scopes", "enabled", "updated_at").Updates(map[string]any{
		"name": row.Name, "redirect_uris": row.RedirectURIs, "scopes": row.Scopes,
		"enabled": row.Enabled, "updated_at": row.UpdatedAt,
	}).Error
}

func DeleteOAuthClient(id int) error {
	return DB.Delete(&OAuthClient{}, id).Error
}

func SaveOAuthAuthorization(userID int, clientID, name, scopes string) error {
	if userID <= 0 || clientID == "" || DB == nil || !DB.Migrator().HasTable(&OAuthAuthorization{}) {
		return nil
	}
	name = oauthGrantLabel(name)
	now := common.GetTimestamp()
	var row OAuthAuthorization
	err := DB.Where("user_id = ? AND client_id = ?", userID, clientID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DB.Create(&OAuthAuthorization{
			UserID: userID, ClientID: clientID, Name: name, Scopes: scopes, CreatedAt: now, UpdatedAt: now,
		}).Error
	}
	if err != nil {
		return err
	}
	return DB.Model(&row).Select("name", "scopes", "revoked_at", "updated_at").Updates(map[string]any{
		"name": name, "scopes": scopes, "revoked_at": 0, "updated_at": now,
	}).Error
}

func ListOAuthAuthorizations(userID int) ([]OAuthAuthorization, error) {
	if userID <= 0 || !DB.Migrator().HasTable(&OAuthAuthorization{}) {
		return []OAuthAuthorization{}, nil
	}
	var rows []OAuthAuthorization
	err := DB.Where("user_id = ? AND revoked_at = ?", userID, 0).Order("id desc").Find(&rows).Error
	return rows, err
}

func RevokeOAuthAuthorizationsForClient(clientID string) error {
	if clientID == "" || DB == nil || !DB.Migrator().HasTable(&OAuthAuthorization{}) {
		return nil
	}
	now := common.GetTimestamp()
	return DB.Model(&OAuthAuthorization{}).Where("client_id = ? AND revoked_at = ?", clientID, 0).Updates(map[string]any{
		"revoked_at": now, "updated_at": now,
	}).Error
}

func oauthGrantLabel(name string) string {
	name = strings.NewReplacer("\r", " ", "\n", " ").Replace(strings.TrimSpace(name))
	name = strings.TrimSpace(name)
	runes := []rune(name)
	if len(runes) > 64 {
		return string(runes[:64])
	}
	return name
}

func RevokeOAuthAuthorization(userID int, clientID string) error {
	if userID <= 0 || clientID == "" || !DB.Migrator().HasTable(&OAuthAuthorization{}) {
		return gorm.ErrRecordNotFound
	}
	var row OAuthAuthorization
	err := DB.Where("user_id = ? AND client_id = ? AND revoked_at = ?", userID, clientID, 0).First(&row).Error
	if err != nil {
		return err
	}
	if err = DisableOAuthIssuedTokens(userID, clientID); err != nil {
		return err
	}
	return DB.Model(&row).Select("revoked_at", "updated_at").Updates(map[string]any{
		"revoked_at": common.GetTimestamp(), "updated_at": common.GetTimestamp(),
	}).Error
}
