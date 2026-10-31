/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
package model

import (
	"errors"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// OAuthPublicClient is the console registry for a public OAuth client.
// It stores no client secret. A row here is not itself a Hydra registration:
// when the public provider is active, the service commits the row only after
// Hydra Admin accepts the same client_id.
type OAuthPublicClient struct {
	ID           int       `json:"id" gorm:"primaryKey"`
	ClientID     string    `json:"client_id" gorm:"column:client_id;type:varchar(64);uniqueIndex;not null"`
	Name         string    `json:"name" gorm:"type:varchar(128);not null"`
	RedirectURIs string    `json:"redirect_uris" gorm:"column:redirect_uris;type:text;not null"`
	Scopes       string    `json:"scopes" gorm:"type:text;not null"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (OAuthPublicClient) TableName() string { return "oauth_public_clients" }

func ListOAuthPublicClients() ([]OAuthPublicClient, error) {
	var clients []OAuthPublicClient
	err := DB.Order("id asc").Find(&clients).Error
	return clients, err
}

func GetOAuthPublicClientByID(id int) (*OAuthPublicClient, error) {
	var client OAuthPublicClient
	err := DB.First(&client, id).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func GetOAuthPublicClientByClientID(clientID string) (*OAuthPublicClient, error) {
	var client OAuthPublicClient
	err := DB.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func CreateOAuthPublicClient(client *OAuthPublicClient) error {
	return DB.Create(client).Error
}

func SaveOAuthPublicClient(client *OAuthPublicClient) error {
	return DB.Save(client).Error
}

func DeleteOAuthPublicClient(id int) error {
	result := DB.Delete(&OAuthPublicClient{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func DecodeOAuthPublicClientList(raw string) ([]string, error) {
	var values []string
	if err := common.UnmarshalJsonStr(raw, &values); err != nil || values == nil {
		return nil, errors.New("invalid OAuth client list")
	}
	return values, nil
}
