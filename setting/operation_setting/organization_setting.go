package operation_setting

import (
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/config"
)

const (
	OrganizationCreatedLimitOptionKey = "organization_setting.max_organizations_created_per_user"
	OrganizationJoinedLimitOptionKey  = "organization_setting.max_organizations_joined_per_user"
)

// OrganizationSetting exposes configurable limits; zero preserves unlimited access.
// Admission reads the persisted options within its transaction, not this cache.
type OrganizationSetting struct {
	MaxOrganizationsCreatedPerUser int64 `json:"max_organizations_created_per_user"`
	MaxOrganizationsJoinedPerUser  int64 `json:"max_organizations_joined_per_user"`
}

var organizationSetting OrganizationSetting

func init() {
	config.GlobalConfig.Register("organization_setting", &organizationSetting)
}

func ParseOrganizationLimit(value string) (int64, error) {
	limit, err := strconv.ParseInt(value, 10, 64)
	if err != nil || limit < 0 || limit > 9007199254740991 || strconv.FormatInt(limit, 10) != value {
		return 0, common.NewMessage("Organization limits must be integers between 0 and 9007199254740991.")
	}
	return limit, nil
}

func IsOrganizationLimitOption(key string) bool {
	return key == OrganizationCreatedLimitOptionKey || key == OrganizationJoinedLimitOptionKey
}
