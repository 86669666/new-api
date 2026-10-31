package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomOAuthProviderReservedSlugs(t *testing.T) {
	for _, slug := range []string{"login", "consent", "logout", "admin", "provider", "telegram"} {
		for _, input := range []string{slug, strings.ToUpper(slug)} {
			t.Run(input, func(t *testing.T) {
				provider := CustomOAuthProvider{Name: "Example", Slug: input}
				err := validateCustomOAuthProvider(&provider)
				require.Error(t, err)
				if slug == "telegram" {
					assert.EqualError(t, err, "the telegram slug is reserved for built-in Telegram OAuth; rename this custom provider")
				} else {
					assert.EqualError(t, err, "provider slug is reserved for OAuth routes; rename this custom provider")
				}
				assert.Equal(t, slug, provider.Slug)
			})
		}
	}

	for _, tc := range []struct {
		name    string
		id      int
		enabled bool
		slug    string
		valid   bool
	}{
		{"new ordinary", 0, true, "Example-Login", true},
		{"existing enabled reserved", 7, true, "Login", false},
		{"existing disable-only reserved", 7, false, "Login", false},
		{"existing valid rename", 7, true, "Example-Login", true},
		{"existing rename and disable", 7, false, "Example-Login", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := CustomOAuthProvider{
				Id: tc.id, Name: "Example", Slug: tc.slug, Enabled: tc.enabled,
				ClientId: "example-client", AuthorizationEndpoint: "https://issuer.example/authorize",
				TokenEndpoint: "https://issuer.example/token", UserInfoEndpoint: "https://issuer.example/userinfo",
			}
			err := validateCustomOAuthProvider(&provider)
			if tc.valid {
				require.NoError(t, err)
				assert.Equal(t, "example-login", provider.Slug)
			} else {
				require.EqualError(t, err, "provider slug is reserved for OAuth routes; rename this custom provider")
			}
			assert.Equal(t, tc.id, provider.Id)
			assert.Equal(t, tc.enabled, provider.Enabled)
		})
	}
}
