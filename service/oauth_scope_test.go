package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthScopeGrantAndMapping(t *testing.T) {
	requested := []string{"openid", "profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write", "admin"}
	registered := []string{"profile", "email", "tokens:read", "tokens:write", "balance:read", "usage:read", "openid"}
	allowed, err := oauthProviderAllowedScopes(requested, registered)
	require.NoError(t, err)
	assert.Equal(t, []string{"openid", "profile", "email", "balance:read", "usage:read", "tokens:read", "tokens:write"}, allowed)

	_, err = oauthProviderAllowedScopes([]string{"email", "openid"}, registered)
	assert.ErrorIs(t, err, ErrOAuthProviderDenied)

	require.NoError(t, oauthProviderGrantScopes([]string{"profile", "tokens:read"}, allowed))
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"email"}, allowed), ErrOAuthProviderDenied)
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"profile", "offline_access"}, allowed), ErrOAuthProviderDenied)
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"profile", "profile"}, allowed), ErrOAuthProviderDenied)
	assert.ErrorIs(t, oauthProviderGrantScopes([]string{"profile", "api_key:reveal"}, allowed), ErrOAuthProviderDenied)

	mapped := OAuthAccessTokenScopes([]string{"openid", "profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write"})
	assert.Equal(t, []string{"profile:read", "wallet:read", "usage:read", "api_key:read", "api_key:write"}, mapped)
	assert.NotContains(t, mapped, "api_key:reveal")
	assert.Empty(t, OAuthAccessTokenScopes([]string{"openid", "offline_access"}))

	assert.NoError(t, OAuthResourceRequireScope([]string{"profile", "tokens:read"}, "profile"))
	assert.NoError(t, OAuthResourceRequireScope([]string{"profile", "tokens:read"}, "tokens:read"))
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"openid"}, "profile"), ErrOAuthInsufficientScope)
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"profile", "balance:read"}, "usage:read"), ErrOAuthInsufficientScope)
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"profile", "tokens:read"}, "api_key:read"), ErrOAuthInsufficientScope)
	assert.ErrorIs(t, OAuthResourceRequireScope([]string{"profile"}, "api_key:reveal"), ErrOAuthInsufficientScope)

	assert.False(t, oauthScopeGrantsOfflineAccess("openid profile email"))
	assert.False(t, oauthScopeGrantsOfflineAccess("openid offline_access_extra"))
	assert.True(t, oauthScopeGrantsOfflineAccess("openid offline_access email"))
	assert.Equal(t, []string{"openid", "profile"}, filterOAuthScopeNames([]string{"openid", "profile", "admin", "bad scope"}))
}
