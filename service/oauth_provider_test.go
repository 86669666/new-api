package service

import (
	"testing"

	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthProviderRedirectFragments(t *testing.T) {
	for _, tc := range []struct {
		name, requested, registered string
		allowed                     bool
	}{
		{"loopback different port", "http://127.0.0.1:39874/oauth/callback", "http://127.0.0.1:29873/oauth/callback", true},
		{"loopback empty fragment", "http://127.0.0.1:39874/oauth/callback#", "http://127.0.0.1:29873/oauth/callback", false},
		{"loopback nonempty fragment", "http://127.0.0.1:39874/oauth/callback#fragment", "http://127.0.0.1:29873/oauth/callback", false},
		{"registered loopback fragment", "http://127.0.0.1:39874/oauth/callback", "http://127.0.0.1:29873/oauth/callback#", false},
		{"https exact match", "https://client.example/callback", "https://client.example/callback", true},
		{"https empty fragment", "https://client.example/callback#", "https://client.example/callback#", false},
		{"https nonempty fragment", "https://client.example/callback#fragment", "https://client.example/callback#fragment", false},
		{"boxnai exact match", "boxnai://oauth/callback", "boxnai://oauth/callback", true},
		{"boxnai unregistered", "boxnai://oauth/callback", "cherrystudio://oauth/callback", false},
		{"boxnai path", "boxnai://oauth/other", "boxnai://oauth/other", false},
		{"boxnai host", "boxnai://other/callback", "boxnai://other/callback", false},
		{"boxnai query", "boxnai://oauth/callback?x=1", "boxnai://oauth/callback?x=1", false},
		{"boxnai empty query", "boxnai://oauth/callback?", "boxnai://oauth/callback?", false},
		{"boxnai port", "boxnai://oauth:123/callback", "boxnai://oauth:123/callback", false},
		{"boxnai fragment", "boxnai://oauth/callback#", "boxnai://oauth/callback#", false},
		{"boxnai credentials", "boxnai://user@oauth/callback", "boxnai://user@oauth/callback", false},
		{"boxnai encoded path", "boxnai://oauth/%63allback", "boxnai://oauth/%63allback", false},
		{"boxnai opaque", "boxnai:oauth/callback", "boxnai:oauth/callback", false},
		{"unknown custom scheme", "other://oauth/callback", "other://oauth/callback", false},
		{"legacy scheme exact match", "cherrystudio://oauth/callback", "cherrystudio://oauth/callback", true},
		{"legacy scheme empty fragment", "cherrystudio://oauth/callback#", "cherrystudio://oauth/callback#", false},
		{"encoded hash in path", "http://127.0.0.1:39874/oauth/callback%23", "http://127.0.0.1:29873/oauth/callback%23", true},
		{"encoded hash in query", "http://127.0.0.1:39874/oauth/callback?context=%23", "http://127.0.0.1:29873/oauth/callback?context=%23", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.allowed, validOAuthProviderRedirect(tc.requested, tc.registered))
		})
	}
}

func TestDesktopOAuthStatusFollowsReadiness(t *testing.T) {
	const issuer = "https://auth.example.com/"
	assert.Equal(t, map[string]any{"enabled": false}, (*OAuthPublic)(nil).Status())

	resource, err := NewOAuthUserInfoResource(OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: "https://hydra-admin.example:4445/admin/oauth2/introspect",
		Issuer: issuer, Audience: "status-userinfo", ClientIDs: []string{"desktop-client", "second-client"},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := NewOAuthProviderBridge(OAuthProviderConfig{
		Enabled: true, RevocationEnabled: true, AdminBaseURL: "https://hydra-admin.example:4445/",
		AuthorizationURL: issuer + "oauth2/auth",
	}, resource)
	require.NoError(t, err)
	public, err := NewOAuthPublic(OAuthPublicConfig{Enabled: true, BaseURL: "https://hydra-public.example:4444/"}, bridge)
	require.NoError(t, err)
	previous := SwapOAuthProviderBridge(bridge)
	t.Cleanup(func() { SwapOAuthProviderBridge(previous) })
	oldAddress := system_setting.ServerAddress
	system_setting.ServerAddress = issuer
	t.Setenv("FRONTEND_BASE_URL", "")
	t.Cleanup(func() { system_setting.ServerAddress = oldAddress })

	assert.Equal(t, map[string]any{"enabled": false}, public.Status())
	assert.Equal(t, public.Status(), CurrentOAuthProviderBridge().Public().Status())

	public.ready.Store(true)
	assert.Equal(t, map[string]any{"enabled": true, "issuer": issuer, "desktop_client_id": "desktop-client"}, public.Status())

	resource.clients = nil
	assert.Equal(t, map[string]any{"enabled": false}, public.Status())
	resource.clients = []string{"desktop-client", "second-client"}

	t.Setenv("FRONTEND_BASE_URL", "https://console.example")
	assert.Equal(t, map[string]any{"enabled": false}, public.Status())
	t.Setenv("FRONTEND_BASE_URL", "")
	system_setting.ServerAddress = "https://other.example"
	disabled := public.Status()
	assert.Equal(t, map[string]any{"enabled": false}, disabled)
	assert.NotContains(t, disabled, "issuer")
	assert.NotContains(t, disabled, "desktop_client_id")
}
