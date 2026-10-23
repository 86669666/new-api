package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
