package service

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTaskMediaTicketBindsSessionResourceAndDigest(t *testing.T) {
	previousSecret := common.CryptoSecret
	common.CryptoSecret = "task-media-ticket-test-secret"
	t.Cleanup(func() { common.CryptoSecret = previousSecret })

	identity := model.AuthSessionIdentity{UserID: 7, SessionID: "sid-7", UserAuthVersion: 3, SessionVersion: 9}
	raw, issued, err := IssueTaskMediaTicket(identity, 42, "video", "digest-1")
	require.NoError(t, err)
	parsed, err := ParseTaskMediaTicket(raw)
	require.NoError(t, err)
	assert.Equal(t, issued, parsed)
	assert.False(t, parsed.ValidAt(time.Unix(parsed.ExpiresAt, 0)))
	assert.True(t, parsed.Matches(identity, 42, "video", "digest-1"))
	assert.False(t, parsed.Matches(identity, 43, "video", "digest-1"))
	assert.False(t, parsed.Matches(identity, 42, "video", "digest-2"))
	assert.False(t, parsed.Matches(model.AuthSessionIdentity{UserID: 8, SessionID: identity.SessionID, UserAuthVersion: identity.UserAuthVersion, SessionVersion: identity.SessionVersion}, 42, "video", "digest-1"))

	_, err = ParseTaskMediaTicket(raw + "x")
	assert.ErrorIs(t, err, ErrTaskMediaTicketInvalid)
}
