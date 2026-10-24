package model

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Run in an isolated installer container, with /birth owned by root. Ordinary
// developer tests cannot manufacture the required provisioning authority.
func TestOAuthBootstrapProducer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root installer and protected /birth directory")
	}
	require.NoError(t, oauthProtectedPath("/birth", false))
	dir, err := os.MkdirTemp("/birth", "producer-test-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	target, journal := filepath.Join(dir, "new.db"), filepath.Join(dir, "birth.json")
	args := []string{"fresh", "--engine", "sqlite", "--target", target, "--journal", journal}
	var out bytes.Buffer
	require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
	original, err := readOAuthBirthJournal(journal, false)
	require.NoError(t, err)
	db, err := openOAuthBootstrapDB("sqlite", target)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()
	require.NoError(t, validateOAuthBirth(db, original, true))
	var marker OAuthDerivedTokenBootstrapIdentity
	var history OAuthDerivedTokenHistory
	require.NoError(t, db.First(&marker).Error)
	require.NoError(t, db.First(&history).Error)
	// A second fresh request must preserve the exact existing identity and seal.
	assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
	args[0] = "resume"
	require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
	after, err := readOAuthBirthJournal(journal, false)
	require.NoError(t, err)
	assert.Equal(t, original, after)
	// Lost acknowledgement/external publication: the authoritative SQL row already
	// exists. Resume must only finish that exact pending operation, never reseal.
	pending := *original
	pending.Phase = "SEAL_PENDING"
	require.NoError(t, writeOAuthBirthJournal(journal, &pending))
	require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
	after, err = readOAuthBirthJournal(journal, false)
	require.NoError(t, err)
	assert.Equal(t, original, after)
	var finalHistory OAuthDerivedTokenHistory
	require.NoError(t, db.First(&finalHistory).Error)
	assert.Equal(t, history, finalHistory)
	t.Run("syntactically_valid_forged_history", func(t *testing.T) {
		require.NoError(t, db.Model(&OAuthDerivedTokenHistory{}).Where("id = ?", 1).Update("history_seal", OAuthDerivedTokenKeyRef("untrusted synthetic seal")).Error)
		assert.Error(t, validateOAuthBirth(db, original, true))
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, db.Model(&OAuthDerivedTokenHistory{}).Where("id = ?", 1).Update("history_seal", history.HistorySeal).Error)
	})
	t.Run("wrong_nonce", func(t *testing.T) {
		require.NoError(t, db.Model(&OAuthDerivedTokenBootstrapIdentity{}).Where("id = ?", 1).Update("creation_nonce", OAuthDerivedTokenKeyRef("foreign birth")).Error)
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, db.Model(&OAuthDerivedTokenBootstrapIdentity{}).Where("id = ?", 1).Update("creation_nonce", marker.CreationNonce).Error)
	})
	t.Run("intent_never_adopts", func(t *testing.T) {
		intent := *original
		intent.Phase = "INTENT"
		require.NoError(t, writeOAuthBirthJournal(journal, &intent))
		assert.Equal(t, 1, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, writeOAuthBirthJournal(journal, original))
	})
	t.Run("clone_inode", func(t *testing.T) {
		// SQLite backup is not a new birth. Keep all DB data but change file identity.
		backup := filepath.Join(dir, "clone.db")
		require.NoError(t, db.Exec("VACUUM INTO ?", backup).Error)
		clone, err := openOAuthBootstrapDB("sqlite", backup)
		require.NoError(t, err)
		conn, err := clone.DB()
		require.NoError(t, err)
		defer conn.Close()
		assert.Error(t, validateOAuthBirth(clone, original, true))
	})
	t.Run("same_uid_is_not_service_isolation", func(t *testing.T) {
		t.Setenv("OAUTH_BOOTSTRAP_JOURNAL", journal)
		assert.ErrorIs(t, validateOAuthDerivedTokenAnchor(db), ErrOAuthDerivedTokenUnknown)
	})
	t.Run("manual_row_does_not_change_birth", func(t *testing.T) {
		require.NoError(t, db.Create(&Token{UserId: 1, Key: "synthetic-only", Status: common.TokenStatusEnabled}).Error)
		require.Equal(t, 0, RunOAuthDatabaseBootstrap(args, &out))
		require.NoError(t, validateOAuthBirth(db, original, true))
	})
}
