package model

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestOAuthTextReconcile(t *testing.T) {
	if os.Getenv("NEWAPI_TEXT_RECONCILE_TEST") != "private" {
		t.Skip("requires dedicated database namespace")
	}
	db, facts := newOAuthTextFixture(t)
	ctx := t.Context()
	kind := db.Dialector.Name()
	open := func() *gorm.DB {
		d, err := openOAuthBootstrapDB(kind, os.Getenv("SQL_DSN"))
		require.NoError(t, err)
		pool, err := d.DB()
		require.NoError(t, err)
		pool.SetMaxOpenConns(1)
		t.Cleanup(func() { require.NoError(t, pool.Close()) })
		return d
	}
	other, observer := open(), open()
	require.NoError(t, other.AutoMigrate(&oauthTextCancellation{}))
	require.NoError(t, other.AutoMigrate(&oauthTextCancellation{}))
	read := func(ref string) OAuthDerivedTextCharge {
		t.Helper()
		var charge OAuthDerivedTextCharge
		require.NoError(t, observer.First(&charge, "ref = ?", ref).Error)
		return charge
	}
	balances := func(wallet, remain, used int) {
		t.Helper()
		var user User
		var token Token
		require.NoError(t, observer.First(&user, facts.UserID).Error)
		require.NoError(t, observer.First(&token, facts.TokenID).Error)
		require.Equal(t, wallet, user.Quota)
		require.Equal(t, remain, token.RemainQuota)
		require.Equal(t, used, token.UsedQuota)
	}
	cancellations := func(want int64) {
		t.Helper()
		var count int64
		require.NoError(t, observer.Model(&oauthTextCancellation{}).Count(&count).Error)
		require.Equal(t, want, count)
	}
	reserve := func(char string, amount int) oauthTextCancellationApproval {
		t.Helper()
		ref := strings.Repeat(char, 64)
		charge, err := ReserveOAuthDerivedText(ctx, ref, facts, amount)
		require.NoError(t, err)
		return oauthTextCancellationApproval{Action: "cancel_reserved", DatabaseSeal: strings.Repeat("1", 64),
			Ref: ref, Fingerprint: charge.Fingerprint, Version: charge.Version, Reserve: amount,
			EvidenceDigest: strings.Repeat("2", 64), ApprovedBy: "reviewer", ExecutedBy: "executor"}
	}
	ordered := func(firstDB, secondDB *gorm.DB, first, second func()) {
		t.Helper()
		if kind != "postgres" {
			first()
			second()
			return
		}
		var firstPID, secondPID, observerPID int
		require.NoError(t, firstDB.Raw("SELECT pg_backend_pid()").Row().Scan(&firstPID))
		require.NoError(t, secondDB.Raw("SELECT pg_backend_pid()").Row().Scan(&secondPID))
		require.NoError(t, observer.Raw("SELECT pg_backend_pid()").Row().Scan(&observerPID))
		require.NotEqual(t, firstPID, secondPID)
		require.NotEqual(t, firstPID, observerPID)
		require.NotEqual(t, secondPID, observerPID)
		locked, release := make(chan struct{}), make(chan struct{})
		var holdOnce, releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		defer unblock()
		const callback = "h29_reconcile_hold_payer"
		require.NoError(t, firstDB.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
			// The first operation has acquired the payer lock when it gets
			// as far as reading its Token in the same transaction.
			if tx.Statement.Table == "tokens" {
				holdOnce.Do(func() {
					close(locked)
					<-release
				})
			}
		}))
		defer func() { require.NoError(t, firstDB.Callback().Query().Remove(callback)) }()
		var workers sync.WaitGroup
		defer func() { unblock(); workers.Wait() }()
		workers.Go(first)
		select {
		case <-locked:
		case <-time.After(5 * time.Second):
			t.Fatal("first transaction did not reach the payer-lock checkpoint")
		}
		workers.Go(second)
		require.Eventually(t, func() bool {
			var waiting bool
			err := observer.Raw("SELECT ? = ANY(pg_blocking_pids(?))", firstPID, secondPID).Row().Scan(&waiting)
			return err == nil && waiting
		}, 5*time.Second, 10*time.Millisecond, "two actual server peers must overlap on the payer lock")
		unblock()
		workers.Wait()
	}

	first := reserve("b", 10)
	before := read(first.Ref)
	require.NoError(t, other.Model(&OAuthDerivedTextCharge{}).Where("ref = ?", first.Ref).
		UpdateColumn("grant_ref", strings.Repeat("9", 64)).Error)
	_, err := cancelReservedOAuthText(ctx, other, first)
	require.ErrorIs(t, err, ErrOAuthTextCharge)
	balances(90, 90, 10)
	cancellations(0)
	require.NoError(t, other.Model(&OAuthDerivedTextCharge{}).Where("ref = ?", first.Ref).
		UpdateColumn("grant_ref", before.GrantRef).Error)
	injected := errors.New("controlled token update failure")
	require.NoError(t, other.Callback().Update().Before("gorm:update").Register("h29_reconcile_fail_token", func(tx *gorm.DB) {
		if tx.Statement.Table == "tokens" {
			tx.AddError(injected)
		}
	}))
	_, err = cancelReservedOAuthText(ctx, other, first)
	require.Error(t, err)
	require.NoError(t, other.Callback().Update().Remove("h29_reconcile_fail_token"))
	require.Equal(t, before, read(first.Ref))
	balances(90, 90, 10)
	cancellations(0)

	var refund *oauthTextCancellation
	var permit *OAuthTextSendPermit
	var refundErr, claimErr error
	ordered(other, db,
		func() { refund, refundErr = cancelReservedOAuthText(ctx, other, first) },
		func() { permit, claimErr = ClaimOAuthDerivedText(ctx, first.Ref, facts, first.Reserve) })
	require.NoError(t, refundErr)
	require.NotNil(t, refund)
	require.NoError(t, claimErr)
	require.Nil(t, permit)
	require.Equal(t, "cancelled", read(first.Ref).State)
	replayed, err := cancelReservedOAuthText(ctx, other, first)
	require.NoError(t, err)
	require.Equal(t, refund, replayed)
	conflicting := first
	conflicting.EvidenceDigest = strings.Repeat("3", 64)
	_, err = cancelReservedOAuthText(ctx, other, conflicting)
	require.ErrorIs(t, err, ErrOAuthTextCharge)
	balances(100, 100, 0)
	cancellations(1)

	// A separate unclaimed row remains available to test the actual CLI.
	cli := reserve("d", 15)
	second := reserve("c", 20)
	ordered(db, other,
		func() { permit, claimErr = ClaimOAuthDerivedText(ctx, second.Ref, facts, second.Reserve) },
		func() { refund, refundErr = cancelReservedOAuthText(ctx, other, second) })
	require.NoError(t, claimErr)
	require.NotNil(t, permit)
	require.ErrorIs(t, refundErr, ErrOAuthTextCharge)
	require.Nil(t, refund)
	require.Equal(t, "send_claimed", read(second.Ref).State)
	require.Equal(t, "reserved", read(cli.Ref).State)
	balances(65, 65, 35)
	cancellations(1)
	t.Logf("%s verified claim-first, cancellation-first, failed transaction rollback and idempotent refund", kind)
}
