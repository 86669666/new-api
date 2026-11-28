package router

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrganizationWalletSync(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	actor := f.users["member"]
	identity := service.AuthIdentity{UserID: actor.Id, SessionID: f.sids["member"], UserAuthVersion: 1, SessionVersion: 1}
	oldOrigins := common.SessionCookieTrustedURLs
	common.SessionCookieTrustedURLs = []string{f.server.URL}
	t.Cleanup(func() { common.SessionCookieTrustedURLs = oldOrigins })
	require.NoError(t, f.db.AutoMigrate(&model.OrganizationCharge{}))
	require.NoError(t, f.db.Create(&model.OrganizationWallet{OrganizationID: f.orgA, Balance: 100}).Error)
	require.NoError(t, f.db.Create(&model.OrganizationWallet{OrganizationID: f.orgB, Balance: 77}).Error)
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", actor.Id).UpdateColumn("quota", 123).Error)

	type wireResult struct{ id, units int64 }
	entered := make(chan wireResult, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var in service.OrganizationWalletSyncDispatch
		if err := common.DecodeJson(io.LimitReader(r.Body, 10240), &in); err != nil {
			w.WriteHeader(400)
			return
		}
		if in.Model != "synthetic-sync" || in.MaxUnits != 6 || in.ChargeID <= 0 {
			w.WriteHeader(400)
			return
		}
		var units int64 = 4
		out := service.OrganizationWalletSyncResult{ChargeID: in.ChargeID, Units: &units, Text: "synthetic output"}
		switch in.Text {
		case "blocked success":
			entered <- wireResult{in.ChargeID, units}
			<-release
		case "no charge":
			out.Units, out.NoCharge, out.Text = nil, true, ""
		case "missing response":
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		encoded, err := common.Marshal(out)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(encoded)
	}))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); upstream.Close() })

	policy := service.OrganizationWalletSyncPolicy{
		OrganizationID: f.orgA, ActorUserID: actor.Id, Model: "synthetic-sync", AdapterID: "fixture/v1", QuotaPerUnit: 10, MaxUnits: 6, Timeout: 5 * time.Second,
		Execute: func(ctx context.Context, dispatch service.OrganizationWalletSyncDispatch) (service.OrganizationWalletSyncResult, error) {
			var result service.OrganizationWalletSyncResult
			raw, err := common.Marshal(dispatch)
			if err != nil {
				return result, err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, strings.NewReader(string(raw)))
			if err != nil {
				return result, err
			}
			res, err := upstream.Client().Do(req)
			if err != nil {
				return result, err
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				return result, fmt.Errorf("synthetic HTTP failure: %d", res.StatusCode)
			}
			err = common.DecodeJson(io.LimitReader(res.Body, 65536), &result)
			return result, err
		},
	}
	route := "/api/organizations/:org_id/wallet/sync-fixture"
	f.engine.POST(route, middleware.UserAuth(), controller.OrganizationWalletSyncHandler(policy))
	late := policy
	late.Timeout = 10 * time.Millisecond
	late.Execute = func(ctx context.Context, dispatch service.OrganizationWalletSyncDispatch) (service.OrganizationWalletSyncResult, error) {
		<-ctx.Done()
		units := int64(4)
		return service.OrganizationWalletSyncResult{ChargeID: dispatch.ChargeID, Units: &units, Text: "late output"}, nil
	}
	f.engine.POST(route+"/late", middleware.UserAuth(), controller.OrganizationWalletSyncHandler(late))
	key := func(n int) string { return fmt.Sprintf("91000000-0000-4000-8000-%012d", n) }
	path := fmt.Sprintf("/api/organizations/%d/wallet/sync-fixture", f.orgA)
	call := func(t *testing.T, path, by, id, input, origin string) (int, map[string]any) {
		t.Helper()
		raw, err := common.Marshal(map[string]string{"request_id": id, "text": input})
		require.NoError(t, err)
		status, _, b := f.request(t, http.MethodPost, path, by, string(raw), http.Header{"Content-Type": {"application/json"}, "Origin": {origin}})
		return status, b
	}
	wallet := func(t *testing.T, balance, reserved int64) {
		t.Helper()
		var original, foreign model.OrganizationWallet
		require.NoError(t, f.db.Where("organization_id = ?", f.orgA).First(&original).Error)
		require.NoError(t, f.db.Where("organization_id = ?", f.orgB).First(&foreign).Error)
		assert.Equal(t, balance, original.Balance)
		assert.Equal(t, reserved, original.Reserved)
		assert.Equal(t, int64(77), foreign.Balance)
		assert.Zero(t, foreign.Reserved)
		var u model.User
		require.NoError(t, f.db.First(&u, actor.Id).Error)
		assert.Equal(t, 123, u.Quota)
	}
	receipt := func(t *testing.T, b map[string]any, state string, actual int64) map[string]any {
		t.Helper()
		require.Equal(t, true, b["success"])
		m, ok := b["data"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, state, m["state"])
		assert.Equal(t, float64(actual), m["actual"])
		return m
	}

	t.Run("policy and same-origin gate", func(t *testing.T) {
		status, b := call(t, path, "member", key(6), "test", "https://invalid.example")
		assert.Equal(t, 403, status)
		assert.Equal(t, "AUTH_ORIGIN_FORBIDDEN", b["code"])
		status, b = call(t, path, "owner", key(6), "test", f.server.URL)
		assert.Equal(t, 403, status)
		assert.Equal(t, "ORG_FORBIDDEN", b["code"])
		status, _ = call(t, strings.Replace(path, fmt.Sprint(f.orgA), fmt.Sprint(f.orgB), 1), "member", key(6), "test", f.server.URL)
		assert.Equal(t, 403, status)
		status, _ = call(t, path, "member", "not-a-uuid", "test", f.server.URL)
		assert.Equal(t, 400, status)
		assert.Zero(t, calls.Load())
		wallet(t, 100, 0)
	})

	t.Run("competing reserves and repeated settlement", func(t *testing.T) {
		body := strings.NewReader(fmt.Sprintf(`{"request_id":"%s","text":"blocked success"}`, key(1)))
		req, err := http.NewRequestWithContext(t.Context(), "POST", f.server.URL+path, body)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+f.bearer["member"])
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", f.server.URL)
		type result struct {
			response *http.Response
			err      error
		}
		results := make(chan result, 1)
		go func() { res, err := f.client.Do(req); results <- result{res, err} }()
		var id int64
		select {
		case sent := <-entered:
			id = sent.id
		case <-time.After(5 * time.Second):
			t.Fatal("synthetic dispatch not reached")
		}
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
		wallet(t, 100, 60)
		status, b := call(t, path, "member", key(1), "blocked success", f.server.URL)
		assert.Equal(t, 202, status)
		receipt(t, b, model.OrganizationChargeDispatched, 0)
		status, b = call(t, path, "member", key(1), "different", f.server.URL)
		assert.Equal(t, 409, status)
		assert.Equal(t, "ORG_IDEMPOTENCY_CONFLICT", b["code"])
		status, b = call(t, path, "member", key(2), "would overspend", f.server.URL)
		assert.Equal(t, 402, status)
		assert.Equal(t, "ORG_WALLET_INSUFFICIENT", b["code"])
		releaseOnce.Do(func() { close(release) })
		done := <-results
		require.NoError(t, done.err)
		defer done.response.Body.Close()
		require.Equal(t, 200, done.response.StatusCode)
		require.NoError(t, common.DecodeJson(done.response.Body, &b))
		assert.Equal(t, "synthetic output", receipt(t, b, model.OrganizationChargeSettled, 40)["text"])
		wallet(t, 60, 0)

		status, b = call(t, path, "member", key(1), "blocked success", f.server.URL)
		require.Equal(t, 200, status)
		assert.NotContains(t, receipt(t, b, model.OrganizationChargeSettled, 40), "text")
		assert.EqualValues(t, 1, calls.Load())
		var charge model.OrganizationCharge
		require.NoError(t, f.db.First(&charge, id).Error)
		assert.Equal(t, f.orgA, charge.OrganizationID)
		assert.Equal(t, actor.Id, charge.ActorUserID)
		assert.EqualValues(t, 10, charge.QuotaPerUnit)
		_, err = model.FinishOrganizationCharge(t.Context(), charge, 40, false)
		require.NoError(t, err)
		_, err = model.FinishOrganizationCharge(t.Context(), charge, 50, false)
		require.ErrorIs(t, err, model.ErrOrganizationConflict)
		for range 2 {
			reversed, err := model.RefundSettledOrganizationCharge(t.Context(), charge)
			require.NoError(t, err)
			assert.Equal(t, model.OrganizationChargeRefunded, reversed.State)
		}
		wallet(t, 100, 0)
	})

	t.Run("bound zero-fee receipt and lost outcome", func(t *testing.T) {
		status, b := call(t, path, "member", key(3), "no charge", f.server.URL)
		require.Equal(t, 200, status)
		receipt(t, b, model.OrganizationChargeReleased, 0)
		wallet(t, 100, 0)
		status, b = call(t, path+"/late", "member", key(7), "late receipt", f.server.URL)
		assert.Equal(t, 502, status)
		assert.Equal(t, "ORG_WALLET_OUTCOME_UNCONFIRMED", b["code"])
		wallet(t, 100, 60)
		var lateCharge model.OrganizationCharge
		require.NoError(t, f.db.Where("state = ?", model.OrganizationChargeDispatched).First(&lateCharge).Error)
		_, err := model.FinishOrganizationCharge(t.Context(), lateCharge, 41, false)
		require.ErrorIs(t, err, model.ErrOrganizationInvalidInput)
		wallet(t, 100, 60)
		// The fixture followed up with a separate exact zero-cost receipt.
		_, err = model.FinishOrganizationCharge(t.Context(), lateCharge, 0, true)
		require.NoError(t, err)
		status, b = call(t, path, "member", key(4), "missing response", f.server.URL)
		assert.Equal(t, 502, status)
		assert.Equal(t, "ORG_WALLET_OUTCOME_UNCONFIRMED", b["code"])
		status, b = call(t, path, "member", key(4), "missing response", f.server.URL)
		assert.Equal(t, 202, status)
		receipt(t, b, model.OrganizationChargeDispatched, 0)
		assert.EqualValues(t, 3, calls.Load())
		wallet(t, 100, 60)
	})

	t.Run("revocation rejects dispatch and preserves original binding", func(t *testing.T) {
		req := model.OrganizationChargeRequest{OrganizationID: f.orgA, RequestKey: key(5),
			PolicyHash: strings.Repeat("1", 64), RequestHash: strings.Repeat("2", 64), QuotaPerUnit: 5, Reserve: 20}
		before, err := model.ReserveOrganizationCharge(t.Context(), identity, req)
		require.NoError(t, err)
		wallet(t, 100, 80)
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, actor.Id).
			UpdateColumn("removed_at", 1).Error)
		_, granted, err := model.DispatchOrganizationCharge(t.Context(), identity, req)
		require.ErrorIs(t, err, model.ErrOrganizationNotFound)
		assert.False(t, granted)
		for range 2 {
			closed, err := model.CancelReservedOrganizationCharge(t.Context(), before)
			require.NoError(t, err)
			assert.Equal(t, model.OrganizationChargeReleased, closed.State)
		}
		var admitted model.OrganizationCharge
		require.NoError(t, f.db.Where("state = ?", model.OrganizationChargeDispatched).First(&admitted).Error)
		changed := admitted
		changed.RequestKeyHash = before.RequestKeyHash
		_, err = model.FinishOrganizationCharge(t.Context(), changed, 20, false)
		require.ErrorIs(t, err, model.ErrOrganizationConflict)
		changed = admitted
		changed.WalletID++
		_, err = model.FinishOrganizationCharge(t.Context(), changed, 20, false)
		require.ErrorIs(t, err, model.ErrOrganizationConflict)
		_, err = model.FinishOrganizationCharge(t.Context(), admitted, 20, false)
		require.NoError(t, err)
		wallet(t, 80, 0)
		status, _ := call(t, path, "member", key(4), "missing response", f.server.URL)
		assert.Equal(t, 404, status)
		assert.EqualValues(t, 3, calls.Load())
	})
}
