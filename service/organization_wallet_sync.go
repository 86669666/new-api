package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

var ErrOrganizationChargeUnconfirmed = errors.New("The organization charge outcome is unconfirmed.")

// The embedding server supplies the whole policy and a trusted adapter. A
// dashboard session by itself does not grant organization spending.
type OrganizationWalletSyncPolicy struct {
	OrganizationID int64
	ActorUserID    int
	Model          string
	AdapterID      string
	QuotaPerUnit   int64
	MaxUnits       int64
	Timeout        time.Duration
	Execute        func(context.Context, OrganizationWalletSyncDispatch) (OrganizationWalletSyncResult, error)
}

type OrganizationWalletSyncDispatch struct {
	ChargeID int64
	Model    string
	Text     string
	MaxUnits int64
}

// The adapter may only report no charge when it has a terminal receipt bound
// to the specified dispatch. A timeout or an HTTP error alone never suffices.
type OrganizationWalletSyncResult struct {
	ChargeID int64
	Units    *int64
	NoCharge bool
	Text     string
}

type OrganizationWalletSyncReceipt struct {
	State  string `json:"state"`
	Actual int64  `json:"actual"`
	Text   string `json:"text,omitempty"`
}

func RunOrganizationWalletSync(ctx context.Context, actor AuthIdentity, orgID int64, key, input string, policy OrganizationWalletSyncPolicy) (OrganizationWalletSyncReceipt, error) {
	var receipt OrganizationWalletSyncReceipt
	if orgID <= 0 || actor.UserID <= 0 || orgID != policy.OrganizationID || actor.UserID != policy.ActorUserID ||
		policy.Model == "" || policy.AdapterID == "" || policy.Execute == nil ||
		policy.Timeout <= 0 || policy.Timeout > 30*time.Second || policy.QuotaPerUnit <= 0 || policy.MaxUnits <= 0 || policy.MaxUnits > math.MaxInt32/policy.QuotaPerUnit {
		return receipt, model.ErrOrganizationForbidden
	}
	if input == "" || len(input) > 4096 || !utf8.ValidString(input) {
		return receipt, model.ErrOrganizationInvalidInput
	}
	policyBytes, err := common.Marshal([]any{policy.Model, policy.AdapterID, policy.MaxUnits, policy.QuotaPerUnit, policy.Timeout})
	if err != nil {
		return receipt, err
	}
	policyHash, requestHash := sha256.Sum256(policyBytes), sha256.Sum256([]byte(input))
	req := model.OrganizationChargeRequest{
		OrganizationID: orgID, RequestKey: key, PolicyHash: hex.EncodeToString(policyHash[:]),
		RequestHash: hex.EncodeToString(requestHash[:]), QuotaPerUnit: policy.QuotaPerUnit, Reserve: policy.MaxUnits * policy.QuotaPerUnit,
	}
	charge, err := model.ReserveOrganizationCharge(ctx, actor, req)
	if err != nil {
		return receipt, err
	}
	if charge.State != model.OrganizationChargeReserved {
		return OrganizationWalletSyncReceipt{State: charge.State, Actual: charge.Actual}, nil
	}
	dispatched, granted, err := model.DispatchOrganizationCharge(ctx, actor, req)
	if err != nil {
		// This cleanup is an atomic release only while the row proves no
		// committed permit exists. An unknown dispatch commit stays held.
		_, releaseErr := model.CancelReservedOrganizationCharge(context.WithoutCancel(ctx), charge)
		return receipt, errors.Join(err, releaseErr)
	}
	if !granted {
		return OrganizationWalletSyncReceipt{State: dispatched.State, Actual: dispatched.Actual}, nil
	}
	// A caller disconnect cannot cancel accounting. The trusted adapter gets
	// a server-owned deadline and the result is settled before publication.
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policy.Timeout)
	out, err := policy.Execute(callCtx, OrganizationWalletSyncDispatch{
		ChargeID: dispatched.ID, Model: policy.Model, Text: input, MaxUnits: policy.MaxUnits,
	})
	deadline, _ := callCtx.Deadline()
	expired := callCtx.Err() != nil || !time.Now().Before(deadline)
	cancel()
	if err != nil || expired || out.ChargeID != dispatched.ID || out.NoCharge == (out.Units != nil) ||
		out.Units != nil && (*out.Units < 0 || *out.Units > dispatched.Reserved/dispatched.QuotaPerUnit) {
		return receipt, ErrOrganizationChargeUnconfirmed
	}
	var actual int64
	if out.Units != nil {
		actual = *out.Units * dispatched.QuotaPerUnit
	}
	charge, err = model.FinishOrganizationCharge(context.WithoutCancel(ctx), dispatched, actual, out.NoCharge)
	if err != nil {
		return receipt, err
	}
	// Recheck current authorization before publishing output. Reusing the
	// exact request retrieves the existing binding without another reserve.
	charge, err = model.ReserveOrganizationCharge(ctx, actor, req)
	if err != nil {
		return receipt, err
	}
	receipt = OrganizationWalletSyncReceipt{State: charge.State, Actual: charge.Actual}
	if charge.State == model.OrganizationChargeSettled && len(out.Text) <= 16384 && utf8.ValidString(out.Text) {
		receipt.Text = out.Text
	}
	return receipt, nil
}
