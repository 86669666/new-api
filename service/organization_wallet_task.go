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

// OrganizationTaskPolicy pins one server-owned adapter and payer. The isolated
// runner supplies it explicitly; runtime production routes do not discover it.
type OrganizationTaskPolicy struct {
	OrganizationID int64
	ActorUserID    int
	AdapterID      string
	Model          string
	MaxUnits       int64
	QuotaPerUnit   int64
	Timeout        time.Duration
	Submit         func(context.Context, OrganizationWalletSyncDispatch) (OrganizationTaskAcceptance, error)
	Poll           func(context.Context, OrganizationTaskQuery) (OrganizationTaskOutcome, error)
}

type OrganizationTaskAcceptance struct {
	ChargeID   int64
	UpstreamID string
}

type OrganizationTaskQuery struct {
	ChargeID   int64
	UpstreamID string
}

type OrganizationTaskOutcome struct {
	ChargeID   int64
	UpstreamID string
	Terminal   bool
	NoCharge   bool
	Units      *int64
}

func (p OrganizationTaskPolicy) digest() (string, error) {
	if p.OrganizationID <= 0 || p.ActorUserID <= 0 || p.AdapterID == "" || p.Model == "" || p.Submit == nil || p.Poll == nil ||
		p.Timeout <= 0 || p.Timeout > 30*time.Second || p.MaxUnits <= 0 || p.QuotaPerUnit <= 0 || p.MaxUnits > math.MaxInt32/p.QuotaPerUnit {
		return "", model.ErrOrganizationForbidden
	}
	data, err := common.Marshal([]any{"organization-task/v1", p.OrganizationID, p.ActorUserID, p.AdapterID, p.Model,
		p.MaxUnits, p.QuotaPerUnit, p.Timeout})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func SubmitOrganizationWalletTask(ctx context.Context, actor AuthIdentity, orgID int64, key, input string, policy OrganizationTaskPolicy) (model.OrganizationTaskReceipt, error) {
	var zero model.OrganizationTaskReceipt
	hash, err := policy.digest()
	if err != nil {
		return zero, err
	}
	if orgID != policy.OrganizationID || actor.UserID != policy.ActorUserID {
		return zero, model.ErrOrganizationForbidden
	}
	if input == "" || len(input) > 4096 || !utf8.ValidString(input) {
		return zero, model.ErrOrganizationInvalidInput
	}
	requestHash := sha256.Sum256([]byte(input))
	req := model.OrganizationChargeRequest{OrganizationID: orgID, RequestKey: key, PolicyHash: hash, RequestHash: hex.EncodeToString(requestHash[:]),
		QuotaPerUnit: policy.QuotaPerUnit, Reserve: policy.MaxUnits * policy.QuotaPerUnit}
	task, err := model.ReserveOrganizationTask(ctx, actor, req)
	if err != nil || task.Charge.State != model.OrganizationChargeReserved {
		return task, err
	}
	dispatch, granted, err := model.DispatchOrganizationTask(ctx, actor, req)
	if err != nil {
		return zero, errors.Join(err, model.CancelUnsentOrganizationTask(context.WithoutCancel(ctx), task))
	}
	if !granted {
		return dispatch, nil
	}
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policy.Timeout)
	ack, err := policy.Submit(callCtx, OrganizationWalletSyncDispatch{ChargeID: dispatch.Charge.ID, Model: policy.Model, Text: input, MaxUnits: policy.MaxUnits})
	expired := organizationTaskCallExpired(callCtx)
	cancel()
	if err != nil || expired || ack.ChargeID != dispatch.Charge.ID || ack.UpstreamID == "" {
		return zero, ErrOrganizationChargeUnconfirmed
	}
	if err := model.RecordOrganizationTaskHandle(context.WithoutCancel(ctx), dispatch, ack.UpstreamID); err != nil {
		return zero, err
	}
	// Revalidate the caller after the upstream wait. Only an active member
	// may receive the public task identity; background polling is independent.
	return model.ReserveOrganizationTask(ctx, actor, req)
}

func PollOrganizationWalletTasks(ctx context.Context, policy OrganizationTaskPolicy) error {
	hash, err := policy.digest()
	if err != nil {
		return err
	}
	through, err := model.OrganizationTaskPollHighWater(ctx, policy.OrganizationID, policy.ActorUserID, hash)
	if err != nil {
		return err
	}
	var result error
	for after := int64(0); after < through; {
		tasks, next, err := model.PendingOrganizationTasks(ctx, policy.OrganizationID, policy.ActorUserID, hash, after, through)
		if err != nil {
			return errors.Join(result, err)
		}
		if next == 0 {
			break
		}
		for _, task := range tasks {
			if err := pollOrganizationWalletTask(ctx, policy, task); err != nil {
				result = errors.Join(result, err)
			}
		}
		after = next
	}
	return result
}

func pollOrganizationWalletTask(ctx context.Context, policy OrganizationTaskPolicy, task model.OrganizationTaskReceipt) error {
	callCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
	out, err := policy.Poll(callCtx, OrganizationTaskQuery{ChargeID: task.Charge.ID, UpstreamID: task.UpstreamID})
	expired := organizationTaskCallExpired(callCtx)
	cancel()
	if err != nil || expired || out.ChargeID != task.Charge.ID || out.UpstreamID != task.UpstreamID {
		return ErrOrganizationChargeUnconfirmed
	}
	if !out.Terminal {
		return nil
	}
	if task.Charge.QuotaPerUnit <= 0 || out.NoCharge == (out.Units != nil) ||
		out.Units != nil && (*out.Units < 0 || *out.Units > task.Charge.Reserved/task.Charge.QuotaPerUnit) {
		return ErrOrganizationChargeUnconfirmed
	}
	var actual int64
	if out.Units != nil {
		actual = *out.Units * task.Charge.QuotaPerUnit
	}
	return model.FinishOrganizationTask(context.WithoutCancel(ctx), task, actual, out.NoCharge)
}

func organizationTaskCallExpired(ctx context.Context) bool {
	deadline, _ := ctx.Deadline()
	return ctx.Err() != nil || !time.Now().Before(deadline)
}
