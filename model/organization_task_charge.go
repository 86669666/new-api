package model

import (
	"context"
	"math"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const (
	OrganizationTaskBillingProtocol = 2
	organizationTaskDispatched      = "dispatched"
)

func organizationTaskBillingRef(chargeID int64) string {
	return "organization-charge-" + strconv.FormatInt(chargeID, 10)
}

type OrganizationTaskReceipt struct {
	Charge     OrganizationCharge
	TaskRowID  int64
	PublicID   string
	UpstreamID string
	Status     TaskStatus
}

func organizationTaskReceipt(charge OrganizationCharge, task Task) OrganizationTaskReceipt {
	return OrganizationTaskReceipt{Charge: charge, TaskRowID: task.ID, PublicID: task.TaskID,
		UpstreamID: task.PrivateData.UpstreamTaskID, Status: task.Status}
}

func organizationTaskQuery(db *gorm.DB, charge OrganizationCharge) *gorm.DB {
	return db.Where("billing_ref = ? AND organization_id = ? AND user_id = ? AND billing_protocol = ? AND billing_progress = ?",
		organizationTaskBillingRef(charge.ID), charge.OrganizationID, charge.ActorUserID, OrganizationTaskBillingProtocol, charge.PolicyHash)
}

// ReserveOrganizationTask creates the task and reserves the wallet in the same
// transaction. Existing matches never create another task or reserve.
func ReserveOrganizationTask(ctx context.Context, actor AuthSessionIdentity, req OrganizationChargeRequest) (OrganizationTaskReceipt, error) {
	var receipt OrganizationTaskReceipt
	if req.Reserve > math.MaxInt32 {
		return receipt, ErrOrganizationInvalidInput
	}
	err := withOrganizationChargeAdmission(ctx, actor, req, func(s *organizationState, wallet *OrganizationWallet, charge *OrganizationCharge) error {
		var task Task
		if charge.ID == 0 {
			if err := reserveOrganizationCharge(s, wallet, charge); err != nil {
				return err
			}
			ref := organizationTaskBillingRef(charge.ID)
			task = Task{OrganizationID: charge.OrganizationID, UserId: charge.ActorUserID,
				TaskID: common.NewRequestId(), Platform: "organization-task", Action: "submit", SubmitTime: charge.CreatedAt,
				Status: TaskStatusUnknown, Progress: "0%", BillingRef: &ref, BillingProtocol: OrganizationTaskBillingProtocol,
				BillingState: TaskBillingIntent, BillingProgress: charge.PolicyHash, BillingRevision: 1}
			if err := s.tx.Create(&task).Error; err != nil {
				return err
			}
		} else if err := organizationTaskQuery(s.tx, *charge).First(&task).Error; err != nil {
			return err
		}
		receipt = organizationTaskReceipt(*charge, task)
		return nil
	})
	return receipt, err
}

func DispatchOrganizationTask(ctx context.Context, actor AuthSessionIdentity, req OrganizationChargeRequest) (OrganizationTaskReceipt, bool, error) {
	var receipt OrganizationTaskReceipt
	var granted bool
	err := withOrganizationChargeAdmission(ctx, actor, req, func(s *organizationState, wallet *OrganizationWallet, charge *OrganizationCharge) error {
		if charge.ID == 0 {
			return ErrOrganizationNotFound
		}
		var task Task
		if err := organizationTaskQuery(lockForUpdate(s.tx), *charge).First(&task).Error; err != nil {
			return err
		}
		if charge.State == OrganizationChargeReserved {
			if task.BillingState != TaskBillingIntent {
				return ErrOrganizationConflict
			}
			var err error
			granted, err = dispatchOrganizationCharge(s.tx, wallet, charge)
			if err != nil {
				return err
			}
			if err := writeOrganizationTask(s.tx, task, map[string]any{"billing_state": organizationTaskDispatched}); err != nil {
				return err
			}
		}
		receipt = organizationTaskReceipt(*charge, task)
		return nil
	})
	return receipt, granted && err == nil, err
}

func withLockedOrganizationTask(ctx context.Context, receipt OrganizationTaskReceipt, run func(*gorm.DB, Organization, *OrganizationWallet, *OrganizationCharge, Task) error) error {
	return withLockedOrganizationCharge(ctx, receipt.Charge, func(tx *gorm.DB, org Organization, wallet *OrganizationWallet, charge *OrganizationCharge) error {
		var task Task
		if err := organizationTaskQuery(lockForUpdate(tx), *charge).Where("id = ? AND task_id = ?", receipt.TaskRowID, receipt.PublicID).First(&task).Error; err != nil {
			return err
		}
		return run(tx, org, wallet, charge, task)
	})
}

func writeOrganizationTask(tx *gorm.DB, task Task, updates map[string]any) error {
	updates["billing_revision"] = task.BillingRevision + 1
	updates["updated_at"] = organizationNow().Unix()
	return organizationCAS(tx.Model(&Task{}).Where("id = ? AND billing_protocol = ? AND billing_revision = ? AND billing_state = ?",
		task.ID, OrganizationTaskBillingProtocol, task.BillingRevision, task.BillingState).Updates(updates))
}

// RecordOrganizationTaskHandle binds a confirmed acceptance to the task. A
// dispatch with an unknown handle stays held and is never selected for polling.
func RecordOrganizationTaskHandle(ctx context.Context, receipt OrganizationTaskReceipt, upstreamID string) error {
	if upstreamID == "" || len(upstreamID) > 128 || strings.ContainsAny(upstreamID, "\x00\r\n") {
		return ErrOrganizationInvalidInput
	}
	return withLockedOrganizationTask(ctx, receipt, func(tx *gorm.DB, _ Organization, _ *OrganizationWallet, charge *OrganizationCharge, task Task) error {
		if task.BillingState == TaskBillingReady && task.PrivateData.UpstreamTaskID == upstreamID && charge.State == OrganizationChargeDispatched {
			return nil
		}
		if charge.State != OrganizationChargeDispatched || task.BillingState != organizationTaskDispatched || task.PrivateData.UpstreamTaskID != "" {
			return ErrOrganizationConflict
		}
		task.PrivateData.UpstreamTaskID = upstreamID
		return writeOrganizationTask(tx, task, map[string]any{"private_data": task.PrivateData,
			"billing_state": TaskBillingReady, "status": TaskStatusSubmitted, "start_time": organizationNow().Unix()})
	})
}

func organizationTaskPollQuery(ctx context.Context, orgID int64, actorID int, policyHash string) *gorm.DB {
	return DB.WithContext(ctx).Model(&Task{}).Where("organization_id = ? AND user_id = ? AND billing_protocol = ? AND billing_state = ? AND billing_progress = ?",
		orgID, actorID, OrganizationTaskBillingProtocol, TaskBillingReady, policyHash)
}

func OrganizationTaskPollHighWater(ctx context.Context, orgID int64, actorID int, policyHash string) (int64, error) {
	var id int64
	err := organizationTaskPollQuery(ctx, orgID, actorID, policyHash).Select("COALESCE(MAX(id), 0)").Scan(&id).Error
	return id, err
}

// PendingOrganizationTasks paginates within a fixed pass so older unfinished
// work cannot starve newer tasks. The cursor follows queried rows even when
// another worker settles a row during this read.
func PendingOrganizationTasks(ctx context.Context, orgID int64, actorID int, policyHash string, after, through int64) ([]OrganizationTaskReceipt, int64, error) {
	db := DB.WithContext(ctx)
	var tasks []Task
	err := organizationTaskPollQuery(ctx, orgID, actorID, policyHash).Where("id > ? AND id <= ?", after, through).
		Order("id").Limit(20).Find(&tasks).Error
	if err != nil || len(tasks) == 0 {
		return nil, 0, err
	}
	receipts := make([]OrganizationTaskReceipt, 0, len(tasks))
	for _, task := range tasks {
		if task.BillingRef == nil || task.PrivateData.UpstreamTaskID == "" {
			return nil, 0, ErrOrganizationConflict
		}
		raw, ok := strings.CutPrefix(*task.BillingRef, "organization-charge-")
		id, err := strconv.ParseInt(raw, 10, 64)
		if !ok || err != nil || id <= 0 || *task.BillingRef != organizationTaskBillingRef(id) {
			return nil, 0, ErrOrganizationConflict
		}
		var charge OrganizationCharge
		if err := db.Where("id = ? AND organization_id = ? AND actor_user_id = ? AND policy_hash = ?", id, orgID, actorID, policyHash).
			First(&charge).Error; err != nil {
			return nil, 0, err
		}
		if charge.State == OrganizationChargeDispatched {
			receipts = append(receipts, organizationTaskReceipt(charge, task))
		}
	}
	return receipts, tasks[len(tasks)-1].ID, nil
}

func CancelUnsentOrganizationTask(ctx context.Context, receipt OrganizationTaskReceipt) error {
	return withLockedOrganizationTask(ctx, receipt, func(tx *gorm.DB, org Organization, wallet *OrganizationWallet, charge *OrganizationCharge, task Task) error {
		if task.BillingState == TaskBillingIntent {
			if err := applyOrganizationChargeTransition(tx, org, wallet, charge, OrganizationChargeReserved, OrganizationChargeReleased, 0); err != nil {
				return err
			}
			return writeOrganizationTask(tx, task, map[string]any{"billing_state": TaskBillingCancelled, "status": TaskStatusFailure,
				"progress": "100%", "finish_time": organizationNow().Unix()})
		}
		if task.BillingState == TaskBillingCancelled && charge.State == OrganizationChargeReleased && charge.DispatchedAt == 0 {
			return nil
		}
		return ErrOrganizationConflict
	})
}

// FinishOrganizationTask publishes the public terminal status and the charge
// transition as one commit, through the original wallet even after revocation.
func FinishOrganizationTask(ctx context.Context, receipt OrganizationTaskReceipt, actual int64, noCharge bool) error {
	if actual < 0 || actual > math.MaxInt32 || noCharge && actual != 0 {
		return ErrOrganizationInvalidInput
	}
	return withLockedOrganizationTask(ctx, receipt, func(tx *gorm.DB, org Organization, wallet *OrganizationWallet, charge *OrganizationCharge, task Task) error {
		if receipt.UpstreamID == "" || task.PrivateData.UpstreamTaskID != receipt.UpstreamID ||
			(task.BillingState != TaskBillingReady && task.BillingState != TaskBillingSettled) {
			return ErrOrganizationConflict
		}
		target, status := OrganizationChargeSettled, TaskStatus(TaskStatusSuccess)
		if noCharge {
			target, status = OrganizationChargeReleased, TaskStatus(TaskStatusFailure)
		}
		if task.BillingState == TaskBillingSettled && (task.Status != status || int64(task.Quota) != actual || charge.State != target) {
			return ErrOrganizationConflict
		}
		if err := applyOrganizationChargeTransition(tx, org, wallet, charge, OrganizationChargeDispatched, target, actual); err != nil {
			return err
		}
		if task.BillingState == TaskBillingSettled {
			return nil
		}
		return writeOrganizationTask(tx, task, map[string]any{"billing_state": TaskBillingSettled, "status": status, "quota": actual,
			"progress": "100%", "finish_time": organizationNow().Unix()})
	})
}
