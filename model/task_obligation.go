package model

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const (
	TaskBillingIntent    = "intent"
	TaskBillingClaimed   = "send_claimed"
	TaskBillingPending   = "pending"
	TaskBillingReady     = "ready"
	TaskBillingSettled   = "settled"
	TaskBillingHeld      = "held"
	TaskBillingCancelled = "cancelled"
)

var ErrTaskObligationConflict = errors.New("task obligation state conflict")

// TaskBillingProgress contains accounting facts only. Request bodies, credentials,
// provider responses and current account preferences are never recovery authority.
type TaskBillingProgress struct {
	SubmitURL   string     `json:"submit_url,omitempty"`
	UserID      int        `json:"user_id"`
	TokenID     int        `json:"token_id"`
	Unlimited   bool       `json:"unlimited"`
	Applied     int        `json:"applied"`
	Target      int        `json:"target"`
	TargetKnown bool       `json:"target_known"`
	Status      TaskStatus `json:"status"`
	Progress    string     `json:"progress"`
}

func taskWalletUnresolved(tx *gorm.DB, userID int, exceptID int64) error {
	var count int64
	if err := tx.Model(&Task{}).Where("user_id = ? AND billing_protocol = 1 AND id <> ? AND billing_state IN ?", userID, exceptID,
		[]string{TaskBillingIntent, TaskBillingClaimed, TaskBillingPending, TaskBillingHeld}).Count(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return ErrTaskObligationConflict
	}
	return nil
}

func decodeTaskBilling(task *Task) (TaskBillingProgress, error) {
	var p TaskBillingProgress
	if task.BillingProtocol != 1 || task.BillingRef == nil || *task.BillingRef == "" || task.BillingProgress == "" {
		return p, ErrTaskObligationConflict
	}
	if err := common.UnmarshalJsonStr(task.BillingProgress, &p); err != nil {
		return p, err
	}
	if p.UserID != task.UserId || task.OrganizationID != 0 || p.TokenID < 0 || p.Applied < 0 || p.Target < 0 ||
		p.Applied > common.MaxWalletQuota || p.Target > common.MaxWalletQuota || task.Quota != p.Applied {
		return p, ErrTaskObligationConflict
	}
	return p, nil
}

func encodeTaskBilling(task *Task, p TaskBillingProgress) error {
	b, err := common.Marshal(p)
	if err != nil {
		return err
	}
	task.BillingProgress = string(b)
	return nil
}

// walletTaskTransaction always locks User -> Token -> Task, then rechecks the
// owner read used to locate those locks. Historical settlement ignores current
// token/grant status and retains the original finite/unlimited accounting fact.
func walletTaskTransaction(ctx context.Context, id int64, fn func(*gorm.DB, *User, *Token, *Task, *TaskBillingProgress) error) error {
	var locator Task
	if err := DB.WithContext(ctx).Select("id", "user_id", "quota", "organization_id", "billing_ref", "billing_protocol", "billing_progress").First(&locator, id).Error; err != nil {
		return err
	}
	original, err := decodeTaskBilling(&locator)
	if err != nil {
		return err
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, original.UserID); err != nil {
			return err
		}
		var user User
		if err := lockForUpdate(tx).First(&user, original.UserID).Error; err != nil {
			return err
		}
		var token Token
		if original.TokenID != 0 {
			if err := lockForUpdate(tx.Unscoped()).First(&token, original.TokenID).Error; err != nil {
				return err
			}
			if token.UserId != original.UserID {
				return ErrTaskObligationConflict
			}
		}
		var task Task
		if err := lockForUpdate(tx).First(&task, id).Error; err != nil {
			return err
		}
		p, err := decodeTaskBilling(&task)
		if err != nil {
			return err
		}
		if p.UserID != original.UserID || p.TokenID != original.TokenID || p.Unlimited != original.Unlimited || *task.BillingRef != *locator.BillingRef {
			return ErrTaskObligationConflict
		}
		revision := task.BillingRevision
		if err := fn(tx, &user, &token, &task, &p); err != nil {
			return err
		}
		if err := encodeTaskBilling(&task, p); err != nil {
			return err
		}
		task.BillingRevision++
		result := tx.Model(&Task{}).Where("id = ? AND billing_protocol = 1 AND billing_revision = ?", id, revision).Select("*").Omit("id").Updates(&task)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrTaskObligationConflict
		}
		return nil
	})
}

// applyWalletTaskDelta changes SQL money and the applied marker in the caller's
// transaction. There are no Redis writes, delayed financial batches or nested DB
// transactions. A negative delta is a historical credit, never new admission.
func applyWalletTaskDelta(tx *gorm.DB, user *User, token *Token, p *TaskBillingProgress, target int) error {
	if target < 0 || target > common.MaxWalletQuota {
		return ErrWalletQuotaLimitExceeded
	}
	delta := target - p.Applied
	if user.Quota < -common.MaxWalletQuota || user.Quota > common.MaxWalletQuota ||
		delta > 0 && user.Quota < -common.MaxWalletQuota+delta || delta < 0 && user.Quota > common.MaxWalletQuota+delta {
		return ErrWalletQuotaLimitExceeded
	}
	if p.TokenID != 0 && (token.RemainQuota < -common.MaxWalletQuota || token.RemainQuota > common.MaxWalletQuota ||
		token.UsedQuota < -common.MaxWalletQuota || token.UsedQuota > common.MaxWalletQuota ||
		delta > 0 && (token.RemainQuota < -common.MaxWalletQuota+delta || token.UsedQuota > common.MaxWalletQuota-delta) ||
		delta < 0 && (token.RemainQuota > common.MaxWalletQuota+delta || token.UsedQuota < -common.MaxWalletQuota-delta)) {
		return ErrWalletQuotaLimitExceeded
	}
	if delta != 0 {
		if err := tx.Model(&User{}).Where("id = ?", p.UserID).UpdateColumn("quota", user.Quota-delta).Error; err != nil {
			return err
		}
		if p.TokenID != 0 {
			if err := tx.Unscoped().Model(&Token{}).Where("id = ?", p.TokenID).Updates(map[string]any{"remain_quota": token.RemainQuota - delta, "used_quota": token.UsedQuota + delta, "accessed_time": common.GetTimestamp()}).Error; err != nil {
				return err
			}
		}
	}
	p.Applied = target
	return nil
}

// CreateWalletTaskObligation persists ownership and the initial debit together,
// before any send permission exists. A failed/ambiguous commit never permits wire.
func CreateWalletTaskObligation(ctx context.Context, task *Task, tokenID, quota int) error {
	if task == nil || task.ID != 0 || task.UserId <= 0 || task.OrganizationID != 0 || task.TaskID == "" || len(task.TaskID) > 64 || tokenID < 0 || quota < 0 || quota > common.MaxWalletQuota {
		return ErrTaskObligationConflict
	}
	ref := task.TaskID
	task.BillingRef = &ref
	task.BillingProtocol = 1
	task.BillingState = TaskBillingIntent
	task.Status = TaskStatusUnknown
	task.Progress = "0%"
	task.PrivateData.Key = ""
	p := TaskBillingProgress{UserID: task.UserId, TokenID: tokenID}
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, task.UserId); err != nil {
			return err
		}
		var user User
		if err := lockForUpdate(tx).First(&user, task.UserId).Error; err != nil {
			return err
		}
		var token Token
		if tokenID != 0 {
			if err := lockForUpdate(tx).First(&token, tokenID).Error; err != nil {
				return err
			}
			if token.UserId != task.UserId || token.Status != common.TokenStatusEnabled || token.ExpiredTime != -1 && token.ExpiredTime <= common.GetTimestamp() {
				return ErrTaskObligationConflict
			}
			p.Unlimited = token.UnlimitedQuota
			if !p.Unlimited && token.RemainQuota < quota {
				return ErrTaskObligationConflict
			}
		}
		if err := oauthTextUnresolved(tx, task.UserId, ""); err != nil {
			return err
		}
		if err := taskWalletUnresolved(tx, task.UserId, 0); err != nil {
			return err
		}
		if quota > 0 && user.Quota < quota {
			return ErrTaskObligationConflict
		}
		if err := encodeTaskBilling(task, p); err != nil {
			return err
		}
		if err := tx.Create(task).Error; err != nil {
			return err
		}
		if err := applyWalletTaskDelta(tx, &user, &token, &p, quota); err != nil {
			return err
		}
		task.Quota = p.Applied
		if err := encodeTaskBilling(task, p); err != nil {
			return err
		}
		return tx.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]any{"quota": task.Quota, "billing_progress": task.BillingProgress}).Error
	})
	if err == nil {
		invalidateWalletTaskProjection(task.UserId, tokenID)
	}
	return err
}

func invalidateWalletTaskProjection(userID, tokenID int) {
	_ = cacheDecrUserQuota(userID, 0)
	if tokenID != 0 {
		// Key stays transient and is not part of the durable obligation.
		if token, err := GetTokenById(tokenID); err == nil {
			_ = invalidateTokenCacheForMutation(token.Key)
		}
	}
}

func ClaimWalletTaskSend(ctx context.Context, id int64, selectedURL ...string) error {
	return walletTaskTransaction(ctx, id, func(tx *gorm.DB, user *User, token *Token, t *Task, p *TaskBillingProgress) error {
		if t.BillingState != TaskBillingIntent || user.Status != common.UserStatusEnabled || p.TokenID != 0 && (token.DeletedAt.Valid || token.Status != common.TokenStatusEnabled || token.UnlimitedQuota != p.Unlimited || token.ExpiredTime != -1 && token.ExpiredTime <= common.GetTimestamp()) {
			return ErrTaskObligationConflict
		}
		if err := oauthTextUnresolved(tx, p.UserID, ""); err != nil {
			return err
		}
		if err := taskWalletUnresolved(tx, p.UserID, id); err != nil {
			return err
		}
		if len(selectedURL) == 1 && selectedURL[0] == "https://ark.cn-beijing.volces.com/api/v3/contents/generations/tasks" {
			p.SubmitURL = selectedURL[0]
		}
		t.BillingState = TaskBillingClaimed
		return nil
	})
}

// StageWalletTaskOutcome stores a known server-priced target before adjusting
// money. Existing Task columns hold the result; billing progress holds no payload.
// The public status stays UNKNOWN until reconciliation commits the target.
func StageWalletTaskOutcome(ctx context.Context, snapshot *Task, target int) error {
	if snapshot == nil || target < 0 || target > common.MaxWalletQuota {
		return ErrTaskObligationConflict
	}
	return walletTaskTransaction(ctx, snapshot.ID, func(_ *gorm.DB, _ *User, _ *Token, t *Task, p *TaskBillingProgress) error {
		if t.BillingState != TaskBillingClaimed && t.BillingState != TaskBillingReady {
			return ErrTaskObligationConflict
		}
		if snapshot.BillingRevision != t.BillingRevision || snapshot.UserId != p.UserID || snapshot.OrganizationID != 0 || snapshot.ChannelId != t.ChannelId {
			return ErrTaskObligationConflict
		}
		ref, protocol, revision, progress := t.BillingRef, t.BillingProtocol, t.BillingRevision, t.BillingProgress
		*t = *snapshot
		t.BillingRef, t.BillingProtocol, t.BillingRevision, t.BillingProgress = ref, protocol, revision, progress
		t.PrivateData.Key = ""
		t.PrivateData.TokenId = p.TokenID
		t.PrivateData.BillingSource = "wallet"
		t.PrivateData.SubscriptionId = 0
		p.Target, p.TargetKnown, p.Status, p.Progress = target, true, snapshot.Status, snapshot.Progress
		t.Status, t.Progress, t.Quota = TaskStatusUnknown, "0%", p.Applied
		t.BillingState = TaskBillingPending
		return nil
	})
}

func ReconcileWalletTask(ctx context.Context, id int64) error {
	var userID, tokenID int
	err := walletTaskTransaction(ctx, id, func(tx *gorm.DB, u *User, token *Token, t *Task, p *TaskBillingProgress) error {
		if t.BillingState == TaskBillingReady || t.BillingState == TaskBillingSettled || t.BillingState == TaskBillingCancelled {
			return nil
		}
		if t.BillingState != TaskBillingPending || !p.TargetKnown {
			return ErrTaskObligationConflict
		}
		if err := applyWalletTaskDelta(tx, u, token, p, p.Target); err != nil {
			return err
		}
		t.Quota, t.Status, t.Progress = p.Applied, p.Status, p.Progress
		t.BillingState = TaskBillingReady
		if t.Status == TaskStatusSuccess || t.Status == TaskStatusFailure {
			t.BillingState = TaskBillingSettled
		}
		userID, tokenID = p.UserID, p.TokenID
		return nil
	})
	if err == nil && userID != 0 {
		invalidateWalletTaskProjection(userID, tokenID)
	}
	return err
}

func CancelUnclaimedWalletTask(ctx context.Context, id int64) error {
	var userID, tokenID int
	err := walletTaskTransaction(ctx, id, func(tx *gorm.DB, u *User, token *Token, t *Task, p *TaskBillingProgress) error {
		if t.BillingState == TaskBillingCancelled {
			return nil
		}
		if t.BillingState != TaskBillingIntent {
			return ErrTaskObligationConflict
		}
		if err := applyWalletTaskDelta(tx, u, token, p, 0); err != nil {
			return err
		}
		p.Target, p.TargetKnown = 0, true
		t.Quota, t.Status, t.Progress = 0, TaskStatusFailure, "100%"
		t.BillingState = TaskBillingCancelled
		userID, tokenID = p.UserID, p.TokenID
		return nil
	})
	if err == nil && userID != 0 {
		invalidateWalletTaskProjection(userID, tokenID)
	}
	return err
}

// HoldWalletTask preserves ownership without converting an uncertain outcome
// into a refund or another permission to send. Pending known money is recoverable.
func HoldWalletTask(ctx context.Context, id int64) error {
	return walletTaskTransaction(ctx, id, func(_ *gorm.DB, _ *User, _ *Token, t *Task, _ *TaskBillingProgress) error {
		if t.BillingState == TaskBillingPending || t.BillingState == TaskBillingSettled || t.BillingState == TaskBillingCancelled {
			return ErrTaskObligationConflict
		}
		t.BillingState = TaskBillingHeld
		t.Status = TaskStatusUnknown
		t.Progress = "0%"
		return nil
	})
}

// PendingWalletTasks is independent of execution status: immediate SUCCESS and
// per-call results with an unapplied target must still be reconciled after restart.
func PendingWalletTasks(ctx context.Context, limit int) ([]Task, error) {
	var tasks []Task
	err := DB.WithContext(ctx).Where("billing_protocol = 1 AND billing_state = ?", TaskBillingPending).Order("id").Limit(limit).Find(&tasks).Error
	return tasks, err
}

// WalletTaskReadQueryURL is an explicitly documented provider read contract,
// bound to the exact server-selected submission endpoint captured before wire.
// It is not inferred from a plugin name, GET method, key format or client input.
// Contract: https://console.volcengine.com/ark/region%3Acn-beijing/docs/get-video-generation-task-api
func WalletTaskReadQueryURL(task *Task) (string, error) {
	p, err := decodeTaskBilling(task)
	if err != nil || task.BillingState != TaskBillingReady || p.SubmitURL != "https://ark.cn-beijing.volces.com/api/v3/contents/generations/tasks" {
		return "", ErrTaskObligationConflict
	}
	id := task.PrivateData.UpstreamTaskID
	if len(id) == 0 || len(id) > 191 {
		return "", ErrTaskObligationConflict
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", ErrTaskObligationConflict
		}
	}
	return p.SubmitURL + "/" + id, nil
}
