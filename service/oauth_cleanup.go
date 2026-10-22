package service

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// OAuthCleanupHandler uses the existing durable scheduler; its wakeup channel
// is never the source of truth for a revocation. Issuance may be disabled while
// this handler continues to service a historical store.
type OAuthCleanupHandler struct{}

func (OAuthCleanupHandler) Type() string            { return "oauth_cleanup" }
func (OAuthCleanupHandler) Enabled() bool           { return model.OAuthCleanupReady() }
func (OAuthCleanupHandler) Interval() time.Duration { return 15 * time.Second }
func (OAuthCleanupHandler) NewPayload() any         { return nil }
func (OAuthCleanupHandler) Run(ctx context.Context, task *model.SystemTask, runnerID string) {
	code := ""
	count, err := RunOAuthCleanup(ctx, CurrentOAuthProviderBridge(), runnerID)
	status := model.SystemTaskStatusSucceeded
	if err != nil {
		status, code = model.SystemTaskStatusFailed, "oauth_cleanup_store_unavailable"
	}
	// Never persist an HTTP/driver error, which can contain request credentials.
	if err := model.FinishSystemTask(task.TaskID, runnerID, status, map[string]any{"processed": count}, code); err != nil {
		common.SysError(common.LogText("OAuth cleanup task result could not be persisted"))
	}
}

// RunOAuthCleanup performs at most twenty independently claimed events. A
// missing/mismatched bridge retains the job and never redirects it to an issuer
// taken from a database row. Only configured, TLS-verified Admin is contacted.
func RunOAuthCleanup(ctx context.Context, bridge *OAuthProviderBridge, owner string) (int, error) {
	if !model.OAuthCleanupReady() {
		return 0, nil
	}
	// Age only moves an abandoned sending permission into a permanent hold;
	// it never proves that the issuer stopped or permits remote deletion.
	var abandoned []model.OAuthOperation
	if err := model.DB.WithContext(ctx).Where("state = ? AND created_at < ?", "sent", time.Now().Unix()-60).Order("operation_ref").Limit(100).Find(&abandoned).Error; err != nil {
		return 0, err
	}
	for i := range abandoned {
		if err := model.HoldOAuthOperation(&abandoned[i], time.Now().Unix()-60); err != nil {
			return 0, err
		}
	}
	if err := model.ReconcileExpiredOAuthGrants(ctx); err != nil {
		return 0, err
	}
	var jobs []model.OAuthCleanupJob
	now := time.Now().Unix()
	if err := model.DB.WithContext(ctx).Where("state <> ? AND next_attempt_at <= ?", "complete", now).Order("next_attempt_at, job_ref").Limit(20).Find(&jobs).Error; err != nil {
		return 0, err
	}
	count := 0
	for _, seed := range jobs {
		job, err := model.ClaimOAuthCleanup(ctx, seed.JobRef, owner, time.Now().Unix())
		if err != nil {
			return count, err
		}
		if job == nil {
			continue
		}
		code, retry := "configuration", int64(0)
		if bridge != nil && bridge.resource != nil && bridge.resource.issuer == job.Issuer {
			callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			code, retry = bridge.cleanOAuthJob(callCtx, job)
			cancel()
		}
		if err := model.FinishOAuthCleanup(ctx, job, code, retry); err != nil {
			return count, err
		}
		if code != "" {
			common.SysLog(common.LogText("OAuth cleanup deferred: event=%s state=%s attempt=%d", job.JobRef, code, job.Attempt))
		}
		count++
	}
	return count, nil
}

func (b *OAuthProviderBridge) cleanOAuthJob(ctx context.Context, job *model.OAuthCleanupJob) (string, int64) {
	var targets []model.OAuthCleanupTarget
	if common.UnmarshalJsonStr(job.Targets, &targets) != nil {
		return "configuration", 0
	}
	type removal struct {
		path  string
		query url.Values
	}
	var removals []removal
	switch job.Scope {
	case "user":
		removals = append(removals, removal{"consent", url.Values{"subject": {job.Subject}, "all": {"true"}}}, removal{"login", url.Values{"subject": {job.Subject}}})
	case "client":
		removals = append(removals, removal{"consent", url.Values{"subject": {job.Subject}, "client": {job.Value}}})
	default:
		for _, target := range targets {
			if target.ConsentID != "" {
				removals = append(removals, removal{"consent", url.Values{"consent_request_id": {target.ConsentID}}})
			}
		}
	}
	if job.Scope != "user" {
		for _, target := range targets {
			if target.LoginSID != "" {
				removals = append(removals, removal{"login", url.Values{"sid": {target.LoginSID}}})
			}
		}
		// An accepted login without a trusted Hydra SID cannot safely be widened to
		// subject logout. Retain the scope until a separate recovery is proven.
		if len(targets) == 0 {
			return "configuration", 0
		}
	}
	for _, removal := range removals {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.admin+"/admin/oauth2/auth/sessions/"+removal.path+"?"+removal.query.Encode(), nil)
		if err != nil {
			return "configuration", 0
		}
		req.Header.Set("Accept", "application/json")
		response, err := b.resource.client.Do(req)
		if err != nil {
			return "unavailable", 0
		}
		size, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
		response.Body.Close()
		if readErr != nil || size > 4096 {
			return "unavailable", 0
		}
		if response.StatusCode == http.StatusNoContent {
			continue
		}
		if response.StatusCode == http.StatusTooManyRequests {
			retry, _ := strconv.ParseInt(response.Header.Get("Retry-After"), 10, 64)
			return "rate_limited", min(max(retry, 0), 3600)
		}
		if response.StatusCode >= 500 {
			return "unavailable", 0
		}
		return "configuration", 0
	}
	return "", 0
}

func oauthOperationFromActor(issuer, client, kind, grant string, actor AuthIdentity) *model.OAuthOperation {
	return &model.OAuthOperation{Issuer: issuer, ClientID: client, Kind: kind, GrantRef: grant, UserID: actor.UserID, OriginSID: actor.SessionID, AuthVersion: actor.UserAuthVersion, SessionVersion: actor.SessionVersion}
}

// finishOAuthAttempt is a deferred fail-closed fallback. A failed store update
// leaves the already committed sent row in place, which blocks cleanup/sends.
func finishOAuthAttempt(op *model.OAuthOperation, published *bool) {
	if op == nil || *published {
		return
	}
	if err := model.HoldOAuthOperation(op, 0); err != nil {
		common.SysError(common.LogText("OAuth uncertain operation could not be reconciled"))
	}
}
