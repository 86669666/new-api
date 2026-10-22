package service

import (
	"context"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// startOAuthSessionRevocation runs the process loop at most once.
var startOAuthSessionRevocation sync.Once

// StartOAuthSessionRevocation polls Hydra session deletes until the process
// exits. The goroutine is the process retry loop, not a bounded WaitGroup task.
func StartOAuthSessionRevocation() {
	startOAuthSessionRevocation.Do(func() {
		wake := make(chan struct{}, 1)
		model.SetOAuthRevocationWaker(func() {
			select {
			case wake <- struct{}{}:
			default:
			}
		})
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-wake:
				case <-ticker.C:
				}
				FlushOAuthSessionRevocations(context.Background())
			}
		}()
	})
}

// FlushOAuthSessionRevocations performs due admin deletes. A missing provider
// bridge completes the job after the relay keys were already disabled. Hydra
// errors stay queued and are logged without the token.
func FlushOAuthSessionRevocations(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		jobs, err := model.ListDueOAuthRevocations(20)
		if err != nil {
			common.SysError(common.LogText("oauth session revocation list failed"))
			return
		}
		if len(jobs) == 0 {
			return
		}
		bridge := CurrentOAuthProviderBridge()
		for _, job := range jobs {
			if ctx.Err() != nil {
				return
			}
			if bridge == nil || bridge.admin == "" {
				common.SysError(common.LogText("oauth session revocation skipped for user %d because the provider bridge is off", job.UserID))
				if err := model.CompleteOAuthRevocation(job.ID); err != nil {
					common.SysError(common.LogText("oauth session revocation failed for user %d", job.UserID))
				}
				continue
			}
			if err := bridge.RevokeSessions(ctx, job.UserID, job.ClientID); err != nil {
				common.SysError(common.LogText("oauth session revocation failed for user %d", job.UserID))
				_ = model.DeferOAuthRevocation(job.ID, job.Attempts+1, oauthRevocationNextAt(job.Attempts+1))
				continue
			}
			if err := model.CompleteOAuthRevocation(job.ID); err != nil {
				common.SysError(common.LogText("oauth session revocation failed for user %d", job.UserID))
			}
		}
		if len(jobs) < 20 {
			return
		}
	}
}

func oauthRevocationNextAt(attempts int) int64 {
	delay := int64(15)
	if attempts < 1 {
		attempts = 1
	}
	for range attempts - 1 {
		if delay >= 900 {
			break
		}
		delay *= 2
	}
	if delay > 900 {
		delay = 900
	}
	return common.GetTimestamp() + delay
}
