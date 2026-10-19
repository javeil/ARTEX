package intercept

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/db"
)

const targetCapacityWaitLimit = 30 * time.Second

// Reserve only actual outbound requests. Retrying a rolled-back capacity claim
// neither sends traffic nor consumes account/total counters. Every attempt uses
// the same authorization version and the DB's shared atomic budget checks.
func (i *Interceptor) reserveTargetCapacity(ctx context.Context, op Operation, budget db.TargetBudget, version string) (int64, error) {
	waitCtx, cancel := context.WithTimeout(ctx, targetCapacityWaitLimit)
	defer cancel()
	id := TaskIDFromContext(ctx)
	for {
		if err := waitCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return 0, fmt.Errorf("等待目标速率/并发额度超时，未发送请求")
		}
		current, err := i.db.AuthorizationVersion(waitCtx, id)
		if err != nil {
			return 0, err
		}
		if current != version {
			return 0, fmt.Errorf("等待目标额度期间授权或策略已变化，请重新发起请求")
		}
		if err = i.CheckTarget(waitCtx, op.Target.URL); err != nil {
			return 0, err
		}
		requestID, err := i.db.BeginTargetRequest(waitCtx, id, op.Target, op.Method, op.Account, budget)
		var capacity *db.TargetCapacityError
		if !errors.As(err, &capacity) {
			return requestID, err
		}
		delay := capacity.RetryAfter
		if delay < 25*time.Millisecond {
			delay = 25 * time.Millisecond
		}
		if delay > time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return 0, fmt.Errorf("等待目标速率/并发额度超时，未发送请求：%s", capacity.Error())
		case <-timer.C:
		}
	}
}
