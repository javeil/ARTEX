package intercept

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

type TaskPauseHandler func(string, *db.ExecutionBlock) error

func (i *Interceptor) SetTaskPauseHandler(handler TaskPauseHandler) {
	i.mu.Lock()
	i.pauseHandler = handler
	i.mu.Unlock()
}
func (i *Interceptor) CanRequestOperator() bool {
	if i == nil {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.pauseHandler != nil
}

// The caller can own a target lease. Block admission immediately, then use the
// server's normal pause/drain path asynchronously to avoid waiting on itself.
func (i *Interceptor) requestPause(id string, block *db.ExecutionBlock) error {
	i.mu.RLock()
	handler := i.pauseHandler
	i.mu.RUnlock()
	if handler == nil || id == "" {
		return fmt.Errorf("任务暂停控制器不可用")
	}
	if i.db != nil && block.AuthorizationEpoch == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := i.db.QueryRowContext(ctx, `SELECT authorization_epoch FROM tasks WHERE id::text=$1`, id).Scan(&block.AuthorizationEpoch)
		cancel()
		if err != nil {
			return fmt.Errorf("读取任务暂停周期失败: %w", err)
		}
	}
	if _, loaded := i.pausing.LoadOrStore(id, true); loaded {
		return nil
	}
	i.runtime.mu.Lock()
	i.targetStateLocked(id).blocked = true
	i.runtime.mu.Unlock()
	i.CancelTargetIO(id)
	go func() {
		defer i.pausing.Delete(id)
		if err := handler(id, block); err != nil {
			log.Printf("[task-progress] task %s pause failed; target access remains blocked: %v", id, err)
		}
	}()
	return nil
}
func (i *Interceptor) CheckProgress(ctx context.Context, id string) error {
	if i == nil || i.db == nil || id == "" {
		return nil
	}
	block, err := i.db.TaskExecutionBlock(ctx, id)
	if err != nil {
		failure := fmt.Errorf("无法检查任务停手条件：%w", err)
		i.requestPause(id, &db.ExecutionBlock{Code: "progress_check_failed", Reason: failure.Error()})
		return failure
	}
	if block != nil {
		i.requestPause(id, block)
		return block
	}
	return nil
}
func (i *Interceptor) observeProgress(ctx context.Context, id string) {
	bound, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := i.CheckProgress(bound, id); err != nil {
		var b *db.ExecutionBlock
		if !errors.As(err, &b) {
			i.requestPause(id, &db.ExecutionBlock{Code: "progress_check_failed", Reason: err.Error()})
		}
	}
}
func (i *Interceptor) RequestOperator(ctx context.Context, reason string) error {
	id := TaskIDFromContext(ctx)
	reason = strings.TrimSpace(reason)
	if id == "" || !i.CanRequestOperator() {
		return fmt.Errorf("没有可用的任务暂停控制器")
	}
	if reason == "" || len([]rune(reason)) > 2000 {
		return fmt.Errorf("请填写 1..2000 字的具体原因与已完成检查")
	}
	return i.requestPause(id, &db.ExecutionBlock{Code: "operator_required", Reason: reason})
}
