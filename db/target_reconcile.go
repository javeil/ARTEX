package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ReconcileTargetRequests releases only explicitly identified abandoned
// reservations after an administrator verifies remote execution has stopped.
// It never removes attempts from the cumulative or account-window counters.
func (d *DB) ReconcileTargetRequests(ctx context.Context, taskID string, ids []int64, actor, reason string) error {
	if len(ids) < 1 || len(ids) > 100 || strings.TrimSpace(reason) == "" || strings.TrimSpace(actor) == "" {
		return fmt.Errorf("需要 1..100 条请求 ID、操作者和核对原因")
	}
	ids = append([]int64(nil), ids...)
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for j, id := range ids {
		if id < 1 || j > 0 && ids[j-1] == id {
			return fmt.Errorf("请求 ID 无效或重复")
		}
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "target-task:"+taskID); err != nil {
		return err
	}
	var paused bool
	if err = tx.QueryRowContext(ctx, `SELECT paused FROM tasks WHERE id::text=$1 FOR UPDATE`, taskID).Scan(&paused); err != nil {
		return err
	}
	if !paused {
		return fmt.Errorf("请先暂停任务并确认远端执行已停止")
	}
	keys := map[string]bool{}
	for _, id := range ids {
		var key, state string
		if err = tx.QueryRowContext(ctx, `SELECT target_key,state FROM target_requests WHERE id=$1 AND task_id=$2`, id, taskID).Scan(&key, &state); err != nil {
			return err
		}
		if state != "running" {
			return fmt.Errorf("请求 #%d 不是待核对 running 记录", id)
		}
		keys[key] = true
	}
	ordered := []string{}
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "target-budget:"+key); err != nil {
			return err
		}
	}
	for _, id := range ids {
		var key string
		if err = tx.QueryRowContext(ctx, `UPDATE target_requests SET state='reconciled',error=$3,finished_at=now() WHERE id=$1 AND task_id=$2 AND state='running' RETURNING target_key`, id, taskID, "人工核对远端已停止；执行结果未知："+reason).Scan(&key); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO target_control_events(task_id,actor,action,reason,target_key) VALUES($1,$2,'reconcile_request',$3,$4)`, taskID, actor, fmt.Sprintf("request #%d: %s", id, reason), key); err != nil {
			return err
		}
	}
	return tx.Commit()
}
