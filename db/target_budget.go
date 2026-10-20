package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// BeginTargetRequest atomically reserves actual target traffic. RPS, concurrent
// requests and account windows are shared across tasks/instances for the service;
// MaxRequests is the engagement's total request budget. No model/worker cache can
// reset these counters.
func (d *DB) BeginTargetRequest(ctx context.Context, taskID string, target Target, method, account string, budget TargetBudget) (int64, error) {
	version, err := d.AuthorizationVersion(ctx, taskID)
	if err != nil {
		return 0, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "target-task:"+taskID); err != nil {
		return 0, err
	}
	key := target.ServiceKey()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "target-budget:"+key); err != nil {
		return 0, err
	}
	var until *time.Time
	var reason string
	err = tx.QueryRowContext(ctx, `SELECT blocked_until,reason FROM target_safety_state WHERE target_key=$1`, key).Scan(&until, &reason)
	if err == nil && until != nil && time.Now().Before(*until) {
		return 0, fmt.Errorf("目标安全冷却至 %s：%s", until.Format(time.RFC3339), reason)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	raw, _ := json.Marshal(budget)
	if _, err = tx.ExecContext(ctx, `INSERT INTO target_budget_claims(task_id,target_key,budget) VALUES ($1,$2,$3::jsonb) ON CONFLICT(task_id,target_key) DO UPDATE SET budget=excluded.budget`, taskID, key, raw); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.budget FROM target_budget_claims c JOIN tasks t ON t.id::text=c.task_id WHERE c.target_key=$1 AND NOT t.paused AND NOT t.queued AND t.archived_at IS NULL AND t.status NOT IN ('done','failed','timeout')`, key)
	if err != nil {
		return 0, err
	}
	budgets := []TargetBudget{budget}
	for rows.Next() {
		var b []byte
		var v TargetBudget
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return 0, err
		}
		if err := json.Unmarshal(b, &v); err != nil {
			rows.Close()
			return 0, err
		}
		budgets = append(budgets, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	strict := func(selectValue func(TargetBudget) int) int {
		out := 0
		for _, b := range budgets {
			v := selectValue(b)
			if v > 0 && (out == 0 || v < out) {
				out = v
			}
		}
		return out
	}
	var active, recent, total int
	var earliestRecent *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE state='running'),count(*) FILTER (WHERE started_at>clock_timestamp()-interval '1 second'),min(started_at) FILTER (WHERE started_at>clock_timestamp()-interval '1 second') FROM target_requests WHERE target_key=$1 AND state<>'denied' AND (state='running' OR started_at>clock_timestamp()-interval '1 second')`, key).Scan(&active, &recent, &earliestRecent); err != nil {
		return 0, err
	}
	if budget.MaxRequests > 0 {
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM target_requests WHERE task_id=$1 AND state<>'denied'`, taskID).Scan(&total); err != nil {
			return 0, err
		}
		if total >= budget.MaxRequests {
			return 0, fmt.Errorf("本任务累计目标请求预算已达上限 %d", budget.MaxRequests)
		}
	}
	digest := ""
	if account != "" {
		sum := sha256.Sum256([]byte(account))
		digest = hex.EncodeToString(sum[:])
	}
	if digest != "" {
		for _, b := range budgets {
			if b.AccountAttempts <= 0 {
				continue
			}
			var attempts int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM target_requests WHERE target_key=$1 AND state<>'denied' AND account_hash=$2 AND started_at>clock_timestamp()-($3 * interval '1 second')`, key, digest, b.AccountWindowSeconds).Scan(&attempts); err != nil {
				return 0, err
			}
			if attempts >= b.AccountAttempts {
				return 0, fmt.Errorf("目标账号尝试预算已达上限，等待授权窗口重置")
			}
		}
	}
	// Check hard engagement/account limits before suggesting a capacity wait.
	if cap := strict(func(b TargetBudget) int { return b.MaxConcurrent }); cap > 0 && active >= cap {
		return 0, &TargetCapacityError{Message: fmt.Sprintf("目标并发预算已达上限 %d", cap), RetryAfter: 250 * time.Millisecond}
	}
	if cap := strict(func(b TargetBudget) int { return b.RequestsPerSecond }); cap > 0 && recent >= cap {
		delay := 100 * time.Millisecond
		if earliestRecent != nil {
			delay = time.Until(earliestRecent.Add(time.Second))
		}
		return 0, &TargetCapacityError{Message: fmt.Sprintf("目标速率预算已达上限 %d/s", cap), RetryAfter: delay}
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO target_requests(task_id,target_key,url,method,account_hash,budget,started_at,authorization_epoch,authorization_version) VALUES ($1,$2,$3,$4,$5,$6::jsonb,clock_timestamp(),COALESCE((SELECT authorization_epoch FROM tasks WHERE id::text=$1),0),$7) RETURNING id`, taskID, key, target.URL, method, digest, raw, version).Scan(&id)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (d *DB) FinishTargetRequest(ctx context.Context, id int64, status, latencyMS int, requestErr string, retryAfterSeconds int, signals ...string) error {
	return d.FinishTargetRequestOutcome(ctx, id, status, latencyMS, requestErr, "", retryAfterSeconds, signals...)
}

func (d *DB) FinishTargetRequestOutcome(ctx context.Context, id int64, status, latencyMS int, requestErr, errorKind string, retryAfterSeconds int, signals ...string) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var key string
	var raw []byte
	// Use the same service-lock order as reserve/reconcile before touching the
	// request row, so operator recovery cannot deadlock an in-flight completion.
	if err = tx.QueryRowContext(ctx, `SELECT target_key FROM target_requests WHERE id=$1`, id).Scan(&key); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "target-budget:"+key); err != nil {
		return err
	}
	err = tx.QueryRowContext(ctx, `UPDATE target_requests SET state='finished',status_code=$2,latency_ms=$3,error=$4,error_kind=$5,finished_at=now() WHERE id=$1 AND state='running' RETURNING target_key,budget`, id, status, latencyMS, requestErr, errorKind).Scan(&key, &raw)
	if err != nil {
		return err
	}

	var b TargetBudget
	if err = json.Unmarshal(raw, &b); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO target_safety_state(target_key) VALUES ($1) ON CONFLICT DO NOTHING`, key); err != nil {
		return err
	}
	var sharedFailures, sharedLatency, sharedCooldown int
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(min((c.budget->>'consecutive_failures')::int) FILTER(WHERE (c.budget->>'consecutive_failures')::int>0),0),COALESCE(min((c.budget->>'max_latency_ms')::int) FILTER(WHERE (c.budget->>'max_latency_ms')::int>0),0),COALESCE(max((c.budget->>'cooldown_seconds')::int),0) FROM target_budget_claims c JOIN tasks t ON t.id::text=c.task_id WHERE c.target_key=$1 AND NOT t.paused AND NOT t.queued AND t.archived_at IS NULL AND t.status NOT IN ('done','failed','timeout')`, key).Scan(&sharedFailures, &sharedLatency, &sharedCooldown); err != nil {
		return err
	}
	if sharedFailures > 0 && (b.ConsecutiveFailures == 0 || sharedFailures < b.ConsecutiveFailures) {
		b.ConsecutiveFailures = sharedFailures
	}
	if sharedLatency > 0 && (b.MaxLatencyMS == 0 || sharedLatency < b.MaxLatencyMS) {
		b.MaxLatencyMS = sharedLatency
	}
	if sharedCooldown > b.CooldownSeconds {
		b.CooldownSeconds = sharedCooldown
	}
	failed := status >= 500 || requestErr != "" || (b.MaxLatencyMS > 0 && latencyMS > b.MaxLatencyMS)
	var failures int
	if err = tx.QueryRowContext(ctx, `UPDATE target_safety_state SET consecutive_failures=CASE WHEN $2 THEN consecutive_failures+1 ELSE 0 END WHERE target_key=$1 RETURNING consecutive_failures`, key, failed).Scan(&failures); err != nil {
		return err
	}
	reason := ""
	cooldown := b.CooldownSeconds
	if cooldown <= 0 {
		cooldown = 60
	}
	if status == 429 {
		reason = "目标返回 429"
		if retryAfterSeconds > cooldown {
			cooldown = retryAfterSeconds
		}
	}
	locked := status == 423
	for _, signal := range signals {
		locked = locked || signal == "account_locked"
	}
	if locked {
		reason = "目标报告账号锁定"
	}
	if b.ConsecutiveFailures > 0 && failures >= b.ConsecutiveFailures {
		reason = "目标连续失败或健康指标超限"
	}
	if reason != "" {
		if cooldown > 86400 {
			cooldown = 86400
		}
		if _, err = tx.ExecContext(ctx, `UPDATE target_safety_state SET blocked_until=GREATEST(COALESCE(blocked_until,now()),now()+($2 * interval '1 second')),reason=$3 WHERE target_key=$1`, key, cooldown, reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type TargetRequestRecord struct {
	ID         int64      `json:"id"`
	TaskID     string     `json:"task_id"`
	TargetKey  string     `json:"target_key"`
	URL        string     `json:"url"`
	Method     string     `json:"method"`
	State      string     `json:"state"`
	Status     int        `json:"status_code"`
	LatencyMS  int        `json:"latency_ms"`
	Error      string     `json:"error"`
	ErrorKind  string     `json:"error_kind"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (d *DB) ListTargetRequests(ctx context.Context, id string, before int64, limit int) ([]TargetRequestRecord, error) {
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := d.QueryContext(ctx, `SELECT id,task_id,target_key,url,method,state,status_code,latency_ms,error,error_kind,started_at,finished_at FROM target_requests WHERE task_id=$1 AND ($2::bigint=0 OR id<$2) ORDER BY id DESC LIMIT $3`, id, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TargetRequestRecord{}
	for rows.Next() {
		var r TargetRequestRecord
		if err := rows.Scan(&r.ID, &r.TaskID, &r.TargetKey, &r.URL, &r.Method, &r.State, &r.Status, &r.LatencyMS, &r.Error, &r.ErrorKind, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) RecordDeniedTargetRequest(ctx context.Context, taskID string, target Target, method, reason string) error {
	version, err := d.AuthorizationVersion(ctx, taskID)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `INSERT INTO target_requests(task_id,target_key,url,method,budget,state,status_code,error,error_kind,authorization_version,authorization_epoch,finished_at)
 VALUES ($1,$2,$3,$4,'{}','denied',403,$5,'control',$6,COALESCE((SELECT authorization_epoch FROM tasks WHERE id::text=$1),0),clock_timestamp())`, taskID, target.ServiceKey(), target.URL, method, reason, version)
	return err
}
func (d *DB) TargetHasAccountBudget(ctx context.Context, key string) (bool, error) {
	var enabled bool
	e := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM target_budget_claims c JOIN tasks t ON t.id::text=c.task_id WHERE c.target_key=$1 AND COALESCE((c.budget->>'account_attempts')::int,0)>0 AND NOT t.paused AND NOT t.queued AND t.archived_at IS NULL AND t.status NOT IN ('done','failed','timeout'))`, key).Scan(&enabled)
	return enabled, e
}
