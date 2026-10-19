package db

import (
	"context"
	"time"
)

// ToolCallAudit is one bounded, durable entry per PreToolUse invocation. Decision
// retains ask while EffectiveAction tracks its resolution. It records decisions,
// not execution success (intercept_pending's detailed trace has that lifecycle).
type ToolCallAudit struct {
	ID              int64     `json:"id"`
	TaskID          string    `json:"task_id"`
	ToolName        string    `json:"tool_name"`
	InputSummary    string    `json:"input_summary"`
	Decision        string    `json:"decision"`
	EffectiveAction string    `json:"effective_action"`
	Source          string    `json:"decision_source"`
	Reason          string    `json:"reason"`
	CreatedAt       time.Time `json:"created_at"`
}

func (d *DB) SaveToolCallAudit(ctx context.Context, a *ToolCallAudit) error {
	if a.ID != 0 {
		_, err := d.ExecContext(ctx, `UPDATE tool_call_audit SET decision=$2,effective_action=$3,decision_source=$4,reason=$5 WHERE id=$1`, a.ID, a.Decision, a.EffectiveAction, a.Source, a.Reason)
		return err
	}
	return d.QueryRowContext(ctx, `INSERT INTO tool_call_audit(task_id,tool_name,input_summary,decision,effective_action,decision_source,reason)
 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,created_at`, a.TaskID, a.ToolName, a.InputSummary, a.Decision, a.EffectiveAction, a.Source, a.Reason).Scan(&a.ID, &a.CreatedAt)
}

// ListTaskToolCalls uses an indexed keyset cursor (beforeID=0 for newest). Limit
// is bounded even for caller errors; audit reads never scan an entire task log.
func (d *DB) ListTaskToolCalls(ctx context.Context, taskID string, beforeID int64, limit int) ([]ToolCallAudit, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := d.QueryContext(ctx, `SELECT id,task_id,tool_name,input_summary,decision,effective_action,decision_source,reason,created_at
 FROM tool_call_audit WHERE task_id=$1 AND ($2::bigint=0 OR id<$2) ORDER BY id DESC LIMIT $3`, taskID, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ToolCallAudit{}
	for rows.Next() {
		var a ToolCallAudit
		if err := rows.Scan(&a.ID, &a.TaskID, &a.ToolName, &a.InputSummary, &a.Decision, &a.EffectiveAction, &a.Source, &a.Reason, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
