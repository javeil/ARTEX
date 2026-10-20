package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ExecutionBlock pauses an engagement for an operator; it never proves a goal,
// expands authorization, or converts a failed assessment into success.
type ExecutionBlock struct {
	AuthorizationEpoch int64  `json:"-"`
	Code               string `json:"code"`
	Reason             string `json:"reason"`
}

func (b *ExecutionBlock) Error() string { return b.Reason }

// TaskExecutionBlock reads indexed, bounded tails in the current authorization
// cycle. Ordinary local tools/facts are not target progress. Human approvals and
// actual HTTP responses (including 403/404/500) reset a refusal streak.
func (d *DB) TaskExecutionBlock(ctx context.Context, id string) (*ExecutionBlock, error) {
	var epoch int64
	if err := d.QueryRowContext(ctx, `SELECT authorization_epoch FROM tasks WHERE id::text=$1`, id).Scan(&epoch); err != nil {
		return nil, err
	}
	p, err := d.LoadTargetPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	noResponse, denials := 8, 3
	if p.NoResponseLimit != nil {
		noResponse = *p.NoResponseLimit
	}
	if p.RepeatDenialLimit != nil {
		denials = *p.RepeatDenialLimit
	}
	if noResponse > 0 {
		var count int
		err = d.QueryRowContext(ctx, `SELECT count(*) FROM (
   SELECT r.status_code,r.error_kind FROM target_requests r JOIN tasks t ON t.id::text=r.task_id
   WHERE r.task_id=$1 AND r.authorization_epoch=t.authorization_epoch AND r.state='finished'
   ORDER BY r.id DESC LIMIT $2
  ) tail WHERE status_code=0 AND error_kind='transport'`, id, noResponse).Scan(&count)
		if err != nil {
			return nil, err
		}
		if count >= noResponse {
			return &ExecutionBlock{AuthorizationEpoch: epoch, Code: "no_http_response", Reason: fmt.Sprintf("连续 %d 次请求未收到 HTTP 响应，已暂停等待操作者检查连通性。EOF/TLS 错误不能证明平台拦截或目标防御；请勿创建重复恢复监视意图。", count)}, nil
		}
	}
	if denials > 0 {
		version, e := d.AuthorizationVersion(ctx, id)
		if e != nil {
			return nil, e
		}
		var source string
		err = d.QueryRowContext(ctx, `WITH progress AS (
 SELECT GREATEST(
 COALESCE((SELECT max(updated_at) FROM tool_call_audit WHERE task_id=$1 AND authorization_version=$2 AND decision='ask' AND effective_action='allow'),'-infinity'::timestamptz),
 COALESCE((SELECT max(r.finished_at) FROM target_requests r JOIN tasks t ON t.id::text=r.task_id WHERE r.task_id=$1 AND r.authorization_epoch=t.authorization_epoch AND r.state='finished' AND r.status_code>0),'-infinity'::timestamptz)) AS at
 ), denied AS (
 SELECT a.decision_source AS source,a.updated_at AS at FROM tool_call_audit a
 WHERE a.task_id=$1 AND a.authorization_version=$2 AND a.effective_action='deny'
 UNION ALL
 SELECT 'target_gateway',r.finished_at FROM target_requests r WHERE r.task_id=$1 AND r.authorization_version=$2 AND (r.state='denied' OR (r.state='finished' AND r.status_code=0 AND r.error_kind='control'))
 ) SELECT COALESCE((SELECT source FROM denied,progress WHERE denied.at>progress.at
 GROUP BY source HAVING count(*)>=$3 ORDER BY max(denied.at) DESC LIMIT 1),'')`, id, version, denials).Scan(&source)
		if err != nil {
			return nil, err
		}
		if source != "" {
			return &ExecutionBlock{AuthorizationEpoch: epoch, Code: "repeated_denial", Reason: fmt.Sprintf("当前授权下同类平台拒绝（%s）累计达到 %d 次，已暂停等待操作者处理。不要换工具、改写命令或创建重复意图继续申请。", source, denials)}, nil
		}
	}
	return nil, nil
}

// Pause reasons are tied to the post-pause epoch. A deliberate human resume
// advances that epoch, retaining history without showing an obsolete reason.
func (d *DB) TaskPauseReason(ctx context.Context, id string) (string, error) {
	var reason string
	err := d.QueryRowContext(ctx, `SELECT COALESCE((SELECT e.reason FROM target_control_events e
  WHERE e.task_id=t.id::text AND e.action='auto_pause' AND e.target_key='epoch:'||t.authorization_epoch::text
  ORDER BY e.id DESC LIMIT 1),'') FROM tasks t WHERE t.id::text=$1 AND t.paused`, id).Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return reason, err
}
