package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type TargetResource struct {
	ConditionalCleanup bool      `json:"conditional_cleanup"`
	ID                 int64     `json:"id"`
	TaskID             string    `json:"task_id"`
	URL                string    `json:"url"`
	CreationRequestID  int64     `json:"creation_request_id"`
	ETag               string    `json:"etag"`
	State              string    `json:"state"`
	CreatedAt          time.Time `json:"created_at"`
}

func canonicalResourceURL(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("无效资源 URL")
	}
	u.Fragment = ""
	return u.String(), nil
}
func StrongETag(etag string) bool {
	return len(etag) >= 2 && strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`) && !strings.ContainsAny(etag, "\r\n")
}

// RegisterTargetResource is called only after an operator-declared creation route
// returned 201 + Location. It cannot be invoked by an agent tool or a name claim.
func (d *DB) RegisterTargetResource(ctx context.Context, taskID string, requestID int64, raw, etag string, conditional ...bool) error {
	raw, e := canonicalResourceURL(raw)
	if e != nil {
		return e
	}
	enabled := len(conditional) > 0 && conditional[0]
	result, e := d.ExecContext(ctx, `INSERT INTO target_test_resources(task_id,url,creation_request_id,etag,conditional_cleanup)
 SELECT $1,$3,id,$4,$5 FROM target_requests WHERE id=$2 AND task_id=$1 AND method='POST'
 ON CONFLICT DO NOTHING`, taskID, requestID, raw, etag, enabled)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		var exists bool
		if e := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM target_test_resources WHERE creation_request_id=$1 AND task_id=$2 AND url=$3)`, requestID, taskID, raw).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return fmt.Errorf("缺少唯一、真实的本任务创建请求证据，不能登记资源归属")
		}
	}
	return nil
}
func (d *DB) OwnedTargetResource(ctx context.Context, taskID, raw string) (*TargetResource, error) {
	raw, e := canonicalResourceURL(raw)
	if e != nil {
		return nil, e
	}
	var r TargetResource
	e = d.QueryRowContext(ctx, `SELECT id,task_id,url,creation_request_id,etag,state,created_at,conditional_cleanup FROM target_test_resources WHERE task_id=$1 AND url=$2 AND state='active'`, taskID, raw).Scan(&r.ID, &r.TaskID, &r.URL, &r.CreationRequestID, &r.ETag, &r.State, &r.CreatedAt, &r.ConditionalCleanup)
	if e == sql.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !r.ConditionalCleanup || !StrongETag(r.ETag) {
		return nil, nil
	}
	return &r, nil
}
func (d *DB) FinishTargetResource(ctx context.Context, taskID, raw, method, etag string) error {
	raw, e := canonicalResourceURL(raw)
	if e != nil {
		return e
	}
	state := "active"
	if method == "DELETE" {
		state = "cleaned"
	}
	_, e = d.ExecContext(ctx, `UPDATE target_test_resources SET state=$3,etag=$4 WHERE task_id=$1 AND url=$2 AND state='active'`, taskID, raw, state, etag)
	return e
}
func (d *DB) ListTargetResources(ctx context.Context, taskID string) ([]TargetResource, error) {
	rows, e := d.QueryContext(ctx, `SELECT id,task_id,url,creation_request_id,etag,state,created_at,conditional_cleanup FROM target_test_resources WHERE task_id=$1 ORDER BY id DESC LIMIT 500`, taskID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []TargetResource{}
	for rows.Next() {
		var r TargetResource
		if e := rows.Scan(&r.ID, &r.TaskID, &r.URL, &r.CreationRequestID, &r.ETag, &r.State, &r.CreatedAt, &r.ConditionalCleanup); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
