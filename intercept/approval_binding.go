package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type ApprovalBinding struct {
	ExpiresAt            time.Time `json:"expires_at"`
	AuthorizationVersion string    `json:"authorization_version,omitempty"`
	CallDigest           string    `json:"call_digest"`
}

func (i *Interceptor) BindApproval(ctx context.Context, tool string, input []byte) (ApprovalBinding, error) {
	b := ApprovalBinding{ExpiresAt: time.Now().Add(5 * time.Minute)}
	hosts, unknown := ScopeTargets(tool, input)
	if TaskIDFromContext(ctx) != "" && (len(hosts) > 0 || unknown || tool == "add_task_scope" || tool == "add_company_scope") {
		if err := i.db.CheckTaskExecution(ctx, TaskIDFromContext(ctx)); err != nil {
			return b, err
		}
		var err error
		b.AuthorizationVersion, err = i.db.AuthorizationVersion(ctx, TaskIDFromContext(ctx))
		if err != nil {
			return b, err
		}
	}
	review, err := BuildReviewInput(ctx, tool, input)
	if err != nil {
		return b, err
	}
	// Current arguments and referenced script contents are bound to the approval.
	// This is independent of human/agent background prose.
	payload, _ := json.Marshal(struct {
		Tool      string
		Arguments json.RawMessage
		Directory string
		Scripts   []ReviewScript
		Status    string
	}{tool, input, review.WorkingDir, review.Scripts, review.ScriptCaptureStatus})
	b.CallDigest = digestInput(payload)
	return b, nil
}
func (i *Interceptor) ValidateApproval(ctx context.Context, tool string, input []byte, b ApprovalBinding) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("审批后任务已停止: %w", err)
	}
	if !time.Now().Before(b.ExpiresAt) {
		return fmt.Errorf("本次执行审批已过期")
	}
	now, err := i.BindApproval(ctx, tool, input)
	if err != nil {
		return err
	}
	if now.AuthorizationVersion != b.AuthorizationVersion || now.CallDigest != b.CallDigest {
		return fmt.Errorf("授权范围、策略或待执行内容已变化，原审批失效")
	}
	if d, gated := i.ScopeDecision(ctx, tool, input); gated && d.Action == "deny" {
		return fmt.Errorf("审批后授权复验失败：%s", d.Message)
	}
	return nil
}
