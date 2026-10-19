package intercept

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Autumn-27/artex/db"
)

// QueryAuthorizedDNS is a logical DNS enrichment operation, not a claim to
// account every resolver retry packet. Strict request/account budgets therefore
// reject automatic DNS enrichment until a packet-aware adapter is provided.
func QueryAuthorizedDNS(ctx context.Context, host string, lookup func(context.Context) error) (result error) {
	ic := FromContext(ctx)
	if ic == nil {
		return fmt.Errorf("DNS lookup requires task authorization")
	}
	bound, release, err := BeginTargetActivity(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err = ic.CheckTarget(bound, host); err != nil {
		return err
	}
	policy, err := ic.TrustedTaskPolicy(bound)
	if err != nil {
		return err
	}
	if policy.Policy.Budget != (db.TargetBudget{}) || len(policy.Policy.Accounts) > 0 {
		return fmt.Errorf("DNS 自动补全无法逐请求执行当前预算，已拒绝；请使用已适配工具")
	}
	target, err := db.ParseTarget("dns://" + net.JoinHostPort(host, "53"))
	if err != nil {
		return err
	}
	id, err := ic.db.BeginTargetRequest(bound, TaskIDFromContext(bound), target, "DNS_LOOKUP", "", db.TargetBudget{})
	if err != nil {
		return err
	}
	began := time.Now()
	defer func() {
		done, cancel := context.WithTimeout(context.WithoutCancel(bound), 2*time.Second)
		defer cancel()
		status := 200
		message := ""
		if result != nil {
			status = 0
			message = result.Error()
		}
		if err := ic.db.FinishTargetRequest(done, id, status, int(time.Since(began).Milliseconds()), message, 0); err != nil {
			ic.runtime.mu.Lock()
			ic.targetStateLocked(TaskIDFromContext(bound)).blocked = true
			ic.runtime.mu.Unlock()
			ic.CancelTargetIO(TaskIDFromContext(bound))
			result = fmt.Errorf("DNS 访问结果审计失败，目标访问已停止: %w", err)
		}
	}()
	return lookup(bound)
}
