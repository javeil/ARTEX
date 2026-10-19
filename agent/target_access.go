package agent

import (
	"context"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"strconv"
)

func prepareTargetAccess(ctx context.Context, upstream, ca string) (context.Context, func(), error) {
	if intercept.TaskIDFromContext(ctx) == "" {
		return ctx, func() {}, nil
	}
	if !intercept.HasScopeContext(ctx) {
		return ctx, func() {}, fmt.Errorf("任务安全上下文缺少目标校验器，拒绝启动")
	}
	ctx, finish, err := intercept.BeginTargetRun(ctx)
	if err != nil {
		return ctx, func() {}, err
	}
	g, err := intercept.NewTargetGateway(ctx, upstream, ca)
	if err != nil {
		finish()
		return ctx, func() {}, err
	}
	return intercept.WithGateway(ctx, g), func() { g.Close(); finish() }, nil
}
func targetProxyEnv(ctx context.Context, upstream, ca string) []string {
	if g := intercept.GatewayFromContext(ctx); g != nil {
		return append(proxyEnv(g.URL, g.CACert), "NO_PROXY=", "no_proxy=", "CURL_HOME=", "WGETRC=/dev/null")
	}
	return proxyEnv(upstream, ca)
}

// A host method's task argument and inherited context must describe the same
// task. Bind the role/emitter so pending approvals and audits reach its stream.
func bindTaskAgentContext(ctx context.Context, id int64, role string, emit func(db.Activity)) (context.Context, error) {
	inherited := intercept.TaskIDFromContext(ctx)
	if id <= 0 {
		if inherited != "" && !intercept.HasScopeContext(ctx) {
			return ctx, fmt.Errorf("任务安全上下文缺少目标校验器，拒绝启动")
		}
		return ctx, nil
	}
	task := strconv.FormatInt(id, 10)
	if inherited != "" && inherited != task {
		return ctx, fmt.Errorf("agent task identity mismatch")
	}
	if !intercept.HasScopeContext(ctx) {
		return ctx, fmt.Errorf("任务安全上下文缺少目标校验器，拒绝启动")
	}
	return intercept.WithTaskContext(ctx, task, role, emit), nil
}
