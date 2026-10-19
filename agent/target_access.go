package agent

import (
	"context"
	"github.com/Autumn-27/artex/intercept"
)

func prepareTargetAccess(ctx context.Context, upstream, ca string) (context.Context, func(), error) {
	if intercept.TaskIDFromContext(ctx) == "" || !intercept.HasScopeContext(ctx) {
		return ctx, func() {}, nil
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
