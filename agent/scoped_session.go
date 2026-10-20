package agent

import (
	"context"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/internal/scopedfetch"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/tool"
)

func newScopedSession(ctx context.Context, opts agentcore.Options) *agentcore.Session {
	// Worker steering and ChatAgent already carry Guard. Every other role gets
	// the same mandatory floor here; an omitted hook must never mean bypass.
	if opts.Hooks == nil {
		opts.Hooks = guard.NewWithInterceptor(intercept.FromContext(ctx)).Hooks()
	}
	if opts.Tools == nil {
		opts.Tools = tool.DefaultTools()
	}
	if i := intercept.FromContext(ctx); i != nil && i.CanRequestOperator() && intercept.TaskIDFromContext(ctx) != "" {
		opts.Tools = append(opts.Tools, requestOperatorTool())
	}
	enableTargetHTTP := opts.EnableWebFetch
	for _, t := range opts.Tools {
		enableTargetHTTP = enableTargetHTTP || t.Name() == "Bash"
	}
	if enableTargetHTTP {
		opts.Tools = append(opts.Tools, targetHTTPTool())
	}
	if opts.EnableWebFetch {
		if opts.Tools == nil {
			opts.Tools = tool.DefaultTools()
		}
		opts.Tools = append(opts.Tools, scopedfetch.NewWebFetch(scopedfetch.WebFetchConfig{Proxy: opts.WebFetchProxy, CACert: opts.WebFetchCACert, InsecureTLS: opts.WebFetchInsecureTLS}))
		opts.EnableWebFetch = false
	}
	return agentcore.NewSession(opts)
}
