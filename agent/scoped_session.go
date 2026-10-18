package agent

import (
	"github.com/Autumn-27/artex/internal/scopedfetch"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/tool"
)

func newScopedSession(opts agentcore.Options) *agentcore.Session {
	if opts.Tools == nil {
		opts.Tools = tool.DefaultTools()
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
