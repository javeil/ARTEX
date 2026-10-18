package agent

import (
	"github.com/Autumn-27/artex/internal/scopedfetch"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/tool"
)

func newScopedSession(opts agentcore.Options) *agentcore.Session {
	if opts.EnableWebFetch {
		if opts.Tools == nil {
			opts.Tools = tool.DefaultTools()
		}
		opts.Tools = append(opts.Tools, scopedfetch.NewWebFetch(scopedfetch.WebFetchConfig{Proxy: opts.WebFetchProxy, CACert: opts.WebFetchCACert, InsecureTLS: opts.WebFetchInsecureTLS}))
		opts.EnableWebFetch = false
	}
	return agentcore.NewSession(opts)
}
