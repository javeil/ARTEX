package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// browserTargetGateway gives Playwright a task-specific proxy, rather than the
// global recording proxy. Its redirects, subresources and script fetches pass the
// same target gate. User config is merged into a temporary per-run copy.
func browserTargetGateway(ctx context.Context, m *db.MCPServer) (*db.MCPServer, func(), error) {
	g := intercept.GatewayFromContext(ctx)
	if g == nil || m.Name != "browser" || m.Transport != "stdio" {
		return m, func() {}, nil
	}
	clone := *m
	args := jsonStrSlice(m.Args)
	kept := []string{}
	config := map[string]any{}
	for j := 0; j < len(args); j++ {
		switch args[j] {
		case "--config":
			if j+1 >= len(args) {
				return nil, nil, fmt.Errorf("browser --config 缺少路径")
			}
			j++
			b, e := os.ReadFile(args[j])
			if e != nil {
				return nil, nil, e
			}
			if e = json.Unmarshal(b, &config); e != nil {
				return nil, nil, e
			}
		case "--proxy-server", "--proxy-bypass":
			if j+1 < len(args) {
				j++
			}
		default:
			kept = append(kept, args[j])
		}
	}
	u, e := url.Parse(g.URL)
	if e != nil {
		return nil, nil, e
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	u.User = nil
	browser, _ := config["browser"].(map[string]any)
	if browser == nil {
		browser = map[string]any{}
	}
	browser["proxy"] = map[string]any{"server": u.String(), "username": username, "password": password, "bypass": ""}
	// TLS remains terminated and inspected at the task gateway; this trust setting
	// is confined to this browser context and never creates a direct fallback.
	options, _ := browser["contextOptions"].(map[string]any)
	if options == nil {
		options = map[string]any{}
	}
	options["ignoreHTTPSErrors"] = true
	browser["contextOptions"] = options
	config["browser"] = browser
	dir, e := os.MkdirTemp("", "artex-browser-target-")
	if e != nil {
		return nil, nil, e
	}
	cleanup := func() { os.RemoveAll(dir) }
	b, e := json.Marshal(config)
	if e != nil {
		cleanup()
		return nil, nil, e
	}
	path := filepath.Join(dir, "config.json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		cleanup()
		return nil, nil, e
	}
	kept = append(kept, "--config", path)
	clone.Args, _ = json.Marshal(kept)
	return &clone, cleanup, nil
}
