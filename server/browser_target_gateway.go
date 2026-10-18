package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

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
	known := filepath.Base(m.Command) == "playwright-mcp"
	for _, a := range args {
		known = known || a == "@playwright/mcp" || strings.HasPrefix(a, "@playwright/mcp@")
	}
	normalized := []string{}
	for _, a := range args {
		if strings.HasPrefix(a, "--config=") {
			normalized = append(normalized, "--config", strings.TrimPrefix(a, "--config="))
		} else {
			normalized = append(normalized, a)
		}
	}
	args = normalized
	if !known {
		return nil, nil, fmt.Errorf("browser MCP 尚未提供可验证的 Playwright 目标网关适配")
	}
	kept := []string{}
	config := map[string]any{}
	for j := 0; j < len(args); j++ {
		if strings.HasPrefix(args[j], "--proxy-server=") || strings.HasPrefix(args[j], "--proxy-bypass=") {
			continue
		}
		if args[j] == "--extension" || strings.HasPrefix(args[j], "--cdp-endpoint") || strings.HasPrefix(args[j], "--endpoint") {
			return nil, nil, fmt.Errorf("外接浏览器无法证明使用任务目标网关，拒绝启动")
		}
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
	if browser["cdpEndpoint"] != nil || browser["remoteEndpoint"] != nil || config["extension"] == true {
		return nil, nil, fmt.Errorf("外接浏览器无法证明使用任务目标网关，拒绝启动")
	}
	proxy := map[string]any{"server": u.String(), "username": username, "password": password, "bypass": "<-loopback>"}
	delete(browser, "proxy") // Proxy belongs to LaunchOptions / BrowserContextOptions.
	env := map[string]string{}
	_ = json.Unmarshal(m.Env, &env)
	if env == nil {
		env = map[string]string{}
	}
	for _, key := range []string{"PLAYWRIGHT_MCP_PROXY_SERVER", "PLAYWRIGHT_MCP_PROXY_BYPASS", "PLAYWRIGHT_MCP_CDP_ENDPOINT", "PLAYWRIGHT_MCP_EXTENSION"} {
		env[key] = ""
	}
	clone.Env, _ = json.Marshal(env)
	// TLS remains terminated and inspected at the task gateway; this trust setting
	// is confined to this browser context and never creates a direct fallback.
	options, _ := browser["contextOptions"].(map[string]any)
	if options == nil {
		options = map[string]any{}
	}
	options["ignoreHTTPSErrors"] = true
	options["proxy"] = proxy
	browser["contextOptions"] = options
	launch, _ := browser["launchOptions"].(map[string]any)
	if launch == nil {
		launch = map[string]any{}
	}
	launch["proxy"] = proxy
	launchArgs := []any{}
	if old, ok := launch["args"].([]any); ok {
		launchArgs = append(launchArgs, old...)
	}
	launch["args"] = append(launchArgs, "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
	browser["launchOptions"] = launch
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
