package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
	"mvdan.cc/sh/v3/syntax"
)

type scopeContextKey struct{}

// WithScope binds the request-time HTTP validator to a task run.
func (i *Interceptor) WithScope(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, scopeContextKey{}, i)
	if ctx.Value(ticketKey{}) == nil {
		ctx = context.WithValue(ctx, ticketKey{}, &operationTickets{items: map[string][]operationTicket{}})
	}
	return ctx
}
func TaskIDFromContext(ctx context.Context) string { id, _ := taskInfoFromCtx(ctx); return id }

// CheckURL is called by the HTTP transport before every request (including
// redirects). A task with missing policy wiring fails closed.
func CheckURL(ctx context.Context, raw string) error {
	if TaskIDFromContext(ctx) == "" {
		return fmt.Errorf("目标不在本任务授权范围：主动测试必须绑定授权任务")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("目标不在本任务授权范围：无效 HTTP URL")
	}
	i, _ := ctx.Value(scopeContextKey{}).(*Interceptor)
	if i == nil {
		return fmt.Errorf("目标不在本任务授权范围：范围校验器不可用")
	}
	return i.CheckTarget(ctx, raw)
}

func (i *Interceptor) CheckTarget(ctx context.Context, raw string) error {
	id := TaskIDFromContext(ctx)
	if id == "" {
		return fmt.Errorf("目标不在本任务授权范围：主动测试必须绑定授权任务")
	}
	t, err := db.ParseTarget(raw)
	if err != nil {
		return err
	}
	if err = i.db.CheckTaskTarget(ctx, id, t); err != nil {
		return fmt.Errorf("目标不在本任务授权范围：%w", err)
	}
	return nil
}

func (i *Interceptor) ScopeDecision(ctx context.Context, tool string, input []byte) (Decision, bool) {
	if tool == "add_task_scope" || tool == "add_company_scope" {
		return Decision{Action: "ask", Message: "修改授权范围需要人工审批", TimeoutEnabled: true, TimeoutSeconds: 300, TimeoutAction: "deny"}, true
	}
	if TaskIDFromContext(ctx) == "" {
		hosts, unknown := ScopeTargets(tool, input)
		if len(hosts) > 0 || unknown {
			return Decision{Action: "deny", Message: "主动测试必须绑定授权任务，当前会话没有授权上下文"}, true
		}
		return Decision{}, false
	}
	hosts, unknown := ScopeTargets(tool, input)
	if (len(hosts) > 0 || unknown) && i.TargetIOState(TaskIDFromContext(ctx)).Blocked {
		return Decision{Action: "deny", Message: "目标访问已停止，需用户明确恢复"}, true
	}
	if GatewayFromContext(ctx) == nil && shellFollowsRedirects(tool, input) {
		return Decision{Action: "deny", Message: "Bash 自动重定向无法逐跳确认授权范围，请改用 WebFetch 或关闭重定向"}, true
	}
	for _, h := range ScopeTargetDetails(tool, input, hosts) {
		if err := i.CheckTarget(ctx, h); err != nil {
			return Decision{Action: "deny", Message: err.Error()}, true
		}
	}
	// HTTP input must be concrete; approvals cannot waive malformed/missing URLs.
	if strings.EqualFold(tool, "webfetch") && unknown {
		return Decision{Action: "deny", Message: "目标不在本任务授权范围：无法确认 HTTP 目标"}, true
	}
	if unknown {
		action := i.getSettingChoice("scope_unknown_target_action", "ask", "ask", "deny", "allow")
		return Decision{Action: action, Message: "无法静态确认本次调用的全部网络目标，需要确认授权范围", TimeoutEnabled: true, TimeoutSeconds: 300, TimeoutAction: "deny"}, true
	}
	return Decision{}, false
}

var scopeURL = regexp.MustCompile(`(?i)https?://[^\s'"<>` + "`" + `]+`)
var scopeIP = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]+)?\b`)
var scopeDomain = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+\.?(:[0-9]+)?$`)

// ScopeTargets never executes expansions to discover targets. Any executable or
// parameter whose effect cannot be bounded remains uncertain even if some other
// literal target was found in the same call.
func ScopeTargets(tool string, input []byte) (hosts []string, unknown bool) {
	var in map[string]json.RawMessage
	if json.Unmarshal(input, &in) != nil {
		return nil, true
	}
	seen := map[string]bool{}
	add := func(v string) {
		if strings.Contains(v, "://") {
			u, e := url.Parse(v)
			if e != nil || u.Hostname() == "" {
				unknown = true
				return
			}
			v = u.Hostname()
		}
		v = db.NormalizeScopeHost(v)
		if v != "" && !seen[v] {
			hosts = append(hosts, v)
			seen[v] = true
		}
	}
	if strings.EqualFold(tool, "webfetch") {
		var raw string
		_ = json.Unmarshal(in["url"], &raw)
		u, e := url.Parse(raw)
		if e != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, true
		}
		add(raw)
		return hosts, false
	}
	switch tool {
	case "Bash", "Monitor", "shell_open", "shell_send":
		var command string
		key := "command"
		if tool == "shell_send" {
			key = "text"
		}
		_ = json.Unmarshal(in[key], &command)
		tree, err := syntax.NewParser().Parse(strings.NewReader(command), "scope")
		if err != nil {
			return nil, true
		}
		syntax.Walk(tree, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if !ok {
				return true
			}
			if len(call.Args) == 0 {
				if len(call.Assigns) > 0 {
					unknown = true
				}
				return true
			}
			args := []string{}
			for _, w := range call.Args {
				v, ok := staticWord(w)
				if !ok {
					unknown = true
				}
				args = append(args, v)
			}
			name := filepath.Base(args[0])
			network := false
			switch name {
			case "curl", "wget", "nmap", "nc", "netcat", "http", "https", "httpx", "nikto", "sqlmap", "ffuf", "gobuster":
				network = true
			case "ls", "pwd", "cat", "head", "tail", "wc", "echo", "printf", "mkdir", "rm", "cp", "mv", "touch", "grep", "rg", "sort", "uniq", "cut", "tr", "true", "false", "test", "[", "cd":
				// Known local commands. Dynamic arguments still require review.
			default:
				unknown = true
			}
			found := false
			for _, arg := range args[1:] {
				if network {
					if prefix, e := netip.ParsePrefix(arg); e == nil {
						add(prefix.Masked().String())
						found = true
					}
					if scopeIP.MatchString(arg) && strings.ContainsAny(arg, "-,") {
						unknown = true
					}
					if ip, e := netip.ParseAddr(strings.Trim(arg, "[]")); e == nil {
						add(ip.String())
						found = true
					}
				}
				for _, raw := range scopeURL.FindAllString(arg, -1) {
					add(raw)
					found = true
				}
				for _, raw := range scopeIP.FindAllString(arg, -1) {
					if ip, e := netip.ParseAddr(raw); e == nil {
						add(ip.String())
						found = true
					} else if p, e := netip.ParsePrefix(raw); e == nil {
						add(p.String())
						found = true
					}
				}
				if network && scopeDomain.MatchString(arg) && !(scopeIP.MatchString(arg) && strings.ContainsAny(arg, "-,")) {
					add(arg)
					found = true
				}
				if network && (strings.HasPrefix(arg, "--") || strings.HasPrefix(arg, "-")) {
					switch {
					case arg == "-L", strings.Contains(arg, "location"), strings.Contains(arg, "config"), arg == "-K", arg == "-iL", arg == "--input-file", strings.Contains(arg, "proxy"), strings.Contains(arg, "resolve"), strings.Contains(arg, "connect-to"), strings.Contains(arg, "interface"), strings.Contains(arg, "globoff"):
						unknown = true
					}
				}
			}
			if network && !found {
				unknown = true
			}
			// Shell clients cannot authorize a future redirect destination. Deny automatic
			// redirect following below, rather than mistaking initial URL validation for it.
			if name == "wget" && !strings.Contains(strings.Join(args, " "), "--max-redirect=0") {
				unknown = true
			}
			return true
		})
		if strings.Contains(command, "/dev/tcp/") || strings.Contains(command, "/dev/udp/") {
			unknown = true
		}
		if command == "" {
			unknown = true
		}
	default:
		// Explicit target-bearing custom/HTTP tools are checked. Opaque MCP/execution
		// tools require approval; known local/domain bookkeeping tools have no egress.
		for _, key := range []string{"url", "host", "hostname", "target", "ip"} {
			var v string
			if json.Unmarshal(in[key], &v) == nil && v != "" {
				add(v)
			}
		}
		unknown = strings.HasPrefix(tool, "mcp__") || strings.Contains(strings.ToLower(tool), "http") || strings.Contains(strings.ToLower(tool), "fetch")
	}
	return
}

func shellFollowsRedirects(tool string, input []byte) bool {
	if tool != "Bash" && tool != "Monitor" && tool != "shell_open" && tool != "shell_send" {
		return false
	}
	var in struct {
		Command string `json:"command"`
		Text    string `json:"text"`
	}
	_ = json.Unmarshal(input, &in)
	command := in.Command
	if tool == "shell_send" {
		command = in.Text
	}
	tree, e := syntax.NewParser().Parse(strings.NewReader(command), "redirect")
	if e != nil {
		return false
	}
	unsafe := false
	syntax.Walk(tree, func(n syntax.Node) bool {
		c, ok := n.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		name, _ := staticWord(c.Args[0])
		name = filepath.Base(name)
		if name != "curl" && name != "wget" {
			return true
		}
		safeWget := false
		for _, w := range c.Args[1:] {
			a, _ := staticWord(w)
			if name == "curl" && (strings.HasPrefix(a, "--location") || (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "L"))) {
				unsafe = true
			}
			if a == "--max-redirect=0" {
				safeWget = true
			}
		}
		if name == "wget" && !safeWget {
			unsafe = true
		}
		return true
	})
	return unsafe
}

// UnwrapToolCall closes the SDK deferred-tool trampoline: ExecuteExtraTool calls
// CoreTool.Call directly, so the target would otherwise never run PreToolUse.
func UnwrapToolCall(tool string, input []byte) (string, []byte, error) {
	for depth := 0; tool == "ExecuteExtraTool"; depth++ {
		if depth >= 4 {
			return "", nil, fmt.Errorf("嵌套工具调用超过安全检查上限")
		}
		var in struct {
			Tool   string          `json:"tool_name"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(input, &in) != nil || in.Tool == "" {
			return "", nil, fmt.Errorf("无法解析转发工具调用")
		}
		tool = in.Tool
		input = in.Params
		if len(input) == 0 {
			input = []byte(`{}`)
		}
	}
	return tool, input, nil
}

// ScopeTargetDetails preserves URLs rather than erasing service/path identity.
// Non-URL scan targets remain host-only and fail closed under service restrictions.
func ScopeTargetDetails(tool string, input []byte, hosts []string) []string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(input, &obj)
	values := []string{}
	covered := map[string]bool{}
	if strings.EqualFold(tool, "WebFetch") || tool == "TargetRequest" {
		var v string
		_ = json.Unmarshal(obj["url"], &v)
		values = append(values, v)
		if u, e := url.Parse(v); e == nil {
			covered[db.NormalizeScopeHost(u.Hostname())] = true
		}
	}
	if tool == "Bash" || tool == "Monitor" || tool == "shell_open" || tool == "shell_send" {
		field := "command"
		if tool == "shell_send" {
			field = "text"
		}
		var cmd string
		_ = json.Unmarshal(obj[field], &cmd)
		for _, raw := range scopeURL.FindAllString(cmd, -1) {
			if u, e := url.Parse(raw); e == nil && u.Hostname() != "" {
				values = append(values, raw)
				covered[db.NormalizeScopeHost(u.Hostname())] = true
			}
		}
	}
	for _, h := range hosts {
		if !covered[h] {
			values = append(values, h)
		}
	}
	return values
}
