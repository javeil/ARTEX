package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

type Operation struct {
	ResourceETag string    `json:"resource_etag,omitempty"`
	Target       db.Target `json:"target"`
	Method       string    `json:"method,omitempty"`
	Body         string    `json:"body,omitempty"`
	Effect       string    `json:"effect"`
	Account      string    `json:"account,omitempty"`
}
type TrustedPolicy struct {
	TaskID           string          `json:"task_id"`
	Version          string          `json:"version"`
	Policy           db.TargetPolicy `json:"policy"`
	HumanConstraints []string        `json:"human_constraints,omitempty"`
}

var authPath = regexp.MustCompile(`(?i)(?:^|/)(?:login|signin|sign-in|authenticate|auth|token)(?:/|$)`)
var mutationPath = regexp.MustCompile(`(?i)(?:^|/)(?:delete|remove|cancel|erase|wipe|reset|destroy|truncate|drop)[-_a-z]*(?:/|$)`)
var mutationValue = regexp.MustCompile(`(?i)^(?:delete|remove|cancel|erase|wipe|reset|destroy|update|disable|enable|refund|transfer|set_balance|set_stock)$`)
var humanReadOnly = regexp.MustCompile(`(?i)(?:仅|只)(?:允许)?只读|read[- ]only|禁止(?:任何)?写操作`)
var humanPassive = regexp.MustCompile(`(?i)(?:仅|只)(?:允许)?被动|passive[- ]only`)

func classifyOperation(o Operation) string {
	if mutationPath.MatchString(o.Target.Path) {
		return "business_write"
	}
	values := map[string]string{}
	if o.Target.URL != "" {
		if u, e := url.Parse(o.Target.URL); e == nil {
			for k, v := range u.Query() {
				if len(v) > 0 {
					values[strings.ToLower(k)] = v[0]
				}
			}
		}
	}
	var obj map[string]any
	if json.Unmarshal([]byte(o.Body), &obj) == nil {
		for k, v := range obj {
			if s, ok := v.(string); ok {
				values[strings.ToLower(k)] = s
			}
		}
	} else if q, e := url.ParseQuery(o.Body); e == nil {
		for k, v := range q {
			if len(v) > 0 {
				values[strings.ToLower(k)] = v[0]
			}
		}
	}
	for _, key := range []string{"action", "operation", "op", "cmd"} {
		if mutationValue.MatchString(values[key]) {
			return "business_write"
		}
	}
	if o.Method == "GET" || o.Method == "HEAD" || o.Method == "OPTIONS" {
		return "read"
	}
	if authPath.MatchString(o.Target.Path) {
		return "authenticate"
	}
	if q := strings.TrimSpace(values["query"]); (strings.HasPrefix(q, "{") || strings.HasPrefix(q, "query ")) && !strings.Contains(q, "mutation") {
		return "read"
	}
	if o.Method == "DELETE" || o.Method == "PUT" || o.Method == "PATCH" {
		return "business_write"
	}
	return "unknown_write"
}

// DescribeOperations interprets direct HTTP arguments, not claims such as an
// agent-supplied effect. Unknown programs retain the separate scope approval gate.
func DescribeOperations(tool string, input []byte) []Operation {
	out := []Operation{}
	add := func(raw, method, body, effect string) {
		t, e := db.ParseTarget(raw)
		if e != nil {
			return
		}
		if method == "" {
			method = "GET"
		}
		o := Operation{Target: t, Method: strings.ToUpper(method), Body: body, Effect: effect}
		if effect == "" {
			o.Effect = classifyOperation(o)
		}
		out = append(out, o)
	}
	var in struct {
		URL     string `json:"url"`
		Method  string `json:"method"`
		Body    string `json:"body"`
		Command string `json:"command"`
		Text    string `json:"text"`
	}
	_ = json.Unmarshal(input, &in)
	if strings.EqualFold(tool, "WebFetch") || tool == "TargetRequest" {
		add(in.URL, in.Method, in.Body, "")
		return out
	}
	if tool != "Bash" && tool != "Monitor" && tool != "shell_open" && tool != "shell_send" {
		return out
	}
	command := in.Command
	if tool == "shell_send" {
		command = in.Text
	}
	tree, e := syntax.NewParser().Parse(strings.NewReader(command), "operation")
	if e != nil {
		return out
	}
	syntax.Walk(tree, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		args := []string{}
		for _, w := range call.Args {
			v, k := operationWord(w)
			if !k {
				return true
			}
			args = append(args, v)
		}
		name := filepath.Base(args[0])
		if name != "curl" && name != "wget" && name != "http" && name != "https" && name != "sqlmap" {
			return true
		}
		method, body := "GET", ""
		urls := []string{}
		for j := 1; j < len(args); j++ {
			a := args[j]
			switch {
			case a == "-X" || a == "--request" || a == "--method":
				if j+1 < len(args) {
					j++
					method = args[j]
				}
			case strings.HasPrefix(a, "-X") && len(a) > 2:
				method = strings.TrimPrefix(a, "-X")
			case strings.HasPrefix(a, "--request="):
				method = strings.TrimPrefix(a, "--request=")
			case a == "-d" || a == "--data" || a == "--data-raw" || a == "--data-binary" || a == "--json" || a == "--post-data":
				if j+1 < len(args) {
					j++
					body = args[j]
					if method == "GET" {
						method = "POST"
					}
				}
			case strings.HasPrefix(a, "--data="):
				body = strings.TrimPrefix(a, "--data=")
				if method == "GET" {
					method = "POST"
				}
			default:
				if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
					urls = append(urls, a)
				}
			}
		}
		effect := ""
		if name == "sqlmap" {
			effect = "probe"
		}
		for _, u := range urls {
			add(u, method, body, effect)
		}
		return true
	})
	return out
}
func (i *Interceptor) TrustedTaskPolicy(ctx context.Context) (*TrustedPolicy, error) {
	id := TaskIDFromContext(ctx)
	if id == "" {
		return nil, fmt.Errorf("主动测试没有授权任务")
	}
	p, err := i.db.LoadTargetPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	version, err := i.db.AuthorizationVersion(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := i.db.QueryContext(ctx, `SELECT c.text FROM task_constraints c JOIN tasks t ON t.exploration_id=c.exploration_id WHERE t.id::text=$1 AND c.origin='human' AND c.kind='deny' ORDER BY c.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	constraints := []string{}
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, err
		}
		constraints = append(constraints, text)
		if humanPassive.MatchString(text) {
			p.Mode = "passive"
		} else if humanReadOnly.MatchString(text) && p.Mode != "passive" {
			p.Mode = "read_only"
		}
	}
	return &TrustedPolicy{TaskID: id, Version: version, Policy: p, HumanConstraints: constraints}, rows.Err()
}
func effectiveOperation(p db.TargetPolicy, o Operation) Operation {
	// User bindings can identify an otherwise ambiguous operation. Explicit
	// destructive evidence is never hidden by a generic read/probe binding.
	if o.Effect == "unknown_write" || o.Effect == "authenticate" {
		for _, rule := range p.Operations {
			if !rule.Target.Matches(o.Target) {
				continue
			}
			for _, m := range rule.Methods {
				if m == o.Method {
					o.Effect = rule.Effect
					return o
				}
			}
		}
	}
	return o
}
func operationRestriction(p db.TargetPolicy, o Operation) (string, string) {
	if p.Mode == "passive" {
		return "deny", "本任务仅允许被动分析"
	}
	for _, e := range p.DeniedEffects {
		if e == o.Effect {
			return "deny", "任务明确禁止该操作效果：" + o.Effect
		}
	}
	switch o.Effect {
	case "business_write", "account_change", "service_change":
		return "deny", "禁止改变目标真实业务数据、账号或服务状态"
	case "unknown_write":
		if p.Mode == "read_only" {
			return "deny", "本任务只读，无法确认该调用不会改动业务状态"
		}
		return "ask", "操作的业务副作用不明，需要核对任务授权"
	case "artifact_create", "artifact_cleanup", "artifact_update":
		if p.Mode == "read_only" {
			return "deny", "本任务只读，不允许创建测试产物"
		}
	}
	return "", ""
}
func (i *Interceptor) OperationDecision(ctx context.Context, tool string, input []byte) (Decision, bool) {
	ops := DescribeOperations(tool, input)
	if len(ops) == 0 {
		return Decision{}, false
	}
	policy, err := i.TrustedTaskPolicy(ctx)
	if err != nil {
		return Decision{Action: "deny", Message: "任务操作策略不可用：" + err.Error()}, true
	}
	var uncertain string
	for _, op := range ops {
		op = i.ownedOperation(ctx, op)
		op = effectiveOperation(policy.Policy, op)
		action, reason := operationRestriction(policy.Policy, op)
		if action == "deny" {
			return Decision{Action: action, Message: reason}, true
		}
		if action == "ask" {
			uncertain = reason
		}
	}
	if uncertain != "" {
		if dec, judged := i.Judge(ctx, tool, input); judged {
			return dec, true
		}
		return Decision{Action: "ask", Message: uncertain, TimeoutEnabled: true, TimeoutSeconds: 300, TimeoutAction: "deny"}, true
	}
	return Decision{}, false
}

// Literal punctuation in a URL is still useful to classify its proposed effect;
// the scope gate separately treats shell glob expansion as uncertain.
func operationWord(w *syntax.Word) (string, bool) {
	if v, ok := staticWord(w); ok {
		return v, true
	}
	var known func([]syntax.WordPart) bool
	known = func(parts []syntax.WordPart) bool {
		for _, p := range parts {
			switch v := p.(type) {
			case *syntax.Lit, *syntax.SglQuoted:
			case *syntax.DblQuoted:
				if !known(v.Parts) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !known(w.Parts) {
		return "", false
	}
	fields, err := expand.Fields(&expand.Config{NoUnset: true}, w)
	if err != nil || len(fields) != 1 {
		return "", false
	}
	return fields[0], true
}
