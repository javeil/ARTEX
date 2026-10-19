package intercept

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func HasScopeContext(ctx context.Context) bool {
	i, _ := ctx.Value(scopeContextKey{}).(*Interceptor)
	return i != nil
}
func shellLiteral(v string) *syntax.Word {
	return &syntax.Word{Parts: []syntax.WordPart{&syntax.SglQuoted{Value: v}}}
}

// PrepareShellInput pins known HTTP clients to the target gateway. Local curl
// configuration, proxy overrides, --next and alternate destination mappings must
// not replace authorization after PreToolUse inspected the original command.
func (i *Interceptor) PrepareShellInput(ctx context.Context, tool string, input []byte) ([]byte, error) {
	g := GatewayFromContext(ctx)
	if g == nil || !(tool == "Bash" || tool == "Monitor" || tool == "shell_open") {
		return nil, nil
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, err
	}
	var command string
	_ = json.Unmarshal(in["command"], &command)
	tree, err := syntax.NewParser().Parse(strings.NewReader(command), "target-gateway")
	if err != nil {
		return nil, err
	}
	changed := false
	var problem error
	syntax.Walk(tree, func(n syntax.Node) bool {
		c, ok := n.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		originalName, known := operationWord(c.Args[0])
		name := originalName
		if !known {
			return true
		}
		name = filepath.Base(name)
		if name != "curl" && name != "wget" {
			return true
		}
		trustedPath, e := exec.LookPath(name)
		if e != nil {
			problem = e
			return false
		}
		trustedPath, e = filepath.EvalSymlinks(trustedPath)
		if e != nil {
			problem = e
			return false
		}
		if strings.Contains(originalName, "/") {
			provided, e := filepath.EvalSymlinks(originalName)
			if e != nil || provided != trustedPath {
				problem = fmt.Errorf("HTTP 客户端路径不是已知客户端，不能作为受控工具执行")
				return false
			}
		}
		c.Args[0] = shellLiteral(trustedPath)
		args := []string{name}
		for _, w := range c.Args[1:] {
			arg, known := operationWord(w)
			if !known {
				problem = fmt.Errorf("HTTP 客户端含动态参数，无法证明网关约束，请用 TargetHTTP 传入明确请求")
				return false
			}
			args = append(args, arg)
		}
		if err := validateHTTPClientArgs(name, args); err != nil {
			problem = err
			return false
		}
		prefix := []*syntax.Word{c.Args[0]}
		suffix := []*syntax.Word{}
		if name == "curl" {
			prefix = append(prefix, shellLiteral("-q"))
			for _, v := range []string{"--proxy", g.URL, "--noproxy", "", "--proto", "=http,https", "--proto-redir", "=http,https"} {
				suffix = append(suffix, shellLiteral(v))
			}
		} else {
			prefix = append(prefix, shellLiteral("--no-config"))
			for _, v := range []string{"-e", "use_proxy=yes", "-e", "http_proxy=" + g.URL, "-e", "https_proxy=" + g.URL, "-e", "ftp_proxy=" + g.URL, "-e", "no_proxy="} {
				suffix = append(suffix, shellLiteral(v))
			}
		}
		c.Args = append(append(prefix, c.Args[1:]...), suffix...)
		changed = true
		return true
	})
	if problem != nil {
		return nil, problem
	}
	if !changed {
		return nil, nil
	}
	var b bytes.Buffer
	if err := syntax.NewPrinter().Print(&b, tree); err != nil {
		return nil, err
	}
	in["command"], _ = json.Marshal(b.String())
	return json.Marshal(in)
}
func RewriteForwardedInput(tool string, original, updated []byte) ([]byte, error) {
	if tool != "ExecuteExtraTool" {
		return updated, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(original, &m); err != nil {
		return nil, err
	}
	var inner string
	_ = json.Unmarshal(m["tool_name"], &inner)
	nested, err := RewriteForwardedInput(inner, m["params"], updated)
	if err != nil {
		return nil, err
	}
	m["params"] = nested
	return json.Marshal(m)
}
