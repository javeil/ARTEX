// Package guard enforces immutable destructive protections and task authorization
// before configurable intercept rules, and records tool-call decisions.
package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/shellinput"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/internal/shellguard"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional in DB-free unit tests
	auditWrite  func(context.Context, *db.ToolCallAudit) error
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	if ic != nil {
		g.auditWrite = ic.SaveToolCallAudit
	}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

type auditKey struct{}

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) (result hook.Result) {
	grantVersion := ""
	a := &db.ToolCallAudit{TaskID: intercept.TaskIDFromContext(ctx), ToolName: ev.ToolName, InputSummary: inputSummary(ev.Input), Decision: "allow", EffectiveAction: "allow", Source: "default_allow"}
	ctx = context.WithValue(ctx, auditKey{}, a)
	defer func() {
		if result.Decision == "block" {
			a.EffectiveAction = "deny"
			if a.Decision != "ask" {
				a.Decision = "deny"
			}
		}
		if err := g.persistAudit(ctx, a); err != nil {
			result = hook.Result{Decision: "block", Message: systemBlockMessage("调用审计写入失败，安全停止：" + err.Error())}
		}
		if result.Decision != "block" && grantVersion != "" && g.interceptor != nil {
			g.interceptor.GrantOperations(ctx, ev.ToolName, ev.Input, grantVersion)
		}
		action := "allow"
		if result.Decision == "block" {
			action = "block"
		}
		g.record(ev.ToolName, action, result.Message, shellguard.Command(ev.ToolName, ev.Input))
	}()
	outerTool, outerInput := ev.ToolName, ev.Input
	tool, input, err := intercept.UnwrapToolCall(ev.ToolName, ev.Input)
	if err != nil {
		setAudit(ctx, "scope", "deny", err.Error())
		return hook.Result{Decision: "block", Message: systemBlockMessage(err.Error())}
	}
	ev.ToolName, ev.Input = tool, input
	// Decode every terminal representation before immutable checks.
	cmd := ""
	switch ev.ToolName {
	case "Bash", "Monitor", "shell_open", "shell_send":
		surface := shellinput.Read(ev.ToolName, ev.Input)
		if surface.Err != nil {
			setAudit(ctx, "scope", "deny", surface.Err.Error())
			return g.block(ev.ToolName, systemBlockMessage(surface.Err.Error()), surface.Command)
		}
		cmd = surface.Command
	}

	if reason := shellguard.Check(cmd); reason != "" && !(reason == "递归强制删除" && shellguard.SafeWorkspaceRemoval(cmd, intercept.TaskWorkspace(ctx))) {
		setAudit(ctx, "core", "deny", reason)
		return g.block(ev.ToolName, systemBlockMessage("核心防护："+reason), cmd)
	}
	if hosts, unknown := intercept.ScopeTargets(ev.ToolName, ev.Input); g.interceptor == nil && (len(hosts) > 0 || unknown) {
		setAudit(ctx, "scope", "deny", "范围校验器不可用")
		return g.block(ev.ToolName, systemBlockMessage("目标不在本任务授权范围：范围校验器不可用"), cmd)
	}
	if g.interceptor != nil {
		if dec, gated := g.interceptor.ScopeDecision(ctx, ev.ToolName, ev.Input); gated {
			setAudit(ctx, "scope", dec.Action, dec.Message)
			if result := g.applyDecision(ctx, ev, dec); result.Decision == "block" {
				return result
			}
		}
	}
	if g.interceptor != nil {
		if dec, gated := g.interceptor.OperationDecision(ctx, ev.ToolName, ev.Input); gated {
			setAudit(ctx, "task_policy", dec.Action, dec.Message)
			if result := g.applyDecision(ctx, ev, dec); result.Decision == "block" {
				return result
			}
			grantVersion = dec.AuthorizationVersion
		}
	}
	result = g.applyIntercept(ctx, ev)
	if result.Decision == "block" {
		return result
	}
	if g.interceptor != nil {
		updated, err := g.interceptor.PrepareShellInput(ctx, ev.ToolName, ev.Input)
		if err != nil {
			setAudit(ctx, "scope", "deny", err.Error())
			return g.block(ev.ToolName, systemBlockMessage(err.Error()), cmd)
		}
		if len(updated) > 0 {
			result.UpdatedInput, err = intercept.RewriteForwardedInput(outerTool, outerInput, updated)
			if err != nil {
				return g.block(ev.ToolName, systemBlockMessage(err.Error()), cmd)
			}
		}
	}
	return result
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.MatchContext(ctx, ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
		setAudit(ctx, "judge", dec.Action, dec.Message)
	} else {
		setAudit(ctx, "rule", dec.Action, dec.Message)
	}
	return g.applyDecision(ctx, ev, dec)
}

func (g *Guard) applyDecision(ctx context.Context, ev hook.Event, dec intercept.Decision) hook.Result {
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		binding, err := g.interceptor.BindApproval(ctx, ev.ToolName, ev.Input)
		if err != nil {
			return g.block(ev.ToolName, systemBlockMessage("无法绑定本次审批授权："+err.Error()), "")
		}
		dec.AuthorizationVersion = binding.AuthorizationVersion
		dec.ApprovedCallDigest = binding.CallDigest
		a, _ := ctx.Value(auditKey{}).(*db.ToolCallAudit)
		if a != nil {
			a.EffectiveAction = "pending"
			if err := g.persistAudit(ctx, a); err != nil {
				return hook.Result{Decision: "block", Message: systemBlockMessage("审批前调用审计写入失败")}
			}
		}
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		if err := g.interceptor.ValidateApproval(ctx, ev.ToolName, ev.Input, binding); err != nil {
			return g.block(ev.ToolName, systemBlockMessage(err.Error()), "")
		}
		if a != nil {
			a.EffectiveAction = "allow"
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【ARTEX 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}

func setAudit(ctx context.Context, source, decision, reason string) {
	if a, ok := ctx.Value(auditKey{}).(*db.ToolCallAudit); ok {
		a.Source = source
		a.Decision = decision
		a.Reason = boundedAudit(reason, 2048)
		a.EffectiveAction = decision
		if decision == "ask" {
			a.EffectiveAction = "pending"
		}
	}
}
func (g *Guard) persistAudit(ctx context.Context, a *db.ToolCallAudit) error {
	if g.auditWrite == nil {
		return nil
	} // New() is intentionally DB-free; production uses NewWithInterceptor.
	// Cancellation must not erase the audit of a cancelled/denied call. Bound the
	// write without retaining a long-lived goroutine or dropping records on a queue.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return g.auditWrite(writeCtx, a)
}
func boundedAudit(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
func inputSummary(input []byte) string {
	var v map[string]json.RawMessage
	if json.Unmarshal(input, &v) != nil {
		return "[invalid JSON]"
	}
	// Bound each field and overall JSON, excluding common credential fields.
	out := map[string]string{}
	for k, raw := range v {
		switch k {
		case "password", "token", "api_key", "authorization", "headers":
			out[k] = "[redacted]"
			continue
		}
		out[k] = boundedAudit(string(raw), 512)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fmt.Sprint("[summary unavailable]")
	}
	return boundedAudit(string(b), 2048)
}
