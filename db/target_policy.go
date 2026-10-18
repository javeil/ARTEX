package db

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// Target retains the service identity. Scope normalization must never silently
// turn authorization for one port/path into authorization for the entire host.
type Target struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme,omitempty"`
	Port   int    `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
	URL    string `json:"url,omitempty"`
}

func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	t := Target{}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || u.User != nil {
			return t, fmt.Errorf("无效目标 URL")
		}
		t.Host = NormalizeScopeHost(u.Hostname())
		t.Scheme = strings.ToLower(u.Scheme)
		if u.Port() != "" {
			if _, err := fmt.Sscan(u.Port(), &t.Port); err != nil || t.Port < 1 || t.Port > 65535 {
				return t, fmt.Errorf("无效端口")
			}
		} else {
			switch t.Scheme {
			case "http":
				t.Port = 80
			case "https":
				t.Port = 443
			}
		}
		t.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
		t.URL = raw
	} else {
		t.Host = NormalizeScopeHost(raw)
		if h, p, err := net.SplitHostPort(raw); err == nil {
			t.Host = NormalizeScopeHost(h)
			if _, err := fmt.Sscan(p, &t.Port); err != nil || t.Port < 1 || t.Port > 65535 {
				return t, fmt.Errorf("无效端口")
			}
		}
	}
	if t.Host == "" {
		return t, fmt.Errorf("目标 host 为空或无效")
	}
	return t, nil
}
func (t Target) ServiceKey() string {
	return t.Scheme + "://" + net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
}

type TargetSpec struct {
	Host                 string   `json:"host"`
	IncludeSubdomains    bool     `json:"include_subdomains,omitempty"`
	Schemes              []string `json:"schemes,omitempty"`
	Ports                []int    `json:"ports,omitempty"`
	PathPrefixes         []string `json:"path_prefixes,omitempty"`
	ExcludedPathPrefixes []string `json:"excluded_path_prefixes,omitempty"`
}
type OperationRule struct {
	CleanupIfMatch bool       `json:"cleanup_if_match,omitempty"`
	Target         TargetSpec `json:"target"`
	Methods        []string   `json:"methods"`
	Effect         string     `json:"effect"` // read|probe|authenticate|artifact_create
	AccountField   string     `json:"account_field,omitempty"`
}
type TargetBudget struct {
	RequestsPerSecond    int `json:"requests_per_second,omitempty"`
	MaxConcurrent        int `json:"max_concurrent,omitempty"`
	MaxRequests          int `json:"max_requests,omitempty"`
	AccountAttempts      int `json:"account_attempts,omitempty"`
	AccountWindowSeconds int `json:"account_window_seconds,omitempty"`
	ConsecutiveFailures  int `json:"consecutive_failures,omitempty"`
	MaxLatencyMS         int `json:"max_latency_ms,omitempty"`
	CooldownSeconds      int `json:"cooldown_seconds,omitempty"`
}

// TargetPolicy is operator-owned. Models cannot write this through a tool.
// Missing target restrictions retain legacy manually granted hosts, never grant
// new hosts. An explicit target list narrows those grants.
type TargetPolicy struct {
	Mode          string          `json:"mode"` // standard|read_only|passive
	Targets       []TargetSpec    `json:"targets,omitempty"`
	DeniedEffects []string        `json:"denied_effects,omitempty"`
	Accounts      []string        `json:"accounts,omitempty"`
	Operations    []OperationRule `json:"operations,omitempty"`
	Budget        TargetBudget    `json:"budget"`
	StartsAt      *time.Time      `json:"starts_at,omitempty"`
	ExpiresAt     *time.Time      `json:"expires_at,omitempty"`
}

func (p TargetPolicy) Validate() error {
	switch p.Mode {
	case "", "standard", "read_only", "passive":
	default:
		return fmt.Errorf("mode 必须是 standard/read_only/passive")
	}
	if len(p.Targets) > 200 || len(p.Operations) > 200 || len(p.Accounts) > 10000 {
		return fmt.Errorf("策略条目过多")
	}
	validateSpec := func(s TargetSpec) error {
		if NormalizeScopeHost(s.Host) == "" || strings.Contains(s.Host, "://") {
			return fmt.Errorf("target.host 必须是域名/IP/CIDR")
		}
		if len(s.Ports) > 65535 {
			return fmt.Errorf("端口过多")
		}
		for _, n := range s.Ports {
			if n < 1 || n > 65535 {
				return fmt.Errorf("端口必须在 1..65535")
			}
		}
		for _, v := range s.Schemes {
			switch v {
			case "http", "https", "tcp", "udp":
			default:
				return fmt.Errorf("不支持的协议 %s", v)
			}
		}
		for _, v := range append(append([]string{}, s.PathPrefixes...), s.ExcludedPathPrefixes...) {
			if !strings.HasPrefix(v, "/") {
				return fmt.Errorf("URL 路径前缀必须以 / 开头")
			}
		}
		return nil
	}
	for _, s := range p.Targets {
		if err := validateSpec(s); err != nil {
			return err
		}
	}
	for _, r := range p.Operations {
		if err := validateSpec(r.Target); err != nil {
			return err
		}
		if len(r.Methods) == 0 {
			return fmt.Errorf("operation.methods 不能为空")
		}
		for _, m := range r.Methods {
			switch m {
			case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE":
			default:
				return fmt.Errorf("无效 HTTP 方法")
			}
		}
		switch r.Effect {
		case "read", "probe", "authenticate", "artifact_create":
		default:
			return fmt.Errorf("operation.effect 不是可授权的测试效果")
		}
	}
	for _, e := range p.DeniedEffects {
		switch e {
		case "read", "probe", "authenticate", "artifact_create", "artifact_cleanup", "artifact_update", "business_write", "account_change", "service_change", "unknown_write":
		default:
			return fmt.Errorf("无效 denied_effect %s", e)
		}
	}
	for _, n := range []int{p.Budget.RequestsPerSecond, p.Budget.MaxConcurrent, p.Budget.MaxRequests, p.Budget.AccountAttempts, p.Budget.AccountWindowSeconds, p.Budget.ConsecutiveFailures, p.Budget.MaxLatencyMS, p.Budget.CooldownSeconds} {
		if n < 0 || n > 100000000 {
			return fmt.Errorf("预算必须是有限非负整数")
		}
	}
	if p.Budget.AccountAttempts > 0 && p.Budget.AccountWindowSeconds <= 0 {
		return fmt.Errorf("账号尝试预算必须设置时间窗口")
	}
	if p.StartsAt != nil && p.ExpiresAt != nil && !p.StartsAt.Before(*p.ExpiresAt) {
		return fmt.Errorf("授权起止时间无效")
	}
	return nil
}
func pathWithin(p, prefix string) bool {
	prefix = path.Clean(prefix)
	p = path.Clean(p)
	return prefix == "/" || p == prefix || strings.HasPrefix(p, prefix+"/")
}
func (s TargetSpec) Matches(t Target) bool {
	h := NormalizeScopeHost(s.Host)
	hostOK := h == t.Host || (s.IncludeSubdomains && strings.HasSuffix(t.Host, "."+h))
	if prefix, err := netip.ParsePrefix(h); err == nil {
		if addr, e := netip.ParseAddr(t.Host); e == nil {
			hostOK = prefix.Contains(addr)
		} else if sub, e := netip.ParsePrefix(t.Host); e == nil {
			hostOK = prefix.Bits() <= sub.Bits() && prefix.Contains(sub.Masked().Addr())
		}
	}
	if !hostOK {
		return false
	}
	if len(s.Schemes) > 0 {
		ok := false
		for _, v := range s.Schemes {
			ok = ok || v == t.Scheme
		}
		if !ok {
			return false
		}
	}
	if len(s.Ports) > 0 {
		ok := false
		for _, v := range s.Ports {
			ok = ok || v == t.Port
		}
		if !ok {
			return false
		}
	}
	for _, p := range s.ExcludedPathPrefixes {
		if t.Path == "" || pathWithin(t.Path, p) {
			return false
		}
	}
	if len(s.PathPrefixes) > 0 {
		ok := false
		for _, p := range s.PathPrefixes {
			ok = ok || (t.Path != "" && pathWithin(t.Path, p))
		}
		if !ok {
			return false
		}
	}
	return true
}
func (d *DB) LoadTargetPolicy(ctx context.Context, id string) (TargetPolicy, error) {
	var raw []byte
	err := d.QueryRowContext(ctx, `SELECT COALESCE(p.policy,'{}'::jsonb) FROM tasks t LEFT JOIN task_target_policies p ON p.task_id=t.id WHERE t.id::text=$1`, id).Scan(&raw)
	if err != nil {
		return TargetPolicy{}, err
	}
	var p TargetPolicy
	if err = json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if err = p.Validate(); err != nil {
		return p, err
	}
	if p.Mode == "" {
		p.Mode = "standard"
	}
	return p, nil
}
func (d *DB) SaveTargetPolicy(ctx context.Context, id string, p TargetPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Mode == "" {
		p.Mode = "standard"
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO task_target_policies(task_id,policy) SELECT id,$2::jsonb FROM tasks WHERE id::text=$1 ON CONFLICT(task_id) DO UPDATE SET policy=excluded.policy,revision=task_target_policies.revision+1,updated_at=now()`, id, raw)
	if err != nil {
		return err
	}
	budget, _ := json.Marshal(p.Budget)
	if _, err = tx.ExecContext(ctx, `UPDATE target_budget_claims SET budget=$2::jsonb WHERE task_id=$1`, id, budget); err != nil {
		return err
	}
	return tx.Commit()
}
func (d *DB) CheckTaskTarget(ctx context.Context, id string, t Target) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var paused, queued bool
	var status string
	var deadline *time.Time
	if err := d.QueryRowContext(ctx, `SELECT paused,queued,status,deadline_at FROM tasks WHERE id::text=$1 AND archived_at IS NULL`, id).Scan(&paused, &queued, &status, &deadline); err != nil {
		return fmt.Errorf("授权任务不可用: %w", err)
	}
	if paused || queued || IsTerminal(status) || (deadline != nil && !time.Now().Before(*deadline)) {
		return fmt.Errorf("授权任务已暂停、排队、结束或到期")
	}
	rules, err := d.TaskNetworkScope(ctx, id)
	if err != nil {
		return err
	}
	if !NetworkScopeAllows(rules, t.Host) {
		return fmt.Errorf("目标 %s 未被任务授权", t.Host)
	}
	p, err := d.LoadTargetPolicy(ctx, id)
	if err != nil {
		return err
	}
	if p.Mode == "passive" {
		return fmt.Errorf("本任务只允许被动分析，不允许主动访问目标")
	}
	now := time.Now()
	if (p.StartsAt != nil && now.Before(*p.StartsAt)) || (p.ExpiresAt != nil && !now.Before(*p.ExpiresAt)) {
		return fmt.Errorf("不在任务授权时间窗口")
	}
	if len(p.Targets) > 0 {
		ok := false
		for _, s := range p.Targets {
			ok = ok || s.Matches(t)
		}
		if !ok {
			return fmt.Errorf("目标协议、端口或路径不在本任务授权范围")
		}
	}
	block, err := d.ListAssetInterceptRules()
	if err != nil {
		return err
	}
	taskID := int64(0)
	if _, err = fmt.Sscan(id, &taskID); err != nil {
		return err
	}
	tb, allow, err := d.Assets().TaskInterceptRulesSplit(taskID)
	if err != nil {
		return err
	}
	block = append(block, tb...)
	domains, ips, urls := []string{}, []string{}, []string{}
	if net.ParseIP(t.Host) != nil {
		ips = append(ips, t.Host)
	} else {
		domains = append(domains, t.Host)
	}
	if t.URL != "" {
		urls = append(urls, t.URL)
	}
	if decision := EvaluateAssetGate(block, allow, domains, ips, urls); !decision.Allowed {
		return fmt.Errorf("禁止访问目标：%s", decision.Reason)
	}
	return nil
}

// AuthorizationVersion is a single MVCC snapshot of every authorization source.
// Approvals cannot survive changes to scope, company scope, exclusions, policy,
// task state or human constraints merely because a policy row was not edited.
func (d *DB) AuthorizationVersion(ctx context.Context, id string) (string, error) {
	var raw string
	err := d.QueryRowContext(ctx, `SELECT jsonb_build_object(
 'task',jsonb_build_array(t.status,t.paused,t.queued,t.deadline_at,t.archived_at),
 'policy',(SELECT policy FROM task_target_policies WHERE task_id=t.id),
 'scope',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM task_scope s WHERE s.task_id=t.id AND s.source='manual'),
 'company',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM company_scope c WHERE c.company_id IN (SELECT company_id FROM task_scope WHERE task_id=t.id AND kind='company' AND source='manual')),
 'exclude',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM task_intercept_rules r WHERE r.task_id=t.id),
 'global',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM asset_intercept_rules r),
 'resources',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM target_test_resources r WHERE r.task_id=t.id::text),
 'constraints',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM task_constraints c WHERE c.exploration_id=t.exploration_id AND c.origin='human')
 )::text FROM tasks t WHERE t.id::text=$1`, id).Scan(&raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(raw))), nil
}

// CheckTaskExecution also applies to opaque approved programs without a literal
// target: no pending approval may revive a paused/expired/finished engagement.
func (d *DB) CheckTaskExecution(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var paused, queued bool
	var status string
	var deadline *time.Time
	if err := d.QueryRowContext(ctx, `SELECT paused,queued,status,deadline_at FROM tasks WHERE id::text=$1 AND archived_at IS NULL`, id).Scan(&paused, &queued, &status, &deadline); err != nil {
		return err
	}
	if paused || queued || IsTerminal(status) || (deadline != nil && !time.Now().Before(*deadline)) {
		return fmt.Errorf("授权任务已暂停、结束或到期")
	}
	p, err := d.LoadTargetPolicy(ctx, id)
	if err != nil {
		return err
	}
	now := time.Now()
	if (p.StartsAt != nil && now.Before(*p.StartsAt)) || (p.ExpiresAt != nil && !now.Before(*p.ExpiresAt)) {
		return fmt.Errorf("不在任务授权时间窗口")
	}
	return nil
}
