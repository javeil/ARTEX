package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestScopeTargets(t *testing.T) {
	for _, tc := range []struct {
		command   string
		hosts     []string
		uncertain bool
	}{
		{`curl https://api.example.com:8443/a`, []string{"api.example.com"}, false},
		{`nmap -p 80,443 10.2.3.4`, []string{"10.2.3.4"}, false},
		{`nmap 10.2.3.0/24`, []string{"10.2.3.0/24"}, false},
		{`nmap -6 2001:db8:1::/48`, []string{"2001:db8:1::/48"}, false},
		{`nmap 10.2.3.1-254`, []string{"10.2.3.1"}, true},
		{`nc example.com 443`, []string{"example.com"}, false},
		{`wget --max-redirect=0 https://example.com`, []string{"example.com"}, false},
		{`curl "https://${HOST}/a"`, nil, true},
		{`python3 -c 'import requests; requests.get("https://"+"outside.test")'`, nil, true},
		{`curl https://example.com; python3 attack.py`, []string{"example.com"}, true},
		{`curl -L https://example.com`, []string{"example.com"}, true},
		{`ls -la`, nil, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]string{"command": tc.command})
			hosts, unknown := intercept.ScopeTargets("Bash", raw)
			if strings.Join(hosts, ",") != strings.Join(tc.hosts, ",") || unknown != tc.uncertain {
				t.Fatalf("hosts=%v uncertain=%v", hosts, unknown)
			}
		})
	}
}

func TestScopeMatching(t *testing.T) {
	rules := []db.NetworkScope{{Kind: "root_domain", Domain: "example.com"}, {Kind: "subdomain", Domain: "exact.test"}, {Kind: "cidr", Net: "10.2.0.0/16"}, {Kind: "cidr", Net: "2001:db8::/32"}}
	for _, tc := range []struct {
		host    string
		allowed bool
	}{
		{"EXAMPLE.com.:443", true}, {"a.example.com", true}, {"example.com.evil.test", false}, {"notexample.com", false},
		{"exact.test", true}, {"a.exact.test", false}, {"10.2.3.4:8080", true}, {"10.3.0.1", false}, {"10.2.3.0/24", true}, {"10.0.0.0/8", false}, {"2001:db8:1::/48", true}, {"[2001:db8::1]:80", true},
	} {
		if got := db.NetworkScopeAllows(rules, tc.host); got != tc.allowed {
			t.Errorf("%s=%v", tc.host, got)
		}
	}
}

func TestTaskScopeCannotBeSkippedWithNoInterceptor(t *testing.T) {
	ctx := intercept.WithTaskContext(context.Background(), "7", "worker", nil)
	b, msg, _ := New().Hooks().PreToolUse(ctx, "WebFetch", []byte(`{"url":"https://outside.test"}`))
	if !b || !strings.Contains(msg, "授权范围") {
		t.Fatalf("block=%v message=%s", b, msg)
	}
}

func TestDeferredToolCannotBypassScope(t *testing.T) {
	ctx := intercept.WithTaskContext(t.Context(), "42", "worker", nil)
	b, msg, _ := New().Hooks().PreToolUse(ctx, "ExecuteExtraTool", []byte(`{"tool_name":"WebFetch","params":{"url":"https://outside.test"}}`))
	if !b || !strings.Contains(msg, "授权范围") {
		t.Fatal("deferred trampoline bypassed task scope")
	}
}
