package intercept

import (
	"context"
	"testing"
)

func TestScopeUnknownPolicyAndMutationCannotBeAllowRuleBypassed(t *testing.T) {
	for _, action := range []string{"", "ask", "deny", "allow"} {
		settings := map[string]string{}
		if action != "" {
			settings["scope_unknown_target_action"] = action
		}
		i := retryTestInterceptor(t, settings)
		ctx := WithTaskContext(t.Context(), "42", "worker", nil)
		dec, ok := i.ScopeDecision(ctx, "Bash", []byte(`{"command":"python3 attack.py"}`))
		want := action
		if want == "" {
			want = "ask"
		}
		if got := i.getSettingChoice("scope_unknown_target_action", "ask", "ask", "deny", "allow"); got != want {
			t.Fatalf("config=%s want=%s", got, want)
		}
		if !ok || dec.Action != "deny" {
			t.Fatalf("missing task policy must fail closed: %+v", dec)
		}
		dec, ok = i.ScopeDecision(ctx, "add_company_scope", []byte(`{}`))
		if !ok || dec.Action != "ask" {
			t.Fatal("scope mutation must require human approval")
		}
		dec, ok = i.ScopeDecision(ctx, "Bash", []byte(`{"command":"curl -sSL https://example.com"}`))
		if !ok || dec.Action != "deny" {
			t.Fatal("automatic redirects must be denied even with unknown=allow")
		}
	}
	if err := CheckURL(WithTaskContext(context.Background(), "42", "", nil), "https://example.com"); err == nil {
		t.Fatal("missing transport wiring must deny")
	}
}
