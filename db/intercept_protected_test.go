package db

import (
	"errors"
	"testing"
)

func TestProtectedRulesCannotBeRemovedAndDisableIsAudited(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rules, err := d.ListInterceptRules()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range rules {
		if !r.Protected {
			continue
		}
		found++
		if err := d.DeleteInterceptRule(r.ID); !errors.Is(err, ErrProtectedRule) {
			t.Fatalf("delete protected=%v", err)
		}
		if err := d.ToggleInterceptRule(r.ID, false); err == nil {
			t.Fatal("unattributed disable accepted")
		}
		if err := d.ToggleInterceptRule(r.ID, false, RuleChange{Actor: "test-admin", Reason: "maintenance test"}); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := d.QueryRow(`SELECT count(*) FROM intercept_rule_changes WHERE rule_id=$1 AND actor='test-admin' AND reason='maintenance test'`, r.ID).Scan(&count); err != nil || count < 1 {
			t.Fatalf("audit count=%d err=%v", count, err)
		}
		listed, err := d.ListInterceptRules()
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range listed {
			if v.ID == r.ID && !v.CoreProtectionDisabled {
				t.Fatal("disabled core status hidden")
			}
		}
		if _, err := d.UpdateInterceptRule(r.ID, "renamed", r.MatchTarget, r.MatchType, r.Pattern, "allow", "", r.Priority, false, true, 60, "deny"); !errors.Is(err, ErrProtectedRule) {
			t.Fatalf("update bypass=%v", err)
		}
		if err := d.ToggleInterceptRule(r.ID, true, RuleChange{Actor: "test-admin", Reason: "restore"}); err != nil {
			t.Fatal(err)
		}
	}
	if found < 6 {
		t.Fatalf("protected core count=%d", found)
	}
}
