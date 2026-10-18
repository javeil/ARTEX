package db

import (
	"strconv"
	"testing"
)

func TestTaskNetworkScopeUsesHumanGrantsOnly(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("network scope regression", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	for _, tc := range []struct{ domain, source string }{{"manual.example", "manual"}, {"discovered.example", "auto"}, {"self-granted.example", "agent"}} {
		if _, err := d.Assets().AddAgentScope(task.ID, "subdomain", tc.domain, "test", tc.source); err != nil {
			t.Fatal(err)
		}
	}
	rules, err := d.TaskNetworkScope(t.Context(), strconv.FormatInt(task.ID, 10))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !NetworkScopeAllows(rules, "manual.example") || NetworkScopeAllows(rules, "self-granted.example") {
		t.Fatalf("rules=%+v", rules)
	}
	if _, err := d.Exec(`DELETE FROM task_scope WHERE task_id=$1 AND source='manual'`, task.ID); err != nil {
		t.Fatal(err)
	}
	rules, err = d.TaskNetworkScope(t.Context(), strconv.FormatInt(task.ID, 10))
	if err != nil || len(rules) != 0 {
		t.Fatalf("revocation: %v %v", rules, err)
	}
}

func TestTaskNetworkScopeIncludesOnlyItsLinkedCompany(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("company network scope", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	cid, _, err := d.Companies().UpsertCompany("network-boundary-"+strconv.FormatInt(task.ID, 10), "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Companies().DeleteCompany(cid)
	added, _, invalid, messages := d.Companies().AddScope(cid, []string{"authorized.test", "198.51.100.0/24"}, "test human authorization")
	if added != 2 || invalid != 0 || len(messages) > 0 {
		t.Fatalf("company scope: added=%d invalid=%d messages=%v", added, invalid, messages)
	}
	_, err = d.Assets().AddAgentScope(task.ID, "company", strconv.FormatInt(cid, 10), "human grant", "manual")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := d.TaskNetworkScope(t.Context(), strconv.FormatInt(task.ID, 10))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host string
		want bool
	}{{"api.authorized.test", true}, {"198.51.100.42", true}, {"outside.test", false}, {"198.51.101.42", false}} {
		if got := NetworkScopeAllows(rules, tc.host); got != tc.want {
			t.Errorf("%s=%v", tc.host, got)
		}
	}
}
