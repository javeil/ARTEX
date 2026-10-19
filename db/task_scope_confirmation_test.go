package db

import (
	"strconv"
	"testing"
)

func TestManualConfirmationPromotesOnlyMatchingDiscoveredScope(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("scope confirmation regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	as := d.Assets()
	id := strconv.FormatInt(task.ID, 10)
	for _, entry := range []struct{ kind, value, source string }{{"ip", "192.0.2.1", "agent"}, {"cidr", "192.0.2.0/24", "agent"}, {"subdomain", "discovered.example", "auto"}} {
		if _, err = as.AddAgentScope(task.ID, entry.kind, entry.value, "discovered", entry.source); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = as.AddAgentScope(task.ID, "ip", "192.0.2.1", "user confirmed this single host", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err = as.AddAgentScope(task.ID, "subdomain", "discovered.example", "user confirmed this domain", "manual"); err != nil {
		t.Fatal(err)
	}
	rules, err := d.TaskNetworkScope(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !NetworkScopeAllows(rules, "192.0.2.1") || !NetworkScopeAllows(rules, "discovered.example") {
		t.Errorf("manual confirmation was silently ignored: %+v", rules)
	}
	if NetworkScopeAllows(rules, "192.0.2.2") {
		t.Fatal("single-host confirmation promoted the whole discovered subnet")
	}
	if _, err = as.AddAgentScope(task.ID, "ip", "192.0.2.1", "agent re-added", "agent"); err != nil {
		t.Fatal(err)
	}
	rules, _ = d.TaskNetworkScope(t.Context(), id)
	if !NetworkScopeAllows(rules, "192.0.2.1") {
		t.Fatal("agent downgraded human authorization")
	}
	var confirmations int
	if err = d.QueryRow(`SELECT count(*) FROM target_control_events WHERE task_id=$1 AND action='authorize_scope'`, id).Scan(&confirmations); err != nil {
		t.Fatal(err)
	}
	if confirmations != 2 {
		t.Errorf("manual confirmations need one durable event each: %d", confirmations)
	}
	if _, err = as.AddAgentScope(task.ID, "ip", "192.0.2.1", "same confirmation", "manual"); err != nil {
		t.Fatal(err)
	}
	var repeated int
	d.QueryRow(`SELECT count(*) FROM target_control_events WHERE task_id=$1 AND action='authorize_scope'`, id).Scan(&repeated)
	if repeated != confirmations {
		t.Fatal("idempotent confirmation produced a duplicate grant event")
	}
}
