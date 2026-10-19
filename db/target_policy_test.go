package db

import (
	"strconv"
	"testing"
)

func TestTargetPolicyEnforcesExclusionsAndServiceBoundary(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("target control regression", "local mock only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	if _, err := d.Assets().AddAgentScope(task.ID, "root_domain", "example.com", "human authorization", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Assets().CreateTaskInterceptRule(task.ID, "block", "fuzzy_url", "/excluded", "must not contact", true); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveTargetPolicy(t.Context(), id, TargetPolicy{Targets: []TargetSpec{{Host: "api.example.com", Schemes: []string{"https"}, Ports: []int{443}, PathPrefixes: []string{"/api"}}}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		raw   string
		allow bool
	}{{"https://api.example.com/api/items", true}, {"https://api.example.com/api/excluded", false}, {"https://api.example.com:22/api", false}, {"http://api.example.com/api", false}, {"https://api.example.com/admin", false}, {"https://other.example.com/api", false}, {"https://api.example.com/apiary", false}} {
		target, err := ParseTarget(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		err = d.CheckTaskTarget(t.Context(), id, target)
		if (err == nil) != tc.allow {
			t.Errorf("%s allowed=%v err=%v", tc.raw, err == nil, err)
		}
	}
}

func TestCanonicalURLAndCIDRExclusionsCannotBeBypassed(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	task, e := d.CreateTask("canonical exclusions", "mock", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	for _, entry := range []struct{ kind, value string }{{"subdomain", "api.example.com"}, {"cidr", "10.24.0.0/16"}} {
		if _, e = d.Assets().AddAgentScope(task.ID, entry.kind, entry.value, "manual", "manual"); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = d.Assets().CreateTaskInterceptRule(task.ID, "block", "exact_url", "https://api.example.com/admin", "excluded", true); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Assets().CreateTaskInterceptRule(task.ID, "block", "exact_ip", "10.24.1.9", "excluded", true); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"https://API.EXAMPLE.COM:443/a/../admin#fragment", "10.24.0.0/16"} {
		target, e := ParseTarget(raw)
		if e != nil {
			t.Fatal(e)
		}
		if e = d.CheckTaskTarget(t.Context(), id, target); e == nil {
			t.Fatalf("exclusion bypassed: %s", raw)
		}
	}
}
