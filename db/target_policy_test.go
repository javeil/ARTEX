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
