package db

import (
	"strconv"
	"testing"
)

func TestTaskProgressStopsNoResponseButAcceptsHTTPResponses(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("bounded failures", "mock only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	target, _ := ParseTarget("https://progress-" + id + ".example.test/")
	finish := func(status int, kind string) {
		t.Helper()
		requestID, e := d.BeginTargetRequest(t.Context(), id, target, "GET", "", TargetBudget{})
		if e != nil {
			t.Fatal(e)
		}
		if e = d.FinishTargetRequestOutcome(t.Context(), requestID, status, 1, "test failure", kind, 0); e != nil {
			t.Fatal(e)
		}
	}
	check := func(want string) {
		t.Helper()
		b, e := d.TaskExecutionBlock(t.Context(), id)
		if e != nil {
			t.Fatal(e)
		}
		got := ""
		if b != nil {
			got = b.Code
		}
		if got != want {
			t.Fatalf("block=%+v want=%s", b, want)
		}
	}
	for range 7 {
		finish(0, "transport")
	}
	check("")
	finish(403, "")
	check("") // actual target response is progress
	for range 7 {
		finish(0, "transport")
	}
	check("")
	finish(0, "cancelled")
	check("")
	for range 8 {
		finish(0, "transport")
	}
	check("no_http_response")
	if _, e := d.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, task.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, task.ID); e != nil {
		t.Fatal(e)
	}
	check("") // operator resume starts a new epoch; historical rows survive
	zero := 0
	if e := d.SaveTargetPolicy(t.Context(), id, TargetPolicy{NoResponseLimit: &zero}); e != nil {
		t.Fatal(e)
	}
	for range 9 {
		finish(0, "transport")
	}
	check("")
}

func TestTaskProgressDenialsBindAuthorizationAndHumanApproval(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	task, e := d.CreateTask("bounded denials", "mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	version, e := d.AuthorizationVersion(t.Context(), id)
	if e != nil {
		t.Fatal(e)
	}
	write := func(decision, effective, source string) {
		t.Helper()
		a := ToolCallAudit{TaskID: id, ToolName: "TargetHTTP", InputSummary: "mock", Decision: decision, EffectiveAction: effective, Source: source, AuthorizationVersion: version}
		if e := d.SaveToolCallAudit(t.Context(), &a); e != nil {
			t.Fatal(e)
		}
	}
	check := func(want bool) {
		t.Helper()
		b, e := d.TaskExecutionBlock(t.Context(), id)
		if e != nil {
			t.Fatal(e)
		}
		if (b != nil) != want {
			t.Fatalf("block=%+v want=%v", b, want)
		}
	}
	write("deny", "deny", "scope")
	write("allow", "allow", "default_allow")
	write("ask", "deny", "scope")
	check(false)
	write("ask", "allow", "scope")
	check(false) // explicit human approval resets refusal streak
	for range 3 {
		write("deny", "deny", "scope")
	}
	check(true)
	if e := d.SaveTargetPolicy(t.Context(), id, TargetPolicy{Mode: "read_only"}); e != nil {
		t.Fatal(e)
	}
	check(false)
	version, e = d.AuthorizationVersion(t.Context(), id)
	if e != nil {
		t.Fatal(e)
	}
	for range 3 {
		write("deny", "deny", "scope")
	}
	check(true)
}

func TestTaskProgressCountsActualGatewayRefusals(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	task, e := d.CreateTask("gateway refusal loop", "mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	target, _ := ParseTarget("https://refused-" + id + ".example.test/")
	for j := 1; j <= 3; j++ {
		if e = d.RecordDeniedTargetRequest(t.Context(), id, target, "GET", "budget exhausted"); e != nil {
			t.Fatal(e)
		}
		b, e := d.TaskExecutionBlock(t.Context(), id)
		if e != nil || ((b != nil) != (j == 3)) {
			t.Fatalf("gateway refusal %d: %+v %v", j, b, e)
		}
	}
}

func TestTaskProgressApprovalResolutionResetsAtResolutionTime(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	task, e := d.CreateTask("approval resolution boundary", "mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	version, e := d.AuthorizationVersion(t.Context(), id)
	if e != nil {
		t.Fatal(e)
	}
	pending := ToolCallAudit{TaskID: id, ToolName: "Bash", InputSummary: "mock", Source: "scope", Decision: "ask", EffectiveAction: "pending", AuthorizationVersion: version}
	if e = d.SaveToolCallAudit(t.Context(), &pending); e != nil {
		t.Fatal(e)
	}
	for range 3 {
		a := ToolCallAudit{TaskID: id, ToolName: "Bash", InputSummary: "mock", Source: "scope", Decision: "deny", EffectiveAction: "deny", AuthorizationVersion: version}
		if e = d.SaveToolCallAudit(t.Context(), &a); e != nil {
			t.Fatal(e)
		}
	}
	b, e := d.TaskExecutionBlock(t.Context(), id)
	if e != nil || b == nil {
		t.Fatalf("missing stop: %+v %v", b, e)
	}
	pending.EffectiveAction = "allow"
	pending.AuthorizationVersion = "must not rebind"
	if e = d.SaveToolCallAudit(t.Context(), &pending); e != nil {
		t.Fatal(e)
	}
	b, e = d.TaskExecutionBlock(t.Context(), id)
	if e != nil || b != nil {
		t.Fatalf("late human approval did not reset: %+v %v", b, e)
	}
	var bound string
	if e = d.QueryRow(`SELECT authorization_version FROM tool_call_audit WHERE id=$1`, pending.ID).Scan(&bound); e != nil || bound != version {
		t.Fatalf("old approval rebound: %s %v", bound, e)
	}
}
func TestTaskProgressLimitsAreOperatorBounded(t *testing.T) {
	for _, n := range []int{-1, 1001} {
		p := TargetPolicy{NoResponseLimit: &n}
		if p.Validate() == nil {
			t.Fatalf("invalid threshold accepted: %d", n)
		}
	}
	for _, n := range []int{0, 3, 8, 1000} {
		p := TargetPolicy{NoResponseLimit: &n, RepeatDenialLimit: &n}
		if e := p.Validate(); e != nil {
			t.Fatalf("valid threshold %d: %v", n, e)
		}
	}
}
