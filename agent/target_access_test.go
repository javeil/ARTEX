package agent

import (
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

func TestTaskAgentRejectsMissingSafetyContext(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		ctx := t.Context()
		if inherited {
			ctx = intercept.WithTaskContext(ctx, "42", "planner", nil)
		}
		if _, err := bindTaskAgentContext(ctx, 42, "planner", nil); err == nil {
			t.Errorf("task-bound session silently accepted missing interceptor (inherited=%v)", inherited)
		}
	}
	ctx := intercept.WithTaskContext(t.Context(), "42", "worker", nil)
	_, cleanup, err := prepareTargetAccess(ctx, "", "")
	cleanup()
	if err == nil {
		t.Fatal("target preparation silently skipped missing interceptor")
	}
	if _, err := bindTaskAgentContext(ctx, 0, "goals", nil); err == nil {
		t.Fatal("inherited task identity lost its safety requirement")
	}
	if _, err := bindTaskAgentContext(t.Context(), 0, "local", nil); err != nil {
		t.Fatalf("unbound offline use should remain available: %v", err)
	}
	ctx = intercept.New(nil).WithScope(t.Context())
	bound, err := bindTaskAgentContext(ctx, 42, "planner", nil)
	if err != nil || intercept.TaskIDFromContext(bound) != "42" {
		t.Fatalf("correctly wired task rejected: %v", err)
	}
	if _, err := bindTaskAgentContext(bound, 43, "planner", nil); err == nil {
		t.Fatal("mismatching task identity accepted")
	}
}
