package agent

import (
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"testing"
	"time"
)

func TestRequestOperatorIsBoundToCurrentTask(t *testing.T) {
	i := intercept.New(nil)
	called := make(chan string, 1)
	i.SetTaskPauseHandler(func(id string, _ *db.ExecutionBlock) error { called <- id; return nil })
	ctx := i.WithScope(intercept.WithTaskContext(t.Context(), "42", "worker", nil))
	result, err := requestOperatorTool().Call(ctx, []byte(`{"reason":"EOF twice, operator must check connectivity","task_id":"99"}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("request: %s %v", result.Flatten(), err)
	}
	select {
	case id := <-called:
		if id != "42" {
			t.Fatalf("foreign task paused: %s", id)
		}
	case <-time.After(time.Second):
		t.Fatal("pause not requested")
	}
	result, err = requestOperatorTool().Call(t.Context(), []byte(`{"reason":"no context"}`), nil)
	if err != nil || !result.IsError {
		t.Fatal("unbound pause accepted")
	}
}
