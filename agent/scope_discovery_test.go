package agent

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
)

func TestScopeDiscoveryDoesNotAskOrGrantNetworkAuthorization(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("discovery registration", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	ic := intercept.New(d)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "planner", nil))
	input := json.RawMessage(`{"kind":"cidr","value":"192.0.2.0/24","reason":"discovered","source":"manual"}`)
	if dec, gated := ic.ScopeDecision(ctx, "add_task_scope", input); gated {
		t.Fatalf("metadata registration asks for irrelevant network approval: %+v", dec)
	}
	blocked, msg, _ := guard.NewWithInterceptor(ic).Hooks().PreToolUse(ctx, "add_task_scope", input)
	if blocked {
		t.Fatal(msg)
	}
	ts := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	ts.SetTaskID(task.ID)
	ts.SetAssetStore(d.Assets(), d.Companies())
	result, err := ts.addTaskScope().Call(ctx, input, nil)
	if err != nil || result.IsError {
		t.Fatalf("%v %s", err, result.Flatten())
	}
	var body map[string]any
	json.Unmarshal([]byte(result.Flatten()), &body)
	if body["registration_only"] != true || body["network_authorization_changed"] != false {
		t.Fatal("tool result implies authorization was granted")
	}
	scope, err := d.TaskNetworkScope(ctx, id)
	if err != nil || db.NetworkScopeAllows(scope, "192.0.2.1") {
		t.Fatalf("discovery self-authorized network: %+v %v", scope, err)
	}
	if dec, gated := ic.ScopeDecision(ctx, "TargetHTTP", []byte(`{"url":"http://192.0.2.1/"}`)); !gated || dec.Action != "deny" {
		t.Fatalf("discovered target was not denied: %+v", dec)
	}
}
