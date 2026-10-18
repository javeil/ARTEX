package server

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
)

func TestHumanReadonlyConstraintCannotBeOverriddenByAllowRule(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("readonly effect regression", "local mock", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "subdomain", "example.com", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	_, e = pg.Exploration(task.ExplorationID).AddConstraint("deny", "仅允许只读验证，禁止修改目标既有业务订单", "human")
	if e != nil {
		t.Fatal(e)
	}
	rule, e := pg.CreateInterceptRule("cannot override task policy", "tool_name", "string", "Bash", "allow", "", 99999, true, false, 0, "deny")
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteInterceptRule(rule.ID)
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "test", nil))
	cmd := `curl -X POST https://example.com/api/action -d '{"action":"cancel","order_id":"mock-1"}'`
	raw, _ := json.Marshal(map[string]string{"command": cmd})
	blocked, _, _ := guard.NewWithInterceptor(ic).Hooks().PreToolUse(ctx, "Bash", raw)
	if !blocked {
		t.Fatal("business mutation bypassed human policy")
	}
	// Normal exploit/read techniques are not globally disabled by the policy.
	raw, _ = json.Marshal(map[string]string{"command": `sqlmap -u 'https://example.com/?id=1' --dump`})
	blocked, _, _ = guard.NewWithInterceptor(ic).Hooks().PreToolUse(ctx, "Bash", raw)
	if blocked {
		t.Fatal("ordinary data export technique was disabled")
	}
	var received *intercept.TrustedPolicy
	ic.SetReviewer(func(_ context.Context, _ int64, _ string, in intercept.ReviewInput) (intercept.Decision, error) {
		received = in.TrustedPolicy
		return intercept.Decision{Action: "allow"}, nil
	})
	old := ic.GetJudgeConfig()
	defer ic.SetJudgeConfig(old)
	cfg := old
	cfg.Enabled = true
	if e := ic.SetJudgeConfig(cfg); e != nil {
		t.Fatal(e)
	}
	_, _ = ic.Judge(ctx, "WebFetch", []byte(`{"url":"https://example.com/api"}`))
	if received == nil || received.Policy.Mode != "read_only" || len(received.HumanConstraints) != 1 {
		t.Fatalf("trusted constraints missing: %+v", received)
	}
}
