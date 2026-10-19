package server

import (
	"context"
	"encoding/json"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestToolCallHistoryHTTP(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	s := &Server{m: &Manager{pg: pg}}
	for _, tc := range []struct {
		query string
		code  int
	}{{"", 200}, {"?limit=501", 400}, {"?before_id=-1", 400}, {"?limit=oops", 400}} {
		req := httptest.NewRequest("GET", "/api/intercept/task/none/calls"+tc.query, nil)
		req.SetPathValue("taskID", "none")
		w := httptest.NewRecorder()
		s.interceptListTaskCalls(w, req)
		if w.Code != tc.code {
			t.Fatalf("%s=%d body=%s", tc.query, w.Code, w.Body.String())
		}
	}
}

func TestGuardDurableAuditForRuleJudgeDefaultAndDisabledTools(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	for _, key := range []string{"intercept_enabled_tools", "llm_judge_enabled"} {
		v, exists, err := pg.GetSetting(key)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if exists {
				_ = pg.SetSetting(key, v)
			} else {
				_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, key)
			}
		}()
	}
	ic := intercept.New(pg)
	if err := ic.SetEnabledTools([]string{"AuditProbe"}); err != nil {
		t.Fatal(err)
	}
	fixture, err := pg.CreateTask("durable guard audit", "local probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(fixture.ID)
	task := strconv.FormatInt(fixture.ID, 10)
	defer pg.Exec(`DELETE FROM tool_call_audit WHERE task_id=$1`, task)
	defer pg.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, task)
	ctx := intercept.WithTaskContext(t.Context(), task, "test-agent", func(a db.Activity) {
		rows, err := pg.ListTaskToolCalls(t.Context(), task, 0, 1)
		if err != nil || len(rows) != 1 || rows[0].Decision != "ask" || rows[0].EffectiveAction != "pending" {
			t.Errorf("ask not durable before approval: rows=%v err=%v", rows, err)
		}
		var detail struct {
			ID int64 `json:"pending_id"`
		}
		_ = json.Unmarshal([]byte(a.Detail), &detail)
		if err := ic.Decide(detail.ID, true); err != nil {
			t.Error(err)
		}
	})
	g := guard.NewWithInterceptor(ic)
	for _, action := range []string{"allow", "deny", "ask"} {
		rule, err := pg.CreateInterceptRule("durable audit fixture", "tool_name", "string", "AuditProbe", action, "fixture", 1000, true, true, 1, "deny")
		if err != nil {
			t.Fatal(err)
		}
		ic.Invalidate()
		blocked, _, _ := g.Hooks().PreToolUse(ctx, "AuditProbe", []byte(`{}`))
		if blocked != (action == "deny") {
			t.Fatalf("%s blocked=%v", action, blocked)
		}
		if err := pg.DeleteInterceptRule(rule.ID); err != nil {
			t.Fatal(err)
		}
		ic.Invalidate()
	}
	if err := pg.SetSetting("llm_judge_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		return intercept.Decision{Action: "allow", Message: "audit test"}, nil
	})
	g.Hooks().PreToolUse(ctx, "AuditProbe", []byte(`{}`))
	if err := pg.SetSetting("llm_judge_enabled", "false"); err != nil {
		t.Fatal(err)
	}
	g.Hooks().PreToolUse(ctx, "AuditProbe", []byte(`{}`))
	if err := ic.SetEnabledTools([]string{}); err != nil {
		t.Fatal(err)
	}
	g.Hooks().PreToolUse(ctx, "AuditProbe", []byte(`{}`))
	rows, err := pg.ListTaskToolCalls(t.Context(), task, 0, 100)
	if err != nil || len(rows) != 6 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	for j, want := range []string{"default_allow", "default_allow", "judge", "rule", "rule", "rule"} {
		if rows[j].Source != want {
			t.Fatalf("row[%d]=%+v", j, rows[j])
		}
	}
	if rows[3].Decision != "ask" || rows[3].EffectiveAction != "allow" {
		t.Fatal("ask resolution not saved")
	}
}
