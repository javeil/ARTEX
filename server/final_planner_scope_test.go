package server

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
)

type finalScopeProvider struct {
	sessionToolProvider
	scope bool
}

func (p *finalScopeProvider) Stream(ctx context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.scope = intercept.HasScopeContext(ctx)
	return p.sessionToolProvider.Stream(ctx, r)
}

func (p *finalScopeProvider) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.scope = intercept.HasScopeContext(ctx)
	return p.sessionToolProvider.Complete(ctx, r)
}

func TestFinalPlannerPreservesSafetyAndAuditAfterPauseOrExpiry(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("isolated PG required: %v", err)
	}
	defer m.Close()
	for _, state := range []string{"paused", "expired"} {
		for _, network := range []bool{false, true} {
			t.Run(state+"/network="+strconv.FormatBool(network), func(t *testing.T) {
				var hits atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
				defer target.Close()
				task, err := m.CreateTask("final planner safety regression", "mock only", nil, 1, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer m.DeleteTask(task.ID, DeleteTaskOptions{})
				id, _ := strconv.ParseInt(task.ID, 10, 64)
				if _, err = m.assets.AddAgentScope(id, "ip", "127.0.0.1", "human", "manual"); err != nil {
					t.Fatal(err)
				}
				engine := NewEngine(m)
				if state == "paused" {
					if err = m.ApplyTaskPause(task.ID); err != nil {
						t.Fatal(err)
					}
					if err = m.interceptor.StopTargetIO(t.Context(), task.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err = m.pg.Exec(`UPDATE tasks SET deadline_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
						t.Fatal(err)
					}
					engine.deadline.Store(task.ID, time.Now().Add(-time.Second).Unix())
				}
				command := "printf final-local-analysis"
				if network {
					command = "curl -sS " + target.URL + "/must-not-send"
				}
				input, _ := json.Marshal(map[string]string{"command": command})
				prov := &finalScopeProvider{sessionToolProvider: sessionToolProvider{tool: "Bash", input: input}}
				planner := agent.NewPlanner(prov, "mock", t.TempDir(), nil, 0, 3)
				engine.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return planner, nil })
				engine.runFinalPlannerRound(t.Context(), task)
				if !prov.scope {
					t.Fatal("final planner lost interceptor context")
				}
				if hits.Load() != 0 {
					t.Fatal("paused/expired final planner contacted target")
				}
				records, err := m.pg.ListTaskToolCalls(t.Context(), task.ID, 0, 100)
				if err != nil || len(records) != 1 {
					t.Fatalf("expected one durable call: %+v %v", records, err)
				}
				want := "allow"
				if network {
					want = "deny"
				}
				if records[0].EffectiveAction != want {
					t.Fatalf("final decision=%s want=%s", records[0].EffectiveAction, want)
				}
				if !network {
					var completed int
					if err = m.pg.QueryRow(`SELECT count(*) FROM activity WHERE exploration_id=$1 AND kind='tool_result' AND summary LIKE '%final-local-analysis%'`, task.ExpID).Scan(&completed); err != nil || completed == 0 {
						t.Fatalf("local analysis did not execute: %v", err)
					}
				}
				if state == "paused" && !m.interceptor.TargetIOState(task.ID).Blocked {
					t.Fatal("final analysis restored stopped target access")
				}
			})
		}
	}
}
