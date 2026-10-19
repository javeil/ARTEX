package server

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
)

type sessionToolProvider struct {
	tool  string
	input json.RawMessage
	turns int
}

func (p *sessionToolProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.turns++
		events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "done"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
		if p.turns == 1 {
			events = []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "scope-proof", ToolName: p.tool}, {Type: llm.SEToolInputJSON, Text: string(p.input)}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
		}
		for _, event := range events {
			if !yield(event, nil) {
				return
			}
		}
	}
}
func (p *sessionToolProvider) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for e, err := range p.Stream(ctx, r) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(e)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func TestPlannerAndMainAgentEnforceGuardOnRealSessions(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	for _, role := range []string{"planner", "mainagent"} {
		for _, allowed := range []bool{false, true} {
			t.Run(role+"/allowed="+strconv.FormatBool(allowed), func(t *testing.T) {
				var hits atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
				defer target.Close()
				task, err := pg.CreateTask("session guard regression", "local mock", nil, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer pg.DeleteTask(task.ID)
				if allowed {
					if _, err = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "operator", "manual"); err != nil {
						t.Fatal(err)
					}
				}
				ic := intercept.New(pg)
				// Real server callers supply the interceptor; the agent knows the host task ID.
				ctx := ic.WithScope(t.Context())
				command := "curl -sS " + target.URL + "/probe"
				if !allowed {
					command = "curl -sS --noproxy '*' " + target.URL + "/outside"
				}
				input, _ := json.Marshal(map[string]string{"command": command})
				prov := &sessionToolProvider{tool: "Bash", input: input}
				exp := pg.Exploration(task.ExplorationID)
				if role == "mainagent" {
					_, err = agent.NewMainAgent(prov, "mock", t.TempDir(), nil, 0, 3).Chat(ctx, task.ID, 0, pg.Assets(), exp, "test", "test", nil, nil, nil, nil, nil)
				} else {
					_, _, err = agent.NewPlanner(prov, "mock", t.TempDir(), nil, 0, 3).Plan(ctx, task.ID, pg.Assets(), exp, "test", nil, nil)
				}
				if err != nil {
					t.Fatal(err)
				}
				want := int32(0)
				if allowed {
					want = 1
				}
				if hits.Load() != want {
					t.Fatalf("actual target hits=%d want=%d", hits.Load(), want)
				}
				records, err := pg.ListTaskToolCalls(t.Context(), strconv.FormatInt(task.ID, 10), 0, 100)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, record := range records {
					if record.ToolName == "Bash" {
						found = true
						if !allowed && record.EffectiveAction != "deny" {
							t.Fatalf("outside call not audited denied: %+v", record)
						}
					}
				}
				if !found {
					t.Fatal("session tool call has no durable audit")
				}
			})
		}
	}
}
