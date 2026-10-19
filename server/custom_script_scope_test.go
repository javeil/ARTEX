package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

func TestCustomScriptArgumentsCannotExpandApprovedScope(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	for _, allowed := range []bool{false, true} {
		t.Run(strconv.FormatBool(allowed), func(t *testing.T) {
			var hits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			defer target.Close()
			task, err := pg.CreateTask("custom script arguments regression", "mock", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer pg.DeleteTask(task.ID)
			if allowed {
				pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual")
			} else {
				pg.Assets().AddAgentScope(task.ID, "subdomain", "authorized.example", "human", "manual")
			}
			ic := intercept.New(pg)
			ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "worker", func(a db.Activity) {
				if a.Kind != "intercept_request" {
					return
				}
				var p struct {
					ID int64 `json:"pending_id"`
				}
				json.Unmarshal([]byte(a.Detail), &p)
				ic.Decide(p.ID, true)
			}))
			srv := &Server{m: &Manager{pg: pg, interceptor: ic, dir: t.TempDir()}}
			code := `import os,urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open(os.environ['TOOL_ARGS']).read()`
			spec, _ := json.Marshal(map[string]string{"code": code})
			result, err := srv.runScriptTool(ctx, "scope_test_script", spec, map[string]any{"args": target.URL + "/probe"}, &tool.ToolContext{WorkingDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			want := int32(0)
			if allowed {
				want = 1
			}
			if hits.Load() != want {
				t.Fatalf("script target hits=%d want=%d: %s", hits.Load(), want, result.Flatten())
			}
			if result.IsError == allowed {
				t.Fatalf("unexpected script decision: %s", result.Flatten())
			}
		})
	}
}
