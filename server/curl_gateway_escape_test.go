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
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

func TestCurlTransfersCannotEscapeTaskGateway(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	var outsideHits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits.Add(1); w.WriteHeader(200) }))
	defer outside.Close()
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer inside.Close()
	task, err := pg.CreateTask("curl transfer scope regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	if _, err = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual"); err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(task.ID, 10)
	target, _ := db.ParseTarget(inside.URL)
	if err = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{Mode: "read_only", Targets: []db.TargetSpec{{Host: target.Host, Ports: []int{target.Port}, Schemes: []string{"http"}}}}); err != nil {
		t.Fatal(err)
	}
	old, had, _ := pg.GetSetting("scope_unknown_target_action")
	pg.SetSetting("scope_unknown_target_action", "deny")
	defer func() {
		if had {
			pg.SetSetting("scope_unknown_target_action", old)
		} else {
			pg.Exec("DELETE FROM settings WHERE key='scope_unknown_target_action'")
		}
	}()
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "worker", nil))
	gateway, err := intercept.NewTargetGateway(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	ctx = intercept.WithGateway(ctx, gateway)
	external, _ := db.ParseTarget(outside.URL)
	// Ordinary GET avoids relying on the optional built-in HTTP DELETE deny rule.
	command := `curl -sS -sx "" "http://127.0.0.1:${AUDIT_PORT:-` + strconv.Itoa(external.Port) + `}/outside" -: ` + inside.URL + `/ok`
	raw, _ := json.Marshal(map[string]string{"command": command})
	blocked, _, updated := guard.NewWithInterceptor(ic).Hooks().PreToolUse(ctx, "Bash", raw)
	if !blocked {
		if len(updated) == 0 {
			updated = raw
		}
		result, e := tool.NewBash().Call(ctx, updated, &tool.ToolContext{WorkingDir: t.TempDir(), Env: []string{"HTTP_PROXY=" + gateway.URL, "HTTPS_PROXY=" + gateway.URL, "ALL_PROXY=" + gateway.URL, "NO_PROXY=", "no_proxy="}})
		if e != nil {
			t.Fatal(e)
		}
		t.Log(result.Flatten())
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("task gateway escaped: outside received %d requests", outsideHits.Load())
	}
	if !blocked {
		t.Fatal("unsafe curl transfer command was not rejected")
	}
}
