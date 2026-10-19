package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

func TestStrictShellSendAndMonitorScriptSwapFailClosed(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("interactive and monitor regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	pg.Assets().AddAgentScope(task.ID, "subdomain", "example.test", "human", "manual")
	if err = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{Targets: []db.TargetSpec{{Host: "example.test", Ports: []int{443}}}}); err != nil {
		t.Fatal(err)
	}
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "worker", nil))
	g := guard.NewWithInterceptor(ic)
	for _, input := range []map[string]any{{"text": "curl -x '' https://example.test/"}, {"paste": "curl https://example.test/"}} {
		raw, _ := json.Marshal(input)
		blocked, _, _ := g.Hooks().PreToolUse(ctx, "shell_send", raw)
		if !blocked {
			t.Fatal("strict task admitted unobservable terminal input")
		}
	}
	pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{})
	dir := t.TempDir()
	path := filepath.Join(dir, "job.py")
	os.WriteFile(path, []byte("print('v1')\n"), 0600)
	callback := func(a db.Activity) {
		if a.Kind != "intercept_request" {
			return
		}
		var in struct {
			ID int64 `json:"pending_id"`
		}
		json.Unmarshal([]byte(a.Detail), &in)
		os.WriteFile(path, []byte("print('swapped')\n"), 0600)
		ic.Decide(in.ID, true)
	}
	ctx = ic.WithScope(intercept.WithTaskContext(t.Context(), id, "worker", callback))
	ctx = intercept.WithReviewWorkingDirectory(ctx, dir)
	blocked, _, _ := g.Hooks().PreToolUse(ctx, "Monitor", []byte(`{"command":"python3 job.py"}`))
	if !blocked {
		t.Fatal("Monitor approval survived script content replacement")
	}
}

func TestActualMonitorProcessGetsTaskProxyEnvironment(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("monitor environment regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "worker", nil))
	gw, err := intercept.NewTargetGateway(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	ctx = intercept.WithGateway(ctx, gw)
	raw := []byte(`{"command":"printf '%s' \"$HTTP_PROXY\""}`)
	updated, err := ic.PrepareShellInput(ctx, "Monitor", raw)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := tool.NewManager("monitor-proxy-regression")
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Cleanup()
	result, err := tool.NewMonitor().Call(ctx, updated, &tool.ToolContext{Tasks: manager, WorkingDir: t.TempDir()})
	if err != nil || result.IsError {
		t.Fatalf("monitor: %v %s", err, result.Flatten())
	}
	// SDK returns the exact output file path; wait for the owned process and read it.
	words := strings.Split(result.Flatten(), "Output file: ")
	if len(words) != 2 {
		t.Fatal(result.Flatten())
	}
	file := strings.SplitN(words[1], "\n", 2)[0]
	for n := 0; n < 100; n++ {
		data, _ := os.ReadFile(file)
		if string(data) == gw.URL {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("actual Monitor subprocess did not inherit pinned task proxy")
}
