package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

func TestTargetHTTPKeepsFullExportAndEnforcesBudget(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("controlled HTTP export", "mock", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	id := strconv.FormatInt(task.ID, 10)
	if e = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{Budget: db.TargetBudget{MaxRequests: 1}}); e != nil {
		t.Fatal(e)
	}
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte(strings.Repeat("x", 3<<20))) }))
	defer target.Close()
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	raw, _ := json.Marshal(map[string]string{"url": target.URL})
	result, e := targetHTTPTool().Call(ctx, raw, &tool.ToolContext{WorkingDir: t.TempDir(), OutputDir: t.TempDir()})
	if e != nil || result.IsError {
		t.Fatalf("result=%s err=%v", result.Flatten(), e)
	}
	var output struct {
		File  string `json:"body_file"`
		Bytes int64  `json:"body_bytes"`
	}
	if e = json.Unmarshal([]byte(result.Flatten()), &output); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(output.File)
	if e != nil || info.Size() != 3<<20 || output.Bytes != 3<<20 {
		t.Fatalf("full export missing: %+v %v", output, e)
	}
	result, e = targetHTTPTool().Call(ctx, raw, &tool.ToolContext{WorkingDir: t.TempDir()})
	if e != nil || !result.IsError || hits.Load() != 1 {
		t.Fatalf("budget bypass: %s %v hits=%d", result.Flatten(), e, hits.Load())
	}
}

func TestTargetHTTPNoResponseStopsBeforeNinthRequest(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("bounded target failures", "local mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual")
	if e != nil {
		t.Fatal(e)
	}
	id := strconv.FormatInt(task.ID, 10)
	ic := intercept.New(pg)
	stopped := make(chan *db.ExecutionBlock, 1)
	ic.SetTaskPauseHandler(func(_ string, b *db.ExecutionBlock) error {
		select {
		case stopped <- b:
		default:
		}
		return nil
	})
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer target.Close()
	input, _ := json.Marshal(map[string]string{"url": target.URL})
	for range 8 {
		result, err := targetHTTPTool().Call(ctx, input, nil)
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "未收到 HTTP 响应") || strings.Contains(result.Flatten(), "【ARTEX 平台拒绝】") {
			t.Fatalf("EOF attribution: %s %v", result.Flatten(), err)
		}
	}
	select {
	case b := <-stopped:
		if b.Code != "no_http_response" {
			t.Fatalf("cause=%+v", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("automatic stop not requested")
	}
	result, e := targetHTTPTool().Call(ctx, input, nil)
	if e != nil || !result.IsError || hits.Load() != 8 {
		t.Fatalf("retry escaped stop: hits=%d %s %v", hits.Load(), result.Flatten(), e)
	}
}
