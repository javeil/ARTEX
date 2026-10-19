package server

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
)

func TestScopeRevocationInvalidatesPendingApproval(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("revoke during approval", "mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "subdomain", "example.com", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	ic := intercept.New(pg)
	ctx := intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "test", func(a db.Activity) {
		var d struct {
			ID int64 `json:"pending_id"`
		}
		if a.Kind != "intercept_request" {
			return
		}
		if e := json.Unmarshal([]byte(a.Detail), &d); e != nil {
			t.Error(e)
			return
		}
		if _, e := pg.Exec(`DELETE FROM task_scope WHERE task_id=$1`, task.ID); e != nil {
			t.Error(e)
		}
		if e := ic.Decide(d.ID, true); e != nil {
			t.Error(e)
		}
	})
	ctx = ic.WithScope(ctx)
	blocked, message, _ := guard.NewWithInterceptor(ic).Hooks().PreToolUse(ctx, "Bash", []byte(`{"command":"python3 -c 'print(\"https://example.com/\")'"}`))
	if !blocked || !strings.Contains(message, "授权") {
		t.Fatalf("stale approval executed: blocked=%v %s", blocked, message)
	}
}
