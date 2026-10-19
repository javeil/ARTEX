package server

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestImpossibleHTTPClientCallsDoNotAskBeforeHardDenial(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("HTTP preflight", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	if _, err = pg.Assets().AddAgentScope(task.ID, "subdomain", "example.test", "human", "manual"); err != nil {
		t.Fatal(err)
	}
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "worker", nil))
	ctx = intercept.WithGateway(ctx, &intercept.TargetGateway{URL: "http://127.0.0.1:1"})
	for _, cmd := range []string{`curl --noproxy '*' https://example.test/`, `curl -d "$PAYLOAD" https://example.test/`} {
		raw, _ := json.Marshal(map[string]string{"command": cmd})
		dec, gated := ic.ScopeDecision(ctx, "Bash", raw)
		if !gated || dec.Action != "deny" {
			t.Errorf("unexecutable client requested approval: %s %+v", cmd, dec)
		}
	}
}
