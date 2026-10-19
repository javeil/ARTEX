package server

import (
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestOwnedSDKRunExpiresWithTaskAuthorization(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("owned SDK expiry", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	until := time.Now().Add(150 * time.Millisecond)
	if err = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{ExpiresAt: &until}); err != nil {
		t.Fatal(err)
	}
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	owned, release, err := intercept.BeginTargetRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	select {
	case <-owned.Done():
	case <-time.After(time.Second):
		t.Fatal("SDK process retained an unbounded context beyond authorization expiry")
	}
	// Starting local analysis after expiry is useful; active tools still must deny.
	analysis, closeAnalysis, err := intercept.BeginTargetRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAnalysis()
	if analysis.Err() != nil {
		t.Fatal("expired task cannot perform local result analysis")
	}
	if d, handled := ic.ScopeDecision(analysis, "Bash", []byte(`{"command":"python3 probe.py"}`)); !handled || d.Action != "deny" {
		t.Fatalf("expired opaque call: %+v", d)
	}
}
