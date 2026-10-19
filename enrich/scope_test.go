package enrich

import (
	"context"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnboundBackgroundEnrichmentDoesNotContactTargets(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	engine := New(nil, nil, 1)
	defer engine.Close()
	engine.ProbeSite(1, target.URL)
	time.Sleep(100 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("unbound enrichment sent %d requests", hits.Load())
	}
}

func TestTaskBoundEnrichmentHonorsBudgetScopeAndStop(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("enrichment control regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual")
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(100) }))
	defer outside.Close()
	parsed, _ := db.ParseTarget(target.URL)
	if err = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{Targets: []db.TargetSpec{{Host: "127.0.0.1", Ports: []int{parsed.Port}}}, Budget: db.TargetBudget{MaxRequests: 1}}); err != nil {
		t.Fatal(err)
	}
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "worker", nil))
	engine := New(pg.Assets(), nil, 1)
	defer engine.Close()
	wait := func() {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if ic.TargetIOState(id).Active == 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("background lease not released")
	}
	if err = engine.ProbeSiteForTask(ctx, 1, outside.URL); err == nil {
		t.Fatal("outside enrichment accepted")
	}
	if err = engine.ProbeSiteForTask(ctx, 1, target.URL); err != nil {
		t.Fatal(err)
	}
	wait()
	if hits.Load() != 1 {
		t.Fatalf("authorized enrichment hits=%d", hits.Load())
	}
	if err = engine.ProbeSiteForTask(ctx, 2, target.URL); err != nil {
		t.Fatal(err)
	}
	wait()
	if hits.Load() != 1 {
		t.Fatal("enrichment bypassed actual request budget")
	}
	if err = ic.StopTargetIO(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if err = engine.ProbeSiteForTask(ctx, 3, target.URL); err == nil {
		t.Fatal("enrichment accepted after confirmed stop")
	}
	if hits.Load() != 1 {
		t.Fatal("outside/stopped enrichment contacted target")
	}
}

func TestEnrichmentInFlightIsCancelledBeforeStopConfirmation(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("enrich cancellation", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual")
	started := make(chan struct{})
	cancelled := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(cancelled) }))
	defer target.Close()
	id := strconv.FormatInt(task.ID, 10)
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "worker", nil))
	engine := New(pg.Assets(), nil, 1)
	defer engine.Close()
	if err = engine.ProbeSiteForTask(ctx, 1, target.URL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("mock was not contacted")
	}
	stop, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err = ic.StopTargetIO(stop, id); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("remote request remained alive after stopped confirmation")
	}
}
