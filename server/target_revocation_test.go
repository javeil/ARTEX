package server

import (
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestGlobalExclusionMutationCancelsActiveTargetRun(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("revocation cancels run", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "test", nil))
	active, release, err := intercept.BeginTargetRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	s := &Server{m: &Manager{pg: pg, interceptor: ic}}
	request := httptest.NewRequest("POST", "/api/asset-intercept/rules", strings.NewReader(`{"enabled":true,"kind":"exact_domain","pattern":"revoked.invalid"}`))
	response := httptest.NewRecorder()
	s.assetInterceptCreateRule(response, request)
	if response.Code != 200 {
		t.Fatalf("save exclusion: %d %s", response.Code, response.Body.String())
	}
	// Remove only our fixture, retaining existing operator rules.
	defer pg.Exec(`DELETE FROM asset_intercept_rules WHERE pattern='revoked.invalid'`)
	select {
	case <-active.Done():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("new exclusion left active target run alive")
	}
}
