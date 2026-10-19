package server

import (
	"fmt"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestReconcileAbandonedReservationsKeepsAttemptBudget(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("reservation reconciliation", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	target, _ := db.ParseTarget("https://reconcile-" + id + ".example.test/login")
	budget := db.TargetBudget{MaxConcurrent: 1, MaxRequests: 1}
	pending, err := pg.BeginTargetRequest(t.Context(), id, target, "POST", "alice", budget)
	if err != nil {
		t.Fatal(err)
	}
	ic := intercept.New(pg)
	s := &Server{m: &Manager{pg: pg, interceptor: ic}}
	request := func(confirmed bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/tasks/"+id+"/target-control/reconcile", strings.NewReader(fmt.Sprintf(`{"request_ids":[%d],"reason":"operator verified remote process stopped after crash","confirmed_remote_stopped":%v}`, pending, confirmed)))
		req.SetPathValue("id", id)
		w := httptest.NewRecorder()
		s.targetControl(w, req)
		return w
	}
	if w := request(true); w.Code == 200 {
		t.Fatal("active task reservations released")
	}
	pg.SetPaused(task.ID, true)
	ic.StopTargetIO(t.Context(), id)
	if w := request(false); w.Code == 200 {
		t.Fatal("missing remote stop confirmation accepted")
	}
	if w := request(true); w.Code != 200 {
		t.Fatalf("audited recovery unavailable: %d %s", w.Code, w.Body.String())
	}
	var state string
	if err = pg.QueryRow(`SELECT state FROM target_requests WHERE id=$1`, pending).Scan(&state); err != nil || state != "reconciled" {
		t.Fatalf("reservation not reconciled: %s %v", state, err)
	}
	if _, err = pg.BeginTargetRequest(t.Context(), id, target, "POST", "alice", budget); err == nil || !strings.Contains(err.Error(), "累计") {
		t.Fatalf("recovery reset attempted request budget: %v", err)
	}
	var count int
	pg.QueryRow(`SELECT count(*) FROM target_control_events WHERE task_id=$1 AND action='reconcile_request'`, id).Scan(&count)
	if count != 1 {
		t.Fatalf("recovery audit missing: %d", count)
	}
}
