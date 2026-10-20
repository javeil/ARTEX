package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestTaskProgressAutomaticPauseIsDurableAndVisible(t *testing.T) {
	m, e := NewManager(t.TempDir(), "")
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	task, e := m.CreateTask("progress auto pause", "mock only", nil, 1, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{})
	s := newAdmissionTestServer(m, nil)
	m.interceptor.SetTaskPauseHandler(s.pauseTaskForProgress)
	version, e := m.pg.AuthorizationVersion(t.Context(), task.ID)
	if e != nil {
		t.Fatal(e)
	}
	for range 3 {
		a := db.ToolCallAudit{TaskID: task.ID, ToolName: "TargetHTTP", InputSummary: "mock", Decision: "deny", EffectiveAction: "deny", Source: "scope", AuthorizationVersion: version}
		if e = m.interceptor.SaveToolCallAudit(t.Context(), &a); e != nil {
			t.Fatal(e)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for !task.lifecycleSnapshot().Paused && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !task.lifecycleSnapshot().Paused || !s.engine.IsPaused(task.ID) {
		t.Fatal("execution did not pause")
	}
	r := httptest.NewRequest("GET", "/tasks/control", nil)
	r.SetPathValue("id", task.ID)
	w := httptest.NewRecorder()
	s.targetControl(w, r)
	var result struct {
		Paused bool   `json:"task_paused"`
		Reason string `json:"pause_reason"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil || w.Code != 200 || !result.Paused || result.Reason == "" {
		t.Fatalf("reason missing: %d %s %v", w.Code, w.Body.String(), e)
	}
	// Persisted state and reason survive a fresh interceptor, without reviving work.
	restored := intercept.New(m.pg)
	if e = restored.CheckProgress(t.Context(), task.ID); e != nil {
		t.Fatal(e)
	}
	if state := m.interceptor.TargetIOState(task.ID); !state.Blocked || !state.Stopped {
		t.Fatalf("not stopped: %+v", state)
	}
	n, _ := strconv.ParseInt(task.ID, 10, 64)
	row, e := m.pg.GetTask(n)
	if e != nil || !row.Paused {
		t.Fatal("pause not durable")
	}
}
func TestTaskProgressStalePauseCannotStopNewOperatorCycle(t *testing.T) {
	m, e := NewManager(t.TempDir(), "")
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	task, e := m.CreateTask("stale pause", "mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{})
	var epoch int64
	if e = m.pg.QueryRow(`SELECT authorization_epoch FROM tasks WHERE id=$1`, task.ID).Scan(&epoch); e != nil {
		t.Fatal(e)
	}
	if e = m.ApplyTaskPause(task.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = m.pg.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, task.ID); e != nil {
		t.Fatal(e)
	}
	if e = m.applyTaskPauseControl(task.ID, false, &db.ExecutionBlock{Code: "stale", Reason: "stale", AuthorizationEpoch: epoch}); e == nil {
		t.Fatal("stale pause accepted")
	}
	var paused bool
	if e = m.pg.QueryRowContext(context.Background(), `SELECT paused FROM tasks WHERE id=$1`, task.ID).Scan(&paused); e != nil || paused {
		t.Fatal("new cycle paused")
	}
}
