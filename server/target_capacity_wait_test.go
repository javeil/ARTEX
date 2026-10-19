package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func capacityTestTask(t *testing.T, pg *db.DB, ic *intercept.Interceptor, budget db.TargetBudget) (string, context.Context) {
	t.Helper()
	task, err := pg.CreateTask("target capacity waiting", "local mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	if _, err = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "test operator", "manual"); err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(task.ID, 10)
	if err = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{Mode: "standard", Budget: budget}); err != nil {
		t.Fatal(err)
	}
	return id, ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
}

func capacityTestDB(t *testing.T) (*db.DB, *intercept.Interceptor) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return pg, intercept.New(pg)
}

func capacityRequest(ctx context.Context, method, target, body string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return intercept.TargetRoundTrip(&http.Transport{}, r)
}

func consumeCapacityResponse(resp *http.Response, err error) error {
	if err != nil {
		return err
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return readErr
	}
	return closeErr
}

func TestTargetRateCapacityWaitIsSharedAcrossTasks(t *testing.T) {
	pg, ic := capacityTestDB(t)
	firstID, first := capacityTestTask(t, pg, ic, db.TargetBudget{RequestsPerSecond: 1, MaxLatencyMS: 500, ConsecutiveFailures: 1})
	secondID, second := capacityTestTask(t, pg, ic, db.TargetBudget{RequestsPerSecond: 2, MaxLatencyMS: 500, ConsecutiveFailures: 1})
	var mu sync.Mutex
	var times []time.Time
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer target.Close()
	if err := consumeCapacityResponse(capacityRequest(first, "GET", target.URL, "")); err != nil {
		t.Fatal(err)
	}
	if err := consumeCapacityResponse(capacityRequest(second, "GET", target.URL, "")); err != nil {
		t.Fatalf("temporary shared capacity should wait: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(times) != 2 || times[1].Sub(times[0]) < 850*time.Millisecond {
		t.Fatalf("shared rate limit bypassed: %v", times)
	}
	var denied, cooled int
	if err := pg.QueryRow(`SELECT count(*) FROM target_requests WHERE task_id IN ($1,$2) AND state='denied'`, firstID, secondID).Scan(&denied); err != nil || denied != 0 {
		t.Fatalf("capacity polling created denial noise: %d %v", denied, err)
	}
	if err := pg.QueryRow(`SELECT count(*) FROM target_safety_state WHERE blocked_until>now() AND target_key IN (SELECT target_key FROM target_requests WHERE task_id IN ($1,$2))`, firstID, secondID).Scan(&cooled); err != nil || cooled != 0 {
		t.Fatalf("capacity waiting counted as slow target health: %d %v", cooled, err)
	}
}

func TestQueuedTargetRequestRechecksStopPolicyAndDeadline(t *testing.T) {
	for _, mode := range []string{"release", "pause", "policy", "stop", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			pg, ic := capacityTestDB(t)
			id, base := capacityTestTask(t, pg, ic, db.TargetBudget{MaxConcurrent: 1})
			var hits atomic.Int32
			release := make(chan struct{})
			var releaseOnce sync.Once
			free := func() { releaseOnce.Do(func() { close(release) }) }
			defer free()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1) == 1 {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
					}
					return
				}
				w.WriteHeader(200)
			}))
			defer target.Close()
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			first, err := capacityRequest(ctx, "GET", target.URL+"/held", "")
			if err != nil {
				t.Fatal(err)
			}
			defer first.Body.Close()
			queued := ctx
			var deadlineCancel context.CancelFunc
			if mode == "deadline" {
				queued, deadlineCancel = context.WithTimeout(ctx, 250*time.Millisecond)
				defer deadlineCancel()
			}
			done := make(chan error, 1)
			go func() { done <- consumeCapacityResponse(capacityRequest(queued, "GET", target.URL+"/queued", "")) }()
			select {
			case err := <-done:
				t.Fatalf("capacity was rejected instead of queued: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			switch mode {
			case "release":
				free()
				if err = consumeCapacityResponse(first, nil); err != nil {
					t.Fatal(err)
				}
			case "pause":
				_, err = pg.Exec(`UPDATE tasks SET paused=true WHERE id::text=$1`, id)
			case "policy":
				err = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{Mode: "passive", Budget: db.TargetBudget{MaxConcurrent: 1}})
			case "stop":
				stopCtx, stopCancel := context.WithTimeout(t.Context(), 2*time.Second)
				err = ic.StopTargetIO(stopCtx, id)
				stopCancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if mode == "release" {
					if err != nil || hits.Load() != 2 {
						t.Fatalf("released request failed: hits=%d err=%v", hits.Load(), err)
					}
				} else if err == nil || hits.Load() != 1 {
					t.Fatalf("queued request escaped %s: hits=%d err=%v", mode, hits.Load(), err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("capacity wait did not finish/cancel promptly")
			}
			if mode == "stop" && ic.TargetIOState(id).Active != 0 {
				t.Fatal("stop returned before queued request cleanup")
			}
		})
	}
}

func TestTargetHardBudgetsNeverWaitForAutomaticReset(t *testing.T) {
	for _, mode := range []string{"total", "account", "cooldown"} {
		t.Run(mode, func(t *testing.T) {
			pg, ic := capacityTestDB(t)
			budget := db.TargetBudget{RequestsPerSecond: 1, MaxRequests: 1}
			if mode == "account" {
				budget = db.TargetBudget{RequestsPerSecond: 1, AccountAttempts: 1, AccountWindowSeconds: 300}
			} else if mode == "cooldown" {
				budget = db.TargetBudget{RequestsPerSecond: 1, CooldownSeconds: 30}
			}
			id, ctx := capacityTestTask(t, pg, ic, budget)
			var hits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if mode == "cooldown" {
					w.WriteHeader(429)
				} else {
					w.WriteHeader(200)
				}
			}))
			defer target.Close()
			method, body, path := "GET", "", "/"
			if mode == "account" {
				p := db.TargetPolicy{Mode: "standard", Budget: budget, Operations: []db.OperationRule{{Target: db.TargetSpec{Host: "127.0.0.1", PathPrefixes: []string{"/login"}}, Methods: []string{"POST"}, Effect: "authenticate", AccountField: "username"}}}
				if err := pg.SaveTargetPolicy(t.Context(), id, p); err != nil {
					t.Fatal(err)
				}
				method, body, path = "POST", "username=alice&password=example", "/login"
			}
			if err := consumeCapacityResponse(capacityRequest(ctx, method, target.URL+path, body)); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err := consumeCapacityResponse(capacityRequest(ctx, method, target.URL+path, body))
			if err == nil || hits.Load() != 1 {
				t.Fatalf("hard limit bypassed: %d %v", hits.Load(), err)
			}
			if time.Since(started) > 500*time.Millisecond {
				t.Fatalf("hard limit waited: %v", err)
			}
		})
	}
}
