package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestTargetStopConfirmsInflightCancelledAndRejectsNewRequests(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("stop target traffic", "mock", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	started := make(chan struct{})
	cancelled := make(chan struct{})
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/slow" {
			close(started)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		w.WriteHeader(200)
	}))
	defer target.Close()
	ic := intercept.New(pg)
	id := strconv.FormatInt(task.ID, 10)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	g, e := intercept.NewTargetGateway(ctx, "", "")
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	p, _ := url.Parse(g.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(p)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r, e := client.Get(target.URL + "/slow")
		if e == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("mock not contacted")
	}
	stopCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if e := ic.StopTargetIO(stopCtx, id); e != nil {
		t.Fatal(e)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("target request still alive after stop confirmation")
	}
	<-done
	if state := ic.TargetIOState(id); !state.Blocked || !state.Stopped || state.Active != 0 {
		t.Fatalf("stop state=%+v", state)
	}
	r, e := client.Get(target.URL + "/after-stop")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 403 || hits.Load() != 1 {
		t.Fatalf("new request after stop: %d hits=%d", r.StatusCode, hits.Load())
	}
	ic.ResumeTargetIO(id)
	r, e = client.Get(target.URL + "/resumed")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 200 || hits.Load() != 2 {
		t.Fatal("explicit resume failed")
	}
}

func TestPolicyExpiryCancelsAnAlreadyRunningTargetRequest(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("expiry target traffic", "mock", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	stopped := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done(); close(stopped) }))
	defer target.Close()
	id := strconv.FormatInt(task.ID, 10)
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	g, e := intercept.NewTargetGateway(ctx, "", "")
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	expires := time.Now().Add(300 * time.Millisecond)
	if e = pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{ExpiresAt: &expires}); e != nil {
		t.Fatal(e)
	}
	proxy, _ := url.Parse(g.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	began := time.Now()
	r, _ := client.Get(target.URL)
	if r != nil {
		r.Body.Close()
	}
	if time.Since(began) > time.Second {
		t.Fatal("目标请求没有在授权到期时停止")
	}
	select {
	case <-stopped:
	case <-time.After(700 * time.Millisecond):
		t.Fatal("active target request survived authorization expiry")
	}
}
