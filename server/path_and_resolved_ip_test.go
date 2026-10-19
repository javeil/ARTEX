package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestPathInterpretationsAndResolvedIPExclusionsApplyOnWire(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	var hits, protected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.RawPath == "/admin%2f..%2fapi/secret" {
			protected.Add(1)
		}
		w.WriteHeader(200)
	}))
	defer target.Close()
	task, err := pg.CreateTask("path and DNS exclusions regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual")
	parsed, _ := db.ParseTarget(target.URL)
	pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{Targets: []db.TargetSpec{{Host: "127.0.0.1", Ports: []int{parsed.Port}, PathPrefixes: []string{"/api"}, ExcludedPathPrefixes: []string{"/admin"}}}})
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "worker", nil))
	g, err := intercept.NewTargetGateway(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	proxy, _ := url.Parse(g.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	resp, err := client.Get(target.URL + "/admin%2f..%2fapi/secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || protected.Load() != 0 {
		t.Errorf("ambiguous path reached protected raw-path router: status=%d hits=%d", resp.StatusCode, protected.Load())
	}
	resp, err = client.Get(target.URL + "/api/items%2fpart")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("encoded path entirely within authorized prefix was blocked")
	}
	pg.Assets().AddAgentScope(task.ID, "subdomain", "localhost", "human", "manual")
	pg.SaveTargetPolicy(t.Context(), id, db.TargetPolicy{})
	rule, err := pg.Assets().CreateTaskInterceptRule(task.ID, "block", "cidr", "127.0.0.0/8", "explicit production exclusion", true)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Assets().DeleteTaskInterceptRule(task.ID, rule.ID)
	before := hits.Load()
	resp, err = client.Get("http://localhost:" + strconv.Itoa(parsed.Port) + "/api/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || hits.Load() != before {
		t.Errorf("authorized name bypassed explicit IP exclusion: status=%d actualExtraHits=%d", resp.StatusCode, hits.Load()-before)
	}
}

func TestVirtualHostRequiresItsOwnTaskAuthorization(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	task, err := pg.CreateTask("virtual host regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual")
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "worker", nil))
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	defer base.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	request.Host = "virtual.authorized.test"
	resp, err := intercept.TargetRoundTrip(base, request)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || hits.Load() != 0 {
		t.Fatal("unapproved virtual host was reached")
	}
	pg.Assets().AddAgentScope(task.ID, "subdomain", "virtual.authorized.test", "human", "manual")
	request, _ = http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	request.Host = "virtual.authorized.test"
	resp, err = intercept.TargetRoundTrip(base, request)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatal("explicitly authorized virtual-host technique stopped working")
	}
}
