package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

func TestTargetGatewayChecksActualRedirectAndExcludedPath(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("actual target gateway", "local mock", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	var hits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer outside.Close()
	u, _ := url.Parse(outside.URL)
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+u.Port()+"/outside", 302)
	}))
	defer inside.Close()
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "test", nil))
	gateway, e := intercept.NewTargetGateway(ctx, "", "")
	if e != nil {
		t.Fatal(e)
	}
	defer gateway.Close()
	proxyURL, _ := url.Parse(gateway.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, e := client.Get(inside.URL)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("redirect escaped: status=%d hits=%d", resp.StatusCode, hits.Load())
	}
	// A curl config can enable redirect following; the actual gateway still rejects it.
	dir := t.TempDir()
	if e := os.WriteFile(dir+"/.curlrc", []byte("location\n"), 0600); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(map[string]string{"command": "curl -sS " + inside.URL})
	result, e := tool.NewBash().Call(context.Background(), raw, &tool.ToolContext{WorkingDir: dir, Env: []string{"HTTP_PROXY=" + gateway.URL, "HTTPS_PROXY=" + gateway.URL, "ALL_PROXY=" + gateway.URL, "http_proxy=" + gateway.URL, "NO_PROXY=", "no_proxy=", "CURL_HOME=" + dir}})
	if e != nil || !strings.Contains(result.Flatten(), "授权范围") || hits.Load() != 0 {
		t.Fatalf("curl escaped: %s err=%v hits=%d", result.Flatten(), e, hits.Load())
	}
}

func TestTargetGatewayInspectsHTTPSPathsBeforeContact(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("HTTPS target policy", "mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	_, e = pg.Assets().CreateTaskInterceptRule(task.ID, "block", "fuzzy_url", "/blocked", "excluded endpoint", true)
	if e != nil {
		t.Fatal(e)
	}
	certFile := t.TempDir() + "/target.pem"
	if e = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "test", nil))
	g, e := intercept.NewTargetGateway(ctx, "", certFile)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	p, _ := url.Parse(g.URL)
	pool := x509.NewCertPool()
	ca, e := os.ReadFile(g.CACert)
	if e != nil {
		t.Fatal(e)
	}
	pool.AppendCertsFromPEM(ca)
	tr := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{RootCAs: pool}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, tc := range []struct {
		path   string
		status int
	}{{"/blocked", 403}, {"/allowed", 200}} {
		resp, e := client.Get(target.URL + tc.path)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s=%d", tc.path, resp.StatusCode)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("excluded HTTPS request contacted target: %d", hits.Load())
	}
}
