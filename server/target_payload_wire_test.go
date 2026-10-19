package server

import (
	"bytes"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestMultipartWireRespectsReadOnlyAccountsAndBudget(t *testing.T) {
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
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	task, err := pg.CreateTask("multipart actual HTTP", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "human", "manual")
	id := strconv.FormatInt(task.ID, 10)
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	request := func(path string, fields [][2]string) error {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		for _, f := range fields {
			w.WriteField(f[0], f[1])
		}
		w.Close()
		req, _ := http.NewRequestWithContext(ctx, "POST", target.URL+path, &b)
		req.Header.Set("Content-Type", w.FormDataContentType())
		resp, e := intercept.TargetRoundTrip(http.DefaultTransport, req)
		if resp != nil {
			resp.Body.Close()
		}
		return e
	}
	pg.SaveTargetPolicy(ctx, id, db.TargetPolicy{Mode: "read_only"})
	if err = request("/action", [][2]string{{"action", "delete"}}); err == nil || hits.Load() != 0 {
		t.Fatalf("write reached readonly target: %v hits=%d", err, hits.Load())
	}
	pg.SaveTargetPolicy(ctx, id, db.TargetPolicy{Accounts: []string{"alice"}, Budget: db.TargetBudget{AccountAttempts: 2, AccountWindowSeconds: 60}})
	if err = request("/login", [][2]string{{"username", "alice"}, {"username", "bob"}}); err == nil {
		t.Fatal("conflicting multipart identities allowed")
	}
	for j := 0; j < 2; j++ {
		if err = request("/login", [][2]string{{"username", "alice"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err = request("/login", [][2]string{{"username", "alice"}}); err == nil || hits.Load() != 2 {
		t.Fatalf("budget bypassed: %v hits=%d", err, hits.Load())
	}
}
