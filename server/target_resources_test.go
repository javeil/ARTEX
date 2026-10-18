package server

import (
	"bytes"
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

func TestObservedTestResourceCleanupCannotDeleteOtherOrReusedObject(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	task, e := pg.CreateTask("artifact ownership", "mock only", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	_, e = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "manual", "manual")
	if e != nil {
		t.Fatal(e)
	}
	var version atomic.Int32
	version.Store(1)
	var deletes atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Header().Set("Location", "/items/created")
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(201)
			return
		}
		if r.Method == "DELETE" {
			expected := `"v` + strconv.Itoa(int(version.Load())) + `"`
			if r.Header.Get("If-Match") != expected {
				w.WriteHeader(412)
				return
			}
			deletes.Add(1)
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(200)
	}))
	defer target.Close()
	id := strconv.FormatInt(task.ID, 10)
	policy := db.TargetPolicy{Operations: []db.OperationRule{{Target: db.TargetSpec{Host: "127.0.0.1", PathPrefixes: []string{"/items"}}, Methods: []string{"POST"}, Effect: "artifact_create", CleanupIfMatch: true}}}
	if e = pg.SaveTargetPolicy(t.Context(), id, policy); e != nil {
		t.Fatal(e)
	}
	ic := intercept.New(pg)
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
	response, e := client.Post(target.URL+"/items", "application/json", bytes.NewBufferString(`{"name":"task-probe"}`))
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 201 {
		t.Fatalf("create=%d", response.StatusCode)
	}
	resources, e := pg.ListTargetResources(t.Context(), id)
	if e != nil || len(resources) != 1 {
		t.Fatalf("creation evidence=%v %v", resources, e)
	}
	// A real business object never receives a DELETE request.
	request, _ := http.NewRequest("DELETE", target.URL+"/items/real", nil)
	response, e = client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 403 || deletes.Load() != 0 {
		t.Fatal("real object deletion allowed")
	}
	// Even a reused URL must retain the observed resource identity.
	version.Store(2)
	request, _ = http.NewRequest("DELETE", target.URL+"/items/created", nil)
	response, e = client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 412 || deletes.Load() != 0 {
		t.Fatal("reused URL deleted a different object")
	}
	version.Store(1)
	request, _ = http.NewRequest("DELETE", target.URL+"/items/created", nil)
	response, e = client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 204 || deletes.Load() != 1 {
		t.Fatal("proven test artifact could not be cleaned")
	}
	owned, e := pg.OwnedTargetResource(t.Context(), id, target.URL+"/items/created")
	if e != nil || owned != nil {
		t.Fatal("cleaned resource retained deletion permission")
	}
}
