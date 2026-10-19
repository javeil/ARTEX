package server

import (
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestTargetPolicyAndConversationBindingAPI(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("target policy API", "mock only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	c, err := pg.CreateConversation("pentest", "authorization test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteConversation(c.ID)
	s := &Server{m: &Manager{pg: pg, interceptor: intercept.New(pg)}, chatBusy: map[string]bool{}}
	r := httptest.NewRequest("PUT", "/tasks/policy", strings.NewReader(`{"targets":[{"host":"example.com","ports":[443],"schemes":["https"]}]}`))
	r.SetPathValue("id", strconv.FormatInt(task.ID, 10))
	w := httptest.NewRecorder()
	s.targetPolicy(w, r)
	if w.Code != 200 {
		t.Fatalf("policy: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("PUT", "/conversations/authorization", strings.NewReader(`{"task_id":`+strconv.FormatInt(task.ID, 10)+`}`))
	r.SetPathValue("id", strconv.FormatInt(c.ID, 10))
	w = httptest.NewRecorder()
	s.bindConversationAuthorization(w, r)
	if w.Code != 200 {
		t.Fatalf("binding: %d %s", w.Code, w.Body.String())
	}
	saved, err := pg.GetConversation(c.ID)
	if err != nil || saved.TaskID == nil || *saved.TaskID != task.ID {
		t.Fatalf("binding not persisted: %v %v", saved, err)
	}
	s.chatBusy[s.convBusyKey(c.ID)] = true
	r = httptest.NewRequest("PUT", "/conversations/authorization", strings.NewReader(`{"task_id":null}`))
	r.SetPathValue("id", strconv.FormatInt(c.ID, 10))
	w = httptest.NewRecorder()
	s.bindConversationAuthorization(w, r)
	if w.Code != 409 {
		t.Fatalf("changed active authorization: %d", w.Code)
	}
}
func TestUnboundActiveTestingIsDenied(t *testing.T) {
	i := intercept.New(nil)
	dec, gated := i.ScopeDecision(t.Context(), "WebFetch", []byte(`{"url":"https://outside.invalid"}`))
	if !gated || dec.Action != "deny" {
		t.Fatal("unbound network operation permitted")
	}
	if err := intercept.CheckURL(t.Context(), "https://outside.invalid"); err == nil {
		t.Fatal("unbound transport permitted")
	}
}
