package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

func TestRenderedCustomHTTPRejectsOutOfScopeRedirect(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("custom HTTP scope", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	_, err = pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "test", "manual")
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "http://outside.invalid/no", 302)
	}))
	defer inside.Close()
	ic := intercept.New(pg)
	s := &Server{m: &Manager{pg: pg, interceptor: ic}}
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	raw, _ := json.Marshal(map[string]string{"url": inside.URL, "method": "GET"})
	res, err := s.runHTTPTool(ctx, raw, nil, &tool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "目标不在本任务授权范围") || hits != 1 {
		t.Fatalf("result=%s err=%v initial hits=%d", res.Flatten(), err, hits)
	}
	// The rendered template is checked, rather than just the model's innocuous parameters.
	raw = []byte(`{"command":"curl https://outside.invalid/{path}"}`)
	res, err = s.runCommandTool(ctx, raw, map[string]any{"path": "status"}, &tool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "授权范围") {
		t.Fatalf("command=%s err=%v", res.Flatten(), err)
	}
}

func TestScopeUnknownActionConfigValidation(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	old, exists, _ := pg.GetSetting("scope_unknown_target_action")
	defer func() {
		if exists {
			_ = pg.SetSetting("scope_unknown_target_action", old)
		} else {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key='scope_unknown_target_action'`)
		}
	}()
	s := &Server{m: &Manager{pg: pg}}
	for _, tc := range []struct {
		action string
		code   int
	}{{"ask", 200}, {"deny", 200}, {"allow", 200}, {"", 400}, {"silent", 400}} {
		r := httptest.NewRequest("PUT", "/api/intercept/scope-config", strings.NewReader(`{"unknown_target_action":"`+tc.action+`"}`))
		w := httptest.NewRecorder()
		s.interceptScopeConfig(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.action, w.Code, w.Body.String())
		}
	}
}

func TestScopePrecedesToolDisableAndAllowRules(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	ic := intercept.New(pg)
	old, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	defer ic.SetEnabledTools(old)
	if err := ic.SetEnabledTools([]string{}); err != nil {
		t.Fatal(err)
	}
	rule, err := pg.CreateInterceptRule("scope bypass regression", "tool_name", "string", "Bash", "allow", "", 9999, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteInterceptRule(rule.ID)
	ctx := intercept.WithTaskContext(t.Context(), "scope-bypass-test", "test", nil)
	blocked, message, _ := guard.NewWithInterceptor(ic).Hooks().PreToolUse(ctx, "Bash", []byte(`{"command":"curl https://outside.invalid"}`))
	if !blocked || !strings.Contains(message, "目标不在本任务授权范围") {
		t.Fatalf("blocked=%v message=%s", blocked, message)
	}
}
