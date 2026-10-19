package server

import (
	"os"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestApprovalCannotSurviveAuthorizationABAOrLocalRuleChange(t *testing.T) {
	pg, err := db.Open(func() string {
		d := os.Getenv("ARTEX_PG_DSN")
		if d == "" {
			t.Skip("isolated PG required")
		}
		return d
	}())
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("approval generation", "local mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	ic := intercept.New(pg)
	ctx := ic.WithScope(intercept.WithTaskContext(t.Context(), id, "test", nil))
	for _, name := range []string{"pause-resume", "policy-change-back", "local-read-rule"} {
		t.Run(name, func(t *testing.T) {
			tool, input := "Bash", []byte(`{"command":"python3 -c 'print(1)'"}`)
			if name == "local-read-rule" {
				tool = "Read"
				input = []byte(`{"file_path":"report.txt"}`)
			}
			b, err := ic.BindApproval(ctx, tool, input)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "pause-resume":
				if err = pg.SetPaused(task.ID, true); err != nil {
					t.Fatal(err)
				}
				if err = pg.SetPaused(task.ID, false); err != nil {
					t.Fatal(err)
				}
			case "policy-change-back":
				p, e := pg.LoadTargetPolicy(ctx, id)
				if e != nil {
					t.Fatal(e)
				}
				changed := p
				changed.Mode = "read_only"
				if err = pg.SaveTargetPolicy(ctx, id, changed); err != nil {
					t.Fatal(err)
				}
				if err = pg.SaveTargetPolicy(ctx, id, p); err != nil {
					t.Fatal(err)
				}
			case "local-read-rule":
				r, e := pg.CreateInterceptRule("approval local deny", "tool_name", "string", "Read", "deny", "deny", 999, true, false, 0, "deny")
				if e != nil {
					t.Fatal(e)
				}
				defer pg.DeleteInterceptRule(r.ID)
			}
			if err = ic.ValidateApproval(ctx, tool, input, b); err == nil {
				t.Fatal("stale approval remained valid")
			}
		})
	}
}
