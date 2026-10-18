package guard

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestEveryPreToolCallIsAudited(t *testing.T) {
	g := New()
	var rows []db.ToolCallAudit
	g.auditWrite = func(_ context.Context, a *db.ToolCallAudit) error {
		a.ID = int64(len(rows) + 1)
		rows = append(rows, *a)
		return nil
	}
	for _, tc := range []struct{ tool, input, decision, source string }{
		{"Bash", `{"command":"ls -la"}`, "allow", "default_allow"},
		{"Read", `{"file_path":"notes.txt"}`, "allow", "default_allow"},
		{"Bash", `{"command":"mkfs.ext4 /dev/sda"}`, "deny", "core"},
	} {
		g.Hooks().PreToolUse(t.Context(), tc.tool, []byte(tc.input))
		row := rows[len(rows)-1]
		if row.Decision != tc.decision || row.Source != tc.source || row.ToolName != tc.tool || row.InputSummary == "" {
			t.Fatalf("row=%+v", row)
		}
	}
	if len(rows) != 3 || len(g.Audit()) != 3 {
		t.Fatalf("durable=%d memory=%d", len(rows), len(g.Audit()))
	}
}

func TestAuditFailureCannotSilentlyAllow(t *testing.T) {
	g := New()
	g.auditWrite = func(context.Context, *db.ToolCallAudit) error { return errors.New("storage unavailable") }
	b, msg, _ := g.Hooks().PreToolUse(t.Context(), "Read", []byte(`{"file_path":"notes.txt"}`))
	if !b || msg == "" {
		t.Fatal("audit failure silently allowed call")
	}
}
