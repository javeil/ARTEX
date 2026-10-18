package db

import (
	"context"
	"testing"
)

func TestToolCallAuditPersistsAndPagesByTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	task := "all-tool-calls-" + t.Name()
	defer func() {
		_, _ = d.Exec(`DELETE FROM tool_call_audit WHERE task_id IN ($1,$2)`, task, task+"-other")
		d.Close()
	}()
	var ids []int64
	for _, source := range []string{"rule", "judge", "default_allow", "scope", "core"} {
		a := ToolCallAudit{TaskID: task, ToolName: "Bash", InputSummary: `{"command":"echo ok"}`, Decision: "allow", EffectiveAction: "allow", Source: source}
		if source == "scope" {
			a.Decision = "ask"
			a.EffectiveAction = "pending"
		}
		if err := d.SaveToolCallAudit(t.Context(), &a); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
		if source == "scope" {
			a.EffectiveAction = "deny"
			if err := d.SaveToolCallAudit(t.Context(), &a); err != nil {
				t.Fatal(err)
			}
		}
	}
	other := ToolCallAudit{TaskID: task + "-other", ToolName: "Read", Decision: "allow", EffectiveAction: "allow", Source: "default_allow"}
	if err := d.SaveToolCallAudit(t.Context(), &other); err != nil {
		t.Fatal(err)
	}
	// A new connection sees the records: the memory Guard ring is not authoritative.
	reopened, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	first, err := reopened.ListTaskToolCalls(t.Context(), task, 0, 2)
	if err != nil || len(first) != 2 || first[0].ID != ids[4] || first[1].Decision != "ask" || first[1].EffectiveAction != "deny" {
		t.Fatalf("page=%+v err=%v", first, err)
	}
	rest, err := reopened.ListTaskToolCalls(t.Context(), task, first[1].ID, 5000)
	if err != nil || len(rest) != 3 {
		t.Fatalf("remaining=%v err=%v", rest, err)
	}
}

func BenchmarkToolCallAuditInsert(b *testing.B) {
	dsn, _, err := DSN()
	if err != nil {
		b.Skip(err)
	}
	d, err := Open(dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer d.Close()
	defer d.Exec(`DELETE FROM tool_call_audit WHERE task_id='audit-benchmark'`)
	b.ResetTimer()
	for range b.N {
		a := ToolCallAudit{TaskID: "audit-benchmark", ToolName: "Read", InputSummary: "small file", Decision: "allow", EffectiveAction: "allow", Source: "default_allow"}
		if err := d.SaveToolCallAudit(context.Background(), &a); err != nil {
			b.Fatal(err)
		}
	}
}
