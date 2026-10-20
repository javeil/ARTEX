package db

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestDefaultPromptUpgradePreservesCustomAndVersions(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	a, e := d.CreateAgent("progress_prompt_migration_test", "progress migration", "test only")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Exec(`DELETE FROM agents WHERE id=$1`, a.ID)
	old := "old default"
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(old)))
	if _, e = d.SavePrompt(a.ID, old, "fixture", "test"); e != nil {
		t.Fatal(e)
	}
	changed, e := d.UpgradeDefaultPromptHash(a.ID, hash, "new default")
	if e != nil || !changed {
		t.Fatalf("upgrade=%v %v", changed, e)
	}
	changed, e = d.UpgradeDefaultPromptHash(a.ID, hash, "new default")
	if e != nil || changed {
		t.Fatalf("not idempotent: %v %v", changed, e)
	}
	if _, e = d.SavePrompt(a.ID, "operator custom", "fixture", "test"); e != nil {
		t.Fatal(e)
	}
	changed, e = d.UpgradeDefaultPromptHash(a.ID, hash, "new default")
	if e != nil || changed {
		t.Fatalf("custom overwritten: %v %v", changed, e)
	}
	current, e := d.CurrentPrompt(a.ID)
	if e != nil || current != "operator custom" {
		t.Fatalf("custom lost: %s %v", current, e)
	}
	versions, e := d.ListPromptVersions(a.ID)
	if e != nil || len(versions) != 3 {
		t.Fatalf("versions=%d %v", len(versions), e)
	}
}
