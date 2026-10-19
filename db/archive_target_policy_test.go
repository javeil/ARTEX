package db

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestArchiveRestoresTargetRestrictionsAndRequiresHumanReview(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("archive authorization regression", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Exec("DELETE FROM task_archives WHERE task_id=$1", task.ID); d.DeleteTask(task.ID) }()
	id := strconv.FormatInt(task.ID, 10)
	d.Assets().AddAgentScope(task.ID, "subdomain", "authorized.example", "human", "manual")
	policy := TargetPolicy{Mode: "read_only", Targets: []TargetSpec{{Host: "authorized.example", Ports: []int{443}, PathPrefixes: []string{"/api"}}}, Budget: TargetBudget{MaxRequests: 7}}
	if err = d.SaveTargetPolicy(t.Context(), id, policy); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Assets().CreateTaskInterceptRule(task.ID, "block", "exact_domain", "blocked.authorized.example", "keep exclusion", true); err != nil {
		t.Fatal(err)
	}
	d.SetPaused(task.ID, true)
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataCounts["task_target_policies"] != 1 || snapshot.DataCounts["task_intercept_rules"] != 1 {
		t.Errorf("authorization missing from archive: %v", snapshot.DataCounts)
	}
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/authorization-test.tar.zst", "sha", 100, 50); err != nil {
		t.Fatal(err)
	}
	// Simulate restoring only the package, not relying on accidentally retained hot rows.
	d.Exec("DELETE FROM task_target_policies WHERE task_id=$1", task.ID)
	d.Exec("DELETE FROM task_intercept_rules WHERE task_id=$1", task.ID)
	if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	restored, err := d.LoadTargetPolicy(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Mode != "read_only" || restored.Budget.MaxRequests != 7 || len(restored.Targets) != 1 {
		t.Errorf("restored authorization silently widened: %+v", restored)
	}
	raw, _ := json.Marshal(restored)
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	if fields["restore_review_required"] != true {
		t.Error("restored authorization did not require operator confirmation")
	}
	rules, err := d.Assets().ListTaskInterceptRules(task.ID)
	if err != nil || len(rules) != 1 {
		t.Errorf("restored exclusions: %+v %v", rules, err)
	}
	d.Exec(`UPDATE tasks SET paused=false,queued=false,status='pending' WHERE id=$1`, task.ID)
	target, _ := ParseTarget("https://authorized.example/api/test")
	if err = d.CheckTaskTarget(t.Context(), id, target); err == nil {
		t.Fatal("archive restore silently regranted active network authorization")
	}
}
