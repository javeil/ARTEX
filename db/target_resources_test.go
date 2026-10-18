package db

import (
	"strconv"
	"testing"
)

func TestResourceOwnershipRequiresObservedCreationAndExactTask(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	task, e := d.CreateTask("test artifact ownership", "mock", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	target, _ := ParseTarget("https://resources-" + id + ".example.test/items")
	request, e := d.BeginTargetRequest(t.Context(), id, target, "POST", "", TargetBudget{})
	if e != nil {
		t.Fatal(e)
	}
	if e := d.RegisterTargetResource(t.Context(), id, request, target.URL+"/created", `"v1"`, true); e != nil {
		t.Fatal(e)
	}
	r, e := d.OwnedTargetResource(t.Context(), id, target.URL+"/created")
	if e != nil || r == nil || r.ETag != `"v1"` {
		t.Fatalf("resource=%+v err=%v", r, e)
	}
	r, e = d.OwnedTargetResource(t.Context(), "other-task", target.URL+"/created")
	if e != nil || r != nil {
		t.Fatal("another task claimed ownership")
	}
	r, e = d.OwnedTargetResource(t.Context(), id, target.URL+"/same-name")
	if e != nil || r != nil {
		t.Fatal("filename similarity granted ownership")
	}
	if e = d.RegisterTargetResource(t.Context(), id, request+999999, target.URL+"/forged", `"v1"`); e == nil {
		t.Fatal("forged creation evidence accepted")
	}
}
