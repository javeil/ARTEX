package db

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTargetBudgetIsAtomicAndSharedAcrossTasks(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	tasks := []string{}
	for range 2 {
		task, e := d.CreateTask("shared target budget", "local mock", nil, 0, 0)
		if e != nil {
			t.Fatal(e)
		}
		defer d.DeleteTask(task.ID)
		tasks = append(tasks, strconv.FormatInt(task.ID, 10))
	}
	target, _ := ParseTarget("http://budget-" + tasks[0] + ".example.test:18081/api")
	var won atomic.Int32
	var wg sync.WaitGroup
	ids := make(chan int64, 20)
	for j := range 20 {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			id, e := d.BeginTargetRequest(context.Background(), tasks[j%2], target, "GET", "", TargetBudget{MaxConcurrent: 1})
			if e == nil {
				won.Add(1)
				ids <- id
			}
		}(j)
	}
	wg.Wait()
	close(ids)
	if won.Load() != 1 {
		t.Fatalf("concurrency cap was bypassed: %d", won.Load())
	}
	for id := range ids {
		if e := d.FinishTargetRequest(t.Context(), id, 200, 1, "", 0); e != nil {
			t.Fatal(e)
		}
	}
	next, e := d.BeginTargetRequest(t.Context(), tasks[1], target, "GET", "", TargetBudget{MaxConcurrent: 1})
	if e != nil {
		t.Fatal(e)
	}
	if e := d.FinishTargetRequest(t.Context(), next, 429, 1, "", 5); e != nil {
		t.Fatal(e)
	}
	if _, e = d.BeginTargetRequest(t.Context(), tasks[0], target, "GET", "", TargetBudget{}); e == nil {
		t.Fatal("shared cooldown bypassed by another task")
	}
}

func TestTargetAccountAndTotalBudgetsCannotBeResetByAnotherTask(t *testing.T) {
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ids := []string{}
	for range 2 {
		task, e := d.CreateTask("account target budget", "mock", nil, 0, 0)
		if e != nil {
			t.Fatal(e)
		}
		defer d.DeleteTask(task.ID)
		ids = append(ids, strconv.FormatInt(task.ID, 10))
	}
	target, _ := ParseTarget("https://account-" + ids[0] + ".example.test/login")
	budget := TargetBudget{AccountAttempts: 1, AccountWindowSeconds: 60, MaxRequests: 1}
	id, e := d.BeginTargetRequest(t.Context(), ids[0], target, "POST", "alice", budget)
	if e != nil {
		t.Fatal(e)
	}
	if e = d.FinishTargetRequest(t.Context(), id, 200, 1, "", 0); e != nil {
		t.Fatal(e)
	}
	if _, e = d.BeginTargetRequest(t.Context(), ids[1], target, "POST", "alice", budget); e == nil {
		t.Fatal("account attempts reset across tasks")
	}
	if _, e = d.BeginTargetRequest(t.Context(), ids[0], target, "POST", "bob", budget); e == nil {
		t.Fatal("total request budget reset by switching account")
	}
}
