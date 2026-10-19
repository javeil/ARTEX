package server

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestApprovalDecisionFromOtherInterceptor(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("shared approval", "mock", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	for _, allowed := range []bool{true, false} {
		t.Run(strconv.FormatBool(allowed), func(t *testing.T) {
			waiter, decider := intercept.New(pg), intercept.New(pg)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			ctx = intercept.WithTaskContext(ctx, strconv.FormatInt(task.ID, 10), "test", func(a db.Activity) {
				var d struct {
					ID int64 `json:"pending_id"`
				}
				if a.Kind != "intercept_request" {
					return
				}
				json.Unmarshal([]byte(a.Detail), &d)
				if err := decider.Decide(d.ID, allowed); err != nil {
					t.Error(err)
				}
			})
			start := time.Now()
			got := waiter.HandleAsk(ctx, 0, intercept.Decision{Action: "ask"}, "Read", []byte(`{"file_path":"local.txt"}`))
			if got != allowed || time.Since(start) > time.Second {
				t.Fatalf("decision not delivered from shared store: got=%v want=%v elapsed=%s", got, allowed, time.Since(start))
			}
		})
	}
}
