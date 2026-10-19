package db

import "time"

// TargetCapacityError is temporary contention for a shared service slot. Only
// rate/concurrency limits use it; account, total-request and cooldown limits
// remain hard denials and must never be retried automatically.
type TargetCapacityError struct {
	Message    string
	RetryAfter time.Duration
}

func (e *TargetCapacityError) Error() string { return e.Message }
