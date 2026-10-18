package intercept

import (
	"context"
	"fmt"
	"sync"
)

type targetRunState struct {
	blocked, draining bool
	next              uint64
	active            map[uint64]context.CancelFunc
	changed           chan struct{}
}
type TargetIOState struct {
	Blocked  bool `json:"blocked"`
	Stopping bool `json:"stopping"`
	Active   int  `json:"active"`
	Stopped  bool `json:"stopped"`
}
type targetRuntime struct {
	mu    sync.Mutex
	tasks map[string]*targetRunState
}

func (i *Interceptor) targetStateLocked(id string) *targetRunState {
	if i.runtime.tasks == nil {
		i.runtime.tasks = map[string]*targetRunState{}
	}
	s := i.runtime.tasks[id]
	if s == nil {
		s = &targetRunState{active: map[uint64]context.CancelFunc{}, changed: make(chan struct{})}
		i.runtime.tasks[id] = s
	}
	return s
}
func (i *Interceptor) TargetIOState(id string) TargetIOState {
	i.runtime.mu.Lock()
	defer i.runtime.mu.Unlock()
	s := i.targetStateLocked(id)
	return TargetIOState{Blocked: s.blocked, Stopping: s.draining || (s.blocked && len(s.active) > 0), Active: len(s.active), Stopped: s.blocked && !s.draining && len(s.active) == 0}
}
func (i *Interceptor) acquireTargetIO(ctx context.Context, kind string) (context.Context, func(), error) {
	id := TaskIDFromContext(ctx)
	if id == "" {
		return ctx, nil, fmt.Errorf("主动测试未绑定授权任务")
	}
	child, cancel := context.WithCancel(ctx)
	i.runtime.mu.Lock()
	s := i.targetStateLocked(id)
	if (s.blocked && kind != "analysis_run") || s.draining {
		i.runtime.mu.Unlock()
		cancel()
		return ctx, nil, fmt.Errorf("目标访问已停止或正在停止，需用户明确恢复")
	}
	s.next++
	key := s.next
	s.active[key] = cancel
	i.runtime.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			i.runtime.mu.Lock()
			delete(s.active, key)
			close(s.changed)
			s.changed = make(chan struct{})
			i.runtime.mu.Unlock()
		})
	}
	return child, release, nil
}

// BeginTargetRun binds SDK background/interactive work to the host run lifecycle.
// Cleanup is deferred after Session.Close/MCP cleanup, so a stop waits for those
// to finish instead of returning merely because a cancel signal was sent.
func BeginTargetRun(ctx context.Context) (context.Context, func(), error) {
	i, _ := ctx.Value(scopeContextKey{}).(*Interceptor)
	if i == nil || TaskIDFromContext(ctx) == "" {
		return ctx, func() {}, nil
	}
	return i.acquireTargetIO(ctx, "analysis_run")
}
func (i *Interceptor) StopTargetIO(ctx context.Context, id string) error {
	i.runtime.mu.Lock()
	s := i.targetStateLocked(id)
	s.blocked = true
	s.draining = true
	cancels := []context.CancelFunc{}
	for _, cancel := range s.active {
		cancels = append(cancels, cancel)
	}
	i.runtime.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for {
		i.runtime.mu.Lock()
		if len(s.active) == 0 {
			s.draining = false
			i.runtime.mu.Unlock()
			return nil
		}
		changed := s.changed
		i.runtime.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			i.runtime.mu.Lock()
			s.draining = false
			i.runtime.mu.Unlock()
			return fmt.Errorf("目标访问仍在停止，尚不能确认已停止: %w", ctx.Err())
		}
	}
}
func (i *Interceptor) ResumeTargetIO(id string) {
	i.runtime.mu.Lock()
	s := i.targetStateLocked(id)
	if !s.draining {
		s.blocked = false
	}
	i.runtime.mu.Unlock()
}
func (i *Interceptor) CancelTargetIO(id string) {
	i.runtime.mu.Lock()
	s := i.targetStateLocked(id)
	cancels := []context.CancelFunc{}
	for _, c := range s.active {
		cancels = append(cancels, c)
	}
	i.runtime.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}
