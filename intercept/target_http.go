package intercept

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type operationTicket struct {
	version string
	expires time.Time
}
type operationTickets struct {
	mu    sync.Mutex
	items map[string][]operationTicket
}
type ticketKey struct{}

func operationDigest(o Operation) string {
	b, _ := json.Marshal(struct{ URL, Method, Body string }{o.Target.URL, o.Method, o.Body})
	return digestInput(b)
}
func (i *Interceptor) GrantOperations(ctx context.Context, tool string, input []byte) {
	tickets, _ := ctx.Value(ticketKey{}).(*operationTickets)
	if tickets == nil {
		return
	}
	version, err := i.db.AuthorizationVersion(ctx, TaskIDFromContext(ctx))
	if err != nil {
		return
	}
	tickets.mu.Lock()
	defer tickets.mu.Unlock()
	for _, o := range DescribeOperations(tool, input) {
		if o.Effect == "unknown_write" {
			key := operationDigest(o)
			tickets.items[key] = append(tickets.items[key], operationTicket{version, time.Now().Add(5 * time.Minute)})
		}
	}
}
func (i *Interceptor) consumeOperation(ctx context.Context, o Operation) bool {
	tickets, _ := ctx.Value(ticketKey{}).(*operationTickets)
	if tickets == nil {
		return false
	}
	version, err := i.db.AuthorizationVersion(ctx, TaskIDFromContext(ctx))
	if err != nil {
		return false
	}
	tickets.mu.Lock()
	defer tickets.mu.Unlock()
	key := operationDigest(o)
	list := tickets.items[key]
	for len(list) > 0 {
		v := list[0]
		list = list[1:]
		tickets.items[key] = list
		if time.Now().Before(v.expires) && v.version == version {
			return true
		}
	}
	return false
}

// RequestOperation reads a bounded inspection copy and restores the exact body.
// Large/streaming request bodies retain an unknown-write classification unless a
// trusted operator route explicitly declares their effect.
func RequestOperation(req *http.Request) (Operation, error) {
	target, err := parseRequestTarget(req)
	if err != nil {
		return Operation{}, err
	}
	o := Operation{Target: target, Method: req.Method}
	if req.Body != nil && req.Body != http.NoBody {
		original := req.Body
		b, err := io.ReadAll(io.LimitReader(original, (1<<20)+1))
		if err != nil {
			return o, err
		}
		req.Body = &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(b), original), closer: original}
		if len(b) > 1<<20 {
			o.Body = "[request body exceeds review limit]"
			o.Effect = "unknown_write"
		} else {
			o.Body = string(b)
		}
	}
	if o.Effect == "" {
		o.Effect = classifyOperation(o)
	}
	return o, nil
}

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error { return r.closer.Close() }
func parseRequestTarget(req *http.Request) (db.Target, error) {
	return db.ParseTarget(req.URL.String())
}

// AuthorizeRequest is called immediately before a real HTTP exchange. No
// operator approval can exempt an explicitly excluded/out-of-scope destination.
func (i *Interceptor) AuthorizeRequest(ctx context.Context, req *http.Request) (Operation, error) {
	if err := i.CheckTarget(ctx, req.URL.String()); err != nil {
		return Operation{}, err
	}
	o, err := RequestOperation(req)
	if err != nil {
		return o, err
	}
	policy, err := i.TrustedTaskPolicy(ctx)
	if err != nil {
		return o, err
	}
	o = effectiveOperation(policy.Policy, o)
	action, reason := operationRestriction(policy.Policy, o)
	if action == "deny" {
		return o, fmt.Errorf("目标操作被任务策略拒绝：%s", reason)
	}
	if action == "ask" && !i.consumeOperation(ctx, o) {
		input, _ := json.Marshal(map[string]string{"url": o.Target.URL, "method": o.Method, "body": o.Body})
		dec, gated := i.OperationDecision(ctx, "TargetRequest", input)
		if gated {
			if dec.Action == "deny" {
				return o, fmt.Errorf("目标操作拒绝：%s", dec.Message)
			}
			if dec.Action == "ask" {
				binding, err := i.BindApproval(ctx, "TargetRequest", input)
				if err != nil {
					return o, err
				}
				dec.AuthorizationVersion, dec.ApprovedCallDigest = binding.AuthorizationVersion, binding.CallDigest
				if !i.HandleAsk(ctx, ConvIDFromContext(ctx), dec, "TargetRequest", input) {
					return o, fmt.Errorf("目标请求人工审批未通过")
				}
				if err := i.ValidateApproval(ctx, "TargetRequest", input, binding); err != nil {
					return o, err
				}
			}
		}
	}
	if err := i.CheckTarget(ctx, req.URL.String()); err != nil {
		return o, err
	}
	return o, nil
}

// TargetRoundTrip is shared by built-in HTTP tools, custom HTTP and the task
// gateway. The request context carries authorization supplied by the host.
func TargetRoundTrip(base http.RoundTripper, req *http.Request) (*http.Response, error) {
	i, _ := req.Context().Value(scopeContextKey{}).(*Interceptor)
	if i == nil {
		return nil, fmt.Errorf("目标访问校验器不可用，必须绑定授权任务")
	}
	leaseCtx, releaseLease, err := i.acquireTargetIO(req.Context(), "http")
	if err != nil {
		return nil, err
	}
	req = req.Clone(leaseCtx)
	deadlineCancel := func() {}
	release := func() { releaseLease(); deadlineCancel() }
	op, err := i.AuthorizeRequest(req.Context(), req)
	if err != nil {
		release()
		return nil, err
	}
	p, err := i.db.LoadTargetPolicy(req.Context(), TaskIDFromContext(req.Context()))
	if err != nil {
		release()
		return nil, err
	}
	account, err := operationAccount(p, op)
	if err != nil {
		release()
		return nil, err
	}
	op.Account = account
	var taskDeadline *time.Time
	if err := i.db.QueryRowContext(leaseCtx, `SELECT deadline_at FROM tasks WHERE id::text=$1`, TaskIDFromContext(leaseCtx)).Scan(&taskDeadline); err != nil {
		release()
		return nil, err
	}
	deadline := p.ExpiresAt
	if taskDeadline != nil && (deadline == nil || taskDeadline.Before(*deadline)) {
		deadline = taskDeadline
	}
	if deadline != nil {
		var bound context.Context
		bound, deadlineCancel = context.WithDeadline(leaseCtx, *deadline)
		req = req.Clone(bound)
	}
	id, err := i.db.BeginTargetRequest(req.Context(), TaskIDFromContext(req.Context()), op.Target, op.Method, account, p.Budget)
	if err != nil {
		release()
		return nil, err
	}
	started := time.Now()
	resp, err := base.RoundTrip(req)
	latency := int(time.Since(started).Milliseconds())
	if err != nil {
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 2*time.Second)
		defer cancel()
		defer release()
		if saveErr := i.db.FinishTargetRequest(finishCtx, id, 0, latency, err.Error(), 0); saveErr != nil {
			return nil, fmt.Errorf("目标请求失败且审计结果写入失败: %w", saveErr)
		}
		return nil, err
	}
	retry := 0
	if raw := resp.Header.Get("Retry-After"); raw != "" {
		if n, e := strconv.Atoi(raw); e == nil {
			retry = n
		} else if at, e := http.ParseTime(raw); e == nil {
			retry = int(time.Until(at).Seconds())
		}
	}
	body := &targetResponseBody{ReadCloser: resp.Body, interceptor: i, ctx: req.Context(), id: id, status: resp.StatusCode, latency: latency, retry: retry, release: release}
	if resp.Body == nil {
		body.ReadCloser = http.NoBody
	}
	body.locked = resp.Header.Get("X-Account-Locked") == "true"
	body.mu.Lock()
	body.stopWatch = context.AfterFunc(req.Context(), func() { _ = body.Close() })
	body.mu.Unlock()
	resp.Body = body
	return resp, nil
}

type targetResponseBody struct {
	release   func()
	stopWatch func() bool
	io.ReadCloser
	interceptor            *Interceptor
	ctx                    context.Context
	id                     int64
	status, latency, retry int
	locked                 bool
	mu                     sync.Mutex
	prefix                 []byte
	once                   sync.Once
	finishErr              error
}

func (b *targetResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	if len(b.prefix) < 8192 {
		left := 8192 - len(b.prefix)
		if n < left {
			left = n
		}
		b.prefix = append(b.prefix, p[:left]...)
	}
	b.mu.Unlock()
	if err != nil {
		message := ""
		if err != io.EOF {
			message = err.Error()
		}
		b.finish(message)
	}
	return n, err
}
func (b *targetResponseBody) finish(message string) {
	b.once.Do(func() {
		b.mu.Lock()
		stopWatch := b.stopWatch
		b.mu.Unlock()
		if stopWatch != nil {
			stopWatch()
		}
		if b.release != nil {
			defer b.release()
		}
		b.mu.Lock()
		prefix := strings.ToLower(string(b.prefix))
		locked := b.locked
		b.mu.Unlock()
		for _, marker := range []string{"account locked", "account is locked", "账号已锁定", "账户已锁定", "too many login attempts"} {
			locked = locked || strings.Contains(prefix, marker)
		}
		signals := []string{}
		if locked {
			signals = append(signals, "account_locked")
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(b.ctx), 2*time.Second)
		defer cancel()
		b.finishErr = b.interceptor.db.FinishTargetRequest(ctx, b.id, b.status, b.latency, message, b.retry, signals...)
	})
}
func (b *targetResponseBody) Close() error {
	err := b.ReadCloser.Close()
	message := ""
	if err != nil {
		message = err.Error()
	}
	b.finish(message)
	if b.finishErr != nil {
		return b.finishErr
	}
	return err
}
