package intercept

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"io"
	"log"
	"net"
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
func (i *Interceptor) GrantOperations(ctx context.Context, tool string, input []byte, version string) {
	tickets, _ := ctx.Value(ticketKey{}).(*operationTickets)
	if tickets == nil {
		return
	}
	if version == "" {
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
	o := Operation{Target: target, Method: req.Method, ContentType: req.Header.Get("Content-Type")}
	if req.Body != nil && req.Body != http.NoBody {
		original := req.Body
		b, err := io.ReadAll(io.LimitReader(original, (1<<20)+1))
		if err != nil {
			return o, err
		}
		req.Body = &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(b), original), closer: original}
		if len(b) > 1<<20 {
			o.Body = "[request body exceeds review limit]"
			o.BodyTruncated = true
			o.Effect = "unknown_write"
		} else {
			o.Body = string(b)
		}
	}
	if o.Effect == "" {
		o.Effect = classifyOperation(o)
	}
	if (req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "") && (o.Effect == "read" || o.Effect == "unknown_write" || o.Effect == "authenticate") {
		o.Effect = "authenticate"
		if username, _, ok := req.BasicAuth(); ok && len(req.Header.Values("Authorization")) == 1 && req.Header.Get("Cookie") == "" {
			o.Account = username
		} else {
			o.OpaqueCredential = true
		}
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
	if req.Host != "" && req.Host != req.URL.Host {
		virtual, err := db.ParseTarget(req.URL.Scheme + "://" + req.Host)
		physical, physicalErr := db.ParseTarget(req.URL.String())
		if err != nil || physicalErr != nil {
			return Operation{}, fmt.Errorf("无效的虚拟主机请求")
		}
		if virtual.Host != physical.Host || virtual.Port != physical.Port {
			// A Host header without a port selects a virtual host on the physical
			// service; it does not move the TCP connection to the default port.
			if _, _, e := net.SplitHostPort(req.Host); e != nil {
				virtual.Port = physical.Port
			}
			virtual.Path = physical.Path
			virtual.URL = req.URL.Scheme + "://" + net.JoinHostPort(virtual.Host, strconv.Itoa(virtual.Port)) + req.URL.RequestURI()
			if err = i.checkTargetSpec(ctx, virtual); err != nil {
				return Operation{}, fmt.Errorf("虚拟主机未获任务授权：%w", err)
			}
		}
	}

	o, err := RequestOperation(req)
	if err != nil {
		return o, err
	}
	policy, err := i.TrustedTaskPolicy(ctx)
	if err != nil {
		return o, err
	}
	o = i.ownedOperation(ctx, o)
	o = effectiveOperation(policy.Policy, o)
	requestInput, _ := json.Marshal(map[string]string{"url": o.Target.URL, "method": o.Method, "body": o.Body})
	if rule, matched := i.MatchContext(ctx, "TargetRequest", requestInput); matched && rule.Action == "deny" {
		return o, fmt.Errorf("目标请求命中拦截规则：%s", rule.Message)
	}
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
	if o.ResourceETag != "" {
		req.Header.Set("If-Match", o.ResourceETag)
	}
	return o, nil
}

// TargetRoundTrip is shared by built-in HTTP tools, custom HTTP and the task
// gateway. The request context carries authorization supplied by the host.
func TargetRoundTrip(base http.RoundTripper, req *http.Request) (*http.Response, error) {
	i, _ := req.Context().Value(scopeContextKey{}).(*Interceptor)
	if i == nil || i.db == nil {
		return nil, fmt.Errorf("目标访问校验器不可用，必须绑定授权任务")
	}
	leaseCtx, releaseLease, err := i.acquireTargetIO(req.Context(), "http")
	if err != nil {
		return i.rejectTargetRequest(req, err)
	}
	req = req.Clone(leaseCtx)
	release := releaseLease
	op, err := i.AuthorizeRequest(req.Context(), req)
	if err != nil {
		release()
		return i.rejectTargetRequest(req, err)
	}
	p, err := i.db.LoadTargetPolicy(req.Context(), TaskIDFromContext(req.Context()))
	if err != nil {
		release()
		return i.rejectTargetRequest(req, err)
	}
	if (op.Effect == "authenticate" || op.Effect == "unknown_write") && p.Budget.AccountAttempts == 0 {
		shared, e := i.db.TargetHasAccountBudget(req.Context(), op.Target.ServiceKey())
		if e != nil {
			release()
			return nil, e
		}
		if shared {
			p.Budget.AccountAttempts = 1
		}
	}
	if op.Effect == "unknown_write" && (p.Budget.AccountAttempts > 0 || len(p.Accounts) > 0) {
		release()
		return i.rejectTargetRequest(req, fmt.Errorf("无法确认账号敏感请求用途，需用户声明接口后再执行"))
	}
	account, err := operationAccount(p, op)
	if err != nil {
		release()
		return i.rejectTargetRequest(req, err)
	}
	op.Account = account
	persistedPolicy, e := i.db.LoadTargetPolicy(req.Context(), TaskIDFromContext(req.Context()))
	if e != nil {
		release()
		return nil, e
	}
	p.Budget = persistedPolicy.Budget
	var taskDeadline *time.Time
	if err := i.db.QueryRowContext(leaseCtx, `SELECT deadline_at FROM tasks WHERE id::text=$1`, TaskIDFromContext(leaseCtx)).Scan(&taskDeadline); err != nil {
		release()
		return i.rejectTargetRequest(req, err)
	}
	deadline := p.ExpiresAt
	if taskDeadline != nil && (deadline == nil || taskDeadline.Before(*deadline)) {
		deadline = taskDeadline
	}
	if deadline != nil {
		bound, cancelDeadline := context.WithDeadline(leaseCtx, *deadline)
		previousRelease := release
		release = func() { cancelDeadline(); previousRelease() }
		req = req.Clone(bound)
	}
	networkTransport, cleanupTransport, err := i.checkedTransport(req, base)
	if err != nil {
		release()
		return i.rejectTargetRequest(req, err)
	}
	id, err := i.db.BeginTargetRequest(req.Context(), TaskIDFromContext(req.Context()), op.Target, op.Method, account, p.Budget)
	if err != nil {
		cleanupTransport()
		release()
		return i.rejectTargetRequest(req, err)
	}
	started := time.Now()
	resp, err := networkTransport.RoundTrip(req)
	if err != nil {
		cleanupTransport()
	} else {
		if resp.Body == nil {
			resp.Body = http.NoBody
		}
		resp.Body = &transportBody{ReadCloser: resp.Body, cleanup: cleanupTransport}
	}

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
	if resp.Request == nil {
		resp.Request = req
	}
	if observeErr := i.observeTargetResource(req.Context(), op, id, resp); observeErr != nil {
		resp.Body.Close()
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 2*time.Second)
		_ = i.db.FinishTargetRequest(finishCtx, id, resp.StatusCode, latency, observeErr.Error(), 0)
		cancel()
		release()
		return nil, observeErr
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
		if b.finishErr != nil {
			return n, b.finishErr
		}
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
		if b.finishErr != nil {
			b.interceptor.runtime.mu.Lock()
			state := b.interceptor.targetStateLocked(TaskIDFromContext(b.ctx))
			state.blocked = true
			b.interceptor.runtime.mu.Unlock()
			b.interceptor.CancelTargetIO(TaskIDFromContext(b.ctx))
			log.Printf("[target-control] 请求 %d 结果审计失败，目标访问已停止: %v", b.id, b.finishErr)
		}
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

func (i *Interceptor) rejectTargetRequest(req *http.Request, reason error) (*http.Response, error) {
	target, e := parseRequestTarget(req)
	if e != nil {
		return nil, reason
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 2*time.Second)
	defer cancel()
	if e = i.db.RecordDeniedTargetRequest(ctx, TaskIDFromContext(req.Context()), target, req.Method, reason.Error()); e != nil {
		return nil, fmt.Errorf("目标访问拒绝且审计不可用：%w", e)
	}
	return nil, reason
}
