package intercept

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"io"
	"net/http"
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
	if _, err := i.AuthorizeRequest(req.Context(), req); err != nil {
		return nil, err
	}
	return base.RoundTrip(req)
}
