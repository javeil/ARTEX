// Package enrich is the engine-side (non-AI) asset auto-completion layer described
// in docs/资产模型与自动关联设计.md §5: an async worker pool that resolves domains
// (dnsx) and probes web assets (HTTP, through the recording proxy) and writes the
// results back into the asset graph — creating IP/port nodes, resolves/exposes
// edges, and filling attrs.dns / attrs.http. DNS and HTTP require an explicit task; probing is gated
// by RoE (§5.2).
package enrich

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Autumn-27/artex/intercept"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

type jobKind int

const (
	jobDNS  jobKind = iota // resolve a domain
	jobHTTP                // probe a web asset (site)
)

type job struct {
	ctx     context.Context
	finish  func()
	version string
	kind    jobKind
	id      int64  // asset id (domain for DNS, site for HTTP)
	arg     string // host (DNS) or url (HTTP)
}

// Engine owns the resolver, the proxy-routed HTTP client, and the worker pool.
type Engine struct {
	as      *db.AssetStore
	lookup  func(context.Context, string) (*dnsAnswer, error)
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	stopped bool
	wg      sync.WaitGroup
	client  *http.Client

	jobs   chan job
	cool   sync.Map // dedup/cooldown: "kind:id" -> time.Time (last run)
	once   sync.Once
	closed chan struct{}
}

const (
	cooldown    = 5 * time.Minute
	httpTimeout = 12 * time.Second
	queueSize   = 1024
)

// New builds the engine. proxy() returns the recording-proxy address to route HTTP
// probes through (so they land in the traffic store), evaluated per request so the
// runtime traffic-capture toggle takes effect live; "" = direct. Returns a usable
// engine even if the resolver fails to init (DNS becomes a no-op).
func New(as *db.AssetStore, proxy func() string, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	root, cancel := context.WithCancel(context.Background())
	e := &Engine{
		as:     as,
		lookup: resolveDNS, ctx: root, cancel: cancel,
		client: buildClient(proxy),
		jobs:   make(chan job, queueSize),
		closed: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.worker()
	}
	return e
}

// buildClient returns an HTTP client that dials via the recording proxy (resolved
// per-request via proxy(), so the traffic-capture toggle applies live) and skips
// TLS verification (the proxy re-signs with its MITM CA; targets are often
// self-signed — this is a pentest probe).
func buildClient(proxy func() string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: httpTimeout,
	}
	if proxy != nil {
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			p := proxy()
			if p == "" {
				return nil, nil // direct
			}
			return url.Parse(p)
		}
	}
	return &http.Client{
		Transport: scopedTransport{tr},
		Timeout:   httpTimeout,
		// cap redirects; keep them within scope by re-checking at probe time
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Legacy calls do not identify an authorized task and must not start IO.
func (e *Engine) ResolveDomain(id int64, host string) {
	log.Printf("[enrich] DNS 未绑定授权任务，拒绝自动访问")
}
func (e *Engine) ProbeSite(id int64, rawURL string) {
	log.Printf("[enrich] HTTP 未绑定授权任务，拒绝自动访问")
}
func (e *Engine) ResolveDomainForTask(ctx context.Context, id int64, host string) error {
	return e.enqueue(ctx, jobDNS, id, host)
}
func (e *Engine) ProbeSiteForTask(ctx context.Context, id int64, rawURL string) error {
	return e.enqueue(ctx, jobHTTP, id, rawURL)
}
func (e *Engine) enqueue(ctx context.Context, kind jobKind, id int64, arg string) error {
	if e == nil || id <= 0 || arg == "" {
		return fmt.Errorf("invalid enrichment request")
	}
	ic := intercept.FromContext(ctx)
	if ic == nil || intercept.TaskIDFromContext(ctx) == "" {
		return fmt.Errorf("enrichment requires task authorization")
	}
	if err := ic.CheckTarget(ctx, arg); err != nil {
		return err
	}
	policy, err := ic.TrustedTaskPolicy(ctx)
	if err != nil {
		return err
	}
	parent, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	child, release, err := intercept.BeginTargetActivity(parent)
	if err != nil {
		stop()
		cancel()
		return err
	}
	finish := func() { stop(); cancel(); release() }
	j := job{ctx: child, finish: finish, version: policy.Version, kind: kind, id: id, arg: arg}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		finish()
		return fmt.Errorf("enrichment engine closed")
	}
	select {
	case e.jobs <- j:
		return nil
	default:
		finish()
		return fmt.Errorf("enrichment queue full")
	}
}

func id0(id int64) bool { return id <= 0 }

// Close stops the workers (idempotent).
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.once.Do(func() {
		e.mu.Lock()
		e.stopped = true
		e.cancel()
		close(e.closed)
		e.mu.Unlock()
		e.wg.Wait()
		for {
			select {
			case j := <-e.jobs:
				j.finish()
			default:
				return
			}
		}
	})
}
func (e *Engine) worker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.closed:
			return
		case j := <-e.jobs:
			e.perform(j)
		}
	}
}
func (e *Engine) perform(j job) {
	defer j.finish()
	if j.ctx.Err() != nil {
		return
	}
	ic := intercept.FromContext(j.ctx)
	policy, err := ic.TrustedTaskPolicy(j.ctx)
	if err != nil || policy.Version != j.version || e.onCooldown(j) {
		return
	}
	if j.kind == jobDNS {
		err = e.doDNS(j.ctx, j.id, j.arg)
	} else {
		err = e.doHTTP(j.ctx, j.id, j.arg)
	}
	if err != nil {
		log.Printf("[enrich] 目标访问未执行或失败: %v", err)
	}
}

// onCooldown returns true (skip) if this (kind,id) ran within the cooldown window.
func (e *Engine) onCooldown(j job) bool {
	key := intercept.TaskIDFromContext(j.ctx) + ":" + j.version + ":" + string(rune(j.kind)) + ":" + itoa(j.id)
	if v, ok := e.cool.Load(key); ok {
		if t, ok := v.(time.Time); ok && time.Since(t) < cooldown {
			return true
		}
	}
	e.cool.Store(key, time.Now())
	return false
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- DNS ----

type dnsAnswer struct{ A, AAAA, CNAME []string }

func resolveDNS(ctx context.Context, host string) (*dnsAnswer, error) {
	values, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := &dnsAnswer{}
	for _, value := range values {
		if value.IP.To4() != nil {
			out.A = append(out.A, value.IP.String())
		} else {
			out.AAAA = append(out.AAAA, value.IP.String())
		}
	}
	if canonical, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil && strings.TrimSuffix(canonical, ".") != strings.TrimSuffix(host, ".") {
		out.CNAME = append(out.CNAME, strings.TrimSuffix(canonical, "."))
	}
	return out, nil
}
func (e *Engine) doDNS(ctx context.Context, id int64, host string) error {
	var data *dnsAnswer
	err := intercept.QueryAuthorizedDNS(ctx, host, func(bound context.Context) error { var err error; data, err = e.lookup(bound, host); return err })
	if err != nil {
		return err
	}
	if data == nil || e.as == nil {
		return nil
	}

	ips := uniq(append(append([]string{}, data.A...), data.AAAA...))
	// Upsert resolved IPs into the asset store.
	for _, ip := range ips {
		_, _ = e.as.UpsertIP(db.UpsertIPReq{
			IP:           ip,
			BoundDomains: []string{host},
		})
	}
	// Record A records as subdomains if host looks like a subdomain.
	for _, a := range data.A {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "A",
			RecordValue: []string{a},
		})
	}
	for _, aaaa := range data.AAAA {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "AAAA",
			RecordValue: []string{aaaa},
		})
	}
	for _, cname := range data.CNAME {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "CNAME",
			RecordValue: []string{cname},
		})
	}
	return nil
}

// ---- HTTP probe ----

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (e *Engine) doHTTP(ctx context.Context, id int64, rawURL string) error {
	host := hostOf(rawURL)
	if host == "" {
		return fmt.Errorf("invalid or failed enrichment request")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return fmt.Errorf("invalid or failed enrichment request")
	}
	req.Header.Set("User-Agent", "artex-enrich/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("invalid or failed enrichment request")
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return readErr
	} // cap 1 MiB
	statusCode := resp.StatusCode
	bodyLen := int64(len(body))
	title := extractTitle(body)
	if e.as == nil {
		return nil
	}
	_, err = e.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:           rawURL,
		StatusCode:    &statusCode,
		ContentLength: &bodyLen,
		PageTitle:     title,
	})
	return err
}

func extractTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isBlank(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case float64:
		return x == 0
	case int:
		return x == 0
	}
	return false
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

type scopedTransport struct{ base http.RoundTripper }

func (t scopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return intercept.TargetRoundTrip(t.base, req)
}
