package intercept

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

type gatewayKey struct{}
type TargetGateway struct {
	URL       string
	CACert    string
	dir       string
	token     string
	ctx       context.Context
	cancel    context.CancelFunc
	server    *http.Server
	listener  net.Listener
	ca        cert.CA
	transport http.RoundTripper
	mu        sync.Mutex
	tunnels   map[net.Conn]bool
	mcpTools  map[string]bool
}

func GatewayFromContext(ctx context.Context) *TargetGateway {
	v, _ := ctx.Value(gatewayKey{}).(*TargetGateway)
	return v
}
func WithGateway(ctx context.Context, g *TargetGateway) context.Context {
	return context.WithValue(ctx, gatewayKey{}, g)
}

// NewTargetGateway creates a per-run, authenticated target HTTP gateway. It is
// independent of optional recording and never falls back to an unchecked tunnel.
func NewTargetGateway(ctx context.Context, upstream, caFile string) (*TargetGateway, error) {
	i, _ := ctx.Value(scopeContextKey{}).(*Interceptor)
	if i == nil || TaskIDFromContext(ctx) == "" {
		return nil, fmt.Errorf("目标网关需要授权任务")
	}
	ca, err := cert.NewSelfSignCAMemory()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "artex-target-gateway-")
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(dir)
		}
	}()
	certPath := filepath.Join(dir, "ca.pem")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.GetRootCA().Raw})
	if caFile != "" {
		p, e := os.ReadFile(caFile)
		if e != nil {
			return nil, e
		}
		bundle = append(bundle, p...)
	}
	if err = os.WriteFile(certPath, bundle, 0600); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		ln.Close()
		return nil, err
	}
	root, cancel := context.WithCancel(ctx)
	g := &TargetGateway{dir: dir, CACert: certPath, token: hex.EncodeToString(tokenBytes), ctx: root, cancel: cancel, listener: ln, ca: ca, tunnels: map[net.Conn]bool{}}
	u := &url.URL{Scheme: "http", Host: ln.Addr().String(), User: url.UserPassword(g.token, "")}
	g.URL = u.String()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		p, e := os.ReadFile(caFile)
		if e != nil {
			ln.Close()
			cancel()
			return nil, e
		}
		pool.AppendCertsFromPEM(p)
		tr.TLSClientConfig.RootCAs = pool
	}
	if upstream != "" {
		proxy, e := url.Parse(upstream)
		if e != nil {
			ln.Close()
			cancel()
			return nil, e
		}
		tr.Proxy = http.ProxyURL(proxy)
	}
	g.transport = &gatewayTransport{base: tr}
	g.server = &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return root }}
	go g.server.Serve(ln)
	cleanup = false
	return g, nil
}

type gatewayTransport struct{ base http.RoundTripper }

func (t *gatewayTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return TargetRoundTrip(t.base, r)
}
func (g *TargetGateway) Close() {
	g.cancel()
	_ = g.server.Close()
	g.mu.Lock()
	for c := range g.tunnels {
		_ = c.Close()
	}
	g.mu.Unlock()
	if tr, ok := g.transport.(*gatewayTransport); ok {
		if c, ok := tr.base.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
	_ = os.RemoveAll(g.dir)
}
func (g *TargetGateway) authorized(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	copy := r.Clone(r.Context())
	copy.Header = make(http.Header)
	copy.Header.Set("Authorization", auth)
	user, _, ok := copy.BasicAuth()
	return ok && subtle.ConstantTimeCompare([]byte(user), []byte(g.token)) == 1
}

func (g *TargetGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.authorized(r) {
		http.Error(w, "目标网关凭据无效", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		g.connect(w, r)
		return
	}
	g.forward(w, r, "")
}
func (g *TargetGateway) forward(w http.ResponseWriter, r *http.Request, tunnelAuthority string) {
	if tunnelAuthority != "" {
		if !strings.EqualFold(r.Host, tunnelAuthority) {
			http.Error(w, "隧道目标与请求目标不一致", 403)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = tunnelAuthority
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "目标网关只支持 HTTP(S)", 403)
		return
	}
	// Preserve per-run authorization/emission metadata while honoring disconnects.
	ctx, cancel := context.WithCancel(g.ctx)
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()
	defer cancel()
	req := r.Clone(ctx)
	proxy := &httputil.ReverseProxy{Director: func(out *http.Request) {
		out.Header.Del("Proxy-Authorization")
		out.Header.Del("Proxy-Connection")
		out.RequestURI = ""
	}, Transport: g.transport, FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			w.Header().Set("X-ARTEX-Target-Control", "blocked")
			http.Error(w, "【ARTEX 目标管控·非目标防御】"+err.Error(), http.StatusForbidden)
		},
	}
	proxy.ServeHTTP(w, req)
}
func (g *TargetGateway) connect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "无效 CONNECT 目标", 400)
		return
	}
	// No connection to the target is made during CONNECT/certificate generation.
	// Full host/port/path/method policy runs on each decrypted HTTP request.
	pair, err := g.ca.GetCert(host)
	if err != nil {
		http.Error(w, "无法生成网关证书", 500)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT 不受支持", 500)
		return
	}
	conn, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	g.mu.Lock()
	g.tunnels[conn] = true
	g.mu.Unlock()
	defer func() { conn.Close(); g.mu.Lock(); delete(g.tunnels, conn); g.mu.Unlock() }()
	if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffer.Flush(); err != nil {
		return
	}
	wrapped := &bufferedGatewayConn{Conn: conn, reader: buffer.Reader, done: make(chan struct{})}
	secure := tls.Server(wrapped, &tls.Config{Certificates: []tls.Certificate{*pair}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { g.forward(w, req, r.Host) }), ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return g.ctx }}
	stop := context.AfterFunc(g.ctx, func() { conn.Close() })
	defer stop()
	_ = server.Serve(&gatewayOneListener{conn: secure, done: wrapped.done, addr: conn.LocalAddr()})
}

type bufferedGatewayConn struct {
	net.Conn
	reader *bufio.Reader
	done   chan struct{}
	once   sync.Once
}

func (c *bufferedGatewayConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedGatewayConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

type gatewayOneListener struct {
	conn net.Conn
	done <-chan struct{}
	addr net.Addr
	once sync.Once
}

func (l *gatewayOneListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *gatewayOneListener) Close() error   { return l.conn.Close() }
func (l *gatewayOneListener) Addr() net.Addr { return l.addr }

func MarkGatewayMCP(ctx context.Context, name string) {
	if g := GatewayFromContext(ctx); g != nil {
		g.mu.Lock()
		if g.mcpTools == nil {
			g.mcpTools = map[string]bool{}
		}
		g.mcpTools[name] = true
		g.mu.Unlock()
	}
}
func GatewayMCPObservable(ctx context.Context, name string) bool {
	g := GatewayFromContext(ctx)
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mcpTools[name]
}
