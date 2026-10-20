package intercept

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Bind DNS validation to the IP actually dialed. Do not validate a name and then
// let a second resolver (or an opaque remote HTTP proxy) choose another address.
func (i *Interceptor) checkedTransport(req *http.Request, base http.RoundTripper) (http.RoundTripper, func(), error) {
	rules, err := i.db.TaskIPExclusions(req.Context(), TaskIDFromContext(req.Context()))
	if err != nil {
		return nil, nil, err
	}
	host := req.URL.Hostname()
	if net.ParseIP(host) != nil {
		if err = db.CheckResolvedIP(rules, host); err != nil {
			return nil, nil, err
		}
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		if len(rules) > 0 && net.ParseIP(host) == nil {
			return nil, nil, fmt.Errorf("传输器无法证明解析 IP 排除已执行")
		}
		return base, func() {}, nil
	}
	if transport.Proxy != nil {
		proxy, err := transport.Proxy(req)
		if err != nil {
			return nil, nil, err
		}
		if proxy != nil {
			if len(rules) > 0 && net.ParseIP(host) == nil {
				return nil, nil, fmt.Errorf("当前代理不能固定目标解析 IP，无法执行 IP 排除；请使用直连 TargetHTTP 或固定 IP 目标")
			}
			return base, func() {}, nil
		}
	}
	clone := transport.Clone()
	clone.Proxy = nil
	clone.DialTLS = nil
	clone.DialTLSContext = nil
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	clone.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		name, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if db.NormalizeScopeHost(name) != db.NormalizeScopeHost(host) {
			return nil, controlError(fmt.Errorf("传输器试图改变任务目标"))
		}
		addresses := []net.IPAddr{}
		if ip := net.ParseIP(name); ip != nil {
			addresses = append(addresses, net.IPAddr{IP: ip})
		} else {
			addresses, err = net.DefaultResolver.LookupIPAddr(ctx, name)
			if err != nil {
				return nil, err
			}
		}
		var last error
		for _, address := range addresses {
			ip := address.IP.String()
			if err = db.CheckResolvedIP(rules, ip); err != nil {
				last = controlError(err)
				continue
			}
			if err = i.db.CheckTaskExecution(ctx, TaskIDFromContext(ctx)); err != nil {
				return nil, controlError(err)
			}
			conn, err := dial(ctx, network, net.JoinHostPort(ip, port))
			if err != nil {
				last = err
				continue
			}
			actual, ok := conn.RemoteAddr().(*net.TCPAddr)
			if !ok || !actual.IP.Equal(address.IP) {
				conn.Close()
				last = controlError(fmt.Errorf("目标连接地址与已校验 IP 不一致"))
				continue
			}
			if err = ctx.Err(); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		}
		if last == nil {
			last = fmt.Errorf("目标没有可用且获授权的解析 IP")
		}
		return nil, last
	}
	return clone, clone.CloseIdleConnections, nil
}

type transportBody struct {
	io.ReadCloser
	cleanup func()
}

func (b *transportBody) Close() error { err := b.ReadCloser.Close(); b.cleanup(); return err }
