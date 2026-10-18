package db

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// NetworkScope is an explicit network authorization. ICP/keyword and discovered
// assets are deliberately not network grants. Only human-owned task scope rows
// authorize traffic; agent/auto rows remain useful coverage metadata.
type NetworkScope struct{ Kind, Domain, Net string }

func NormalizeScopeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if prefix, err := netip.ParsePrefix(host); err == nil {
		return prefix.Masked().String()
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return ""
	}
	return ascii
}

func NetworkScopeAllows(rules []NetworkScope, host string) bool {
	host = NormalizeScopeHost(host)
	if host == "" {
		return false
	}
	ip, ipErr := netip.ParseAddr(host)
	targetNet, targetNetErr := netip.ParsePrefix(host)
	for _, r := range rules {
		switch r.Kind {
		case "domain", "root_domain", "subdomain":
			domain := NormalizeScopeHost(r.Domain)
			if ipErr != nil && domain != "" && (host == domain || (r.Kind != "subdomain" && strings.HasSuffix(host, "."+domain))) {
				return true
			}
		case "ip", "cidr":
			if prefix, err := netip.ParsePrefix(r.Net); err == nil && ((ipErr == nil && prefix.Contains(ip)) || (targetNetErr == nil && prefix.Bits() <= targetNet.Bits() && prefix.Contains(targetNet.Masked().Addr()))) {
				return true
			}
		}
	}
	return false
}

// TaskNetworkScope resolves only this task's explicit human authorization and
// company references. It neither inherits other tasks nor grants on fuzzy asset
// attribution. Read on each call so revocations apply without cache invalidation.
func (d *DB) TaskNetworkScope(ctx context.Context, taskID string) ([]NetworkScope, error) {
	rows, err := d.QueryContext(ctx, `SELECT kind, COALESCE(domain,''), COALESCE(net::text,'')
 FROM task_scope WHERE task_id::text=$1 AND source='manual' AND kind IN ('root_domain','subdomain','ip','cidr')
 UNION ALL
 SELECT cs.kind,COALESCE(cs.domain,''),COALESCE(cs.net::text,'') FROM company_scope cs
 JOIN task_scope ts ON ts.company_id=cs.company_id AND ts.kind='company'
 WHERE ts.task_id::text=$1 AND ts.source='manual' AND cs.source='manual' AND cs.kind IN ('domain','ip','cidr')`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NetworkScope{}
	for rows.Next() {
		var r NetworkScope
		if err := rows.Scan(&r.Kind, &r.Domain, &r.Net); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
