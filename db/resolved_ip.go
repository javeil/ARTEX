package db

import (
	"context"
	"fmt"
	"net/netip"
)

// DNS does not grant another hostname; explicit IP exclusions also apply when
// reaching that IP through an authorized name. Domain authorization remains the
// positive grant, so legitimate private/internal names do not need a second IP
// allowlist and are not globally prohibited.
func (d *DB) TaskIPExclusions(ctx context.Context, id string) ([]AssetInterceptRule, error) {
	global, err := d.ListAssetInterceptRules()
	if err != nil {
		return nil, err
	}
	var taskID int64
	if _, err = fmt.Sscan(id, &taskID); err != nil {
		return nil, err
	}
	local, _, err := d.Assets().TaskInterceptRulesSplit(taskID)
	if err != nil {
		return nil, err
	}
	out := []AssetInterceptRule{}
	for _, rule := range append(global, local...) {
		if !rule.Enabled {
			continue
		}
		switch rule.Kind {
		case "exact_ip":
			if _, err := netip.ParseAddr(rule.Pattern); err != nil {
				return nil, fmt.Errorf("invalid enabled IP exclusion")
			}
			rule.Pattern = NormalizeScopeHost(rule.Pattern)
		case "cidr":
			if _, err := netip.ParsePrefix(rule.Pattern); err != nil {
				return nil, fmt.Errorf("invalid enabled CIDR exclusion")
			}
		case "fuzzy_ip":
		default:
			continue
		}
		out = append(out, rule)
	}
	return out, nil
}
func CheckResolvedIP(rules []AssetInterceptRule, ip string) error {
	if gate := EvaluateAssetGate(rules, nil, nil, []string{NormalizeScopeHost(ip)}, nil); !gate.Allowed {
		return fmt.Errorf("目标不在本任务授权范围：解析 IP 被明确排除：%s", ip)
	}
	return nil
}
