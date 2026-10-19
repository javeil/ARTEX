package intercept

import (
	"encoding/json"
	"net/netip"
)

// Script execution mirrors scalar parameters into TOOL_* and sends the entire
// object on stdin. Its network arguments are executable inputs, not metadata.
func parameterTargets(raw json.RawMessage) []string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	out := []string{}
	var walk func(any, string)
	walk = func(value any, key string) {
		switch v := value.(type) {
		case string:
			out = append(out, scopeURL.FindAllString(v, -1)...)
			// The IP inside a URL is already represented with its port/path.
			// Strip only URL spans in this value: an independent bare host in
			// another parameter still needs its own authorization check.
			remaining := scopeURL.ReplaceAllString(v, " ")
			for _, literal := range scopeIP.FindAllString(remaining, -1) {
				if _, e := netip.ParseAddr(literal); e == nil {
					out = append(out, literal)
				} else if _, e = netip.ParsePrefix(literal); e == nil {
					out = append(out, literal)
				}
			}
			switch key {
			case "host", "hostname", "target", "ip":
				if scopeDomain.MatchString(v) {
					out = append(out, v)
				}
			}
		case []any:
			for _, item := range v {
				walk(item, key)
			}
		case map[string]any:
			for name, item := range v {
				walk(item, name)
			}
		}
	}
	walk(value, "")
	return out
}
