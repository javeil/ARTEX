package intercept

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"mvdan.cc/sh/v3/syntax"
)

// ScopeTargetRecords keeps explicit nmap/nc port identity while retaining URLs
// for HTTP. An unspecified port never satisfies a service-specific restriction.
func ScopeTargetRecords(tool string, input []byte, hosts []string) []db.Target {
	details := ScopeTargetDetails(tool, input, hosts)
	out := []db.Target{}
	scan := map[string][]db.Target{}
	if tool == "Bash" || tool == "Monitor" || tool == "shell_open" {
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(input, &in)
		tree, e := syntax.NewParser().Parse(strings.NewReader(in.Command), "scan-target")
		if e == nil {
			syntax.Walk(tree, func(n syntax.Node) bool {
				c, ok := n.(*syntax.CallExpr)
				if !ok || len(c.Args) == 0 {
					return true
				}
				args := []string{}
				for _, w := range c.Args {
					v, k := operationWord(w)
					if !k {
						return true
					}
					args = append(args, v)
				}
				name := filepath.Base(args[0])
				if name != "nmap" && name != "nc" && name != "netcat" {
					return true
				}
				ports := []int{}
				scheme := "tcp"
				if name == "nmap" {
					for j := 1; j < len(args); j++ {
						a := args[j]
						if a == "-sU" {
							scheme = "udp"
						}
						raw := ""
						if a == "-p" && j+1 < len(args) {
							j++
							raw = args[j]
						} else if strings.HasPrefix(a, "-p") {
							raw = strings.TrimPrefix(a, "-p")
						}
						if raw != "" {
							ports = parseScanPorts(raw)
						}
					}
				} else if len(args) > 2 {
					ports = parseScanPorts(args[len(args)-1])
				}
				for _, h := range hosts {
					found := false
					for _, a := range args[1:] {
						found = found || db.NormalizeScopeHost(a) == h
					}
					if found {
						for _, p := range ports {
							scan[h] = append(scan[h], db.Target{Host: h, Port: p, Scheme: scheme})
						}
					}
				}
				return true
			})
		}
	}
	for _, raw := range details {
		target, e := db.ParseTarget(raw)
		if e != nil {
			continue
		}
		if target.Scheme == "" && len(scan[target.Host]) > 0 {
			out = append(out, scan[target.Host]...)
		} else {
			out = append(out, target)
		}
	}
	return out
}
func parseScanPorts(raw string) []int {
	out := []int{}
	for _, part := range strings.Split(raw, ",") {
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(bounds[0])
			hi, e2 := strconv.Atoi(bounds[1])
			if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || hi < lo || hi-lo > 1024 {
				return nil
			}
			for p := lo; p <= hi; p++ {
				out = append(out, p)
			}
		} else {
			p, e := strconv.Atoi(part)
			if e != nil || p < 1 || p > 65535 {
				return nil
			}
			out = append(out, p)
		}
	}
	return out
}
