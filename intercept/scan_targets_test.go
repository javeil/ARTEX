package intercept

import (
	"testing"
)

func TestScanPortAndCIDRIdentityIsPreserved(t *testing.T) {
	for _, tc := range []struct {
		cmd, host, scheme string
		ports             int
	}{
		{`nmap -p 443 example.com`, "example.com", "tcp", 1},
		{`nmap -sU -p 53,161 10.24.0.0/16`, "10.24.0.0/16", "udp", 2},
		{`nc example.com 8443`, "example.com", "tcp", 1},
	} {
		input := []byte(`{"command":"` + tc.cmd + `"}`)
		hosts, _ := ScopeTargets("Bash", input)
		records := ScopeTargetRecords("Bash", input, hosts)
		if len(records) != tc.ports {
			t.Fatalf("%s: %+v", tc.cmd, records)
		}
		for _, target := range records {
			if target.Host != tc.host || target.Scheme != tc.scheme || target.Port == 0 {
				t.Fatalf("service identity lost: %+v", target)
			}
		}
	}
}
