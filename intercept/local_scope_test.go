package intercept

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordedTrafficQueriesDoNotRequireNetworkAuthorization(t *testing.T) {
	i := retryTestInterceptor(t, nil)
	ctx := WithTaskContext(t.Context(), "42", "worker", nil)
	for _, tool := range []string{"traffic_search", "traffic_get", "traffic_blob"} {
		input := []byte(`{"host":"outside.example","url":"https://outside.example/a"}`)
		hosts, unknown := ScopeTargets(tool, input)
		if len(hosts) != 0 || unknown {
			t.Errorf("offline %s misclassified as outbound: %v %v", tool, hosts, unknown)
		}
		if dec, gated := i.ScopeDecision(ctx, tool, input); gated {
			t.Errorf("offline history requires authorization: %+v", dec)
		}
	}
	for _, tool := range []string{"TargetHTTP", "WebFetch", "mcp__external__traffic_search"} {
		hosts, unknown := ScopeTargets(tool, []byte(`{"url":"https://outside.example/a"}`))
		if len(hosts) == 0 && !unknown {
			t.Fatalf("active/untrusted tool %s inherited passive exemption", tool)
		}
	}
}
func TestReadOnlySedDoesNotAskForUnrelatedNetworkApproval(t *testing.T) {
	for _, cmd := range []string{`cd /app/data/tasks/42/work && sed -n '240,410p' CU_HTML.html`, `sed -n -e '1,20p' -- local.html`, `printf '%s\n' 'http://outside.example/in-a-local-note'`} {
		raw, _ := json.Marshal(map[string]string{"command": cmd})
		hosts, unknown := ScopeTargets("Bash", raw)
		if len(hosts) != 0 || unknown {
			t.Errorf("local analysis requires scope approval: %s: %v %v", cmd, hosts, unknown)
		}
	}
	for _, cmd := range []string{`sed -n '1e curl https://outside.example/' local.html`, `sed -i '1p' local.html`, `sed -n '1w /tmp/output' local.html`, `sed -f instructions.sed local.html`, `sed -n '1p' local.html -e 'e curl https://outside.example/'`, `sed -n '1p' local.html -i`, `sed -n "$PROGRAM" local.html`} {
		raw, _ := json.Marshal(map[string]string{"command": cmd})
		_, unknown := ScopeTargets("Bash", raw)
		if !unknown {
			t.Errorf("unsafe/uninspectable sed treated as read-only: %s", cmd)
		}
	}
}
func TestExplicitSocketDestinationsAreCheckedBeforeOpaqueApproval(t *testing.T) {
	for _, cmd := range []string{"python3 - <<'PY'\nimport socket\ns=socket.create_connection(('192.0.2.2',80),timeout=3)\nPY", `timeout 3 bash -c 'echo > /dev/tcp/192.0.2.2/80'`} {
		raw, _ := json.Marshal(map[string]string{"command": cmd})
		hosts, unknown := ScopeTargets("Bash", raw)
		found := false
		for _, host := range hosts {
			found = found || host == "192.0.2.2"
		}
		if !found || !unknown {
			t.Errorf("socket destination hidden by opaque code: %+v unknown=%v", hosts, unknown)
		}
	}
}

func TestLocalDataDoesNotHideTargetsFromExecutablePipelines(t *testing.T) {
	for _, cmd := range []string{`printf '%s' 'curl https://outside.example/' | sh`, `sort --compress-program='curl https://outside.example/' input.txt`, `printf -v 'a[$(curl https://outside.example/)]' x`} {
		raw, _ := json.Marshal(map[string]string{"command": cmd})
		hosts, unknown := ScopeTargets("Bash", raw)
		if len(hosts) == 0 || !unknown {
			t.Errorf("executable use of local data hidden: %s hosts=%v unknown=%v", cmd, hosts, unknown)
		}
	}
}

func TestCustomExecutableCannotBorrowLocalToolClassification(t *testing.T) {
	for _, name := range []string{"sed", "printf"} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
		args := " -n '1p' local.html"
		if name == "printf" {
			args = " '%s' 'a local note'"
		}
		raw, _ := json.Marshal(map[string]string{"command": path + args})
		if _, unknown := ScopeTargets("Bash", raw); !unknown {
			t.Errorf("custom %s executable inherited a local exception", name)
		}
	}
}
