package intercept

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestHTTPClientOptionDataIsNotADestination(t *testing.T) {
	for _, command := range []string{
		`curl -sS -o home.txt https://authorized.example/`,
		`curl --output=home.txt --url https://authorized.example/`,
		`curl -H 'Referer: https://data.example/' --data 'url=https://data.example/' https://authorized.example/`,
		`wget --max-redirect=0 -O home.txt https://authorized.example/`,
	} {
		raw, _ := json.Marshal(map[string]string{"command": command})
		hosts, unknown := ScopeTargets("Bash", raw)
		if unknown || !reflect.DeepEqual(hosts, []string{"authorized.example"}) {
			t.Errorf("%s: hosts=%v unknown=%v", command, hosts, unknown)
		}
		if details := ScopeTargetDetails("Bash", raw, hosts); !reflect.DeepEqual(details, []string{"https://authorized.example/"}) {
			t.Errorf("%s: target details=%v", command, details)
		}
	}
}

func TestHTTPClientStillChecksEveryRealDestination(t *testing.T) {
	raw := []byte(`{"command":"curl -o home.txt https://authorized.example/ --url https://outside.example/"}`)
	hosts, _ := ScopeTargets("Bash", raw)
	if !reflect.DeepEqual(hosts, []string{"authorized.example", "outside.example"}) {
		t.Fatalf("destinations hidden: %v", hosts)
	}
	for _, command := range []string{`curl -K settings.txt https://authorized.example/`, `curl --output "$FILE" "$URL"`, `sleep "$(curl https://outside.example/)"`, `date --file=input.txt`, `./sleep 1`} {
		raw, _ := json.Marshal(map[string]string{"command": command})
		if _, unknown := ScopeTargets("Bash", raw); !unknown {
			t.Errorf("opaque/dynamic call classified as safe: %s", command)
		}
	}
}

func TestStaticWaitAndClockDoNotRequestNetworkApproval(t *testing.T) {
	for _, command := range []string{`sleep 20`, `sleep 900; date -u +%FT%TZ`, `date -Iseconds`, `date '+%Y-%m-%d %H:%M:%S'`} {
		raw, _ := json.Marshal(map[string]string{"command": command})
		if hosts, unknown := ScopeTargets("Bash", raw); unknown || len(hosts) != 0 {
			t.Errorf("local wait/clock: %s: %v %v", command, hosts, unknown)
		}
	}
}
