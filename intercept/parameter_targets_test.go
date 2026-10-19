package intercept

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestParameterURLsPreserveServiceIdentity(t *testing.T) {
	for _, rawURL := range []string{"http://192.0.2.1:8080/api/v1/ok", "https://api.example.test:8443/api/v1/ok", "http://[2001:db8::1]:8080/api/v1/ok"} {
		t.Run(rawURL, func(t *testing.T) {
			input, _ := json.Marshal(map[string]any{"command": "echo known", "params": map[string]any{"args": rawURL}})
			hosts, _ := ScopeTargets("Bash", input)
			details := ScopeTargetDetails("Bash", input, hosts)
			if !reflect.DeepEqual(details, []string{rawURL}) {
				t.Fatalf("URL produced extra targets: %v", details)
			}
			target, err := db.ParseTarget(rawURL)
			if err != nil {
				t.Fatal(err)
			}
			spec := db.TargetSpec{Host: target.Host, Schemes: []string{target.Scheme}, Ports: []int{target.Port}, PathPrefixes: []string{"/api/v1"}}
			for _, raw := range ScopeTargetRecords("Bash", input, hosts) {
				if !spec.Matches(raw) {
					t.Fatalf("authorized URL became a different service: %+v", raw)
				}
			}
		})
	}
}

func TestParameterURLExtractionRetainsIndependentTargets(t *testing.T) {
	for _, tc := range []struct {
		name, params string
		want         []string
	}{
		{"same_string", `{"args":"http://192.0.2.1:8080/api/ok 192.0.2.2"}`, []string{"http://192.0.2.1:8080/api/ok", "192.0.2.2"}},
		{"separate_same_host", `{"url":"http://192.0.2.1:8080/api/ok","host":"192.0.2.1"}`, []string{"http://192.0.2.1:8080/api/ok", "192.0.2.1"}},
		{"nested_and_cidr", `{"batch":[{"url":"http://192.0.2.1:8080/api/ok"},{"args":"198.51.100.0/24"}]}`, []string{"http://192.0.2.1:8080/api/ok", "198.51.100.0/24"}},
		{"different_services", `{"urls":["http://192.0.2.1:8080/api/ok","http://192.0.2.1:9090/private"]}`, []string{"http://192.0.2.1:8080/api/ok", "http://192.0.2.1:9090/private"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[string]bool{}
			for _, v := range parameterTargets(json.RawMessage(tc.params)) {
				seen[v] = true
			}
			got := []string{}
			for v := range seen {
				got = append(got, v)
			}
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("targets=%v want=%v", got, tc.want)
			}
		})
	}
}
