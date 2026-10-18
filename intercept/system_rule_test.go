package intercept

import (
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/shellguard"
	"regexp"
	"testing"
)

func TestSystemRuleMatchesRmOperandsOnly(t *testing.T) {
	r := compiledRule{InterceptRule: db.InterceptRule{Name: shellguard.SystemRule, Protected: true, MatchTarget: "tool_input", MatchType: "regex"}, re: regexp.MustCompile(`rm`)}
	for _, tc := range []struct {
		cmd string
		hit bool
	}{
		{"rm tmp.scan\ncurl -s https://example.com -o /dev/null", false},
		{"rm tmp.scan; echo /etc/passwd", false},
		{"echo 'rm /etc/passwd'", false},
		{"rm tmp.scan /etc/passwd", true},
		{"rm -f -- /etc/passwd", true},
		{"rm '/usr/bin/sh'", true},
	} {
		raw, _ := json.Marshal(map[string]string{"command": tc.cmd})
		if got := ruleMatches(r, "Bash", raw); got != tc.hit {
			t.Errorf("%q=%v", tc.cmd, got)
		}
	}
}
