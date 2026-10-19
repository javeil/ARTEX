package intercept

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/shellguard"
)

func TestRecursiveRuleWorkspaceException(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tasks", "42")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	i := retryTestInterceptor(t, nil)
	i.cached = []compiledRule{{InterceptRule: db.InterceptRule{Name: shellguard.RecursiveRule, Protected: true, MatchType: "regex", MatchTarget: "tool_input", Action: "deny"}, re: regexp.MustCompile(`rm.*-rf`)}}
	ctx := WithReviewWorkingDirectory(WithTaskContext(t.Context(), "42", "", nil), root)
	for _, tc := range []struct {
		target string
		block  bool
	}{{root + "/scratch", false}, {root + "/../outside", true}, {"/etc", true}, {"$DIR/scratch", true}} {
		raw, _ := json.Marshal(map[string]string{"command": "rm -rf " + tc.target})
		_, hit := i.MatchContext(ctx, "Bash", raw)
		if hit != tc.block {
			t.Errorf("%q matched=%v", tc.target, hit)
		}
	}
}
