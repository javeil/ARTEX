package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

func TestRecursiveDeletionWorkspaceException(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tasks", "42")
	if err := os.MkdirAll(filepath.Join(root, "scratch"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	ctx := intercept.WithTaskContext(t.Context(), "42", "worker", nil)
	ctx = intercept.WithReviewWorkingDirectory(ctx, root)
	for _, tc := range []struct {
		cmd   string
		allow bool
	}{
		{"rm -rf " + root + "/scratch", true},
		{"rm -rf " + root + "/../other", false},
		{"rm -rf /etc", false},
		{"rm -rf $WORK/scratch", false},
		{"rm -rf scratch", false},
		{"rm -rf " + root + "/escape/data", false},
		{"cd /; rm -rf scratch", false},
		{"ln -s /etc " + root + "/link; rm -rf " + root + "/link/passwd", false},
		{"rm -rf " + root + "/scratch /var/log", false},
		{"rm -rf " + root, false},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]string{"command": tc.cmd})
			// The immutable floor and rule matcher must agree on the same narrow exception.
			b, _, _ := New().Hooks().PreToolUse(ctx, "Bash", raw)
			// No interceptor is permitted to approve network calls, but a proven local
			// cleanup must pass even when rule storage is absent.
			if b == tc.allow {
				t.Fatalf("blocked=%v want allow=%v", b, tc.allow)
			}
		})
	}
}
