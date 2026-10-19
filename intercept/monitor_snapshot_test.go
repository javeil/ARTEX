package intercept

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMonitorScriptsAreIncludedInReviewSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "probe.py"), []byte("print('v1')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	review, err := BuildReviewInput(WithReviewWorkingDirectory(t.Context(), dir), "Monitor", []byte(`{"command":"python3 probe.py"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Scripts) != 1 {
		t.Fatalf("Monitor script not captured: %+v", review)
	}
}
