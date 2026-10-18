package intercept

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApprovalBindsScriptContentAndExpiry(t *testing.T) {
	i := retryTestInterceptor(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.py")
	if err := os.WriteFile(path, []byte("print('reviewed')"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := WithReviewWorkingDirectory(t.Context(), dir)
	input := []byte(`{"command":"python3 probe.py"}`)
	binding, err := i.BindApproval(ctx, "Bash", input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("print('different operation')"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := i.ValidateApproval(ctx, "Bash", input, binding); err == nil || !strings.Contains(err.Error(), "内容已变化") {
		t.Fatalf("changed script approval: %v", err)
	}
	binding.ExpiresAt = time.Now().Add(-time.Second)
	if err := i.ValidateApproval(ctx, "Bash", input, binding); err == nil || !strings.Contains(err.Error(), "过期") {
		t.Fatalf("expired approval: %v", err)
	}
}
