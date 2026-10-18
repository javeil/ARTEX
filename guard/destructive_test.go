package guard

import (
	"encoding/json"
	"testing"
)

func TestCoreProtectionWithoutDatabase(t *testing.T) {
	for _, cmd := range []string{`rm -rf /tmp/x`, `rm /etc/passwd`, `mkfs.ext4 /dev/sda`, `dd if=/dev/zero of=/dev/sda`, `:(){ :|:& };:`, `shutdown -h now`, `reboot`, `bash -c 'rm -rf /'`, `sudo /bin/rm -rf /`} {
		raw, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := New().Hooks().PreToolUse(t.Context(), "Bash", raw)
		if !b {
			t.Errorf("immutable protection did not block %q", cmd)
		}
	}
}

func TestDeferredToolCannotBypassCore(t *testing.T) {
	raw := []byte(`{"tool_name":"Bash","params":{"command":"rm -rf /"}}`)
	b, _, _ := New().Hooks().PreToolUse(t.Context(), "ExecuteExtraTool", raw)
	if !b {
		t.Fatal("deferred trampoline bypassed core protection")
	}
	b, _, _ = New().Hooks().PreToolUse(t.Context(), "Monitor", []byte(`{"command":"mkfs.ext4 /dev/sda"}`))
	if !b {
		t.Fatal("background monitor bypassed core protection")
	}
}

func TestQuotedEscapedAndInvalidCommandsDoNotDisableCore(t *testing.T) {
	for _, cmd := range []string{`r\m -rf /`, `'rm' -rf /`, `busybox rm -rf /`, `rm -rf /; (`, `$CMD -rf /`, `rm "$SYSTEM_PATH"`, `cd /; rm -r etc`, "cd /etc\nrm passwd"} {
		raw, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := New().Hooks().PreToolUse(t.Context(), "Bash", raw)
		if !b {
			t.Errorf("core bypassed by %q", cmd)
		}
	}
}
