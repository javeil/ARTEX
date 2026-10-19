package guard

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

func TestTerminalPasteAndHexCannotHideProtectedCommandsOrTargets(t *testing.T) {
	command := "rm -rf /"
	encoded := []string{}
	for _, b := range []byte(command) {
		encoded = append(encoded, hex.EncodeToString([]byte{b}))
	}
	for _, input := range []map[string]any{{"paste": command}, {"hex": encoded}, {"text": "r", "hex": encoded[1:]}} {
		raw, _ := json.Marshal(input)
		blocked, message, _ := New().Hooks().PreToolUse(t.Context(), "shell_send", raw)
		if !blocked || !strings.Contains(message, "核心防护") {
			t.Errorf("terminal representation bypassed immutable protection: %s", raw)
		}
	}
	for _, input := range []map[string]any{{"paste": "curl https://outside.example/"}, {"hex": []string{"63", "75", "72", "6c", "20", "68", "74", "74", "70", "73", "3a", "2f", "2f", "6f", "75", "74", "73", "69", "64", "65", "2e", "65", "78", "61", "6d", "70", "6c", "65", "2f"}}} {
		raw, _ := json.Marshal(input)
		hosts, _ := intercept.ScopeTargets("shell_send", raw)
		if len(hosts) != 1 || hosts[0] != "outside.example" {
			t.Errorf("target hidden by terminal input encoding: %s %+v", raw, hosts)
		}
	}
}
