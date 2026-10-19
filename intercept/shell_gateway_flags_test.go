package intercept

import (
	"encoding/json"
	"testing"
)

func TestGatewayRejectsAlternateTransferAndProxyOptions(t *testing.T) {
	ic := New(nil)
	ctx := WithGateway(t.Context(), &TargetGateway{URL: "http://task:token@127.0.0.1:12345"})
	for _, arg := range []string{`-sx ''`, `-sK /tmp/config`, `-:`, `--nex`, `--preproxy http://proxy.invalid`, `--doh-url https://resolver.invalid`, `--unix-socket /tmp/socket`, `--abstract-unix-socket socket`, `"${FLAGS}"`, `--`} {
		input, _ := json.Marshal(map[string]string{"command": "curl " + arg + " https://example.test/"})
		if _, err := ic.PrepareShellInput(ctx, "Bash", input); err == nil {
			t.Errorf("unsafe HTTP arguments accepted: %s", arg)
		}
	}
	// Payload text must remain an argument, not be mistaken for a proxy flag.
	input, _ := json.Marshal(map[string]string{"command": `curl -d '-x literal payload' https://example.test/`})
	if _, err := ic.PrepareShellInput(ctx, "Bash", input); err != nil {
		t.Fatal(err)
	}
}
