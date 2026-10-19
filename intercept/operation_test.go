package intercept

import (
	"encoding/json"
	"testing"
)

func TestOperationEffectsKeepNormalPentestTechniques(t *testing.T) {
	for _, tc := range []struct{ cmd, effect string }{
		{`curl https://example.com/api?q=1%27`, "read"},
		{`curl -X POST https://example.com/login -d 'username=alice&password=test'`, "authenticate"},
		{`curl -X POST https://example.com/api/action -d '{"action":"cancel","order_id":"real-1"}'`, "business_write"},
		{`curl -X POST https://example.com/query -d '{"query":"{ users { id } }"}'`, "read"},
		{`curl -X POST https://example.com/api -d 'id=1'`, "unknown_write"},
		{`sqlmap -u https://example.com/?id=1 --dump`, "probe"},
	} {
		raw, _ := json.Marshal(map[string]string{"command": tc.cmd})
		ops := DescribeOperations("Bash", raw)
		if len(ops) != 1 || ops[0].Effect != tc.effect {
			t.Errorf("%s: %+v", tc.cmd, ops)
		}
	}
}
