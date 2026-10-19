package intercept

import "testing"

func TestExecutableDefinitionChangesAlwaysNeedHumanApproval(t *testing.T) {
	i := retryTestInterceptor(t, nil)
	for _, tool := range []string{"create_mcp", "update_mcp", "create_custom_tool", "update_custom_tool"} {
		d, handled := i.ScopeDecision(t.Context(), tool, []byte(`{"command":"python3 helper.py"}`))
		if !handled || d.Action != "ask" || d.TimeoutAction != "deny" {
			t.Errorf("%s silently changed executable definitions: %+v", tool, d)
		}
	}
}
