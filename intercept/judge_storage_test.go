package intercept

import "testing"

func TestJudgeStorageFailureRequiresHumanReview(t *testing.T) {
	for _, enabled := range []string{"true", "false"} {
		t.Run(enabled, func(t *testing.T) {
			i := retryTestInterceptor(t, map[string]string{settingJudgeEnabled: enabled, settingJudgeFailAction: "allow"})
			if err := i.db.Close(); err != nil {
				t.Fatal(err)
			}
			decision, handled := i.Judge(t.Context(), "Read", []byte(`{"file_path":"local.txt"}`))
			if !handled || decision.Action != "ask" || decision.TimeoutAction != "deny" {
				t.Fatalf("storage failure silently disabled review: %+v handled=%v", decision, handled)
			}
		})
	}
}
