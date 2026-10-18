package intercept

import (
	"context"
	"errors"
	"testing"
)

func TestJudgeDefaultFailureIsAsk(t *testing.T) {
	for _, failure := range []string{"invalid_json", "timeout", "network_error", "unwired"} {
		t.Run(failure, func(t *testing.T) {
			i := retryTestInterceptor(t, map[string]string{settingJudgeEnabled: "true", settingJudgeTimeoutSecs: "1"})
			if failure != "unwired" {
				i.SetReviewer(func(ctx context.Context, _ int64, _ string, _ ReviewInput) (Decision, error) {
					switch failure {
					case "invalid_json":
						v := ParseVerdict(`{"decision":`)
						return Decision{Action: v.Action}, nil
					case "timeout":
						<-ctx.Done()
						return Decision{}, ctx.Err()
					default:
						return Decision{}, errors.New("dial tcp: connection refused")
					}
				})
			}
			dec, ok := i.Judge(t.Context(), "Bash", []byte(`{"command":"echo ok"}`))
			if !ok || dec.Action != "ask" || !dec.TimeoutEnabled || dec.TimeoutAction != "deny" {
				t.Fatalf("decision=%+v judged=%v", dec, ok)
			}
		})
	}
}

func TestJudgeExistingSettingPreservedAndResetUsesSafeDefault(t *testing.T) {
	i := retryTestInterceptor(t, map[string]string{settingJudgeFailAction: "allow"})
	if i.GetJudgeConfig().FailAction != "allow" {
		t.Fatal("existing explicit policy overwritten")
	}
	if err := func() error {
		_, err := i.db.Exec(`UPDATE settings SET value='' WHERE key=$1`, settingJudgeFailAction)
		return err
	}(); err != nil {
		t.Fatal(err)
	}
	if i.GetJudgeConfig().FailAction != "ask" {
		t.Fatal("reset must use safe default")
	}
	if i.HandleAsk(t.Context(), 0, Decision{Action: "ask"}, "Bash", []byte(`{}`)) {
		t.Fatal("missing approval storage must deny")
	}
}

func TestRuleStorageFailureDoesNotBecomeDefaultAllow(t *testing.T) {
	i := retryTestInterceptor(t, nil) // settings exist; rules table is intentionally unavailable.
	if !i.IsToolEnabled("Bash") {
		t.Fatal("storage error silently disabled interception")
	}
	dec, matched := i.Match("Bash", []byte(`{"command":"echo ok"}`))
	if !matched || dec.Action != "ask" || dec.TimeoutAction != "deny" {
		t.Fatalf("decision=%+v matched=%v", dec, matched)
	}
}
