package intercept

import (
	"github.com/Autumn-27/artex/db"
	"testing"
)

func TestAccountBudgetRequiresActualUnambiguousIdentity(t *testing.T) {
	target, _ := db.ParseTarget("https://example.test/login")
	p := db.TargetPolicy{Accounts: []string{"alice"}, Budget: db.TargetBudget{AccountAttempts: 2, AccountWindowSeconds: 60}}
	for _, tc := range []struct {
		body string
		ok   bool
	}{{"username=alice&password=secret", true}, {"username=bob&password=secret", false}, {"username=alice&username=bob", false}, {"password=secret", false}, {`{"username":"alice","password":"secret"}`, true}} {
		_, e := operationAccount(p, Operation{Target: target, Method: "POST", Effect: "authenticate", Body: tc.body})
		if (e == nil) != tc.ok {
			t.Errorf("%s: %v", tc.body, e)
		}
	}
}
