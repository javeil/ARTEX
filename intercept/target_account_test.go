package intercept

import (
	"github.com/Autumn-27/artex/db"
	"net/http"
	"strings"
	"testing"
)

func TestAccountBudgetRequiresActualUnambiguousIdentity(t *testing.T) {
	target, _ := db.ParseTarget("https://example.test/login")
	p := db.TargetPolicy{Accounts: []string{"alice"}, Budget: db.TargetBudget{AccountAttempts: 2, AccountWindowSeconds: 60}}
	for _, tc := range []struct {
		body string
		ok   bool
	}{{"username=alice&password=secret", true}, {"username=bob&password=secret", false}, {"username=alice&username=bob", false}, {"password=secret", false}, {`{"username":"alice","password":"secret"}`, true}, {`{"username":"bob","username":"alice"}`, false}} {
		_, e := operationAccount(p, Operation{Target: target, Method: "POST", Effect: "authenticate", Body: tc.body})
		if (e == nil) != tc.ok {
			t.Errorf("%s: %v", tc.body, e)
		}
	}
}

func TestAccountLimitsInspectActualAuthorizationHeadersAndGETLogin(t *testing.T) {
	p := db.TargetPolicy{Accounts: []string{"alice"}, Budget: db.TargetBudget{AccountAttempts: 2}}
	for _, tc := range []struct {
		url, body, header string
		ok                bool
	}{
		{"https://example.test/private", "", "Basic YWxpY2U6cGFzcw==", true},
		{"https://example.test/private", "", "Basic Ym9iOnBhc3M=", false},
		{"https://example.test/login?username=bob&password=x", "", "", false},
		{"https://example.test/private", "", "Bearer opaque-token", false},
		{"https://example.test/login", "username=bob", "Basic YWxpY2U6cGFzcw==", false},
		{"https://example.test/login", "username=alice", "Bearer opaque-token", false},
	} {
		method := "GET"
		if tc.body != "" {
			method = "POST"
		}
		request, _ := http.NewRequest(method, tc.url, strings.NewReader(tc.body))
		if tc.header != "" {
			request.Header.Set("Authorization", tc.header)
		}
		op, e := RequestOperation(request)
		if e != nil {
			t.Fatal(e)
		}
		if op.Effect != "authenticate" {
			t.Errorf("credential attempt misclassified as %s", op.Effect)
			continue
		}
		// A broad operator probe declaration cannot waive an explicit account limit.
		configured := p
		configured.Operations = []db.OperationRule{{Target: db.TargetSpec{Host: "example.test"}, Methods: []string{"GET", "POST"}, Effect: "probe"}}
		op = effectiveOperation(configured, op)
		if op.Effect != "authenticate" {
			t.Fatal("route declaration erased account-sensitive identity")
		}
		_, e = operationAccount(p, op)
		if (e == nil) != tc.ok {
			t.Errorf("identity enforcement: wantAllowed=%v error=%v", tc.ok, e)
		}
	}
	for _, large := range []bool{false, true} {
		body := ""
		if large {
			body = strings.Repeat("x", (1<<20)+2)
		}
		req, _ := http.NewRequest("POST", "https://example.test/login", strings.NewReader(body))
		req.SetBasicAuth("alice", "pass")
		if !large {
			req.Header.Add("Authorization", "Basic Ym9iOnBhc3M=")
		}
		op, e := RequestOperation(req)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = operationAccount(p, op); e == nil {
			t.Fatal("duplicate or uninspectable credential request passed account limits")
		}
	}

}

func TestMalformedLoginCannotBeReclassifiedAsGenericProbe(t *testing.T) {
	for _, tc := range []struct{ body, contentType string }{
		{`{"username":"bob","username":"alice"}`, "application/json"},
		{"invalid multipart payload", "multipart/form-data; boundary=missing"},
	} {
		req, _ := http.NewRequest("POST", "https://example.test/login", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.contentType)
		op, err := RequestOperation(req)
		if err != nil {
			t.Fatal(err)
		}
		p := db.TargetPolicy{Accounts: []string{"alice"}, Budget: db.TargetBudget{AccountAttempts: 2}, Operations: []db.OperationRule{{Target: db.TargetSpec{Host: "example.test"}, Methods: []string{"POST"}, Effect: "probe"}}}
		op = effectiveOperation(p, op)
		if op.Effect != "authenticate" {
			t.Errorf("invalid login payload hidden by generic declaration: %+v", op)
		}
		if _, err = operationAccount(p, op); err == nil {
			t.Error("invalid login bypassed account controls")
		}
	}
}
