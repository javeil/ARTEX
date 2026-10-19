package intercept

import (
	"bytes"
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"mime/multipart"
	"net/http"
	"testing"
)

func TestMultipartEffectsAndAccountsUseActualFields(t *testing.T) {
	for _, tc := range []struct {
		path      string
		fields    [][2]string
		effect    string
		accountOK bool
	}{
		{"/action", [][2]string{{"action", "delete"}}, "business_write", false},
		{"/login", [][2]string{{"username", "alice"}}, "authenticate", true},
		{"/login", [][2]string{{"username", "alice"}, {"username", "bob"}}, "authenticate", false},
	} {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		for _, f := range tc.fields {
			w.WriteField(f[0], f[1])
		}
		w.Close()
		req, _ := http.NewRequest("POST", "https://example.test"+tc.path, &b)
		req.Header.Set("Content-Type", w.FormDataContentType())
		op, err := RequestOperation(req)
		if err != nil {
			t.Fatal(err)
		}
		if op.Effect != tc.effect {
			t.Errorf("multipart classified as %s; want %s", op.Effect, tc.effect)
		}
		_, err = operationAccount(db.TargetPolicy{Accounts: []string{"alice"}, Budget: db.TargetBudget{AccountAttempts: 2}}, op)
		if op.Effect == "authenticate" && (err == nil) != tc.accountOK {
			t.Errorf("multipart identity: %v", err)
		}
	}
	req, _ := http.NewRequest("GET", "https://example.test/private", nil)
	req.Header.Set("Cookie", "session=opaque")
	op, _ := RequestOperation(req)
	if _, err := operationAccount(db.TargetPolicy{Accounts: []string{"alice"}}, op); err == nil {
		t.Error("opaque session cookie bypassed account restriction")
	}
}
func TestCurlPayloadFlagsAreNotReads(t *testing.T) {
	for _, flag := range []string{"-F 'action=delete'", "--form-string 'action=delete'", "--data-urlencode 'action=delete'", "-T payload.bin"} {
		input, _ := json.Marshal(map[string]string{"command": "curl " + flag + " https://example.test/action"})
		ops := DescribeOperations("Bash", input)
		if len(ops) != 1 || ops[0].Effect == "read" {
			t.Errorf("%s: %+v", flag, ops)
		}
	}
}
func TestScanOptionsPreserveAllServiceRestrictions(t *testing.T) {
	for _, tc := range []struct {
		cmd    string
		ports  int
		scheme string
	}{
		{"nmap -p22 -p80 example.test", 2, "tcp"},
		{"nc -u example.test 53", 1, "udp"},
	} {
		raw, _ := json.Marshal(map[string]string{"command": tc.cmd})
		targets := ScopeTargetRecords("Bash", raw, []string{"example.test"})
		if len(targets) != tc.ports {
			t.Errorf("%s: %+v", tc.cmd, targets)
		}
		for _, target := range targets {
			if target.Scheme != tc.scheme {
				t.Errorf("protocol mismatch: %+v", target)
			}
		}
	}
}
