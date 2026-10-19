package intercept

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type gatewayTestTransport func(*http.Request) (*http.Response, error)

func (f gatewayTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGatewayHTTPSAuthorityUsesDefaultPortSemantics(t *testing.T) {
	for _, tc := range []struct {
		host string
		want int
	}{{"example.test", 200}, {"EXAMPLE.TEST:443", 200}, {"example.test:8443", 403}, {"outside.test", 403}} {
		contacted := false
		gateway := &TargetGateway{ctx: t.Context(), transport: gatewayTestTransport(func(r *http.Request) (*http.Response, error) {
			contacted = true
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})}
		request := httptest.NewRequest("GET", "https://example.test/", nil)
		request.Host = tc.host
		recorder := httptest.NewRecorder()
		gateway.forward(recorder, request, "example.test:443")
		if recorder.Code != tc.want || contacted != (tc.want == 200) {
			t.Errorf("HTTPS Host=%s: status=%d contacted=%v", tc.host, recorder.Code, contacted)
		}
	}
}
