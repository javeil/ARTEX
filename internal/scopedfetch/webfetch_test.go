package scopedfetch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedirectCannotContactOutOfScopeHost(t *testing.T) {
	hits := 0
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; fmt.Fprint(w, "outside") }))
	defer outside.Close()
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, outside.URL, http.StatusFound) }))
	defer inside.Close()
	checked := 0
	client := &http.Client{Transport: scopedTransport{base: http.DefaultTransport, check: func(_ context.Context, raw string) error {
		checked++
		if strings.HasPrefix(raw, outside.URL) {
			return fmt.Errorf("目标不在本任务授权范围")
		}
		return nil
	}}}
	resp, err := client.Get(inside.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "授权范围") || hits != 0 || checked != 2 {
		t.Fatalf("err=%v outside hits=%d checks=%d", err, hits, checked)
	}
}
