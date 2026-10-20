package intercept

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestTargetErrorsDoNotInventPolicyDenials(t *testing.T) {
	for _, tc := range []struct {
		err          error
		kind, marker string
	}{
		{io.EOF, "transport", "未收到 HTTP 响应"},
		{context.DeadlineExceeded, "transport", "未收到 HTTP 响应"},
		{context.Canceled, "cancelled", "请求已取消"},
		{controlError(errors.New("目标不在范围")), "control", "ARTEX 平台拒绝"},
	} {
		err := &url.Error{Op: "Get", URL: "https://mock.test/", Err: tc.err}
		if TargetErrorKind(err) != tc.kind || !strings.Contains(TargetErrorMessage(err), tc.marker) {
			t.Fatalf("misattributed: %s", TargetErrorMessage(err))
		}
	}
}
