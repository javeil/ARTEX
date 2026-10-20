package intercept

import (
	"context"
	"errors"
)

// TargetError distinguishes host policy decisions from failures without an
// HTTP response. An EOF does not identify which peer or intermediary closed it.
type TargetError struct {
	Kind string
	Err  error
}

func (e *TargetError) Error() string { return e.Err.Error() }
func (e *TargetError) Unwrap() error { return e.Err }
func controlError(err error) error {
	if err == nil {
		return nil
	}
	return &TargetError{"control", err}
}
func TargetErrorKind(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var target *TargetError
	if errors.As(err, &target) {
		return target.Kind
	}
	return "transport"
}
func TargetErrorMessage(err error) string {
	switch TargetErrorKind(err) {
	case "control":
		return "【ARTEX 平台拒绝】" + err.Error()
	case "cancelled":
		return "【请求已取消】" + err.Error()
	default:
		return "【未收到 HTTP 响应】" + err.Error() + "。原因尚未确定，不能据此断定平台拦截、目标防御或来源封禁。记录证据，有限重试后请求操作者处理；不要循环创建恢复监视意图。"
	}
}
