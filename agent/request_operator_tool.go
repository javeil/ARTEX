package agent

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

func requestOperatorTool() tool.CoreTool {
	return tool.Build(tool.Spec{Name: "request_operator", Description: "当前任务无法继续有效推进时请求操作者并暂停任务。先记录事实和证据，再说明连通性/授权/配置阻塞及所需人工处理。不能授权新目标、恢复任务或把阻塞标记为目标达成。不要循环生成监视/重试意图。",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"reason": map[string]any{"type": "string"}}, "required": []string{"reason"}},
		Run: func(ctx context.Context, input json.RawMessage, tc *tool.ToolContext) (tool.Result, error) {
			var in struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			i := intercept.FromContext(ctx)
			if i == nil {
				return tool.Errorf("任务控制器不可用"), nil
			}
			if err := i.RequestOperator(ctx, in.Reason); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			return tool.Text("已请求暂停当前任务并通知操作者；停止创建新意图或目标访问，等待人工处理。实际停止状态由任务控制面板确认。"), nil
		}})
}
