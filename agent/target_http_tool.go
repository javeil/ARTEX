package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/tool"
)

// TargetHTTP keeps arbitrary HTTP payloads available when a task requires
// observable per-request policy, account budgets or path restrictions.
func targetHTTPTool() tool.CoreTool {
	return tool.Build(tool.Spec{Name: "TargetHTTP", Description: "向授权目标发 HTTP 请求。每个请求/跳转均强制校验目标、方法与业务效果、账号范围、预算和停手状态。支持正常 SQLi/XSS/路径遍历/登录测试/数据读取；严格任务优先用此工具，不能用脚本绕过策略。响应超过上下文时保存为工具输出。",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"url": map[string]any{"type": "string"}, "method": map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}}, "headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}, "body": map[string]any{"type": "string"}}, "required": []string{"url"}},
		Run: func(ctx context.Context, input json.RawMessage, tc *tool.ToolContext) (tool.Result, error) {
			var in struct {
				URL, Method, Body string
				Headers           map[string]string
			}
			if e := json.Unmarshal(input, &in); e != nil {
				return tool.Errorf(e.Error()), nil
			}
			if in.Method == "" {
				in.Method = "GET"
			}
			request, e := http.NewRequestWithContext(ctx, strings.ToUpper(in.Method), in.URL, bytes.NewBufferString(in.Body))
			if e != nil {
				return tool.Errorf(e.Error()), nil
			}
			for k, v := range in.Headers {
				request.Header.Set(k, v)
			}
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: targetHTTPTransport{transport}, Timeout: 120 * time.Second}
			response, e := client.Do(request)
			if e != nil {
				return tool.Errorf("【ARTEX 目标管控】" + e.Error()), nil
			}
			defer response.Body.Close()
			// Large target reads remain available in full without buffering an entire
			// database export in the control process or truncating it silently.
			data, e := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
			if e != nil {
				return tool.Errorf(e.Error()), nil
			}
			output := map[string]any{"status": response.StatusCode, "headers": response.Header}
			if len(data) > 2<<20 {
				dir := ""
				if tc != nil {
					dir = tc.OutputDir
					if dir == "" && tc.WorkingDir != "" {
						dir = filepath.Join(tc.WorkingDir, "cmd-output")
					}
				}
				if dir == "" {
					return tool.Errorf("大响应需要任务产物目录"), nil
				}
				if e = os.MkdirAll(dir, 0700); e != nil {
					return tool.Errorf(e.Error()), nil
				}
				file, e := os.CreateTemp(dir, "target-http-*.body")
				if e != nil {
					return tool.Errorf(e.Error()), nil
				}
				hash := sha256.New()
				writer := io.MultiWriter(file, hash)
				written, e := writer.Write(data)
				if e != nil {
					file.Close()
					os.Remove(file.Name())
					return tool.Errorf(e.Error()), nil
				}
				remaining, e := io.Copy(writer, response.Body)
				closeErr := file.Close()
				if e != nil || closeErr != nil {
					os.Remove(file.Name())
					if e == nil {
						e = closeErr
					}
					return tool.Errorf(e.Error()), nil
				}
				output["body_preview"] = string(data[:8192])
				output["body_file"] = file.Name()
				output["body_bytes"] = int64(written) + remaining
				output["body_sha256"] = fmt.Sprintf("%x", hash.Sum(nil))
			} else {
				output["body"] = string(data)
			}
			out, _ := json.Marshal(output)
			return tool.Text(tool.Capture(tc, string(out))), nil
		}})
}

type targetHTTPTransport struct{ base http.RoundTripper }

func (t targetHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return intercept.TargetRoundTrip(t.base, r)
}
