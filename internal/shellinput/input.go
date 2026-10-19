// Package shellinput defines the inspected command surface shared by the guard,
// scope extractor, operation classifier and approval script snapshots.
package shellinput

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Surface struct {
	Command, Field string
	Interactive    bool
	Err            error
}

func Read(tool string, input []byte) Surface {
	var in struct {
		Command string   `json:"command"`
		Text    string   `json:"text"`
		Paste   string   `json:"paste"`
		Hex     []string `json:"hex"`
		Keys    []string `json:"keys"`
		Submit  bool     `json:"submit"`
	}
	out := Surface{Field: "command"}
	if err := json.Unmarshal(input, &in); err != nil {
		out.Err = err
		return out
	}
	if tool != "shell_send" {
		out.Command = in.Command
		return out
	}
	out.Interactive = true
	out.Field = "text"
	var body strings.Builder
	body.WriteString(in.Text)
	if in.Submit {
		body.WriteByte('\n')
	}
	// Key strokes can edit previous input/history. They are opaque, but must not
	// conceal any explicit command in the other fields from immutable checks.
	for _, key := range in.Keys {
		if key != "" {
			body.WriteByte('\n')
		}
	}
	for _, value := range in.Hex {
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(value), "0x"), 16, 8)
		if err != nil {
			out.Err = fmt.Errorf("无法审查终端十六进制输入")
			continue
		}
		body.WriteByte(byte(n))
	}
	body.WriteString(in.Paste)
	out.Command = strings.ReplaceAll(body.String(), "\r", "\n")
	if !utf8.ValidString(out.Command) {
		out.Err = fmt.Errorf("终端输入不是可审查的 UTF-8 文本")
	}
	for _, r := range out.Command {
		if r < 32 && r != '\n' && r != '\t' {
			out.Err = fmt.Errorf("终端控制字节可能重写命令，不能作为可审查命令执行")
		}
	}
	if in.Paste != "" && in.Text == "" && len(in.Hex) == 0 && len(in.Keys) == 0 {
		out.Field = "paste"
	}
	if len(in.Hex) > 0 || len(in.Keys) > 0 || in.Paste != "" && in.Text != "" {
		out.Field = ""
	}
	return out
}
func Command(tool string, input []byte) string { return Read(tool, input).Command }
