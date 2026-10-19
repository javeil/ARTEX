// Package shellguard implements the immutable, narrow destructive-command floor.
// It does not classify attack techniques or replace scope/approval policy.
package shellguard

import (
	"bytes"
	"github.com/Autumn-27/artex/internal/shellinput"
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

const RecursiveRule = "[内置] 递归强制删除 rm -rf"
const SystemRule = "[内置] 删除系统关键目录"

var CoreNames = []string{RecursiveRule, SystemRule, "[内置] 磁盘格式化 mkfs", "[内置] 覆写磁盘设备 dd", "[内置] Fork 炸弹", "[内置] 关机 / 重启"}

func IsCoreName(name string) bool {
	for _, n := range CoreNames {
		if n == name {
			return true
		}
	}
	return false
}

var forkBomb = regexp.MustCompile(`:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:`)

func Command(tool string, input []byte) string {
	switch tool {
	case "Bash", "Monitor", "shell_open", "shell_send":
		return shellinput.Command(tool, input)
	}
	return ""
}

// Literal resolves quoting only, never substitutions, variables, globs or code.
func Literal(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var known func([]syntax.WordPart, bool) bool
	known = func(parts []syntax.WordPart, quoted bool) bool {
		for _, part := range parts {
			switch p := part.(type) {
			case *syntax.Lit:
				if !quoted {
					for i := 0; i < len(p.Value); i++ {
						if p.Value[i] == '\\' {
							i++
							continue
						}
						if strings.ContainsRune("*?[]~{}", rune(p.Value[i])) {
							return false
						}
					}
				}
			case *syntax.SglQuoted:
			case *syntax.DblQuoted:
				if !known(p.Parts, true) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !known(w.Parts, false) {
		return "", false
	}
	fields, err := expand.Fields(&expand.Config{NoUnset: true}, w)
	if err != nil || len(fields) != 1 {
		return "", false
	}
	return fields[0], true
}

// Check returns the first destructive class. The guard short-circuits before DB
// matching, so a call generates only one rejection even if both layers match.
func Check(command string) string { return check(command, 0, "") }
func check(command string, depth int, cwd string) string {
	if depth > 4 {
		return "嵌套命令无法安全解析"
	}
	if forkBomb.MatchString(command) {
		return "Fork 炸弹"
	}
	tree, err := syntax.NewParser().Parse(strings.NewReader(command), "guard")
	if err != nil {
		return "Shell 命令无法解析，无法验证核心防护"
	}
	reason := ""
	syntax.Walk(tree, func(n syntax.Node) bool {
		if reason != "" {
			return false
		}
		c, ok := n.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		args := []string{}
		known := []bool{}
		for _, w := range c.Args {
			a, k := Literal(w)
			args = append(args, a)
			known = append(known, k)
		}
		// Interpret sudo/env/command wrappers without running them.
		pos := 0
		for pos < len(args) && (args[pos] == "sudo" || args[pos] == "env" || args[pos] == "command" || args[pos] == "exec") {
			pos++
			for pos < len(args) && (strings.HasPrefix(args[pos], "-") || strings.Contains(args[pos], "=")) {
				if args[pos] == "-u" || args[pos] == "-g" {
					pos++
				}
				pos++
			}
		}
		if pos >= len(args) {
			return true
		}
		if !known[pos] {
			reason = "动态命令名无法验证核心防护"
			return false
		}
		name := path.Base(args[pos])
		args = args[pos+1:]
		known = known[pos+1:]
		switch {
		case name == "cd":
			if len(args) > 0 && known[0] {
				if path.IsAbs(args[0]) {
					cwd = path.Clean(args[0])
				} else if cwd != "" {
					cwd = path.Join(cwd, args[0])
				}
			} else {
				cwd = ""
			}
		case name == "rm":
			recursive := false
			force := false
			operands := []string{}
			end := false
			for j, a := range args {
				if !end && a == "--" {
					end = true
					continue
				}
				if !end && strings.HasPrefix(a, "-") {
					recursive = recursive || a == "--recursive" || (!strings.HasPrefix(a, "--") && strings.ContainsAny(a, "rR"))
					force = force || a == "--force" || (!strings.HasPrefix(a, "--") && strings.Contains(a, "f"))
					if a == "--no-preserve-root" {
						recursive = true
						force = true
					}
					continue
				}
				if !known[j] {
					reason = "删除路径无法验证核心防护"
					operands = append(operands, "")
				} else {
					operands = append(operands, a)
				}
			}
			if recursive && force {
				reason = "递归强制删除"
				return false
			}
			for _, a := range operands {
				if SystemPath(a) || (cwd != "" && !path.IsAbs(a) && SystemPath(path.Join(cwd, a))) {
					reason = "删除系统关键目录"
					return false
				}
			}
		case strings.HasPrefix(name, "mkfs"), name == "mke2fs":
			reason = "磁盘格式化"
		case name == "dd":
			for j, a := range args {
				if strings.HasPrefix(a, "of=") && (!known[j] || strings.HasPrefix(strings.TrimPrefix(a, "of="), "/dev/")) {
					reason = "覆写磁盘设备"
				}
			}
		case name == "shutdown", name == "reboot", name == "halt", name == "poweroff":
			reason = "关机或重启"
		case name == "init", name == "telinit":
			if len(args) > 0 && (args[0] == "0" || args[0] == "6") {
				reason = "关机或重启"
			}
		case name == "busybox":
			if len(args) > 0 {
				var nested strings.Builder
				for j, a := range args {
					if !known[j] {
						reason = "动态 busybox 命令无法验证核心防护"
						return false
					}
					nested.WriteString("'")
					nested.WriteString(strings.ReplaceAll(a, "'", "'\\''"))
					nested.WriteString("' ")
				}
				reason = check(nested.String(), depth+1, cwd)
			}
		case name == "systemctl":
			if len(args) > 0 && (args[0] == "reboot" || args[0] == "poweroff" || args[0] == "halt") {
				reason = "关机或重启"
			}
		case name == "sh", name == "bash", name == "zsh", name == "eval":
			for j, a := range args {
				if name == "eval" || (j > 0 && strings.Contains(args[j-1], "c")) {
					if known[j] {
						if r := check(a, depth+1, cwd); r != "" {
							reason = r
						}
					}
				}
			}
		}
		return true
	})
	return reason
}

func SystemPath(p string) bool {
	if !path.IsAbs(p) {
		return false
	}
	p = path.Clean(p)
	if p == "/" {
		return true
	}
	for _, dir := range []string{"etc", "bin", "usr", "boot", "var", "lib", "lib64", "sys", "proc", "dev", "sbin", "root"} {
		if p == "/"+dir || strings.HasPrefix(p, "/"+dir+"/") {
			return true
		}
	}
	return false
}

// SystemRemoval checks actual rm operands, never unrelated later commands or
// redirects. Used by the DB rule once migrated away from raw JSON proximity.
func SystemRemoval(tool string, input []byte) bool {
	command := Command(tool, input)
	if command == "" {
		return false
	}
	return bytes.Contains([]byte(Check(command)), []byte("删除系统关键目录"))
}
