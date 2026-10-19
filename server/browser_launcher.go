package server

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
)

var playwrightPackage = regexp.MustCompile(`^@playwright/mcp(?:@(?:latest|[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?))?$`)

// A package mentioned as an arbitrary shell argument proves nothing about the
// process being launched. Only the host-resolved entry point is an adapter.
func trustedBrowserLauncher(command string, args []string) (string, error) {
	name := filepath.Base(command)
	if name != "npx" && name != "playwright-mcp" {
		return "", fmt.Errorf("browser MCP 必须使用受信任的 Playwright 启动器")
	}
	trusted, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	trusted, err = filepath.EvalSymlinks(trusted)
	if err != nil {
		return "", err
	}
	if command != name {
		candidate, e := filepath.EvalSymlinks(command)
		if e != nil || candidate != trusted {
			return "", fmt.Errorf("browser MCP 启动路径不是主机受信任程序")
		}
	}
	if name == "npx" {
		j := 0
		for j < len(args) && (args[j] == "-y" || args[j] == "--yes") {
			j++
		}
		if j >= len(args) || !playwrightPackage.MatchString(args[j]) {
			return "", fmt.Errorf("browser MCP 必须直接指定官方 Playwright 包；不接受脚本、别名和本地包")
		}
	}
	return trusted, nil
}
