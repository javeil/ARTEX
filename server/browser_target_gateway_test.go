package server

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestBrowserGatewayUsesSupportedProxyConfiguration(t *testing.T) {
	args, _ := json.Marshal([]string{"@playwright/mcp", "--proxy-server=http://outside.invalid", "--proxy-bypass=*"})
	m := &db.MCPServer{Name: "browser", Transport: "stdio", Command: "npx", Args: args}
	ctx := intercept.WithGateway(t.Context(), &intercept.TargetGateway{URL: "http://task:token@127.0.0.1:12345"})
	configured, cleanup, err := browserTargetGateway(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	result := jsonStrSlice(configured.Args)
	if strings.Contains(strings.Join(result, " "), "outside.invalid") {
		t.Fatal("old proxy override retained")
	}
	data, err := os.ReadFile(result[len(result)-1])
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Browser struct {
			LaunchOptions struct {
				Proxy struct{ Server, Username, Password, Bypass string }
			}
			ContextOptions struct {
				Proxy struct{ Server, Username, Password, Bypass string }
			}
		}
	}
	if err = json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	for _, server := range []string{config.Browser.LaunchOptions.Proxy.Server, config.Browser.ContextOptions.Proxy.Server} {
		if server != "http://127.0.0.1:12345" {
			t.Fatalf("unsupported/absent proxy field: %s", data)
		}
	}
	if config.Browser.ContextOptions.Proxy.Username != "task" || config.Browser.ContextOptions.Proxy.Password != "token" {
		t.Fatal("proxy authentication missing")
	}
}

func TestBrowserGatewayRejectsSpoofedLaunchersAndPackageAliases(t *testing.T) {
	ctx := intercept.WithGateway(t.Context(), &intercept.TargetGateway{URL: "http://task:token@127.0.0.1:12345"})
	for _, tc := range []struct {
		command string
		args    []string
	}{
		{"bash", []string{"-c", "curl https://outside.invalid", "@playwright/mcp"}},
		{"/tmp/playwright-mcp", nil},
		{"npx", []string{"-c", "curl https://outside.invalid", "@playwright/mcp"}},
		{"npx", []string{"@playwright/mcp@file:/tmp/evil"}},
		{"npx", []string{"@playwright/mcp@npm:other-package"}},
	} {
		raw, _ := json.Marshal(tc.args)
		_, cleanup, err := browserTargetGateway(ctx, &db.MCPServer{Name: "browser", Transport: "stdio", Command: tc.command, Args: raw})
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Errorf("unverified executable classified as observable browser: %s %v", tc.command, tc.args)
		}
	}
}
