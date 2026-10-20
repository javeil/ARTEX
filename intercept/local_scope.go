package intercept

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// These host tools read already-recorded data. A host/URL is a database filter,
// rather than a destination. Custom/MCP tool names do not inherit this exemption.
func offlineTrafficTool(tool string) bool {
	return tool == "traffic_search" || tool == "traffic_get" || tool == "traffic_blob"
}

var sedPrint = regexp.MustCompile(`^(?:(?:[0-9]+|\$)(?:\s*,\s*(?:[0-9]+|\$))?)?p$`)

var base64Width = regexp.MustCompile(`^[0-9]+$`)

// Only static encoding/decoding and local input files are classified here.
// Execution in another pipeline stage, substitutions, redirections and custom
// executables still go through the surrounding shell/scope checks.
func localBase64(args []string) bool {
	options := true
	for j := 1; j < len(args); j++ {
		a := args[j]
		if !options || !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		switch {
		case a == "--":
			options = false
		case a == "-d" || a == "-D" || a == "--decode" || a == "-i" || a == "--ignore-garbage" || a == "--help" || a == "--version":
		case a == "-w" || a == "--wrap" || a == "-b":
			j++
			if j >= len(args) || !base64Width.MatchString(args[j]) {
				return false
			}
		case strings.HasPrefix(a, "--wrap="):
			if !base64Width.MatchString(strings.TrimPrefix(a, "--wrap=")) {
				return false
			}
		case strings.HasPrefix(a, "-w") || strings.HasPrefix(a, "-b"):
			if !base64Width.MatchString(a[2:]) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Deliberately narrow: sed can execute commands and write files. Only static
// print/range programs are local reads; -i/-f/e/w and dynamic programs stay opaque.
func readOnlySed(args []string) bool {
	programs := []string{}
	positional := false
	for j := 1; j < len(args); j++ {
		a := args[j]
		if !positional {
			switch {
			case a == "-n" || a == "--quiet" || a == "--silent":
				continue
			case a == "-e" || a == "--expression":
				j++
				if j >= len(args) {
					return false
				}
				programs = append(programs, args[j])
				continue
			case strings.HasPrefix(a, "--expression="):
				programs = append(programs, strings.TrimPrefix(a, "--expression="))
				continue
			case a == "--":
				positional = true
				continue
			case strings.HasPrefix(a, "-") && a != "-":
				return false
			}
		}
		if len(programs) == 0 {
			programs = append(programs, a)
		}
	}
	if len(programs) == 0 {
		return false
	}
	for _, program := range programs {
		for _, part := range strings.Split(program, ";") {
			if !sedPrint.MatchString(strings.TrimSpace(part)) {
				return false
			}
		}
	}
	return true
}

var devSocketTarget = regexp.MustCompile(`/dev/(?:tcp|udp)/(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9_.:-]+)/[0-9]+`)
var pythonSocketTarget = regexp.MustCompile(`(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:create_connection|connect))\s*\(\s*\(\s*["']([^"'\\\s]+)["']\s*,\s*[0-9]+`)

func literalSocketTargets(command string) []string {
	out := []string{}
	for _, pattern := range []*regexp.Regexp{devSocketTarget, pythonSocketTarget} {
		for _, m := range pattern.FindAllStringSubmatch(command, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

// An executable merely named sed/printf in a task directory is not the host
// utility. Bare commands use the host's trusted PATH, as do the SDK tools.
func trustedLocalExecutable(provided, name string) bool {
	if provided == name {
		return true
	}
	actual, err := filepath.EvalSymlinks(provided)
	if err != nil {
		return false
	}
	trusted, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	trusted, err = filepath.EvalSymlinks(trusted)
	return err == nil && trusted == actual
}

// Static bounded waits and clock reads cannot contact a target. Setting the
// clock, reading date programs from files and dynamic expansions stay opaque.
func localWaitOrClock(name string, args []string) bool {
	if name == "sleep" {
		if len(args) < 2 {
			return false
		}
		total := 0.0
		for _, a := range args[1:] {
			scale := 1.0
			if len(a) > 0 {
				switch a[len(a)-1] {
				case 's':
					a = a[:len(a)-1]
				case 'm':
					scale = 60
					a = a[:len(a)-1]
				case 'h':
					scale = 3600
					a = a[:len(a)-1]
				}
			}
			n, err := strconv.ParseFloat(a, 64)
			if err != nil || n < 0 || n > 3600 {
				return false
			}
			total += n * scale
		}
		return total >= 0 && total <= 3600
	}
	for _, a := range args[1:] {
		if a == "-u" || a == "--utc" || a == "--universal" || a == "-I" || a == "-Iseconds" || a == "--iso-8601=seconds" || strings.HasPrefix(a, "+") {
			continue
		}
		return false
	}
	return true
}
