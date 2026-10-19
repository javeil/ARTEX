package shellguard

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SafeWorkspaceRemoval proves a single literal rm invocation removes only strict
// descendants of the task root. Relative operands, compound scripts, symlinks,
// missing/unresolvable roots and expansion are deliberately not exempted.
func SafeWorkspaceRemoval(command, root string) bool {
	if !filepath.IsAbs(root) {
		return false
	}
	root = filepath.Clean(root)
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	tree, err := syntax.NewParser().Parse(strings.NewReader(command), "cleanup")
	if err != nil || len(tree.Stmts) != 1 {
		return false
	}
	stmt := tree.Stmts[0]
	if stmt.Background || stmt.Negated || len(stmt.Redirs) > 0 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) < 2 {
		return false
	}
	name, ok := Literal(call.Args[0])
	if !ok || filepath.Base(name) != "rm" {
		return false
	}
	recursive, force, end := false, false, false
	targets := 0
	for _, w := range call.Args[1:] {
		a, ok := Literal(w)
		if !ok {
			return false
		}
		if !end && a == "--" {
			end = true
			continue
		}
		if !end && strings.HasPrefix(a, "-") {
			switch a {
			case "--recursive":
				recursive = true
			case "--force":
				force = true
			default:
				if strings.HasPrefix(a, "--") {
					return false
				}
				for _, flag := range a[1:] {
					switch flag {
					case 'r', 'R':
						recursive = true
					case 'f':
						force = true
					case 'v', 'd', 'I', 'i':
					default:
						return false
					}
				}
			}
			continue
		}
		for _, part := range strings.Split(a, string(filepath.Separator)) {
			if part == ".." {
				return false
			}
		}
		if !filepath.IsAbs(a) || !strictChild(root, filepath.Clean(a)) {
			return false
		}
		// Reject every symlink component, including existing ancestors of a target
		// that does not yet exist. No string-prefix or lexical-only proof is enough.
		current := filepath.Clean(a)
		for {
			info, e := os.Lstat(current)
			if e == nil && info.Mode()&os.ModeSymlink != 0 {
				return false
			}
			if e != nil && !os.IsNotExist(e) {
				return false
			}
			if current == root {
				break
			}
			parent := filepath.Dir(current)
			if parent == current {
				return false
			}
			current = parent
		}
		// The trusted root itself may have a host-managed parent symlink (macOS /var).
		// Resolve it once, then compare the resulting target to that canonical root.
		rel, e := filepath.Rel(root, filepath.Clean(a))
		if e != nil || !strictChild(realRoot, filepath.Join(realRoot, rel)) {
			return false
		}
		targets++
	}
	return recursive && force && targets > 0
}
func strictChild(root, target string) bool {
	rel, e := filepath.Rel(root, target)
	return e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
