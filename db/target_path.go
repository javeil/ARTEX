package db

import (
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

// Restricted paths must agree before/after decoding and dot-segment removal.
// An unrestricted host policy still permits encoded traversal/injection tests.
func targetPathRepresentations(t Target) ([]string, bool) {
	if t.URL == "" {
		return nil, false
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, false
	}
	current := u.EscapedPath()
	if current == "" {
		current = "/"
	}
	seen := map[string]bool{}
	out := []string{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for depth := 0; depth < 8; depth++ {
		if !utf8.ValidString(current) {
			return nil, false
		}
		add(current)
		add(path.Clean(current))
		slash := strings.ReplaceAll(current, "\\", "/")
		add(slash)
		add(path.Clean(slash))
		decoded, err := url.PathUnescape(current)
		if err != nil {
			return nil, false
		}
		if decoded == current {
			return out, true
		}
		current = decoded
	}
	return nil, false
}
