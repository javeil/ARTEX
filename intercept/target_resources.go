package intercept

import (
	"context"
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"net/http"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func (i *Interceptor) ownedOperation(ctx context.Context, o Operation) Operation {
	if o.Method != "DELETE" && o.Method != "PUT" && o.Method != "PATCH" {
		return o
	}
	r, err := i.db.OwnedTargetResource(ctx, TaskIDFromContext(ctx), o.Target.URL)
	if err != nil || r == nil {
		return o
	}
	p, e := i.db.LoadTargetPolicy(ctx, TaskIDFromContext(ctx))
	if e != nil {
		return o
	}
	var creationURL string
	if e = i.db.QueryRowContext(ctx, `SELECT url FROM target_requests WHERE id=$1 AND task_id=$2`, r.CreationRequestID, TaskIDFromContext(ctx)).Scan(&creationURL); e != nil {
		return o
	}
	createdTarget, e := db.ParseTarget(creationURL)
	if e != nil {
		return o
	}
	allowed := false
	for _, rule := range p.Operations {
		if rule.Effect == "artifact_create" && rule.CleanupIfMatch && rule.Target.Matches(createdTarget) {
			for _, method := range rule.Methods {
				allowed = allowed || method == "POST"
			}
		}
	}
	if !allowed {
		return o
	}
	o.ResourceETag = r.ETag
	if o.Method == "DELETE" {
		o.Effect = "artifact_cleanup"
	} else {
		o.Effect = "artifact_update"
	}
	return o
}
func (i *Interceptor) isOwnedCleanupCall(ctx context.Context, tool string, input []byte) bool {
	if tool == "Bash" {
		command := shellCommand(input)
		tree, e := syntax.NewParser().Parse(strings.NewReader(command), "cleanup")
		if e != nil || len(tree.Stmts) != 1 {
			return false
		}
		stmt := tree.Stmts[0]
		if stmt.Background || stmt.Negated || len(stmt.Redirs) > 0 {
			return false
		}
		c, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(c.Assigns) > 0 || len(c.Args) == 0 {
			return false
		}
		name, ok := operationWord(c.Args[0])
		if !ok || (filepath.Base(name) != "curl" && filepath.Base(name) != "wget") {
			return false
		}
	} else if tool != "WebFetch" && tool != "TargetRequest" {
		return false
	}
	ops := DescribeOperations(tool, input)
	if len(ops) != 1 {
		return false
	}
	o := i.ownedOperation(ctx, ops[0])
	return o.Effect == "artifact_cleanup" || o.Effect == "artifact_update"
}
func (i *Interceptor) observeTargetResource(ctx context.Context, o Operation, requestID int64, response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil
	}
	if o.Effect == "artifact_create" && o.Method == "POST" && response.StatusCode == 201 {
		if location := response.Header.Get("Location"); location != "" {
			u, e := response.Location()
			if e != nil {
				return e
			}
			if e = i.CheckTarget(ctx, u.String()); e != nil {
				return e
			}
			p, e := i.db.LoadTargetPolicy(ctx, TaskIDFromContext(ctx))
			if e != nil {
				return e
			}
			conditional := false
			for _, r := range p.Operations {
				if r.Effect == "artifact_create" && r.Target.Matches(o.Target) && r.CleanupIfMatch {
					conditional = true
				}
			}
			return i.db.RegisterTargetResource(ctx, TaskIDFromContext(ctx), requestID, u.String(), response.Header.Get("ETag"), conditional)
		}
	}
	if o.ResourceETag != "" {
		return i.db.FinishTargetResource(ctx, TaskIDFromContext(ctx), o.Target.URL, o.Method, response.Header.Get("ETag"))
	}
	return nil
}

func shellCommand(input []byte) string {
	var in struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(input, &in)
	return in.Command
}
