package intercept

import (
	"context"
	"path/filepath"
)

// TaskWorkspace derives the task root only from host-controlled run context, not
// tool arguments or shell variables. Runs use <data>/tasks/<id>/[i<intent>].
func TaskWorkspace(ctx context.Context) string {
	id := TaskIDFromContext(ctx)
	if id == "" || filepath.Base(id) != id {
		return ""
	}
	env, _ := ctx.Value(reviewContextKey{}).(reviewEnvironment)
	dir := filepath.Clean(env.workingDir)
	for filepath.IsAbs(dir) && dir != filepath.Dir(dir) {
		if filepath.Base(dir) == id && filepath.Base(filepath.Dir(dir)) == "tasks" {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return filepath.Join("/app/data/tasks", id)
}
