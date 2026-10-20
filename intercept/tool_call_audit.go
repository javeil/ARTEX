package intercept

import (
	"context"
	"github.com/Autumn-27/artex/db"
)

func (i *Interceptor) SaveToolCallAudit(ctx context.Context, a *db.ToolCallAudit) error {
	if a.ID == 0 && a.TaskID != "" {
		// Bind once: resolving an old ask must not relabel it with newer grants.
		version, err := i.db.AuthorizationVersion(ctx, a.TaskID)
		if err == nil {
			a.AuthorizationVersion = version
		}
	}
	if err := i.db.SaveToolCallAudit(ctx, a); err != nil {
		return err
	}
	if a.EffectiveAction == "deny" {
		i.observeProgress(ctx, a.TaskID)
	}
	return nil
}
