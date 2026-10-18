package intercept

import (
	"context"
	"github.com/Autumn-27/artex/db"
)

func (i *Interceptor) SaveToolCallAudit(ctx context.Context, a *db.ToolCallAudit) error {
	return i.db.SaveToolCallAudit(ctx, a)
}
