package server

import (
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func migrateTaskScopeDescription(pg *db.DB) error {
	_, err := pg.Exec(`UPDATE tools SET description=$1,updated_at=now() WHERE key='add_task_scope' AND system AND kind='builtin' AND description=$2`, agent.TaskScopeDiscoveryDescription, agent.LegacyTaskScopeDescription)
	return err
}
