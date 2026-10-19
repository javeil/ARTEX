package server

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestScopeDescriptionMigrationPreservesAdministratorEdits(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PG required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	old, err := pg.GetTool("add_task_scope")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if old == nil {
			pg.Exec(`DELETE FROM tools WHERE key='add_task_scope'`)
		} else {
			agents, _ := json.Marshal(old.Agents)
			pg.Exec(`UPDATE tools SET description=$1,agents=$2::jsonb,enabled=$3 WHERE key='add_task_scope'`, old.Description, string(agents), old.Enabled)
		}
	}()
	pg.SeedTool("add_task_scope", agent.LegacyTaskScopeDescription, json.RawMessage(`{}`), json.RawMessage(`["planner"]`))
	if _, err = pg.Exec(`UPDATE tools SET description=$1,enabled=false,agents='["planner"]'::jsonb WHERE key='add_task_scope'`, agent.LegacyTaskScopeDescription); err != nil {
		t.Fatal(err)
	}
	if err = migrateTaskScopeDescription(pg); err != nil {
		t.Fatal(err)
	}
	row, _ := pg.GetTool("add_task_scope")
	if row.Description != agent.TaskScopeDiscoveryDescription || row.Enabled || len(row.Agents) != 1 || row.Agents[0] != "planner" {
		t.Fatalf("unexpected migration: %+v", row)
	}
	pg.Exec(`UPDATE tools SET description='administrator customized description' WHERE key='add_task_scope'`)
	if err = migrateTaskScopeDescription(pg); err != nil {
		t.Fatal(err)
	}
	row, _ = pg.GetTool("add_task_scope")
	if row.Description != "administrator customized description" {
		t.Fatal("custom description overwritten")
	}
}
