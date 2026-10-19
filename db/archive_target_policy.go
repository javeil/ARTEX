package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// Package-owned authorization is restored with the graph. Every restore needs
// an explicit operator confirmation; an old package cannot silently turn into a
// broader default policy just because its schema predates these tables.
func restoreArchiveTargetPolicy(tx *sql.Tx, taskID int64, tables map[string]json.RawMessage) error {
	rows, err := decodeArchiveRows(tables["task_target_policies"])
	if err != nil {
		return err
	}
	if len(rows) > 1 {
		return fmt.Errorf("archive has multiple task target policies")
	}
	policy := TargetPolicy{}
	if len(rows) == 1 {
		raw, err := json.Marshal(rows[0]["policy"])
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &policy); err != nil {
			return err
		}
	} else {
		var raw []byte
		if err := tx.QueryRow(`SELECT policy FROM task_target_policies WHERE task_id=$1`, taskID).Scan(&raw); err == nil {
			if err = json.Unmarshal(raw, &policy); err != nil {
				return err
			}
		} else if err != sql.ErrNoRows {
			return err
		}
	}
	policy.RestoreReviewRequired = true
	if err = policy.Validate(); err != nil {
		return err
	}
	if policy.Mode == "" {
		policy.Mode = "standard"
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO task_target_policies(task_id,policy) VALUES($1,$2::jsonb) ON CONFLICT(task_id) DO UPDATE SET policy=excluded.policy,revision=task_target_policies.revision+1,updated_at=now()`, taskID, raw); err != nil {
		return err
	}
	rules, err := decodeArchiveRows(tables["task_intercept_rules"])
	if err != nil {
		return err
	}
	for _, row := range rules {
		bytes, err := json.Marshal(row)
		if err != nil {
			return err
		}
		var rule AssetInterceptRule
		if err = json.Unmarshal(bytes, &rule); err != nil {
			return err
		}
		if rule.Action != "block" && rule.Action != "allow" {
			return fmt.Errorf("invalid archived asset-rule action")
		}
		// Fresh IDs avoid silently losing an exclusion to another task's ID collision.
		if _, err = tx.Exec(`INSERT INTO task_intercept_rules(task_id,enabled,action,kind,pattern,note)
 SELECT $1,$2,$3,$4,$5,$6 WHERE NOT EXISTS(SELECT 1 FROM task_intercept_rules WHERE task_id=$1 AND action=$3 AND kind=$4 AND pattern=$5)`, taskID, rule.Enabled, rule.Action, rule.Kind, rule.Pattern, rule.Note); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO target_control_events(task_id,actor,action,reason) VALUES($1,'ARTEX system','archive_restore','Task authorization restored; operator confirmation required')`, fmt.Sprint(taskID))
	return err
}
