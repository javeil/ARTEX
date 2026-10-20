package db

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
)

// UpgradeDefaultPromptHash upgrades only a byte-identical built-in version.
// Lock the agent row so the comparison and current-version switch are atomic.
func (d *DB) UpgradeDefaultPromptHash(agentID int64, oldHash, replacement string) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRow(`SELECT COALESCE(p.template_text,'') FROM agents a LEFT JOIN agent_prompts p ON p.id=a.current_prompt_id WHERE a.id=$1 FOR UPDATE OF a`, agentID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(current))) != oldHash || current == replacement {
		return false, nil
	}
	var version int
	var pid int64
	if err = tx.QueryRow(`SELECT COALESCE(max(version),0)+1 FROM agent_prompts WHERE agent_id=$1`, agentID).Scan(&version); err != nil {
		return false, err
	}
	if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,$2,$3,'升级内置停手与人工处理规则','system') RETURNING id`, agentID, version, replacement).Scan(&pid); err != nil {
		return false, err
	}
	if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$2 WHERE id=$1`, agentID, pid); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
