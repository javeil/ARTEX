package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) targetControl(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reconcile") {
		s.reconcileTargetRequests(w, r)
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id := r.PathValue("id")
	n, e := strconv.ParseInt(id, 10, 64)
	if e != nil || n < 1 {
		writeErr(w, 400, "bad task id")
		return
	}
	task, e := pg.GetTask(n)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	if task == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			Reason string `json:"reason"`
		}
		if e := decode(r, &req); e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		if strings.TrimSpace(req.Reason) == "" {
			writeErr(w, 400, "恢复目标访问必须填写原因")
			return
		}
		if e := pg.CheckTaskExecution(r.Context(), id); e != nil {
			writeErr(w, 409, "请先恢复任务并确认授权时间窗口："+e.Error())
			return
		}
		if _, e := pg.Exec(`INSERT INTO target_control_events(task_id,actor,action,reason) VALUES ($1,'ARTEX administrator','resume',$2)`, id, req.Reason); e != nil {
			writeErr(w, 500, e.Error())
			return
		}
		s.m.interceptor.ResumeTargetIO(id)
	}
	state := s.m.interceptor.TargetIOState(id)
	reason, e := pg.TaskPauseReason(r.Context(), id)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"target_io": state, "task_paused": task.Paused, "pause_reason": reason})
}
func (s *Server) resetTargetSafety(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id := r.PathValue("id")
	var req struct {
		Target string `json:"target_url"`
		Reason string `json:"reason"`
	}
	if e := decode(r, &req); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeErr(w, 400, "重置目标冷却必须填写原因")
		return
	}
	target, e := db.ParseTarget(req.Target)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	scope, e := pg.TaskNetworkScope(r.Context(), id)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	if !db.NetworkScopeAllows(scope, target.Host) {
		writeErr(w, 400, "目标不在本任务授权范围")
		return
	}
	tx, e := pg.Begin()
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO target_control_events(task_id,actor,action,reason,target_key) VALUES ($1,'ARTEX administrator','reset_cooldown',$2,$3)`, id, req.Reason, target.ServiceKey()); e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	if _, e = tx.Exec(`UPDATE target_safety_state SET blocked_until=NULL,consecutive_failures=0,reason='' WHERE target_key=$1`, target.ServiceKey()); e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	if e = tx.Commit(); e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
