package server

import (
	"net/http"
	"strings"
)

func (s *Server) reconcileTargetRequests(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		RequestIDs             []int64 `json:"request_ids"`
		Reason                 string  `json:"reason"`
		ConfirmedRemoteStopped bool    `json:"confirmed_remote_stopped"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !req.ConfirmedRemoteStopped || strings.TrimSpace(req.Reason) == "" {
		writeErr(w, 400, "必须人工核对远端执行已停止，并填写原因；不能只依据本机 active=0")
		return
	}
	if s.m.interceptor == nil || !s.m.interceptor.TargetIOState(r.PathValue("id")).Stopped {
		writeErr(w, 409, "请先停止本任务目标访问并等待清理完成")
		return
	}
	if err := pg.ReconcileTargetRequests(r.Context(), r.PathValue("id"), req.RequestIDs, "ARTEX administrator", req.Reason); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
