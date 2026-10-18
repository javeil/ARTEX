package server

import (
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) targetPolicy(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id := r.PathValue("id")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 {
		writeErr(w, 400, "bad task id")
		return
	}
	task, err := pg.GetTask(n)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if task == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if r.Method == http.MethodPut {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		var p db.TargetPolicy
		if err := decode(r, &p); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := p.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := pg.SaveTargetPolicy(r.Context(), id, p); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if r.Method == http.MethodPut && s.m.interceptor != nil {
		s.m.interceptor.CancelTargetIO(id)
	}
	p, err := pg.LoadTargetPolicy(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	revision, err := pg.AuthorizationVersion(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"policy": p, "authorization_version": revision})
}

func (s *Server) bindConversationAuthorization(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	var req struct {
		TaskID *int64 `json:"task_id"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	if s.chatBusy[s.convBusyKey(c.ID)] {
		writeErr(w, 409, "请先停止当前对话，再修改授权任务")
		return
	}
	if req.TaskID != nil {
		task, err := pg.GetTask(*req.TaskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if task == nil {
			writeErr(w, 400, "授权任务不存在")
			return
		}
	}
	if err := pg.BindConversationTask(c.ID, req.TaskID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	c.TaskID = req.TaskID
	writeJSON(w, 200, c)
}
