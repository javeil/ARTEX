package server

import (
	"net/http"
	"strconv"
)

func (s *Server) targetRequests(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id := r.PathValue("id")
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		writeErr(w, 400, "bad task id")
		return
	}
	before, err := strconv.ParseInt(defaultQuery(r, "before_id", "0"), 10, 64)
	if err != nil || before < 0 {
		writeErr(w, 400, "bad before_id")
		return
	}
	limit, err := strconv.Atoi(defaultQuery(r, "limit", "100"))
	if err != nil || limit < 1 || limit > 500 {
		writeErr(w, 400, "limit 必须在 1..500")
		return
	}
	rows, err := pg.ListTargetRequests(r.Context(), id, before, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var next int64
	if len(rows) == limit {
		next = rows[len(rows)-1].ID
	}
	writeJSON(w, 200, map[string]any{"requests": rows, "next_before_id": next})
}

func (s *Server) targetResources(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rows, err := pg.ListTargetResources(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"resources": rows})
}
