package server

func (s *Server) cancelTargetAuthorization(taskID string) {
	if s.m == nil || s.m.interceptor == nil {
		return
	}
	if taskID == "" {
		s.m.interceptor.CancelAllTargetIO()
	} else {
		s.m.interceptor.CancelTargetIO(taskID)
	}
}
