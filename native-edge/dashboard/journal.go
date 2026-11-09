package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
)

func (s *Server) journalAPI(w http.ResponseWriter, r *http.Request) {
	if s.o.Journal == nil {
		reply(w, 503, map[string]any{"error": "event journal is not configured"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		reply(w, 200, s.o.Journal.Snapshot())
	case http.MethodPost:
		var request struct {
			Action string `json:"action"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(raw) > maxBody || json.Unmarshal(raw, &request) != nil || request.Action != "mark_read" {
			reply(w, 422, map[string]any{"error": "choose mark_read"})
			return
		}
		s.o.Journal.MarkRead()
		reply(w, 200, s.o.Journal.Snapshot())
	default:
		reply(w, 405, map[string]any{"error": "method not allowed"})
	}
}
