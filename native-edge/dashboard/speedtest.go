package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"gamebond.local/nativeedge/atomicio"
)

// The speed test runs inside the client's network helper so that it crosses the bonded tunnel and uses every link
// at once. The dashboard only asks: it writes speedtest-request.json next to the status file, the running client
// picks it up within a second, and progress and the result come back in the status document ("speedtest").

var speedRequest struct {
	mu   sync.Mutex
	last time.Time
}

func (s *Server) speedtestAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, 405, map[string]any{"error": "POST only"})
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 512))
	var req struct {
		Action string `json:"action"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &req) != nil {
		reply(w, 400, map[string]any{"error": "invalid request"})
		return
	}
	if req.Action == "" {
		req.Action = "start"
	}
	doc := ReadStatus(s.o.StatusPath, nil)
	path := filepath.Join(filepath.Dir(s.o.StatusPath), "speedtest-request.json")
	speedRequest.mu.Lock()
	defer speedRequest.mu.Unlock()
	if time.Since(speedRequest.last) < 2*time.Second {
		reply(w, 429, map[string]any{"error": "wait a moment before asking again"})
		return
	}
	switch req.Action {
	case "start":
		if doc["state"] != "running" {
			reply(w, 409, map[string]any{"error": "connect first: the speed test measures the tunnel"})
			return
		}
		if st, _ := doc["speedtest"].(map[string]any); st != nil && st["running"] == true {
			reply(w, 409, map[string]any{"error": "a speed test is already running"})
			return
		}
		id := make([]byte, 6)
		if _, err := rand.Read(id); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		body, _ := json.Marshal(map[string]any{"action": "start", "id": hex.EncodeToString(id)})
		if err := atomicio.WriteFileAtomic(path, body, 0o600); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		speedRequest.last = time.Now()
		reply(w, 202, map[string]any{"ok": true, "id": hex.EncodeToString(id)})
	case "cancel":
		if err := atomicio.WriteFileAtomic(path, []byte(`{"action":"cancel"}`), 0o600); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		speedRequest.last = time.Now()
		reply(w, 202, map[string]any{"ok": true})
	default:
		reply(w, 400, map[string]any{"error": "action must be start or cancel"})
	}
}
