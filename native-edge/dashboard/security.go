package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"gamebond.local/nativeedge/serveradmin"
)

// The firewall, DNS filter and intrusion detection run on the server, so this page only relays: the dashboard logs
// in to the server's admin portal with the saved credentials and passes each request through. Nothing about the
// rules is kept here, and the server's own error text is returned unchanged.

const securityBody = 1 << 20

// securityClient returns a logged-in portal client, reusing it while the saved address, pin and password are the
// same (every login costs the server a password hash, and the page polls).
func (s *Server) securityClient() (*serveradmin.Client, error) {
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		return nil, err
	}
	sa, fresh, err := s.serverAdmin(cfg)
	if err != nil {
		return nil, err
	}
	key := sa.URL + "\x00" + sa.TLSSHA256 + "\x00" + fresh.Password
	s.secMu.Lock()
	defer s.secMu.Unlock()
	if s.secClient != nil && s.secKey == key {
		return s.secClient, nil
	}
	s.secClient, s.secKey = fresh, key
	return fresh, nil
}

// securityAPI relays /api/security, /api/security/catalog and /api/security/action.
func (s *Server) securityAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path != "/api/security" && path != "/api/security/catalog" && path != "/api/security/action" {
		reply(w, 404, map[string]any{"error": "not found"})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		reply(w, 405, map[string]any{"error": "GET or POST only"})
		return
	}
	client, err := s.securityClient()
	if err != nil {
		reply(w, 409, map[string]any{"error": err.Error() + ". Set it up under Settings, Server admin.", "unconfigured": true})
		return
	}
	var body any
	if r.Method == http.MethodPost {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, securityBody+1))
		if len(raw) > securityBody {
			reply(w, 413, map[string]any{"error": "request too large"})
			return
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil || m == nil {
			reply(w, 400, map[string]any{"error": "invalid request"})
			return
		}
		body = m
	}
	// Applying settings downloads country lists first, which can take a while.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	status, out, err := client.Security(ctx, r.Method, path, body)
	if err != nil {
		reply(w, 502, map[string]any{"error": "could not reach the server: " + err.Error()})
		return
	}
	if out == nil {
		out = map[string]any{}
	}
	reply(w, status, out)
}
