// Package fakeportal is an in-memory stand-in for the server's admin portal, for tests. It follows the real
// portal's rules (see GameBond.Server/adminportal): a session cookie and CSRF token from /api/login, 401 without
// them, validation before a write, 202 for a restart.
package fakeportal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Portal follows the real portal's rules: a session cookie and CSRF token from /api/login, 401 without
// them, validation before writing, and 202 for a restart.
type Portal struct {
	mu        sync.Mutex
	Password  string
	Config    string
	token     string
	ExpireOne bool   // the next authenticated call answers 401 once
	Writes    int    // configurations written
	Restarts  int    // restarts requested
	RejectAs  string // when set, validation fails with this message
	Logins    int

	Security     map[string]any   // the settings last saved through /api/security
	SecurityFail string           // when set, saving security settings is refused with this message
	Actions      []map[string]any // security actions requested
}

// New returns a portal with a password and a starting configuration.
func New(password, config string) *Portal { return &Portal{Password: password, Config: config} }

// Lock and Unlock guard the exported fields while the handler is serving.
func (p *Portal) Lock()   { p.mu.Lock() }
func (p *Portal) Unlock() { p.mu.Unlock() }

func (p *Portal) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		reply := func(code int, v any) {
			b, _ := json.Marshal(v)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			w.Write(b)
		}
		body := map[string]any{}
		if r.Method == http.MethodPost {
			if r.Header.Get("Content-Length") == "" && r.ContentLength < 0 {
				reply(400, map[string]any{"error": "invalid request body"})
				return
			}
			raw, _ := io.ReadAll(r.Body)
			if json.Unmarshal(raw, &body) != nil {
				reply(400, map[string]any{"error": "invalid request body"})
				return
			}
		}
		if r.URL.Path == "/api/login" {
			if body["password"] != p.Password {
				reply(401, map[string]any{"error": "invalid password"})
				return
			}
			p.Logins++
			p.token = fmt.Sprintf("tok%d", p.Logins)
			w.Header().Add("Set-Cookie", "gb_session="+p.token+"; Path=/; Secure; HttpOnly; SameSite=Strict")
			reply(200, map[string]any{"ok": true, "csrf": "csrf" + p.token})
			return
		}
		c, err := r.Cookie("gb_session")
		if err != nil || c.Value != p.token || p.token == "" || p.ExpireOne {
			p.ExpireOne = false
			p.token = ""
			reply(401, map[string]any{"error": "login required"})
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("X-CSRF-Token") != "csrf"+p.token {
			reply(403, map[string]any{"error": "bad CSRF token"})
			return
		}
		switch r.URL.Path {
		case "/api/config":
			if r.Method == http.MethodGet {
				reply(200, map[string]any{"text": p.Config})
				return
			}
			if p.RejectAs != "" {
				reply(422, map[string]any{"ok": false, "error": p.RejectAs})
				return
			}
			p.Config = body["text"].(string)
			p.Writes++
			reply(200, map[string]any{"ok": true, "error": nil})
		case "/api/config/validate":
			if p.RejectAs != "" {
				reply(200, map[string]any{"ok": false, "error": p.RejectAs})
				return
			}
			reply(200, map[string]any{"ok": true, "error": nil})
		case "/api/security":
			if r.Method == http.MethodGet {
				reply(200, map[string]any{"settings": p.Security, "ids": map[string]any{"mode": "off"}})
				return
			}
			if p.SecurityFail != "" {
				reply(422, map[string]any{"ok": false, "error": p.SecurityFail})
				return
			}
			p.Security, _ = body["settings"].(map[string]any)
			reply(200, map[string]any{"ok": true, "error": nil})
		case "/api/security/catalog":
			reply(200, map[string]any{"categories": []any{map[string]any{"id": "ads"}}})
		case "/api/security/action":
			p.Actions = append(p.Actions, body)
			reply(200, map[string]any{"ok": true, "error": nil, "result": map[string]any{}})
		case "/api/restart":
			p.Restarts++
			reply(202, map[string]any{"ok": true})
		default:
			reply(404, map[string]any{"error": "not found"})
		}
	})
}
