package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/atomicio"
	"gamebond.local/nativeedge/lan"
	"gamebond.local/nativeedge/serveradmin"
)

// The server forwards a device's traffic only if its tunnel address is in the server's lan_tunnel_ips, so
// every address the client uses has to be on that list. These endpoints show which addresses the server is
// missing and add them through the server's admin portal. Writing the list does not apply it: the server has
// to restart, which drops every device for a few seconds, so that is a separate, explicit request.

const (
	serverAdminSecret = "server-admin.secret"
	syncMinInterval   = 3 * time.Second
)

type serverAdminConfig struct {
	URL        string `json:"url"`
	SecretFile string `json:"secret_file"`
	TLSSHA256  string `json:"tls_sha256"`
}

// serverSyncState is what the dashboard remembers about the server between requests.
type serverSyncState struct {
	mu            sync.Mutex
	checkedAt     time.Time
	serverIPs     []string
	lastErr       string
	restartNeeded bool // the list was written and the server has not been restarted since
	lastCall      time.Time
	apply         sync.Mutex // one change to the server at a time (held across the portal calls)
}

func adminSecretPath(configPath, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(filepath.Dir(configPath), name)
}

func (s *Server) serverAdmin(cfg map[string]any) (serverAdminConfig, *serveradmin.Client, error) {
	var sa serverAdminConfig
	if err := typedValue(cfg["server_admin"], &sa); err != nil || sa.URL == "" {
		return sa, nil, errors.New("the server admin portal is not set up")
	}
	raw, err := os.ReadFile(adminSecretPath(s.o.ConfigPath, sa.SecretFile))
	if err != nil {
		return sa, nil, errors.New("the server admin password is missing")
	}
	c, err := serveradmin.NewClient(sa.URL, strings.TrimSpace(string(raw)), sa.TLSSHA256)
	return sa, c, err
}

// wantedAddresses is every tunnel address the client uses: configured devices and adopted ones.
func (s *Server) wantedAddresses(cfg map[string]any) []lan.AccessEntry {
	var out []lan.AccessEntry
	var devices []struct {
		Name     string `json:"name"`
		TunnelIP string `json:"tunnel_ip"`
		MAC      string `json:"device_mac"`
	}
	_ = typedValue(cfg["lan_devices"], &devices)
	for _, d := range devices {
		if d.TunnelIP != "" {
			out = append(out, lan.AccessEntry{Name: d.Name, IP: d.TunnelIP, MAC: d.MAC})
		}
	}
	a := lan.LoadAccess(filepath.Join(filepath.Dir(s.o.StatusPath), "lan-access.json"))
	return append(out, a.Accepted...)
}

func missing(wanted []lan.AccessEntry, have []string) []lan.AccessEntry {
	set := map[string]bool{}
	for _, ip := range have {
		set[ip] = true
	}
	var out []lan.AccessEntry
	for _, w := range wanted {
		if !set[w.IP] {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func (s *Server) syncView(cfg map[string]any, sa serverAdminConfig, haveClient bool) map[string]any {
	wanted := s.wantedAddresses(cfg)
	st := &s.sync
	st.mu.Lock()
	defer st.mu.Unlock()
	view := map[string]any{"configured": haveClient, "url": sa.URL, "pin_set": sa.TLSSHA256 != "", "restart_needed": st.restartNeeded}
	compact := func(list []lan.AccessEntry) []map[string]string {
		out := make([]map[string]string, 0, len(list))
		for _, w := range list {
			out = append(out, map[string]string{"ip": w.IP, "name": w.Name, "mac": w.MAC})
		}
		return out
	}
	view["wanted"] = compact(wanted)
	if !st.checkedAt.IsZero() {
		view["server_ips"] = st.serverIPs
		view["checked_ago_s"] = time.Since(st.checkedAt).Seconds()
		view["missing"] = compact(missing(wanted, st.serverIPs))
	}
	if st.lastErr != "" {
		view["error"] = st.lastErr
	}
	return view
}

// serverSyncAPI: GET reports the state (with ?check=1 it asks the server first); POST adds the missing
// addresses and, only when {"restart": true}, restarts the server.
func (s *Server) serverSyncAPI(w http.ResponseWriter, r *http.Request) {
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	sa, client, cerr := s.serverAdmin(cfg)
	st := &s.sync
	switch r.Method {
	case http.MethodGet:
		if client != nil && r.URL.Query().Get("check") == "1" {
			st.mu.Lock()
			wait := time.Since(st.lastCall) < syncMinInterval
			st.lastCall = time.Now()
			st.mu.Unlock()
			if !wait {
				ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
				text, err := client.Config(ctx)
				cancel()
				st.mu.Lock()
				if err != nil {
					st.lastErr = err.Error()
				} else if ips, perr := serveradmin.TunnelIPs(text); perr != nil {
					st.lastErr = perr.Error()
				} else {
					st.serverIPs, st.checkedAt, st.lastErr = ips, time.Now(), ""
				}
				st.mu.Unlock()
			}
		}
		reply(w, 200, s.syncView(cfg, sa, client != nil))
	case http.MethodPost:
		if client == nil {
			reply(w, 422, map[string]any{"ok": false, "error": cerr.Error()})
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		var req struct {
			Restart bool `json:"restart"`
		}
		if len(raw) > 0 && json.Unmarshal(raw, &req) != nil {
			reply(w, 400, map[string]any{"error": "invalid request"})
			return
		}
		st.apply.Lock()
		defer st.apply.Unlock()
		ips := []string{}
		for _, w := range s.wantedAddresses(cfg) {
			ips = append(ips, w.IP)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		changed, err := client.EnsureTunnelIPs(ctx, ips)
		if err != nil {
			st.mu.Lock()
			st.lastErr = err.Error()
			st.mu.Unlock()
			reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		st.mu.Lock()
		st.lastErr = ""
		if changed {
			st.restartNeeded = true
		}
		restart := req.Restart && st.restartNeeded
		st.mu.Unlock()
		restarted := false
		if restart {
			if err := client.Restart(ctx); err != nil {
				reply(w, 422, map[string]any{"ok": false, "changed": changed, "error": "the list was updated but the restart failed: " + err.Error()})
				return
			}
			restarted = true
			st.mu.Lock()
			st.restartNeeded = false
			st.mu.Unlock()
		}
		// Re-read the list so the view is the server's own answer, not an assumption.
		if text, err := client.Config(ctx); err == nil {
			if have, perr := serveradmin.TunnelIPs(text); perr == nil {
				st.mu.Lock()
				st.serverIPs, st.checkedAt = have, time.Now()
				st.mu.Unlock()
			}
		}
		out := s.syncView(cfg, sa, true)
		out["ok"], out["changed"], out["restarted"] = true, changed, restarted
		reply(w, 200, out)
	default:
		reply(w, 405, map[string]any{"error": "GET or POST only"})
	}
}

// serverAdminAPI stores how to reach the server's admin portal. The password goes to a private file next to the
// configuration and is never sent back; the login is tried before anything is saved.
func (s *Server) serverAdminAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	var cur serverAdminConfig
	_ = typedValue(cfg["server_admin"], &cur)
	switch r.Method {
	case http.MethodGet:
		_, statErr := os.Stat(adminSecretPath(s.o.ConfigPath, cur.SecretFile))
		reply(w, 200, map[string]any{"url": cur.URL, "tls_sha256": cur.TLSSHA256, "password_saved": cur.SecretFile != "" && statErr == nil, "configured": cur.URL != "" && statErr == nil})
	case http.MethodPost:
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		var req struct {
			URL       string `json:"url"`
			Password  string `json:"password"`
			TLSSHA256 string `json:"tls_sha256"`
			Clear     bool   `json:"clear"`
		}
		if json.Unmarshal(raw, &req) != nil {
			reply(w, 400, map[string]any{"error": "invalid request"})
			return
		}
		if req.Clear {
			if cur.SecretFile != "" {
				_ = os.Remove(adminSecretPath(s.o.ConfigPath, cur.SecretFile))
			}
			delete(cfg, "server_admin")
			if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
				reply(w, 500, map[string]any{"error": err.Error()})
				return
			}
			reply(w, 200, map[string]any{"ok": true, "configured": false})
			return
		}
		password := req.Password
		if password == "" && cur.SecretFile != "" { // keep the saved password when only the address or pin changes
			if b, err := os.ReadFile(adminSecretPath(s.o.ConfigPath, cur.SecretFile)); err == nil {
				password = strings.TrimSpace(string(b))
			}
		}
		client, err := serveradmin.NewClient(strings.TrimSpace(req.URL), password, req.TLSSHA256)
		if err != nil {
			reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		if err := client.Login(ctx); err != nil {
			reply(w, 422, map[string]any{"ok": false, "error": "could not log in to the server: " + err.Error()})
			return
		}
		if err := atomicio.WriteFileAtomic(adminSecretPath(s.o.ConfigPath, serverAdminSecret), []byte(password+"\n"), 0o600); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		cfg["server_admin"] = serverAdminConfig{URL: client.BaseURL, SecretFile: serverAdminSecret, TLSSHA256: client.PinSHA256}
		if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.sync.mu.Lock()
		s.sync.checkedAt, s.sync.lastErr = time.Time{}, ""
		s.sync.mu.Unlock()
		reply(w, 200, map[string]any{"ok": true, "configured": true, "url": client.BaseURL})
	default:
		reply(w, 405, map[string]any{"error": "GET or POST only"})
	}
}
