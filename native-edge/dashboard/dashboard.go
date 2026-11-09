// Package dashboard is the local control page the tray's "Show GameBond" opens:
// live status of the Go client daemon, connect/disconnect through its relay, and
// editing of the per-link roles and limits. It listens on loopback only and every
// request needs the random token the tray puts in the URL.
package dashboard

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/apppolicy"
	"gamebond.local/nativeedge/atomicio"
	"gamebond.local/nativeedge/capture"
	"gamebond.local/nativeedge/dns"
	"gamebond.local/nativeedge/linkpolicy"
)

//go:embed index.html
var indexHTML []byte

const maxBody = 64 << 10

// Options wires the dashboard to the daemon.
type Options struct {
	StatusPath string
	ConfigPath string
	AssetsPath string // original desktop fonts, icons and themes
	// Snapshot supplies a shared live view including supervisor lifecycle state.
	Snapshot func() map[string]any
	// Control runs "stop" or "restart" against the daemon's supervisor relay.
	Control func(command string) (map[string]any, error)
	// Hardware returns the resource sample (hwmon); nil hides the panel.
	Hardware func() map[string]any
	// Log returns the most recent daemon log lines; nil hides the panel.
	Log func() []string
	// Adapters overrides read-only OS discovery (for tests).
	Adapters func() ([]Adapter, error)
}

// Server is a running dashboard.
type Server struct {
	o     Options
	token string
	l     net.Listener
	srv   *http.Server
	mu    sync.Mutex // serialises config edits
}

// Start listens on 127.0.0.1 (random port) and returns the URL to open.
func Start(o Options) (*Server, string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	s := &Server{o: o, token: hex.EncodeToString(raw), l: l}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/widget", s.widgetPage)
	mux.HandleFunc("/api/widget-asset", s.guard(s.widgetAsset))
	mux.HandleFunc("/api/status", s.guard(s.status))
	mux.HandleFunc("/api/control", s.guard(s.control))
	mux.HandleFunc("/api/links", s.guard(s.links))
	mux.HandleFunc("/api/apps", s.guard(s.apps))
	mux.HandleFunc("/api/app-policy", s.guard(s.appPolicy))
	mux.HandleFunc("/api/dns", s.guard(s.dnsConfig))
	mux.HandleFunc("/api/networks", s.guard(s.networks))
	mux.HandleFunc("/api/hardware", s.guard(s.hardware))
	mux.HandleFunc("/api/log", s.guard(s.logLines))
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 190 * time.Second}
	go s.srv.Serve(l)
	return s, "http://" + l.Addr().String() + "/?t=" + s.token, nil
}

func (s *Server) Close() { s.srv.Close() }

func (s *Server) authorised(r *http.Request) bool {
	got := r.Header.Get("X-Token")
	if got == "" {
		got = r.URL.Query().Get("t")
	}
	// A page on another origin cannot read the token, and the Host check stops
	// DNS-rebinding pages from using a loopback listener.
	host, _, _ := net.SplitHostPort(r.Host)
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1 && (host == "127.0.0.1" || host == "localhost")
}

func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorised(r) {
			reply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		h(w, r)
	}
}

func reply(w http.ResponseWriter, code int, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(body)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || !s.authorised(r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Write(bytes.ReplaceAll(indexHTML, []byte("__TOKEN__"), []byte(s.token)))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if s.o.Snapshot != nil {
		reply(w, 200, s.o.Snapshot())
		return
	}
	reply(w, 200, ReadStatus(s.o.StatusPath, nil))
}

// ReadStatus combines metrics with authoritative supervisor lifecycle state.
// A stopped supervisor overrides the last metrics file left by its child.
func ReadStatus(path string, lifecycle func() (map[string]any, error)) map[string]any {
	var doc map[string]any
	if err := atomicio.ReadJSONShared(path, 4<<20, &doc); err != nil || doc == nil {
		doc = map[string]any{"state": "unavailable"}
	}
	if at, ok := doc["updated_at"].(float64); ok && time.Since(time.Unix(int64(at), 0)) > 15*time.Second {
		doc["state"], doc["transport"] = "unavailable", nil
	}
	if lifecycle != nil {
		state, err := lifecycle()
		if err != nil {
			doc["state"], doc["error"] = "unavailable", err.Error()
		} else if value, ok := state["state"].(string); ok {
			doc["state"] = value
		}
	}
	if doc["state"] != "running" {
		doc["transport"] = nil
	}
	return doc
}

func (s *Server) control(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&body); err != nil || (body.Command != "stop" && body.Command != "restart") {
		reply(w, 400, map[string]any{"error": "command must be stop or restart"})
		return
	}
	if s.o.Control == nil {
		reply(w, 503, map[string]any{"error": "no daemon control configured"})
		return
	}
	res, err := s.o.Control(body.Command)
	if err != nil {
		reply(w, 502, map[string]any{"error": err.Error()})
		return
	}
	reply(w, 200, res)
}

// links reads or replaces the client config's link_policies (roles and limits).
func (s *Server) links(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		reply(w, 200, map[string]any{"link_policies": cfg["link_policies"], "bind": cfg["bind"], "interface_names": cfg["interface_names"], "interface_indices": cfg["interface_indices"], "roles": linkpolicy.Roles})
	case http.MethodPut:
		var raw json.RawMessage
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&raw); err != nil {
			reply(w, 400, map[string]any{"error": "invalid request body"})
			return
		}
		if err := ValidatePolicies(raw); err != nil {
			reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		var policies any
		_ = json.Unmarshal(raw, &policies)
		cfg["link_policies"] = policies
		if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]any{"ok": true, "restart_required": true})
	default:
		reply(w, 405, map[string]any{"error": "GET or PUT only"})
	}
}

// ValidatePolicies applies the daemon's own rules: an object keyed by interface
// index, every value a valid linkpolicy.Policy with no unknown fields.
func ValidatePolicies(raw []byte) error {
	var byKey map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byKey); err != nil || byKey == nil {
		return errors.New("link_policies must be an object keyed by interface index")
	}
	for key, value := range byKey {
		if key == "" || strings.TrimSpace(key) != key {
			return errors.New("invalid link key")
		}
		var p linkpolicy.Policy
		if err := json.Unmarshal(value, &p); err != nil {
			return errors.New("link " + key + ": " + err.Error())
		}
		if err := p.Validate(); err != nil {
			return errors.New("link " + key + ": " + err.Error())
		}
	}
	return nil
}

func readConfig(path string) (map[string]any, error) {
	var cfg map[string]any
	if err := atomicio.ReadJSONShared(path, apppolicy.MaxConfigBytes, &cfg); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("configuration is not a JSON object")
	}
	return cfg, nil
}

// writeConfig keeps the previous file as <path>.previous, then replaces atomically.
func writeConfig(path string, cfg map[string]any) error {
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if len(out) > apppolicy.MaxConfigBytes {
		return errors.New("configuration exceeds its size limit")
	}
	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".previous", old, 0o600); err != nil {
			return err
		}
	}
	return atomicio.WriteFileAtomic(path, out, 0o600)
}

// section reads or replaces one top-level key of the client config. validate
// gets the request body and returns the value to store.
func (s *Server) section(w http.ResponseWriter, r *http.Request, key string, validate func(raw []byte) (any, error), extra func(cfg map[string]any) map[string]any) {
	s.configSection(w, r, func(cfg map[string]any) map[string]any {
		out := map[string]any{key: cfg[key]}
		if extra != nil {
			for k, v := range extra(cfg) {
				out[k] = v
			}
		}
		return out
	}, func(raw []byte) (map[string]any, error) {
		v, err := validate(raw)
		return map[string]any{key: v}, err
	})
}

// configSection atomically updates related top-level settings together.
func (s *Server) configSection(w http.ResponseWriter, r *http.Request, view func(map[string]any) map[string]any, validate func([]byte) (map[string]any, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		reply(w, 200, view(cfg))
	case http.MethodPut:
		raw, err := io.ReadAll(io.LimitReader(r.Body, apppolicy.MaxConfigBytes+1))
		if err != nil || len(raw) > apppolicy.MaxConfigBytes {
			reply(w, 400, map[string]any{"error": "invalid request body"})
			return
		}
		value, err := validate(raw)
		if err != nil {
			reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		for key, v := range value {
			cfg[key] = v
		}
		if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]any{"ok": true, "restart_required": true})
	default:
		reply(w, 405, map[string]any{"error": "GET or PUT only"})
	}
}

func policyConfig(p *apppolicy.Policy) map[string]any {
	return map[string]any{"protection_enabled": p.Enabled, "default_app_profile": p.DefaultProfile, "app_rules": p.Snapshot()["rules"]}
}

func (s *Server) appPolicy(w http.ResponseWriter, r *http.Request) {
	s.configSection(w, r, func(cfg map[string]any) map[string]any {
		// Defaults match the daemon; retain invalid stored values for correction.
		out := map[string]any{"protection_enabled": true, "default_app_profile": "automatic", "app_rules": map[string]any{}}
		for k := range out {
			if v, ok := cfg[k]; ok {
				out[k] = v
			}
		}
		return out
	}, func(raw []byte) (map[string]any, error) {
		var cfg map[string]any
		if err := json.Unmarshal(raw, &cfg); err != nil || cfg == nil {
			return nil, errors.New("application policy must be an object")
		}
		for k := range cfg {
			if k != "protection_enabled" && k != "default_app_profile" && k != "app_rules" {
				return nil, errors.New("unknown application policy field: " + k)
			}
		}
		p, err := apppolicy.New(cfg)
		if err != nil {
			return nil, err
		}
		return policyConfig(p), nil
	})
}

// apps edits the captured application list (cod_executables).
func (s *Server) apps(w http.ResponseWriter, r *http.Request) {
	s.section(w, r, "cod_executables", func(raw []byte) (any, error) {
		var list []any
		if err := json.Unmarshal(raw, &list); err != nil || list == nil {
			return nil, errors.New("applications must be a list of executable paths")
		}
		clean, err := capture.NormalizeApps(list)
		if err != nil {
			return nil, err
		}
		out := make([]any, len(clean))
		for i, c := range clean {
			out[i] = c
		}
		return out, nil
	}, nil)
}

// dnsConfig edits the project DNS profile, validated by the daemon's own loader.
func (s *Server) dnsConfig(w http.ResponseWriter, r *http.Request) {
	s.section(w, r, "dns", func(raw []byte) (any, error) {
		if _, err := dns.Load(raw); err != nil {
			return nil, err
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return v, nil
	}, nil)
}

// networks discovers adapters and saves their selection without changing the OS.
func (s *Server) networks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		reply(w, 405, map[string]any{"error": "GET or PUT only"})
		return
	}
	discover := s.o.Adapters
	if discover == nil {
		discover = discoverAdapters
	}
	adapters, err := discover()
	if err != nil {
		reply(w, 503, map[string]any{"error": err.Error()})
		return
	}
	s.configSection(w, r, func(cfg map[string]any) map[string]any {
		return map[string]any{"adapters": adapters, "bind": cfg["bind"], "interface_indices": cfg["interface_indices"], "interface_ids": cfg["interface_ids"], "interface_names": cfg["interface_names"], "gateways": cfg["gateways"]}
	}, func(raw []byte) (map[string]any, error) { return selectAdapters(raw, adapters) })
}

func (s *Server) hardware(w http.ResponseWriter, r *http.Request) {
	if s.o.Hardware == nil {
		reply(w, 200, map[string]any{"available": false})
		return
	}
	reply(w, 200, s.o.Hardware())
}

func (s *Server) logLines(w http.ResponseWriter, r *http.Request) {
	if s.o.Log == nil {
		reply(w, 200, map[string]any{"lines": []string{}})
		return
	}
	reply(w, 200, map[string]any{"lines": s.o.Log()})
}
