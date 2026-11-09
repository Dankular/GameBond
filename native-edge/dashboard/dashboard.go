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
	// Control runs "stop" or "restart" against the daemon's supervisor relay.
	Control func(command string) (map[string]any, error)
	// Hardware returns the resource sample (hwmon); nil hides the panel.
	Hardware func() map[string]any
	// Log returns the most recent daemon log lines; nil hides the panel.
	Log func() []string
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
	mux.HandleFunc("/api/status", s.guard(s.status))
	mux.HandleFunc("/api/control", s.guard(s.control))
	mux.HandleFunc("/api/links", s.guard(s.links))
	mux.HandleFunc("/api/apps", s.guard(s.apps))
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
	var doc map[string]any
	if err := atomicio.ReadJSONShared(s.o.StatusPath, 4<<20, &doc); err != nil {
		reply(w, 200, map[string]any{"state": "unavailable", "error": err.Error()})
		return
	}
	reply(w, 200, doc)
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

var knownFields = map[string]bool{"role": true, "upload_mbps": true, "download_mbps": true, "daily_bytes": true, "monthly_bytes": true, "reset_day": true, "overlimit": true, "overlimit_mbps": true}

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
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(value, &fields); err != nil || fields == nil {
			return errors.New("link " + key + ": policy must be an object")
		}
		for name := range fields {
			if !knownFields[name] { // Python's LinkPolicy(**raw) rejects unknown keys; Policy.UnmarshalJSON ignores them
				return errors.New("link " + key + ": unknown field " + name)
			}
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
	if err := atomicio.ReadJSONShared(path, 1<<20, &cfg); err != nil {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := map[string]any{key: cfg[key]}
		if extra != nil {
			for k, v := range extra(cfg) {
				out[k] = v
			}
		}
		reply(w, 200, out)
	case http.MethodPut:
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			reply(w, 400, map[string]any{"error": "invalid request body"})
			return
		}
		value, err := validate(raw)
		if err != nil {
			reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		cfg[key] = value
		if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]any{"ok": true, "restart_required": true})
	default:
		reply(w, 405, map[string]any{"error": "GET or PUT only"})
	}
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

// networks lists the machine's usable IPv4 adapters beside the configured
// selection. Changing the selection needs gateway discovery, which was not
// ported, so it is read-only here.
func (s *Server) networks(w http.ResponseWriter, r *http.Request) {
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	adapters := []map[string]any{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if ip, _, err := net.ParseCIDR(a.String()); err == nil && ip.To4() != nil {
					adapters = append(adapters, map[string]any{"index": i.Index, "name": i.Name, "address": ip.String()})
				}
			}
		}
	}
	reply(w, 200, map[string]any{"adapters": adapters, "bind": cfg["bind"], "interface_indices": cfg["interface_indices"], "interface_names": cfg["interface_names"], "gateways": cfg["gateways"]})
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
