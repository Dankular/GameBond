package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"gamebond.local/nativeedge/atomicio"
	"gamebond.local/nativeedge/lan"
	"gamebond.local/nativeedge/omr"
)

type OMRLogin func(settings *omr.Settings, password string) (tunnelIP string, err error)

func typedValue(value any, into any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (s *Server) lanDevices(w http.ResponseWriter, r *http.Request) {
	s.configSectionWithConfig(w, r, func(cfg map[string]any) map[string]any {
		devices := cfg["lan_devices"]
		if devices == nil {
			devices = []any{}
		}
		discover := s.o.Adapters
		if discover == nil {
			discover = discoverAdapters
		}
		rows, err := discover()
		out := map[string]any{"lan_devices": devices, "client_tunnel_ip": cfg["client_tunnel_ip"], "interface_indices": cfg["interface_indices"], "interface_ids": cfg["interface_ids"], "adapters": rows}
		if err != nil {
			out["adapter_error"] = err.Error()
		}
		var ids []string
		var indices []int
		_ = typedValue(cfg["interface_ids"], &ids)
		_ = typedValue(cfg["interface_indices"], &indices)
		discoverUSB := s.o.USBNetworkDevices
		if discoverUSB == nil {
			discoverUSB = discoverUSBNetworkDevices
		}
		hardware, usbErr := discoverUSB()
		out["ps5_adapters"] = ps5Adapters(rows, hardware, ids, indices)
		if usbErr != nil {
			out["ps5_adapter_error"] = "USB device identification failed; refresh adapters to retry."
		}
		return out
	}, func(cfg map[string]any, raw []byte) (map[string]any, error) {
		var list []any
		if json.Unmarshal(raw, &list) != nil || list == nil {
			return nil, errors.New("LAN devices must be a list")
		}
		if err := validateLANConfig(raw, cfg); err != nil {
			return nil, err
		}
		return map[string]any{"lan_devices": list}, nil
	})
}

func validateLANConfig(raw []byte, cfg map[string]any) error {
	clientIP, _ := cfg["client_tunnel_ip"].(string)
	if clientIP == "" {
		clientIP = "10.77.0.2"
	}
	client, err := netip.ParseAddr(clientIP)
	if err != nil || !client.Is4() {
		return errors.New("invalid client tunnel address")
	}
	var ids []string
	var indices []int
	if typedValue(cfg["interface_ids"], &ids) != nil || typedValue(cfg["interface_indices"], &indices) != nil {
		return errors.New("invalid selected adapter configuration")
	}
	devices, err := lan.LoadDevices(raw, client, ids, indices)
	if err != nil {
		return err
	}
	for _, device := range devices {
		for _, index := range indices {
			if device.InterfaceIndex != 0 && device.InterfaceIndex == index {
				return errors.New("LAN gateway adapter is already selected as a VPN uplink")
			}
		}
	}
	return nil
}

func object(raw []byte) (map[string]any, error) {
	if !json.Valid(raw) {
		return nil, errors.New("invalid JSON object")
	}
	m, err := omr.ParseConfig(raw)
	if err != nil || m == nil {
		return nil, errors.New("request must be an object")
	}
	return m, nil
}

func privatePassword(password string) (string, error) {
	password = strings.TrimSpace(password)
	if password == "" || utf8.RuneCountInString(password) > 512 || strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("enter an admin password on one line (at most 512 characters)")
	}
	return password, nil
}

func (s *Server) prepareOMR(raw []byte) (map[string]any, *omr.Settings, string, error) {
	m, err := object(raw)
	if err != nil {
		return nil, nil, "", err
	}
	for key := range m {
		if key != "server_type" && key != "omr" && key != "password" {
			return nil, nil, "", errors.New("unknown OMR settings field: " + key)
		}
	}
	mode, ok := m["server_type"].(string)
	if !ok {
		return nil, nil, "", errors.New("choose a server mode")
	}
	password := ""
	if value, has := m["password"]; has {
		var ok bool
		password, ok = value.(string)
		if !ok {
			return nil, nil, "", errors.New("password must be text")
		}
	}
	if password != "" {
		password, err = privatePassword(password)
		if err != nil {
			return nil, nil, "", err
		}
		block, _ := m["omr"].(map[string]any)
		admin, _ := block["admin"].(map[string]any)
		if mode != "both" || admin == nil {
			return nil, nil, "", errors.New("admin password requires OMR admin login mode")
		}
		if s.o.RootPath == "" {
			return nil, nil, "", errors.New("private password directory is not configured")
		}
		admin["password_file"] = filepath.Join("secrets", "omr-admin.pass")
	}
	validation := map[string]any{"role": "client", "server_type": mode, "omr": m["omr"]}
	if mode == "gamebond" {
		validation["omr"] = nil
	}
	_, settings, err := omr.LoadServerMode(validation)
	return m, settings, password, err
}

func (s *Server) omrConfig(w http.ResponseWriter, r *http.Request) {
	s.configSectionWithConfig(w, r, func(cfg map[string]any) map[string]any {
		mode := cfg["server_type"]
		if mode == nil {
			mode = "gamebond"
		}
		return map[string]any{"server_type": mode, "omr": cfg["omr"], "omr_draft": cfg["omr_draft"]}
	}, func(cfg map[string]any, raw []byte) (map[string]any, error) {
		m, _, password, err := s.prepareOMR(raw)
		if err != nil {
			return nil, err
		}
		if m["server_type"] == "gamebond" {
			draft := cfg["omr"]
			if draft == nil {
				draft = cfg["omr_draft"]
			}
			if v, ok := m["omr"]; ok && v != nil {
				draft = v
			}
			if draft != nil {
				if _, ok := draft.(map[string]any); !ok {
					return nil, errors.New("OMR draft must be an object")
				}
			}
			return map[string]any{"server_type": "gamebond", "omr": deleteSetting{}, "omr_draft": draft}, nil
		}
		if password != "" {
			path := filepath.Join(s.o.RootPath, "secrets", "omr-admin.pass")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return nil, err
			}
			if err := atomicio.WriteFileAtomic(path, []byte(password+"\n"), 0600); err != nil {
				return nil, err
			}
		}
		return map[string]any{"server_type": "both", "omr": m["omr"], "omr_draft": deleteSetting{}}, nil
	})
}

func (s *Server) omrCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, 405, map[string]any{"error": "POST only"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		reply(w, 400, map[string]any{"error": "invalid request body"})
		return
	}
	var request struct {
		Action   string          `json:"action"`
		Host     string          `json:"host"`
		Port     int             `json:"port"`
		Settings json.RawMessage `json:"settings"`
	}
	if json.Unmarshal(raw, &request) != nil {
		reply(w, 422, map[string]any{"error": "invalid OMR check request"})
		return
	}
	if request.Action == "pin" {
		if strings.TrimSpace(request.Host) == "" || len(request.Host) > 512 || request.Port < 1 || request.Port > 65535 {
			reply(w, 422, map[string]any{"error": "enter an admin host and port"})
			return
		}
		pin, err := omr.LearnPin(request.Host, request.Port, 5*time.Second)
		if err != nil {
			reply(w, 502, map[string]any{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]any{"pin": pin})
		return
	}
	if request.Action != "test" {
		reply(w, 422, map[string]any{"error": "action must be pin or test"})
		return
	}
	_, settings, password, err := s.prepareOMR(request.Settings)
	if err != nil || settings == nil || settings.Admin == nil {
		message := "choose admin login mode"
		if err != nil {
			message = err.Error()
		}
		reply(w, 422, map[string]any{"error": message})
		return
	}
	a := settings.Admin
	if password == "" {
		path := a.PasswordFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(s.o.RootPath, path)
		}
		raw, readErr := atomicio.ReadBytesShared(path, 2048)
		if readErr != nil {
			reply(w, 422, map[string]any{"error": "could not read the saved OMR password file"})
			return
		}
		password, err = privatePassword(string(raw))
		if err != nil {
			reply(w, 422, map[string]any{"error": err.Error()})
			return
		}
	}
	if s.o.OMRLogin != nil {
		tunnelIP, err := s.o.OMRLogin(settings, password)
		if err != nil {
			reply(w, 502, map[string]any{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]any{"ok": true, "tunnel_ip": tunnelIP})
		return
	}
	admin, err := omr.NewAdminClient(a.Host, a.Port, a.Pin, 5*time.Second)
	if err == nil {
		err = admin.Login(a.Username, password)
	}
	var tunnel omr.Tunnel
	if err == nil {
		var config map[string]any
		config, err = admin.GetConfig()
		if err == nil {
			tunnel, err = omr.TunnelSettings(config)
		}
	}
	if err != nil {
		reply(w, 502, map[string]any{"error": err.Error()})
		return
	}
	// Never return the fetched key or login token to the renderer.
	reply(w, 200, map[string]any{"ok": true, "tunnel_ip": tunnel.TunnelIP})
}
