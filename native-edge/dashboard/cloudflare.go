package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/atomicio"
	"gamebond.local/nativeedge/dnssync"
)

// Reverse tunnel naming. The client can keep a DNS name pointed at whichever exit server it is using
// (reverse_dns in the client config, see cmd/client/reversedns.go). These endpoints set that up: the user pastes a
// Cloudflare API token, it is validated, and a new record is minted in one of the user's zones. The token goes to a
// private file next to the configuration and is never returned or logged.

const cloudflareSecret = "cloudflare.secret"

var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{1,38}[a-z0-9])$`)

type reverseDNSSettings struct {
	Name       string `json:"name"`
	SecretFile string `json:"secret_file"`
	Email      string `json:"email,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
}

var cloudflareMu sync.Mutex

func (s *Server) cloudflareClient(rd reverseDNSSettings) (*dnssync.Client, error) {
	if rd.SecretFile == "" {
		return nil, errors.New("no Cloudflare token saved")
	}
	raw, err := os.ReadFile(adminSecretPath(s.o.ConfigPath, rd.SecretFile))
	if err != nil {
		return nil, errors.New("the Cloudflare token file is missing")
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return nil, errors.New("the Cloudflare token file is empty")
	}
	auth := dnssync.Auth{Token: secret}
	if rd.Email != "" {
		auth = dnssync.Auth{Email: rd.Email, Key: secret}
	}
	return &dnssync.Client{API: s.cfAPI, Auth: auth}, nil
}

// exitIP is the address of the exit server the client is connected to, when it is connected.
func exitIP(doc map[string]any) string {
	if doc["state"] != "running" {
		return ""
	}
	peer, _ := doc["peer"].([]any)
	if len(peer) == 0 {
		return ""
	}
	ip, _ := peer[0].(string)
	if a := net.ParseIP(ip); a == nil || a.To4() == nil || a.IsLoopback() || a.IsUnspecified() {
		return ""
	}
	return ip
}

func (s *Server) cloudflareAPI(w http.ResponseWriter, r *http.Request) {
	cloudflareMu.Lock()
	defer cloudflareMu.Unlock()
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	var rd reverseDNSSettings
	_ = typedValue(cfg["reverse_dns"], &rd)
	_, statErr := os.Stat(adminSecretPath(s.o.ConfigPath, rd.SecretFile))
	tokenSaved := rd.SecretFile != "" && statErr == nil
	doc := ReadStatus(s.o.StatusPath, nil)
	switch r.Method {
	case http.MethodGet:
		suffix := make([]byte, 2)
		_, _ = rand.Read(suffix)
		view := map[string]any{"token_saved": tokenSaved, "name": rd.Name, "email": rd.Email, "active": tokenSaved && rd.Name != "",
			"suggested_label": "bond-" + hex.EncodeToString(suffix), "exit_ip": exitIP(doc), "status": doc["reverse_dns"]}
		reply(w, 200, view)
	case http.MethodPost:
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		var req struct {
			Action       string `json:"action"`
			Token        string `json:"token"`
			Email        string `json:"email"`
			Zone         string `json:"zone"`
			Label        string `json:"label"`
			DeleteRecord bool   `json:"delete_record"`
		}
		if json.Unmarshal(raw, &req) != nil {
			reply(w, 400, map[string]any{"error": "invalid request"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		switch req.Action {
		case "validate":
			token := strings.TrimSpace(req.Token)
			if token == "" {
				reply(w, 422, map[string]any{"ok": false, "error": "paste a Cloudflare API token"})
				return
			}
			auth := dnssync.Auth{Token: token}
			if e := strings.TrimSpace(req.Email); e != "" {
				auth = dnssync.Auth{Email: e, Key: token}
			}
			c := &dnssync.Client{API: s.cfAPI, Auth: auth}
			if err := c.Verify(ctx); err != nil {
				reply(w, 422, map[string]any{"ok": false, "error": "Cloudflare did not accept the token: " + err.Error()})
				return
			}
			zones, err := c.Zones(ctx)
			if err != nil {
				reply(w, 422, map[string]any{"ok": false, "error": "the token works but cannot list your domains (it needs Zone: Read): " + err.Error()})
				return
			}
			if len(zones) == 0 {
				reply(w, 422, map[string]any{"ok": false, "error": "the token works but no domain is available to it"})
				return
			}
			if err := atomicio.WriteFileAtomic(adminSecretPath(s.o.ConfigPath, cloudflareSecret), []byte(token+"\n"), 0o600); err != nil {
				reply(w, 500, map[string]any{"error": err.Error()})
				return
			}
			next := reverseDNSSettings{Name: rd.Name, SecretFile: cloudflareSecret, Email: strings.TrimSpace(req.Email), TTL: rd.TTL}
			cfg["reverse_dns"] = next
			if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
				reply(w, 500, map[string]any{"error": err.Error()})
				return
			}
			reply(w, 200, map[string]any{"ok": true, "zones": zones})
		case "zones":
			c, err := s.cloudflareClient(rd)
			if err != nil {
				reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			zones, err := c.Zones(ctx)
			if err != nil {
				reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			reply(w, 200, map[string]any{"ok": true, "zones": zones})
		case "mint":
			label := strings.ToLower(strings.TrimSpace(req.Label))
			if !labelPattern.MatchString(label) {
				reply(w, 422, map[string]any{"ok": false, "error": "use 3 to 40 lowercase letters, digits or hyphens, not starting or ending with a hyphen"})
				return
			}
			c, err := s.cloudflareClient(rd)
			if err != nil {
				reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			zones, err := c.Zones(ctx)
			if err != nil {
				reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			zone := ""
			for _, z := range zones {
				if strings.EqualFold(z.Name, strings.TrimSpace(req.Zone)) {
					zone = z.Name
				}
			}
			if zone == "" {
				reply(w, 422, map[string]any{"ok": false, "error": "that domain is not one of the domains the token can manage"})
				return
			}
			ip := exitIP(doc)
			if ip == "" {
				reply(w, 409, map[string]any{"ok": false, "error": "connect first: the record points at your exit server, whose address is known once the tunnel is up"})
				return
			}
			name := label + "." + zone
			if err := c.Create(ctx, name, ip, 60); err != nil {
				if errors.Is(err, dnssync.ErrExists) {
					reply(w, 409, map[string]any{"ok": false, "error": name + " already exists. Pick another name; nothing was changed."})
					return
				}
				reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			cfg["reverse_dns"] = reverseDNSSettings{Name: name, SecretFile: rd.SecretFile, Email: rd.Email, TTL: 60}
			if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
				reply(w, 500, map[string]any{"error": "the record was created but the setting could not be saved: " + err.Error()})
				return
			}
			reply(w, 200, map[string]any{"ok": true, "name": name, "address": ip, "reconnect_needed": true})
		case "remove":
			deleted := false
			var deleteErr string
			if req.DeleteRecord && rd.Name != "" {
				if c, err := s.cloudflareClient(rd); err == nil {
					if err := c.Delete(ctx, rd.Name); err != nil {
						deleteErr = err.Error()
					} else {
						deleted = true
					}
				}
			}
			if rd.SecretFile != "" {
				_ = os.Remove(adminSecretPath(s.o.ConfigPath, rd.SecretFile))
			}
			delete(cfg, "reverse_dns")
			if err := writeConfig(s.o.ConfigPath, cfg); err != nil {
				reply(w, 500, map[string]any{"error": err.Error()})
				return
			}
			out := map[string]any{"ok": true, "record_deleted": deleted}
			if deleteErr != "" {
				out["warning"] = "the token was removed but the record could not be deleted: " + deleteErr
			}
			reply(w, 200, out)
		default:
			reply(w, 400, map[string]any{"error": "unknown action"})
		}
	default:
		reply(w, 405, map[string]any{"error": "GET or POST only"})
	}
}
