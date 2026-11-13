package serveradmin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakePortal follows the real portal's rules: a session cookie and CSRF token from /api/login, 401 without
// them, validation before writing, and 202 for a restart.
type fakePortal struct {
	mu        sync.Mutex
	password  string
	config    string
	token     string
	expireOne bool // the next authenticated call answers 401 once
	writes    int
	restarts  int
	rejectAs  string // when set, validation fails with this message
	logins    int
}

func (p *fakePortal) handler() http.Handler {
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
			if body["password"] != p.password {
				reply(401, map[string]any{"error": "invalid password"})
				return
			}
			p.logins++
			p.token = fmt.Sprintf("tok%d", p.logins)
			w.Header().Add("Set-Cookie", "gb_session="+p.token+"; Path=/; Secure; HttpOnly; SameSite=Strict")
			reply(200, map[string]any{"ok": true, "csrf": "csrf" + p.token})
			return
		}
		c, err := r.Cookie("gb_session")
		if err != nil || c.Value != p.token || p.token == "" || p.expireOne {
			p.expireOne = false
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
				reply(200, map[string]any{"text": p.config})
				return
			}
			if p.rejectAs != "" {
				reply(422, map[string]any{"ok": false, "error": p.rejectAs})
				return
			}
			p.config = body["text"].(string)
			p.writes++
			reply(200, map[string]any{"ok": true, "error": nil})
		case "/api/config/validate":
			if p.rejectAs != "" {
				reply(200, map[string]any{"ok": false, "error": p.rejectAs})
				return
			}
			reply(200, map[string]any{"ok": true, "error": nil})
		case "/api/restart":
			p.restarts++
			reply(202, map[string]any{"ok": true})
		default:
			reply(404, map[string]any{"error": "not found"})
		}
	})
}

const baseConfig = `{"role":"server","mtu":1280,"reorder_timeout_ms":30.5,"queues":{"5":{"priority":true}},"lan_tunnel_ips":["10.77.0.3"],"admin":{"enabled":true}}`

func start(t *testing.T) (*fakePortal, *httptest.Server, string) {
	p := &fakePortal{password: "correct horse battery", config: baseConfig}
	srv := httptest.NewTLSServer(p.handler())
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return p, srv, hex.EncodeToString(sum[:])
}

func TestEnsureTunnelIPsWritesValidatedMergedConfig(t *testing.T) {
	p, srv, pin := start(t)
	c, err := NewClient(srv.URL, p.password, pin)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := c.EnsureTunnelIPs(t.Context(), []string{"10.77.0.4", "10.77.0.3", "10.77.0.10"})
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	ips, _ := TunnelIPs(p.config)
	if strings.Join(ips, ",") != "10.77.0.3,10.77.0.4,10.77.0.10" {
		t.Fatalf("lan_tunnel_ips = %v", ips)
	}
	var doc map[string]json.RawMessage
	json.Unmarshal([]byte(p.config), &doc)
	compact := func(raw json.RawMessage) string {
		var buf bytes.Buffer
		if err := json.Compact(&buf, raw); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if string(doc["reorder_timeout_ms"]) != "30.5" || string(doc["mtu"]) != "1280" || compact(doc["queues"]) != `{"5":{"priority":true}}` || compact(doc["admin"]) != `{"enabled":true}` {
		t.Fatalf("other settings were not carried over: %s", p.config)
	}
	if p.restarts != 0 {
		t.Fatal("writing the configuration must not restart the server")
	}
	if changed, err := c.EnsureTunnelIPs(t.Context(), []string{"10.77.0.4"}); err != nil || changed || p.writes != 1 {
		t.Fatalf("a second identical request must write nothing: changed=%v err=%v writes=%d", changed, err, p.writes)
	}
}

func TestRestartIsExplicit(t *testing.T) {
	p, srv, pin := start(t)
	c, _ := NewClient(srv.URL, p.password, pin)
	if err := c.Restart(t.Context()); err != nil || p.restarts != 1 {
		t.Fatalf("restart: %v (%d)", err, p.restarts)
	}
}

func TestCertificatePin(t *testing.T) {
	p, srv, pin := start(t)
	wrong := strings.Repeat("ab", 32)
	c, _ := NewClient(srv.URL, p.password, wrong)
	if err := c.Login(t.Context()); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a wrong pin must be refused: %v", err)
	}
	c, _ = NewClient(srv.URL, p.password, strings.ToUpper(pin[:2])+":"+pin[2:4]+pin[4:]) // colons and case are tolerated
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("the right pin must work: %v", err)
	}
	c, _ = NewClient(srv.URL, p.password, "") // self-signed and unpinned: the system roots do not vouch for it
	if err := c.Login(t.Context()); err == nil {
		t.Fatal("an unpinned self-signed certificate must be refused")
	}
}

func TestWrongPasswordNeverEchoed(t *testing.T) {
	p, srv, pin := start(t)
	c, _ := NewClient(srv.URL, "not the password", pin)
	err := c.Login(t.Context())
	var api *APIError
	if !errors.As(err, &api) || api.Status != 401 || strings.Contains(err.Error(), "not the password") {
		t.Fatalf("err = %v", err)
	}
	_ = p
}

func TestSessionExpiryLogsInAgain(t *testing.T) {
	p, srv, pin := start(t)
	c, _ := NewClient(srv.URL, p.password, pin)
	if _, err := c.Config(t.Context()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.expireOne = true
	p.mu.Unlock()
	if _, err := c.Config(t.Context()); err != nil {
		t.Fatalf("an expired session should be renewed once: %v", err)
	}
	if p.logins != 2 {
		t.Fatalf("logins = %d", p.logins)
	}
}

func TestRejectedConfigurationIsReportedAndNotWritten(t *testing.T) {
	p, srv, pin := start(t)
	p.rejectAs = "ValueError: lan_tunnel_ips must be distinct"
	c, _ := NewClient(srv.URL, p.password, pin)
	_, err := c.EnsureTunnelIPs(t.Context(), []string{"10.77.0.9"})
	if err == nil || !strings.Contains(err.Error(), "must be distinct") || p.writes != 0 {
		t.Fatalf("err=%v writes=%d", err, p.writes)
	}
}

func TestWithTunnelIPs(t *testing.T) {
	out, changed, err := WithTunnelIPs(`{"role":"server"}`, []string{"10.77.0.7"})
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	if ips, _ := TunnelIPs(out); len(ips) != 1 || ips[0] != "10.77.0.7" {
		t.Fatalf("%v", ips)
	}
	for _, bad := range []string{"10.77.0.1", "10.77.0.2", "10.77.0.255", "10.77.1.5", "192.168.1.5", "10.77.0.05", "nope", "::1"} {
		if _, _, err := WithTunnelIPs(`{}`, []string{bad}); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	many := make([]string, 0, 33)
	for i := 3; i < 36; i++ {
		many = append(many, fmt.Sprintf("10.77.0.%d", i))
	}
	if _, _, err := WithTunnelIPs(`{}`, many); err == nil {
		t.Fatal("more than 32 addresses must be refused")
	}
	if _, _, err := WithTunnelIPs(`not json`, []string{"10.77.0.7"}); err == nil {
		t.Fatal("a damaged configuration must be refused")
	}
	same, changed, _ := WithTunnelIPs(baseConfig, []string{"10.77.0.3"})
	if changed || same != baseConfig {
		t.Fatal("an address that is already listed must leave the text untouched")
	}
}

func TestNewClientRefusesPlainHTTPAndBadPin(t *testing.T) {
	if _, err := NewClient("http://203.0.113.5:8443", "pw", ""); err == nil {
		t.Fatal("http must be refused: the password would cross the network in clear")
	}
	if _, err := NewClient("https://203.0.113.5:8443", "pw", "xyz"); err == nil {
		t.Fatal("a malformed pin must be refused")
	}
	if _, err := NewClient("https://203.0.113.5:8443", "", ""); err == nil {
		t.Fatal("an empty password must be refused")
	}
}
