package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"gamebond.local/nativeedge/omr"
)

const uplinkGUID = "{11111111-1111-1111-1111-111111111111}"
const spareGUID = "{22222222-2222-2222-2222-222222222222}"

func transportFixture(t *testing.T) (*Server, string, string) {
	s, url, config, _ := start(t)
	cfg, err := readConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	cfg["client_tunnel_ip"] = "10.77.0.2"
	cfg["interface_indices"] = []int{22}
	cfg["interface_ids"] = []string{uplinkGUID}
	if err := writeConfig(config, cfg); err != nil {
		t.Fatal(err)
	}
	s.o.RootPath = filepath.Dir(config)
	s.o.USBNetworkDevices = func() ([]USBNetworkDevice, error) { return nil, nil }
	s.o.Adapters = func() ([]Adapter, error) {
		return []Adapter{
			{Index: 22, ID: uplinkGUID, Name: "Ethernet", Up: true, Addresses: []string{"192.168.1.93"}, Gateway: "192.168.1.1"},
			{Index: 25, ID: spareGUID, Name: "USB device", Up: true, Addresses: []string{"192.168.5.1"}, Gateway: "192.168.5.2"},
		}, nil
	}
	return s, url[:strings.Index(url, "/?t=")], config
}

func TestLANSettingsValidateWithUplinkContext(t *testing.T) {
	s, base, config := transportFixture(t)
	good := `[{"name":"Console","tunnel_ip":"10.77.0.5","interface_id":"` + spareGUID + `","interface_index":25,"dns":["1.1.1.1"]}]`
	if c, b := do(t, "PUT", base+"/api/lan-devices", s.token, good); c != 200 {
		t.Fatal(c, b)
	}
	if c, b := do(t, "GET", base+"/api/lan-devices", s.token, ""); c != 200 || !strings.Contains(b, "Console") || !strings.Contains(b, "USB device") {
		t.Fatal(c, b)
	}
	before, _ := os.ReadFile(config)
	for _, bad := range []string{`null`, `{}`, strings.Replace(good, "10.77.0.5", "10.77.0.2", 1), strings.Replace(good, spareGUID, uplinkGUID, 1), strings.Replace(good, `"interface_index":25`, `"interface_index":22`, 1), strings.Replace(good, `"1.1.1.1"`, `"::1"`, 1)} {
		if c, b := do(t, "PUT", base+"/api/lan-devices", s.token, bad); c != 422 {
			t.Fatalf("%s: %d %s", bad, c, b)
		}
	}
	if c, b := do(t, "PUT", base+"/api/networks", s.token, `[25]`); c != 422 {
		t.Fatal("LAN adapter selected as uplink", c, b)
	}
	after, _ := os.ReadFile(config)
	if string(before) != string(after) {
		t.Fatal("rejected settings changed config")
	}
	if c, _ := do(t, "PUT", base+"/api/lan-devices", "", good); c != 403 {
		t.Fatal("unauthenticated write", c)
	}
}

func TestLinkSettingsKeepOneSelectedLinkEnabled(t *testing.T) {
	s, base, _ := transportFixture(t)
	if c, b := do(t, "PUT", base+"/api/links", s.token, `{"22":{"role":"never"}}`); c != 422 {
		t.Fatal(c, b)
	}
	if c, b := do(t, "PUT", base+"/api/links", s.token, `{"22":{"role":"backup"}}`); c != 200 {
		t.Fatal(c, b)
	}
}

func TestOMRSettingsPrivatePasswordDraftAndSingleLogin(t *testing.T) {
	s, base, config := transportFixture(t)
	body := `{"server_type":"both","omr":{"server":["203.0.113.7",65001],"admin":{"username":"user","password_file":"existing.pass","pin":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},"password":" private test password "}`
	secretPath := filepath.Join(s.o.RootPath, "secrets", "omr-admin.pass")
	if c, b := do(t, "PUT", base+"/api/omr", s.token, strings.Replace(body, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "invalid", 1)); c != 422 {
		t.Fatal(c, b)
	}
	if _, err := os.Stat(secretPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected config wrote password", err)
	}
	if c, b := do(t, "PUT", base+"/api/omr", s.token, body); c != 200 || strings.Contains(b, "test password") {
		t.Fatal(c, b)
	}
	secret, err := os.ReadFile(secretPath)
	if err != nil || string(secret) != "private test password\n" {
		t.Fatal("private password not stored", err)
	}
	raw, _ := os.ReadFile(config)
	if strings.Contains(string(raw), "test password") || strings.Contains(string(raw), `"password"`) {
		t.Fatal("plaintext password stored in config")
	}
	var calls atomic.Int32
	s.o.OMRLogin = func(settings *omr.Settings, password string) (string, error) {
		calls.Add(1)
		if password != "private test password" || settings.Admin.Username != "user" {
			t.Error("wrong credentials passed")
		}
		return "10.255.254.2", nil
	}
	_, read := do(t, "GET", base+"/api/omr", s.token, "")
	var stored map[string]any
	if err := json.Unmarshal([]byte(read), &stored); err != nil {
		t.Fatal(err)
	}
	check, _ := json.Marshal(map[string]any{"action": "test", "settings": map[string]any{"server_type": "both", "omr": stored["omr"]}})
	if c, b := do(t, "POST", base+"/api/omr-check", s.token, string(check)); c != 200 || !strings.Contains(b, "10.255.254.2") || strings.Contains(b, "test password") {
		t.Fatal(c, b)
	}
	if calls.Load() != 1 {
		t.Fatal("login was retried", calls.Load())
	}
	s.o.OMRLogin = func(*omr.Settings, string) (string, error) { calls.Add(1); return "", omr.ErrAuth }
	if c, _ := do(t, "POST", base+"/api/omr-check", s.token, string(check)); c != 502 {
		t.Fatal(c)
	}
	if calls.Load() != 2 {
		t.Fatal("refused login retried", calls.Load())
	}
	if c, b := do(t, "PUT", base+"/api/omr", s.token, `{"server_type":"gamebond"}`); c != 200 {
		t.Fatal(c, b)
	}
	cfg, err := readConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := cfg["omr"]; has || cfg["omr_draft"] == nil || cfg["bind"] == nil {
		t.Fatal("mode change lost draft/unrelated config", cfg)
	}
	if c, _ := do(t, "PUT", base+"/api/omr", s.token, `{"server_type":"omr"}`); c != 422 {
		t.Fatal("unsupported OMR-only mode accepted", c)
	}
}

func TestOMRPinReadSendsNoHTTP(t *testing.T) {
	var requests atomic.Int32
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer remote.Close()
	u, err := url.Parse(remote.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	s, base, _ := transportFixture(t)
	body, _ := json.Marshal(map[string]any{"action": "pin", "host": u.Hostname(), "port": port})
	want, err := omr.SPKIPin(remote.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	if c, b := do(t, "POST", base+"/api/omr-check", s.token, string(body)); c != 200 || !strings.Contains(b, want) {
		t.Fatal(c, b)
	}
	if requests.Load() != 0 {
		t.Fatal("pin discovery sent HTTP/credentials")
	}
}
