package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gamebond.local/nativeedge/lan"
	"gamebond.local/nativeedge/serveradmin/fakeportal"
)

const portalPassword = "correct horse battery"

// portalFixture starts a fake server portal and a dashboard whose client config already lists one device.
func portalFixture(t *testing.T) (s *Server, base string, p *fakeportal.Portal, pin string, configPath string) {
	t.Helper()
	var url string
	s, url, configPath, _ = start(t)
	base = url[:strings.Index(url, "/?t=")]
	p = fakeportal.New(portalPassword, `{"role":"server","lan_tunnel_ips":["10.77.0.3"]}`)
	srv := httptest.NewTLSServer(p.Handler())
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	pin = hex.EncodeToString(sum[:])
	cfg, _ := readConfig(configPath)
	cfg["client_tunnel_ip"] = "10.77.0.2"
	cfg["lan_devices"] = []any{map[string]any{"name": "PS5", "tunnel_ip": "10.77.0.3"}}
	if err := writeConfig(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_PORTAL_URL", srv.URL)
	return
}

func saveAdmin(t *testing.T, s *Server, base, pin, password string) (int, string) {
	body, _ := json.Marshal(map[string]any{"url": os.Getenv("FAKE_PORTAL_URL"), "password": password, "tls_sha256": pin})
	return do(t, "POST", base+"/api/server-admin", s.token, string(body))
}

func TestServerAdminSettingsAreVerifiedAndThePasswordStaysPrivate(t *testing.T) {
	s, base, _, pin, configPath := portalFixture(t)
	if code, body := saveAdmin(t, s, base, pin, "wrong password!!"); code != 422 || !strings.Contains(body, "could not log in") {
		t.Fatalf("a wrong password must be refused before anything is saved: %d %s", code, body)
	}
	if cfg, _ := readConfig(configPath); cfg["server_admin"] != nil {
		t.Fatal("a refused login must not be saved")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(configPath), serverAdminSecret)); err == nil {
		t.Fatal("a refused login must not leave a password file")
	}
	if code, body := saveAdmin(t, s, base, strings.Repeat("ab", 32), portalPassword); code != 422 {
		t.Fatalf("a wrong certificate pin must be refused: %d %s", code, body)
	}
	if code, body := saveAdmin(t, s, base, pin, portalPassword); code != 200 {
		t.Fatalf("save: %d %s", code, body)
	}
	code, body := do(t, "GET", base+"/api/server-admin", s.token, "")
	if code != 200 || strings.Contains(body, portalPassword) || !strings.Contains(body, `"password_saved":true`) || !strings.Contains(body, `"configured":true`) {
		t.Fatalf("the settings view must say it is configured and never include the password: %s", body)
	}
	raw, _ := os.ReadFile(configPath)
	if strings.Contains(string(raw), portalPassword) {
		t.Fatal("the password must live in its own file, not in the client configuration")
	}
	if st, err := os.Stat(filepath.Join(filepath.Dir(configPath), serverAdminSecret)); err != nil || st.Mode().Perm()&0o077 != 0 && !strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") && os.PathSeparator == '/' {
		t.Fatalf("the password file must be private: %v %v", st, err)
	}
	// Changing only the address keeps the saved password.
	body2, _ := json.Marshal(map[string]any{"url": os.Getenv("FAKE_PORTAL_URL"), "tls_sha256": pin})
	if code, out := do(t, "POST", base+"/api/server-admin", s.token, string(body2)); code != 200 {
		t.Fatalf("re-save without a password: %d %s", code, out)
	}
	if code, _ := do(t, "POST", base+"/api/server-admin", s.token, `{"clear":true}`); code != 200 {
		t.Fatal("clear")
	}
	if code, body := do(t, "GET", base+"/api/server-admin", s.token, ""); !strings.Contains(body, `"configured":false`) || code != 200 {
		t.Fatalf("after clearing: %s", body)
	}
}

func TestAdoptedDeviceIsSyncedToTheServerAndRestartIsExplicit(t *testing.T) {
	s, base, p, pin, configPath := portalFixture(t)
	if code, body := do(t, "POST", base+"/api/server-sync", s.token, `{}`); code != 422 || !strings.Contains(body, "not set up") {
		t.Fatalf("sync before setup: %d %s", code, body)
	}
	if code, body := saveAdmin(t, s, base, pin, portalPassword); code != 200 {
		t.Fatal(code, body)
	}
	// Adopt a device: it gets the next free address locally, which the server does not know yet.
	dir := filepath.Dir(configPath)
	lan.SavePending(filepath.Join(dir, "lan-pending.json"), []lan.Pending{{MAC: "aa:bb:cc:00:00:09", Hostname: "Dans laptop"}})
	if code, body := do(t, "POST", base+"/api/lan-access", s.token, `{"action":"accept","mac":"aa:bb:cc:00:00:09"}`); code != 200 {
		t.Fatal(code, body)
	}
	code, body := do(t, "GET", base+"/api/server-sync?check=1", s.token, "")
	var view struct {
		Configured    bool                `json:"configured"`
		Missing       []map[string]string `json:"missing"`
		ServerIPs     []string            `json:"server_ips"`
		RestartNeeded bool                `json:"restart_needed"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &view) != nil || !view.Configured || len(view.Missing) != 1 || view.Missing[0]["ip"] != "10.77.0.10" || view.Missing[0]["name"] != "Dans laptop" {
		t.Fatalf("the adopted device must show as missing on the server: %d %s", code, body)
	}
	// Syncing writes the list but does not restart.
	code, body = do(t, "POST", base+"/api/server-sync", s.token, `{}`)
	var res struct {
		OK            bool                `json:"ok"`
		Changed       bool                `json:"changed"`
		Restarted     bool                `json:"restarted"`
		RestartNeeded bool                `json:"restart_needed"`
		Missing       []map[string]string `json:"missing"`
	}
	json.Unmarshal([]byte(body), &res)
	if code != 200 || !res.OK || !res.Changed || res.Restarted || !res.RestartNeeded || len(res.Missing) != 0 || p.Restarts != 0 {
		t.Fatalf("sync without restart: %d %s (restarts=%d)", code, body, p.Restarts)
	}
	if !strings.Contains(p.Config, "10.77.0.10") || !strings.Contains(p.Config, "10.77.0.3") {
		t.Fatalf("the server list must keep the existing address and add the new one: %s", p.Config)
	}
	// The restart is a separate, explicit request.
	code, body = do(t, "POST", base+"/api/server-sync", s.token, `{"restart":true}`)
	json.Unmarshal([]byte(body), &res)
	if code != 200 || !res.Restarted || res.RestartNeeded || p.Restarts != 1 {
		t.Fatalf("explicit restart: %d %s (restarts=%d)", code, body, p.Restarts)
	}
	// With nothing to apply, asking for a restart must not restart the server for no reason.
	do(t, "POST", base+"/api/server-sync", s.token, `{"restart":true}`)
	if p.Restarts != 1 {
		t.Fatalf("a restart with nothing pending must not happen (%d)", p.Restarts)
	}
}

func TestServerSyncFailureIsReported(t *testing.T) {
	s, base, p, pin, configPath := portalFixture(t)
	saveAdmin(t, s, base, pin, portalPassword)
	lan.SavePending(filepath.Join(filepath.Dir(configPath), "lan-pending.json"), []lan.Pending{{MAC: "aa:bb:cc:00:00:09"}})
	do(t, "POST", base+"/api/lan-access", s.token, `{"action":"accept","mac":"aa:bb:cc:00:00:09"}`)
	p.Lock()
	p.RejectAs = "ValueError: lan_tunnel_ips must be distinct"
	p.Unlock()
	code, body := do(t, "POST", base+"/api/server-sync", s.token, `{"restart":true}`)
	if code != 422 || !strings.Contains(body, "must be distinct") || p.Restarts != 0 || p.Writes != 0 {
		t.Fatalf("a rejected list must be reported and must not restart anything: %d %s", code, body)
	}
}

func TestAcceptWithAFixedAddress(t *testing.T) {
	dir := t.TempDir()
	s := &Server{}
	access, pending := filepath.Join(dir, "lan-access.json"), filepath.Join(dir, "lan-pending.json")
	cfg := map[string]any{"client_tunnel_ip": "10.77.0.2", "lan_devices": []any{map[string]any{"tunnel_ip": "10.77.0.3"}}}
	if err := s.applyAccess(access, pending, cfg, "accept", "aa:bb:cc:00:00:01", "Camera", "", "10.77.0.40"); err != nil {
		t.Fatal(err)
	}
	if a := lan.LoadAccess(access); len(a.Accepted) != 1 || a.Accepted[0].IP != "10.77.0.40" {
		t.Fatalf("%+v", a)
	}
	for _, bad := range []string{"10.77.0.3", "10.77.0.40", "10.77.0.2", "10.77.0.1", "10.77.0.255", "10.77.1.9", "192.168.1.9", "nope", "10.77.0.05"} {
		if err := s.applyAccess(access, pending, cfg, "accept", "aa:bb:cc:00:00:02", "Other", "", bad); err == nil {
			t.Errorf("fixed address %q must be refused", bad)
		}
	}
	// The same device may be accepted again with its own address.
	if err := s.applyAccess(access, pending, cfg, "accept", "aa:bb:cc:00:00:01", "Camera", "", "10.77.0.40"); err != nil {
		t.Fatalf("re-accepting a device with its own address: %v", err)
	}
	if a := lan.LoadAccess(access); len(a.Accepted) != 1 {
		t.Fatalf("no duplicate entry: %+v", a)
	}
	if err := s.applyAccess(access, pending, cfg, "accept", "aa:bb:cc:00:00:03", "Auto", ""); err != nil {
		t.Fatal(err)
	}
	if a := lan.LoadAccess(access); len(a.Accepted) != 2 || a.Accepted[1].IP == "10.77.0.40" {
		t.Fatalf("an automatic address must skip a fixed one: %+v", a)
	}
}
