package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gamebond.local/nativeedge/dnssync/fakecloudflare"
)

func cfFixture(t *testing.T) (s *Server, base string, cf *fakecloudflare.Account, dir string) {
	t.Helper()
	var url, configPath string
	s, url, configPath, _ = start(t)
	base = url[:strings.Index(url, "/?t=")]
	cf = fakecloudflare.New()
	srv := httptest.NewServer(cf.Handler())
	t.Cleanup(srv.Close)
	s.cfAPI = srv.URL
	return s, base, cf, filepath.Dir(configPath)
}

func cfPost(t *testing.T, s *Server, base string, body map[string]any) (int, map[string]any, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	code, text := do(t, "POST", base+"/api/cloudflare", s.token, string(raw))
	var out map[string]any
	json.Unmarshal([]byte(text), &out)
	return code, out, text
}

func TestCloudflareTokenIsValidatedBeforeAnythingIsSaved(t *testing.T) {
	s, base, _, dir := cfFixture(t)
	code, out, text := cfPost(t, s, base, map[string]any{"action": "validate", "token": "wrong-secret-token-value"})
	if code != 422 || out["ok"] != false || strings.Contains(text, "wrong-secret-token-value") {
		t.Fatalf("a bad token must be refused and never echoed: %d %s", code, text)
	}
	if _, err := os.Stat(filepath.Join(dir, cloudflareSecret)); err == nil {
		t.Fatal("a refused token must not be saved")
	}
	if cfg, _ := readConfig(s.o.ConfigPath); cfg["reverse_dns"] != nil {
		t.Fatal("a refused token must not touch the configuration")
	}
	if code, out, _ := cfPost(t, s, base, map[string]any{"action": "validate", "token": ""}); code != 422 || out["ok"] != false {
		t.Fatalf("an empty token: %d", code)
	}
}

func TestValidTokenListsZonesAndIsStoredPrivately(t *testing.T) {
	s, base, _, dir := cfFixture(t)
	code, out, _ := cfPost(t, s, base, map[string]any{"action": "validate", "token": "good-token"})
	zones, _ := out["zones"].([]any)
	if code != 200 || out["ok"] != true || len(zones) != 2 {
		t.Fatalf("validate: %d %v", code, out)
	}
	st, err := os.Stat(filepath.Join(dir, cloudflareSecret))
	if err != nil || (os.PathSeparator == '/' && st.Mode().Perm()&0o077 != 0) {
		t.Fatalf("the token file must exist and be private: %v %v", st, err)
	}
	raw, _ := os.ReadFile(s.o.ConfigPath)
	if strings.Contains(string(raw), "good-token") {
		t.Fatal("the token must not be in the client configuration")
	}
	code, body := do(t, "GET", base+"/api/cloudflare", s.token, "")
	if code != 200 || strings.Contains(body, "good-token") || !strings.Contains(body, `"token_saved":true`) || !strings.Contains(body, `"active":false`) || !strings.Contains(body, `"suggested_label":"bond-`) {
		t.Fatalf("a saved token with no name is not active yet, and is never returned: %s", body)
	}
}

func TestGlobalKeyNeedsItsEmail(t *testing.T) {
	s, base, _, _ := cfFixture(t)
	if code, out, _ := cfPost(t, s, base, map[string]any{"action": "validate", "token": "good-key", "email": "someone-else@example.com"}); code != 422 {
		t.Fatalf("a key with the wrong email: %d %v", code, out)
	}
	if code, out, _ := cfPost(t, s, base, map[string]any{"action": "validate", "token": "good-key", "email": "me@example.com"}); code != 200 || out["ok"] != true {
		t.Fatalf("a key with its own email: %d %v", code, out)
	}
	cfg, _ := readConfig(s.o.ConfigPath)
	if rd, _ := cfg["reverse_dns"].(map[string]any); rd["email"] != "me@example.com" {
		t.Fatalf("%v", cfg["reverse_dns"])
	}
}

func TestMintCreatesARecordPointingAtTheExitAndSavesTheName(t *testing.T) {
	s, base, cf, _ := cfFixture(t)
	cfPost(t, s, base, map[string]any{"action": "validate", "token": "good-token"})

	writeStatus(t, s.o.StatusPath, "stopped", false)
	if code, out, _ := cfPost(t, s, base, map[string]any{"action": "mint", "zone": "example.com", "label": "bond-test"}); code != 409 || !strings.Contains(out["error"].(string), "connect first") {
		t.Fatalf("minting needs the tunnel up: %d %v", code, out)
	}
	writeStatus(t, s.o.StatusPath, "running", false)

	for _, bad := range []string{"ab", "Bond Test", "-bond", "bond-", "bond.test", strings.Repeat("a", 41)} {
		if code, _, _ := cfPost(t, s, base, map[string]any{"action": "mint", "zone": "example.com", "label": bad}); code != 422 {
			t.Errorf("label %q must be refused (%d)", bad, code)
		}
	}
	if code, out, _ := cfPost(t, s, base, map[string]any{"action": "mint", "zone": "not-mine.org", "label": "bond-test"}); code != 422 || !strings.Contains(out["error"].(string), "not one of the domains") {
		t.Fatalf("a domain the token cannot manage: %d %v", code, out)
	}
	code, out, _ := cfPost(t, s, base, map[string]any{"action": "mint", "zone": "example.com", "label": "Bond-Test"})
	if code != 200 || out["name"] != "bond-test.example.com" || out["address"] != "1.2.3.4" || out["reconnect_needed"] != true {
		t.Fatalf("mint: %d %v", code, out)
	}
	cf.Lock()
	var rec *fakecloudflare.Record
	for i := range cf.Records["z1"] {
		if cf.Records["z1"][i].Name == "bond-test.example.com" {
			rec = &cf.Records["z1"][i]
		}
	}
	cf.Unlock()
	if rec == nil || rec.Type != "A" || rec.Content != "1.2.3.4" || rec.Proxied || rec.TTL != 60 {
		t.Fatalf("record: %+v", rec)
	}
	cfg, _ := readConfig(s.o.ConfigPath)
	rd, _ := cfg["reverse_dns"].(map[string]any)
	if rd["name"] != "bond-test.example.com" || rd["secret_file"] != cloudflareSecret {
		t.Fatalf("reverse_dns: %v", rd)
	}
	if _, body := do(t, "GET", base+"/api/cloudflare", s.token, ""); !strings.Contains(body, `"active":true`) || !strings.Contains(body, "bond-test.example.com") {
		t.Fatalf("%s", body)
	}
}

func TestMintNeverOverwritesAnExistingRecord(t *testing.T) {
	s, base, cf, _ := cfFixture(t)
	cfPost(t, s, base, map[string]any{"action": "validate", "token": "good-token"})
	writeStatus(t, s.o.StatusPath, "running", false)
	code, out, _ := cfPost(t, s, base, map[string]any{"action": "mint", "zone": "example.com", "label": "www"})
	if code != 409 || !strings.Contains(out["error"].(string), "already exists") {
		t.Fatalf("an existing name must be refused: %d %v", code, out)
	}
	cf.Lock()
	first := cf.Records["z1"][0]
	cf.Unlock()
	if first.Content != "9.9.9.9" {
		t.Fatalf("an existing record was changed: %+v", first)
	}
	cfg, _ := readConfig(s.o.ConfigPath)
	if rd, _ := cfg["reverse_dns"].(map[string]any); rd["name"] != nil && rd["name"] != "" {
		t.Fatalf("a refused mint must not save a name: %v", rd)
	}
}

func TestRemoveClearsTheTokenAndOptionallyTheRecord(t *testing.T) {
	s, base, cf, dir := cfFixture(t)
	cfPost(t, s, base, map[string]any{"action": "validate", "token": "good-token"})
	writeStatus(t, s.o.StatusPath, "running", false)
	cfPost(t, s, base, map[string]any{"action": "mint", "zone": "example.com", "label": "bond-gone"})
	code, out, _ := cfPost(t, s, base, map[string]any{"action": "remove", "delete_record": true})
	if code != 200 || out["ok"] != true || out["record_deleted"] != true {
		t.Fatalf("remove: %d %v", code, out)
	}
	cf.Lock()
	n := len(cf.Records["z1"])
	cf.Unlock()
	if n != 2 {
		t.Fatalf("only the minted record should have gone: %d records left", n)
	}
	if _, err := os.Stat(filepath.Join(dir, cloudflareSecret)); err == nil {
		t.Fatal("the token file must be removed")
	}
	if cfg, _ := readConfig(s.o.ConfigPath); cfg["reverse_dns"] != nil {
		t.Fatal("reverse_dns must be cleared")
	}
	if code, _, _ := cfPost(t, s, base, map[string]any{"action": "bogus"}); code != 400 {
		t.Fatalf("unknown action: %d", code)
	}
}
