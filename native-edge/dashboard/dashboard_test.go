package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func start(t *testing.T) (*Server, string, string, *[]string) {
	dir := t.TempDir()
	status := filepath.Join(dir, "status.json")
	config := filepath.Join(dir, "client.json")
	os.WriteFile(status, []byte(`{"state":"running","peer":["1.2.3.4",4433],"transport":{"paths":[{"slot":0,"healthy":true}]}}`), 0o600)
	os.WriteFile(config, []byte(`{"role":"client","bind":[["10.0.0.2",0]],"link_policies":{"22":{"role":"primary"}}}`), 0o600)
	var calls []string
	s, url, err := Start(Options{StatusPath: status, ConfigPath: config, Adapters: func() ([]Adapter, error) { return []Adapter{}, nil }, Control: func(c string) (map[string]any, error) {
		calls = append(calls, c)
		return map[string]any{"state": "ok"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, url, config, &calls
}

func do(t *testing.T, method, url, token, body string) (int, string) {
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTokenRequiredEverywhere(t *testing.T) {
	s, url, _, _ := start(t)
	base := url[:strings.Index(url, "/?t=")]
	for _, p := range []string{"/", "/api/status", "/api/links", "/api/app-policy"} {
		if code, _ := do(t, "GET", base+p, "", ""); code == 200 {
			t.Fatalf("%s served without a token", p)
		}
		if code, _ := do(t, "GET", base+p, "wrong", ""); code == 200 {
			t.Fatalf("%s served with a wrong token", p)
		}
	}
	if code, body := do(t, "GET", url, "", ""); code != 200 || !strings.Contains(body, s.token) || strings.Contains(body, "__TOKEN__") {
		t.Fatal("page must embed the token", code)
	}
	if code, _ := do(t, "GET", base+"/api/status", s.token, ""); code != 200 {
		t.Fatal("status refused with the token")
	}
}

func TestApplicationPolicyEdit(t *testing.T) {
	s, url, config, _ := start(t)
	endpoint := url[:strings.Index(url, "/?t=")] + "/api/app-policy"
	if c, b := do(t, "GET", endpoint, s.token, ""); c != 200 || !strings.Contains(b, `"protection_enabled":true`) || !strings.Contains(b, `"default_app_profile":"automatic"`) || !strings.Contains(b, `"app_rules":{}`) {
		t.Fatalf("defaults: %d %s", c, b)
	}
	before, _ := os.ReadFile(config)
	good := `{"protection_enabled":false,"default_app_profile":"call","app_rules":{"C:/Games/../Games/A.EXE":{"outbound":"block","profile":"gaming"}}}`
	if c, b := do(t, "PUT", endpoint, s.token, good); c != 200 {
		t.Fatalf("save: %d %s", c, b)
	}
	previous, _ := os.ReadFile(config + ".previous")
	if string(previous) != string(before) {
		t.Fatal("previous config not preserved")
	}
	saved, _ := os.ReadFile(config)
	var cfg map[string]any
	if err := json.Unmarshal(saved, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["role"] != "client" || cfg["bind"] == nil || cfg["link_policies"] == nil {
		t.Fatal("unrelated config lost", cfg)
	}
	if cfg["protection_enabled"] != false || cfg["default_app_profile"] != "call" {
		t.Fatal(cfg)
	}
	rules := cfg["app_rules"].(map[string]any)
	rule, ok := rules[`c:\games\a.exe`].(map[string]any)
	if !ok || len(rules) != 1 || rule["outbound"] != "block" || rule["profile"] != "gaming" {
		t.Fatal(rules)
	}
	if c, b := do(t, "GET", endpoint, s.token, ""); c != 200 || !strings.Contains(b, `"protection_enabled":false`) {
		t.Fatal(c, b)
	}
	for _, bad := range []string{
		`null`, `[]`, `{`, `{} {}`, `{"role":"server"}`, `{"protection_enabled":1}`, `{"default_app_profile":"game"}`,
		`{"app_rules":null}`, `{"app_rules":{"relative.exe":{}}}`, `{"app_rules":{"C:/a.exe":{"outbound":"deny"}}}`,
		`{"app_rules":{"C:/a.exe":{"profile":"fast"}}}`, `{"app_rules":{"C:/a.exe":{"unknown":true}}}`,
		`{"app_rules":{"C:/a.exe":{"outbound":"allow"},"c:/A.EXE":{"outbound":"block"}}}`,
	} {
		if c, b := do(t, "PUT", endpoint, s.token, bad); c != 422 {
			t.Fatalf("accepted %s: %d %s", bad, c, b)
		}
		after, _ := os.ReadFile(config)
		if string(after) != string(saved) {
			t.Fatal("rejected edit changed config")
		}
	}
	if c, _ := do(t, "POST", endpoint, s.token, good); c != 405 {
		t.Fatal("POST accepted", c)
	}
}

func TestRebindingHostRefused(t *testing.T) {
	s, url, _, _ := start(t)
	base := url[:strings.Index(url, "/?t=")]
	req, _ := http.NewRequest("GET", base+"/api/status", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Token", s.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("foreign Host header accepted")
	}
}

func TestStatusPassesThroughAndMissingFileIsUnavailable(t *testing.T) {
	s, url, _, _ := start(t)
	base := url[:strings.Index(url, "/?t=")]
	_, body := do(t, "GET", base+"/api/status", s.token, "")
	var d map[string]any
	json.Unmarshal([]byte(body), &d)
	if d["state"] != "running" {
		t.Fatal(body)
	}
	os.Remove(s.o.StatusPath)
	_, body = do(t, "GET", base+"/api/status", s.token, "")
	json.Unmarshal([]byte(body), &d)
	if d["state"] != "unavailable" {
		t.Fatal(body)
	}
}

func TestControlOnlyStopAndRestart(t *testing.T) {
	s, url, _, calls := start(t)
	base := url[:strings.Index(url, "/?t=")]
	for _, c := range []string{"stop", "restart"} {
		if code, _ := do(t, "POST", base+"/api/control", s.token, `{"command":"`+c+`"}`); code != 200 {
			t.Fatal(c, code)
		}
	}
	for _, c := range []string{`{"command":"status"}`, `{"command":"rm -rf"}`, `{}`, `nope`} {
		if code, _ := do(t, "POST", base+"/api/control", s.token, c); code != 400 {
			t.Fatalf("%s: %d", c, code)
		}
	}
	if code, _ := do(t, "GET", base+"/api/control", s.token, ""); code != 405 {
		t.Fatal("GET control", code)
	}
	if len(*calls) != 2 || (*calls)[0] != "stop" || (*calls)[1] != "restart" {
		t.Fatal(*calls)
	}
}

func TestLinkPolicyEditValidatesAndKeepsPrevious(t *testing.T) {
	s, url, config, _ := start(t)
	base := url[:strings.Index(url, "/?t=")]
	good := `{"22":{"role":"secondary","upload_mbps":50,"download_mbps":100,"daily_bytes":0,"monthly_bytes":0,"reset_day":5,"overlimit":"throttle","overlimit_mbps":1}}`
	if code, body := do(t, "PUT", base+"/api/links", s.token, good); code != 200 || !strings.Contains(body, "restart_required") {
		t.Fatal(code, body)
	}
	raw, _ := os.ReadFile(config)
	if !strings.Contains(string(raw), `"secondary"`) || !strings.Contains(string(raw), `"bind"`) {
		t.Fatal("edit lost data", string(raw))
	}
	prev, err := os.ReadFile(config + ".previous")
	if err != nil || !strings.Contains(string(prev), `"primary"`) {
		t.Fatal("previous copy missing", err)
	}
	for name, bad := range map[string]string{
		"role":       `{"22":{"role":"fastest"}}`,
		"unknown":    `{"22":{"role":"primary","turbo":true}}`,
		"negative":   `{"22":{"role":"primary","upload_mbps":-1}}`,
		"not object": `[1]`,
		"reset day":  `{"22":{"role":"primary","reset_day":40}}`,
		"overlimit":  `{"22":{"role":"primary","overlimit":"explode"}}`,
	} {
		if code, _ := do(t, "PUT", base+"/api/links", s.token, bad); code != 422 && code != 400 {
			t.Fatalf("%s accepted: %d", name, code)
		}
	}
	after, _ := os.ReadFile(config)
	if string(after) != string(raw) {
		t.Fatal("a rejected edit changed the config")
	}
}

func TestAppsDNSNetworksSections(t *testing.T) {
	srv, url, config, _ := start(t)
	tok := srv.token
	base := url[:strings.Index(url, "/?t=")]
	if c, b := do(t, "PUT", base+"/api/apps", tok, `["C:\\Games\\a.exe","C:\\Games\\A.EXE"]`); c != 200 {
		t.Fatalf("apps put %d %s", c, b)
	}
	if c, b := do(t, "GET", base+"/api/apps", tok, ""); c != 200 || !strings.Contains(b, "a.exe") || strings.Count(strings.ToLower(b), "a.exe") != 1 {
		t.Fatalf("apps not normalised: %d %s", c, b)
	}
	before, _ := os.ReadFile(config)
	if c, _ := do(t, "PUT", base+"/api/apps", tok, `"x"`); c != 422 {
		t.Fatalf("non-list accepted: %d", c)
	}
	if c, _ := do(t, "PUT", base+"/api/apps", tok, `["relative.exe"]`); c != 422 {
		t.Fatalf("relative path accepted: %d", c)
	}
	if c, _ := do(t, "PUT", base+"/api/dns", tok, `{"records":"nope"}`); c != 422 {
		t.Fatalf("bad dns accepted: %d", c)
	}
	after, _ := os.ReadFile(config)
	if strings.Contains(string(after), "nope") || len(after) < len(before)-200 {
		t.Fatal("rejected edits changed the config")
	}
	if c, b := do(t, "GET", base+"/api/networks", tok, ""); c != 200 || !strings.Contains(b, "adapters") || !strings.Contains(b, "10.0.0.2") {
		t.Fatalf("networks: %d %s", c, b)
	}
	if c, _ := do(t, "GET", base+"/api/hardware", tok, ""); c != 200 {
		t.Fatal("hardware")
	}
	if c, b := do(t, "GET", base+"/api/log", tok, ""); c != 200 || !strings.Contains(b, "lines") {
		t.Fatalf("log: %d %s", c, b)
	}
}
