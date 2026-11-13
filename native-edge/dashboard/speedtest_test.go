package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeStatus(t *testing.T, path string, state string, speedRunning bool) {
	t.Helper()
	doc := map[string]any{"state": state, "updated_at": time.Now().Unix(), "peer": []any{"1.2.3.4", 4433}, "transport": map[string]any{"paths": []any{}}}
	if speedRunning {
		doc["speedtest"] = map[string]any{"running": true}
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSpeedTestRequestNeedsARunningTunnelAndWritesARequest(t *testing.T) {
	speedRequest.last = time.Time{}
	s, url, configPath, _ := start(t)
	base := url[:strings.Index(url, "/?t=")]
	status := s.o.StatusPath
	req := filepath.Join(filepath.Dir(configPath), "speedtest-request.json")

	writeStatus(t, status, "stopped", false)
	if code, body := do(t, "POST", base+"/api/speedtest", s.token, `{"action":"start"}`); code != 409 || !strings.Contains(body, "connect first") {
		t.Fatalf("a stopped tunnel cannot be measured: %d %s", code, body)
	}
	if _, err := os.Stat(req); err == nil {
		t.Fatal("no request may be written for a stopped tunnel")
	}

	speedRequest.last = time.Time{}
	writeStatus(t, status, "running", true)
	if code, body := do(t, "POST", base+"/api/speedtest", s.token, `{"action":"start"}`); code != 409 || !strings.Contains(body, "already running") {
		t.Fatalf("one at a time: %d %s", code, body)
	}

	speedRequest.last = time.Time{}
	writeStatus(t, status, "running", false)
	code, body := do(t, "POST", base+"/api/speedtest", s.token, `{}`)
	var out struct {
		OK bool   `json:"ok"`
		ID string `json:"id"`
	}
	if code != 202 || json.Unmarshal([]byte(body), &out) != nil || !out.OK || len(out.ID) != 12 {
		t.Fatalf("start: %d %s", code, body)
	}
	raw, err := os.ReadFile(req)
	if err != nil {
		t.Fatal(err)
	}
	var written struct{ Action, ID string }
	json.Unmarshal([]byte(strings.ToLower(string(raw))), &written)
	if written.Action != "start" || written.ID != out.ID {
		t.Fatalf("the request file must carry the id the widget was given: %s", raw)
	}
	if code, _ := do(t, "POST", base+"/api/speedtest", s.token, `{"action":"start"}`); code != 429 {
		t.Fatalf("asking again at once must be slowed down: %d", code)
	}
}

func TestSpeedTestCancelAndBadInput(t *testing.T) {
	speedRequest.last = time.Time{}
	s, url, configPath, _ := start(t)
	base := url[:strings.Index(url, "/?t=")]
	if code, _ := do(t, "POST", base+"/api/speedtest", s.token, `{"action":"cancel"}`); code != 202 {
		t.Fatalf("cancel: %d", code)
	}
	if raw, _ := os.ReadFile(filepath.Join(filepath.Dir(configPath), "speedtest-request.json")); !strings.Contains(string(raw), "cancel") {
		t.Fatalf("%s", raw)
	}
	speedRequest.last = time.Time{}
	if code, _ := do(t, "POST", base+"/api/speedtest", s.token, `{"action":"rm -rf"}`); code != 400 {
		t.Fatalf("unknown action: %d", code)
	}
	if code, _ := do(t, "GET", base+"/api/speedtest", s.token, ""); code != 405 {
		t.Fatalf("GET: %d", code)
	}
	if code, _ := do(t, "POST", base+"/api/speedtest", "", `{}`); code == 200 || code == 202 {
		t.Fatalf("a token is required: %d", code)
	}
}
