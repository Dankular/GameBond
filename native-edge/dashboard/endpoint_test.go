package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndpointWatchSettingAndAlerts(t *testing.T) {
	s, url, configPath, _ := start(t)
	base := url[:strings.Index(url, "/?t=")]
	if code, body := do(t, "GET", base+"/api/endpoint", s.token, ""); code != 200 || !strings.Contains(body, `"enabled":false`) {
		t.Fatalf("off by default: %d %s", code, body)
	}
	dir := t.TempDir()
	line := `{"timestamp_utc":"2026-11-13T10:01:00Z","indicator":"evil-c2.example","matched_rule":"Known C2 domain","source_feed":"f","match_type":"domain","protocol":"tls","dst_ip":"198.51.100.4","dst_port":443,"process_name":"chrome.exe","process_pid":999,"process_exe":"C:\\chrome.exe","detection_layer":"sni"}` + "\n"
	os.WriteFile(filepath.Join(dir, "alerts.jsonl"), []byte(line), 0o600)

	for name, body := range map[string]string{"relative": `{"enabled":true,"packetsentinel_dir":"rel"}`, "nothing": `{"enabled":true}`, "unknown": `{"enabled":false,"x":1}`} {
		if code, _ := do(t, "POST", base+"/api/endpoint", s.token, body); code != 422 && code != 400 {
			t.Errorf("%s must be refused: %d", name, code)
		}
	}
	good, _ := json.Marshal(map[string]any{"enabled": true, "packetsentinel_dir": dir})
	if code, body := do(t, "POST", base+"/api/endpoint", s.token, string(good)); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	cfg, _ := readConfig(configPath)
	if cfg["endpoint_watch"] == nil || cfg["role"] != "client" {
		t.Fatalf("the setting is stored and the rest of the config kept: %v", cfg)
	}
	code, body := do(t, "GET", base+"/api/endpoint", s.token, "")
	var got struct {
		Snapshot struct {
			Alerts []struct{ Process, Remote string } `json:"alerts"`
		} `json:"snapshot"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &got) != nil || len(got.Snapshot.Alerts) != 1 || got.Snapshot.Alerts[0].Process != "chrome.exe" || got.Snapshot.Alerts[0].Remote != "evil-c2.example" {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := do(t, "GET", base+"/api/endpoint", "wrong", ""); code != 403 {
		t.Fatalf("the page token is required: %d", code)
	}
	off, _ := json.Marshal(map[string]any{"enabled": false})
	do(t, "POST", base+"/api/endpoint", s.token, string(off))
	if _, body := do(t, "GET", base+"/api/endpoint", s.token, ""); !strings.Contains(body, `"alerts":[]`) {
		t.Fatalf("turning it off forgets the alerts: %s", body)
	}
}
