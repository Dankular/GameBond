package endpointwatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const rustinelProcess = `{"@timestamp":"2026-11-13T10:00:05Z","ecs.version":"9.5.0","event.kind":"alert","event.dataset":"edr.network","rule.name":"Suspicious PowerShell network connection","rule.id":"sigma::x","edr.rule.severity":"High","edr.rule.engine":"Sigma","host.name":"secret-host","user.name":"secret-user","process.executable":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","process.name":"powershell.exe","process.pid":4321,"process.command_line":"powershell -enc SECRETARGS","destination.ip":"203.0.113.9","destination.port":443}`
const rustinelLoss = `{"@timestamp":"2026-11-13T10:00:06Z","event.dataset":"edr.agent","rule.name":"agent::loss::etw_session","edr.rule.engine":"Agent","edr.rule.severity":"Medium","edr.agent.loss.channel":"etw_session","edr.agent.loss.category":"kernel_buffer","edr.agent.loss.dropped":37,"edr.agent.loss.window_secs":60}`
const rustinelEnrichLoss = `{"@timestamp":"2026-11-13T10:00:07Z","event.dataset":"edr.agent","rule.name":"agent::loss::artifact_resolution","edr.rule.engine":"Agent","edr.agent.loss.channel":"artifact_resolution","edr.agent.loss.dropped":5}`
const wireLine = `{"timestamp_utc":"2026-11-13T10:01:00Z","indicator":"evil-c2.example","matched_rule":"Known C2 domain","source_feed":"hagezi-tif","match_type":"domain","protocol":"tls","dst_ip":"198.51.100.4","dst_port":443,"process_name":"chrome.exe","process_pid":999,"process_exe":"C:\\Program Files\\Google\\Chrome\\chrome.exe","detection_layer":"sni"}`

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(text)
}

func TestReadsBothProducersAndKeepsOnlyWhatIsNeeded(t *testing.T) {
	rd, wd := t.TempDir(), t.TempDir()
	write(t, filepath.Join(rd, "alerts.json.2026-11-13"), rustinelProcess+"\n")
	write(t, filepath.Join(wd, "alerts.jsonl"), wireLine+"\n")
	w := New(Config{Enabled: true, RustinelDir: rd, PacketSentinelDir: wd})
	w.Poll()
	s := w.Snapshot()
	if len(s.Alerts) != 2 || s.Alerts[0].Source != "packetsentinel" {
		t.Fatalf("newest first, both sources: %+v", s.Alerts)
	}
	ps := s.Alerts[0]
	if ps.Process != "chrome.exe" || ps.PID != 999 || ps.Remote != "evil-c2.example" || ps.Port != 443 || ps.Kind != "wire" || !strings.Contains(ps.Detail, "hagezi-tif") {
		t.Fatalf("%+v", ps)
	}
	r := s.Alerts[1]
	if r.Severity != "high" || r.Process != "powershell.exe" || r.PID != 4321 || r.Remote != "203.0.113.9" || r.Port != 443 || r.Kind != "behaviour" {
		t.Fatalf("%+v", r)
	}
	for _, a := range s.Alerts {
		all := a.Title + a.Process + a.Exe + a.Remote + a.Detail
		for _, secret := range []string{"secret-user", "secret-host", "SECRETARGS"} {
			if strings.Contains(all, secret) {
				t.Fatalf("%q must never be copied out of an alert", secret)
			}
		}
	}
	if s.Counts["high"] != 1 || s.Counts["medium"] != 1 {
		t.Fatalf("%v", s.Counts)
	}
}

func TestIncrementalReadingPartialLinesAndRotation(t *testing.T) {
	wd := t.TempDir()
	path := filepath.Join(wd, "alerts.jsonl")
	write(t, path, wireLine+"\n")
	w := New(Config{Enabled: true, PacketSentinelDir: wd})
	w.Poll()
	w.Poll()
	if n := len(w.Snapshot().Alerts); n != 1 {
		t.Fatalf("a second poll must not read the same line again: %d", n)
	}
	half := len(wireLine) / 2
	appendTo(t, path, wireLine[:half])
	w.Poll()
	if n := len(w.Snapshot().Alerts); n != 1 {
		t.Fatalf("half a line is not an alert yet: %d", n)
	}
	appendTo(t, path, wireLine[half:]+"\n")
	w.Poll()
	if n := len(w.Snapshot().Alerts); n != 2 {
		t.Fatalf("the completed line is read once: %d", n)
	}
	// rotation: the producer renames the file and starts a short new one
	write(t, path, strings.Replace(wireLine, "chrome.exe", "new.exe", 1)+"\n")
	w.Poll()
	s := w.Snapshot()
	if len(s.Alerts) != 3 || s.Alerts[0].Process != "new.exe" {
		t.Fatalf("a file that got shorter is read from its start: %+v", s.Alerts)
	}
}

func TestANewerDatedEDRFileIsFollowed(t *testing.T) {
	rd := t.TempDir()
	old := filepath.Join(rd, "alerts.json.2026-11-12")
	write(t, old, rustinelProcess+"\n")
	os.Chtimes(old, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	w := New(Config{Enabled: true, RustinelDir: rd})
	w.Poll()
	fresh := filepath.Join(rd, "alerts.json.2026-11-13")
	write(t, fresh, strings.Replace(rustinelProcess, `"process.name":"powershell.exe"`, `"process.name":"cmd.exe"`, 1)+"\n")
	w.Poll()
	s := w.Snapshot()
	if len(s.Alerts) != 2 || s.Alerts[0].Process != "cmd.exe" || s.Sources[0].Path != fresh {
		t.Fatalf("%+v", s)
	}
}

func TestSensorLossMeansBlindButEnrichmentLossDoesNot(t *testing.T) {
	rd := t.TempDir()
	write(t, filepath.Join(rd, "alerts.json.2026-11-13"), rustinelLoss+"\n"+rustinelEnrichLoss+"\n")
	w := New(Config{Enabled: true, RustinelDir: rd})
	w.now = func() time.Time { return time.Date(2026, 11, 13, 10, 2, 0, 0, time.UTC) }
	w.Poll()
	s := w.Snapshot()
	if len(s.Alerts) != 0 {
		t.Fatalf("health alerts are not detections: %+v", s.Alerts)
	}
	if !s.Blind || s.BlindWhy != "etw_session" || s.LostEvents != 37 {
		t.Fatalf("the EDR losing events means detections did not all run: %+v", s)
	}
	w.now = func() time.Time { return time.Date(2026, 11, 13, 10, 30, 0, 0, time.UTC) }
	if w.Snapshot().Blind {
		t.Fatal("blindness is reported only while recent")
	}
}

func TestBadInputIsSkippedAndTextIsCleaned(t *testing.T) {
	wd := t.TempDir()
	huge := `{"indicator":"` + strings.Repeat("a", maxLine) + `"}`
	write(t, filepath.Join(wd, "alerts.jsonl"), "not json\n"+huge+"\n{\"indicator\":\"\"}\n"+
		`{"timestamp_utc":"x","indicator":"a\u0007b\nc.example","process_name":"p\u001b[31m.exe","dst_port":99999}`+"\n"+wireLine+"\n")
	w := New(Config{Enabled: true, PacketSentinelDir: wd})
	w.Poll()
	s := w.Snapshot()
	if len(s.Alerts) != 2 {
		t.Fatalf("only the two valid lines count: %d", len(s.Alerts))
	}
	for _, a := range s.Alerts {
		if strings.ContainsAny(a.Remote+a.Process, "\x07\x1b\n") {
			t.Fatalf("control characters must not reach the GUI: %q %q", a.Remote, a.Process)
		}
		if a.Port > 65535 {
			t.Fatal("bad port")
		}
	}
}

func TestLargeExistingFileIsReadFromItsTailOnly(t *testing.T) {
	wd := t.TempDir()
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString(wireLine + "\n")
	}
	write(t, filepath.Join(wd, "alerts.jsonl"), b.String())
	w := New(Config{Enabled: true, PacketSentinelDir: wd})
	w.Poll()
	n := len(w.Snapshot().Alerts)
	if n == 0 || n > maxAlerts || n >= 5000 {
		t.Fatalf("a big old log must not be replayed whole: %d", n)
	}
}

func TestMissingDirectoriesAndConfigRules(t *testing.T) {
	w := New(Config{Enabled: true, RustinelDir: filepath.Join(t.TempDir(), "nope"), PacketSentinelDir: t.TempDir()})
	w.Poll()
	s := w.Snapshot()
	if len(s.Sources) != 2 || s.Sources[0].Found || s.Sources[0].Error == "" || s.Sources[1].Found || s.Sources[1].Error == "" {
		t.Fatalf("a missing file is reported, not hidden: %+v", s.Sources)
	}
	off := New(Config{Enabled: false, RustinelDir: t.TempDir()})
	off.Poll()
	if s := off.Snapshot(); s.Enabled || len(s.Sources) != 0 {
		t.Fatalf("%+v", s)
	}
	for _, bad := range []Config{{Enabled: true}, {RustinelDir: "relative/dir"}, {PacketSentinelDir: "bad\x00"}} {
		if bad.Validate() == nil {
			t.Errorf("%+v must be refused", bad)
		}
	}
	abs := t.TempDir()
	if err := (Config{Enabled: true, RustinelDir: abs}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedHistory(t *testing.T) {
	wd := t.TempDir()
	path := filepath.Join(wd, "alerts.jsonl")
	write(t, path, "")
	w := New(Config{Enabled: true, PacketSentinelDir: wd})
	w.Poll()
	for i := 0; i < 3; i++ {
		var b strings.Builder
		for j := 0; j < 400; j++ {
			b.WriteString(wireLine + "\n")
		}
		appendTo(t, path, b.String())
		w.Poll()
	}
	if n := len(w.Snapshot().Alerts); n != maxAlerts {
		t.Fatalf("history is capped at %d, got %d", maxAlerts, n)
	}
}
