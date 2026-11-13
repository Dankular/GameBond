package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sent struct{ msgs []map[string]any }

func (s *sent) respond(v any) error {
	raw, _ := json.Marshal(v)
	var m map[string]any
	json.Unmarshal(raw, &m)
	s.msgs = append(s.msgs, m)
	return nil
}

// decode parses JSON the way the bridge does (numbers as json.Number).
func decode(t *testing.T, text string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func writeRequest(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, speedRequestFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInternetPingEventIsParsed(t *testing.T) {
	n := newNetProbes(t.TempDir(), nil)
	if n.pingStatus() != nil {
		t.Fatal("no pings yet")
	}
	ev := decode(t, `{"type":"internet_ping","at":1700000000,"results":[{"name":"Google","target":"8.8.8.8:443","ms":12.5,"ok":true},{"name":"Microsoft","ok":false,"error":"timed out"}]}`)
	if !n.onEvent(ev) {
		t.Fatal("the event must be consumed")
	}
	st := n.pingStatus().(map[string]any)
	res := st["results"].([]any)
	g, m := res[0].(map[string]any), res[1].(map[string]any)
	if len(res) != 2 || g["name"] != "Google" || g["ms"].(float64) != 12.5 || g["ok"] != true || m["ok"] != false || m["error"] != "timed out" || m["ms"] != nil {
		t.Fatalf("%v", res)
	}
	if n.onEvent(decode(t, `{"type":"something_else"}`)) {
		t.Fatal("unrelated events are not ours")
	}
}

func TestSpeedTestRequestRunsAndTheResultIsKept(t *testing.T) {
	dir := t.TempDir()
	var h sent
	n := newNetProbes(dir, h.respond)
	writeRequest(t, dir, `{"action":"start","id":"abc-123"}`)
	n.poll()
	if len(h.msgs) != 1 || h.msgs[0]["type"] != "speedtest_request" || h.msgs[0]["id"] != "abc-123" {
		t.Fatalf("the helper must be asked once: %v", h.msgs)
	}
	if _, err := os.Stat(filepath.Join(dir, speedRequestFile)); err == nil {
		t.Fatal("the request file must be consumed")
	}
	if st := n.speedStatus(); st["running"] != true || st["phase"] != "starting" {
		t.Fatalf("%v", st)
	}
	n.onEvent(decode(t, `{"type":"speedtest_progress","id":"abc-123","phase":"download","mbps":87.5,"elapsed_s":3.5}`))
	if st := n.speedStatus(); st["phase"] != "download" || st["current_mbps"].(float64) != 87.5 {
		t.Fatalf("%v", st)
	}
	n.onEvent(decode(t, `{"type":"speedtest_progress","id":"someone-else","phase":"upload","mbps":1,"elapsed_s":1}`))
	if st := n.speedStatus(); st["phase"] != "download" {
		t.Fatalf("progress for another test must be ignored: %v", st)
	}
	n.onEvent(decode(t, `{"type":"speedtest_result","id":"abc-123","ok":true,"at":1700000100,"down_mbps":412.5,"up_mbps":38.25,"latency_ms":21.5,"jitter_ms":1.5,"down_bytes":104857600,"up_bytes":20971520,"streams":4,"server":"speed.cloudflare.com"}`))
	st := n.speedStatus()
	last := st["last"].(map[string]any)
	if st["running"] != false || last["down_mbps"].(float64) != 412.5 || last["up_mbps"].(float64) != 38.25 || last["server"] != "speed.cloudflare.com" || st["error"] != nil {
		t.Fatalf("%v", st)
	}
	again := newNetProbes(dir, nil) // a restart keeps the last result
	if l := again.speedStatus()["last"].(map[string]any); l["down_mbps"].(float64) != 412.5 || l["at"].(float64) != 1700000100 {
		t.Fatalf("not restored: %v", l)
	}
}

func TestFailedSpeedTestKeepsTheLastGoodResult(t *testing.T) {
	dir := t.TempDir()
	var h sent
	n := newNetProbes(dir, h.respond)
	n.onEvent(decode(t, `{"type":"speedtest_result","id":"","ok":true,"at":1700000000,"down_mbps":100,"up_mbps":10,"latency_ms":20}`))
	writeRequest(t, dir, `{"action":"start","id":"t2"}`)
	n.poll()
	n.onEvent(decode(t, `{"type":"speedtest_result","id":"t2","ok":false,"error":"latency: connection refused","at":1700000200}`))
	st := n.speedStatus()
	if st["running"] != false || st["last"].(map[string]any)["down_mbps"].(float64) != 100 || st["error"].(map[string]any)["error"] != "latency: connection refused" {
		t.Fatalf("%v", st)
	}
	writeRequest(t, dir, `{"action":"start","id":"t3"}`)
	n.poll()
	if n.speedStatus()["error"] != nil {
		t.Fatal("starting a new test clears the old failure")
	}
}

func TestOnlyOneRequestAtATimeAndBadRequestsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	var h sent
	n := newNetProbes(dir, h.respond)
	for _, body := range []string{`{"action":"start","id":"../../etc"}`, `{"action":"start","id":""}`, `{"action":"start","id":"` + strings.Repeat("a", 65) + `"}`, `not json`, `{"action":"format c:","id":"x"}`} {
		writeRequest(t, dir, body)
		n.poll()
	}
	if len(h.msgs) != 0 || n.speedStatus()["running"] != false {
		t.Fatalf("a malformed request must do nothing: %v", h.msgs)
	}
	writeRequest(t, dir, `{"action":"start","id":"first"}`)
	n.poll()
	writeRequest(t, dir, `{"action":"start","id":"second"}`)
	n.poll()
	if len(h.msgs) != 1 || h.msgs[0]["id"] != "first" {
		t.Fatalf("a second request while one runs must be ignored: %v", h.msgs)
	}
}

func TestOldRequestFilesAreNotActedOn(t *testing.T) {
	dir := t.TempDir()
	var h sent
	n := newNetProbes(dir, h.respond)
	writeRequest(t, dir, `{"action":"start","id":"stale"}`)
	old := time.Now().Add(-5 * time.Minute)
	os.Chtimes(filepath.Join(dir, speedRequestFile), old, old)
	n.poll()
	if len(h.msgs) != 0 {
		t.Fatalf("a leftover request from before a restart must not start a test: %v", h.msgs)
	}
	if _, err := os.Stat(filepath.Join(dir, speedRequestFile)); err == nil {
		t.Fatal("but it must be removed")
	}
}

func TestStuckSpeedTestIsCleared(t *testing.T) {
	dir := t.TempDir()
	var h sent
	n := newNetProbes(dir, h.respond)
	clock := time.Now()
	n.now = func() time.Time { return clock }
	writeRequest(t, dir, `{"action":"start","id":"stuck"}`)
	n.poll()
	clock = clock.Add(speedStaleAfter + time.Second)
	n.poll()
	st := n.speedStatus()
	if st["running"] != false || st["error"] == nil {
		t.Fatalf("a helper that never answers must not leave the widget waiting: %v", st)
	}
}

func TestCancelIsForwardedAndAHelperErrorIsReported(t *testing.T) {
	dir := t.TempDir()
	var h sent
	n := newNetProbes(dir, h.respond)
	writeRequest(t, dir, `{"action":"cancel"}`)
	n.poll()
	if len(h.msgs) != 1 || h.msgs[0]["type"] != "speedtest_cancel" {
		t.Fatalf("%v", h.msgs)
	}
	bad := newNetProbes(dir, func(any) error { return os.ErrClosed })
	writeRequest(t, dir, `{"action":"start","id":"x"}`)
	bad.poll()
	if st := bad.speedStatus(); st["running"] != false || st["error"] == nil {
		t.Fatalf("%v", st)
	}
}
