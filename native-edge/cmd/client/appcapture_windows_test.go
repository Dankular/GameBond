//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func ownCreated(t *testing.T) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(int64(c.HighDateTime)<<32|int64(c.LowDateTime), 10)
}

func TestAppCaptureWithRealProcessIdentity(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"app_rules": map[string]any{
		exe: map[string]any{"outbound": "allow", "profile": "gaming"}}})
	cfg := filepath.Join(dir, "client.json")
	os.WriteFile(cfg, raw, 0o600)

	var mu sync.Mutex
	var replies []map[string]any
	respond := func(m map[string]any) error { mu.Lock(); replies = append(replies, m); mu.Unlock(); return nil }
	waitReply := func(n int) map[string]any {
		for i := 0; i < 400; i++ {
			mu.Lock()
			if len(replies) >= n {
				r := replies[n-1]
				mu.Unlock()
				return r
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("no reply %d", n)
		return nil
	}
	request := func(id string) map[string]any {
		return map[string]any{"type": "app_authorization_request", "id": id, "pid": json.Number(strconv.Itoa(os.Getpid())),
			"created_filetime": ownCreated(t), "protocol": "tcp", "destination": "1.2.3.4:443"}
	}

	// Without the capture extension: denied to bulk, nothing recorded.
	off, err := newAppCapture(false, cfg, filepath.Join(dir, "off.json"), raw, respond)
	if err != nil {
		t.Fatal(err)
	}
	if !off.onEvent(request("000000000000000000000001")) {
		t.Fatal("request not handled")
	}
	if r := waitReply(1); r["allow"] != false || r["profile"] != "bulk" {
		t.Fatalf("%v", r)
	}
	off.close()

	on, err := newAppCapture(true, cfg, filepath.Join(dir, "history.json"), raw, respond)
	if err != nil {
		t.Fatal(err)
	}
	defer on.close()
	on.onEvent(request("000000000000000000000002"))
	if r := waitReply(2); r["allow"] != true || r["profile"] != "game" {
		t.Fatalf("own exe should be allowed as game: %v", r)
	}
	// first use of the tunnel by this process is recorded exactly once
	activity := map[string]any{"type": "app_activity", "proof": "tcp_connect", "protocol": "tcp", "destination": "1.2.3.4:443",
		"pid": json.Number(strconv.Itoa(os.Getpid())), "created_filetime": ownCreated(t)}
	on.onEvent(activity)
	on.onEvent(activity)
	doc := map[string]any{}
	on.status(doc)
	ev := doc["app_events"].(map[string]any)
	events, _ := ev["events"].([]map[string]any)
	if len(events) != 1 {
		t.Fatalf("first-use events: %v", ev)
	}
	if doc["app_attribution"].(map[string]any)["available"] != true {
		t.Fatalf("%v", doc["app_attribution"])
	}
	if a := doc["app_authorization"].(map[string]any); a["allowed"] != 1 {
		t.Fatalf("%v", a)
	}
	if err := on.flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "history.json")); err != nil {
		t.Fatal("history not written:", err)
	}
	if on.onEvent(map[string]any{"type": "something_else"}) {
		t.Error("unrelated record claimed")
	}
}
