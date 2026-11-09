package appauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type sink struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (s *sink) send(m map[string]any) error {
	s.mu.Lock()
	s.msgs = append(s.msgs, m)
	s.mu.Unlock()
	return nil
}

func (s *sink) wait(t *testing.T, n int) []map[string]any {
	t.Helper()
	for i := 0; i < 400; i++ {
		s.mu.Lock()
		if len(s.msgs) >= n {
			out := append([]map[string]any(nil), s.msgs...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("only %d of %d responses", len(s.msgs), n)
	return nil
}

const id1, id2 = "000000000000000000000001", "000000000000000000000002"

func ident(path string) map[string]any {
	return map[string]any{"pid": int64(10), "created_at": 1.5, "created_filetime": "133000000000000000", "path": path, "name": "x.exe"}
}

func newAuth(t *testing.T, config any, resolve func(int64, string) map[string]any) (*Authorizer, *sink) {
	t.Helper()
	s := &sink{}
	a := &Authorizer{Enabled: true, Resolve: resolve, Respond: s.send, Clock: func() float64 { return 5 }}
	if err := a.Init(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, s
}

func req(id, proto, dest string) map[string]any {
	return map[string]any{"type": "app_authorization_request", "id": id, "pid": json.Number("10"),
		"created_filetime": "133000000000000000", "protocol": proto, "destination": dest}
}

func TestDecisionsFollowPolicyAndIdentity(t *testing.T) {
	cfg := map[string]any{"default_app_profile": "streaming", "app_rules": map[string]any{
		`C:\Games\cod.exe`: map[string]any{"outbound": "allow", "profile": "gaming"},
		`C:\Bad\bad.exe`:   map[string]any{"outbound": "block", "profile": "bulk"}}}
	path := `C:\Games\cod.exe`
	a, s := newAuth(t, cfg, func(int64, string) map[string]any { return ident(path) })
	a.Handle(req(id1, "udp", "1.2.3.4:5"))
	got := s.wait(t, 1)[0]
	if got["allow"] != true || got["profile"] != "game" || got["type"] != "app_authorization_response" || got["id"] != id1 {
		t.Fatalf("%v", got)
	}
	path = `C:\Bad\bad.exe`
	a.Handle(req(id2, "tcp", "1.2.3.4:5"))
	if got := s.wait(t, 2)[1]; got["allow"] != false {
		t.Fatalf("blocked app allowed: %v", got)
	}
	snap := a.Snapshot()
	if snap["allowed"] != 1 || snap["denied"] != 1 || snap["errors"] != 0 || len(snap["recent"].([]map[string]any)) != 2 {
		t.Fatalf("%v", snap)
	}
	recent := snap["recent"].([]map[string]any)[0]
	if recent["reason"] != "application_allowed" || recent["captured_pid"] != json.Number("10") {
		t.Fatalf("%v", recent)
	}
	// unverifiable process: protection on -> denied to bulk
	a2, s2 := newAuth(t, map[string]any{}, func(int64, string) map[string]any { return nil })
	a2.Handle(req(id1, "tcp", "1.2.3.4:5"))
	if got := s2.wait(t, 1)[0]; got["allow"] != false || got["profile"] != "bulk" {
		t.Fatalf("%v", got)
	}
	// bad protocol / destination
	a2.Handle(req(id2, "icmp", "1.2.3.4:5"))
	if got := s2.wait(t, 2)[1]; got["allow"] != false {
		t.Fatalf("%v", got)
	}
}

func TestRequestFilteringAndDenyPaths(t *testing.T) {
	a, s := newAuth(t, map[string]any{}, func(int64, string) map[string]any { return ident(`C:\a.exe`) })
	for _, bad := range []any{nil, 5, "short", strings.Repeat("g", 24), strings.Repeat("A", 24), strings.Repeat("a", 25)} {
		a.Handle(map[string]any{"id": bad})
	}
	time.Sleep(50 * time.Millisecond)
	if len(s.msgs) != 0 {
		t.Fatalf("invalid ids were answered: %v", s.msgs)
	}
	a.Enabled = false // no capture extension: deny to bulk, never touch the policy
	a.Handle(req(id1, "tcp", "1.1.1.1:1"))
	got := s.wait(t, 1)[0]
	if got["allow"] != false || got["profile"] != "bulk" {
		t.Fatalf("%v", got)
	}
	if snap := a.Snapshot(); snap["denied"] != 0 || snap["allowed"] != 0 {
		t.Fatalf("disabled path must not count: %v", snap)
	}
}

func TestFailuresAreDeniedAndCounted(t *testing.T) {
	a, s := newAuth(t, map[string]any{}, func(int64, string) map[string]any { panic("boom") })
	a.Handle(req(id1, "tcp", "1.1.1.1:1"))
	got := s.wait(t, 1)[0]
	if got["allow"] != false || got["profile"] != "bulk" {
		t.Fatalf("%v", got)
	}
	if snap := a.Snapshot(); snap["errors"] != 1 || snap["denied"] != 1 {
		t.Fatalf("%v", snap)
	}
}

func TestPendingLimitDeniesOverflow(t *testing.T) {
	gate := make(chan struct{})
	a, s := newAuth(t, map[string]any{}, func(int64, string) map[string]any { <-gate; return nil })
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release) // registered after newAuth's Close, so it runs first: a failing test cannot hang
	for i := 0; i < 64+5; i++ {
		id := strings.Repeat("0", 20) + string(rune('a'+i/16)) + string("0123456789abcdef"[i%16]) + "00"
		a.Handle(req(id[:24], "tcp", "1.1.1.1:1"))
	}
	over := s.wait(t, 5) // the five beyond 64 are denied at once
	for _, m := range over {
		if m["allow"] != false || m["profile"] != "bulk" {
			t.Fatalf("%v", m)
		}
	}
	release()
	s.wait(t, 69)
}

func TestPolicyFileReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "client.json")
	write := func(profile string) {
		raw, _ := json.Marshal(map[string]any{"app_rules": map[string]any{`C:\a.exe`: map[string]any{"outbound": "allow", "profile": profile}}})
		os.WriteFile(cfg, raw, 0o600)
	}
	write("gaming")
	s := &sink{}
	a := &Authorizer{Enabled: true, ConfigPath: cfg, Respond: s.send,
		Resolve: func(int64, string) map[string]any { return ident(`C:\a.exe`) }}
	if err := a.Init(map[string]any{}); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.Handle(req(id1, "tcp", "1.1.1.1:1"))
	if got := s.wait(t, 1)[0]; got["profile"] != "game" {
		t.Fatalf("%v", got)
	}
	digest := a.PolicyState()["policy_digest"]
	write("call")
	os.Chtimes(cfg, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	a.Handle(req(id2, "tcp", "1.1.1.1:1"))
	if got := s.wait(t, 2)[1]; got["profile"] != "call" {
		t.Fatalf("policy not reloaded: %v", got)
	}
	if a.PolicyState()["policy_digest"] == digest || a.PolicyState()["rules_total"] != 1 {
		t.Fatalf("state %v", a.PolicyState())
	}
	// a broken file denies and counts an error, then recovery works
	os.WriteFile(cfg, []byte("{not json"), 0o600)
	os.Chtimes(cfg, time.Now().Add(2*time.Hour), time.Now().Add(2*time.Hour))
	a.Handle(req(id1, "tcp", "1.1.1.1:1"))
	if got := s.wait(t, 3)[2]; got["allow"] != false {
		t.Fatalf("%v", got)
	}
	if a.Snapshot()["errors"] != 1 {
		t.Fatalf("%v", a.Snapshot())
	}
}

func TestParsePyInt(t *testing.T) {
	for in, want := range map[string]int64{"12": 12, " 12 ": 12, "+7": 7, "1_000": 1000} {
		if got, err := parsePyInt(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "_1", "1_", "1__0", "x", "1.5"} {
		if _, err := parsePyInt(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

type owners struct {
	mu   sync.Mutex
	seen []map[string]any
}

func (o *owners) RememberAuthorizedOwner(m map[string]any) {
	o.mu.Lock()
	o.seen = append(o.seen, m)
	o.mu.Unlock()
}

func TestAllowedOwnersAreRememberedOnlyWhenAllowed(t *testing.T) {
	cfg := map[string]any{"app_rules": map[string]any{`C:\Bad\bad.exe`: map[string]any{"outbound": "block", "profile": "bulk"}}}
	path := `C:\ok.exe`
	o := &owners{}
	a, s := newAuth(t, cfg, func(int64, string) map[string]any { return ident(path) })
	a.Events = o
	a.Handle(req(id1, "tcp", "1.1.1.1:1"))
	s.wait(t, 1)
	path = `C:\Bad\bad.exe`
	a.Handle(req(id2, "tcp", "1.1.1.1:1"))
	s.wait(t, 2)
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) != 1 || o.seen[0]["path"] != `C:\ok.exe` {
		t.Fatalf("remembered %v", o.seen)
	}
}

func TestRecentIsBoundedTo32(t *testing.T) {
	a, s := newAuth(t, map[string]any{}, func(int64, string) map[string]any { return ident(`C:\a.exe`) })
	for i := 0; i < 40; i++ {
		a.Handle(req(fmt.Sprintf("%024x", i+1), "tcp", "1.1.1.1:1"))
	}
	s.wait(t, 40)
	if n := len(a.Snapshot()["recent"].([]map[string]any)); n != 32 {
		t.Fatalf("recent=%d", n)
	}
	if a.Snapshot()["allowed"] != 40 {
		t.Fatalf("%v", a.Snapshot())
	}
}

func TestNonIntegerPIDIsNotResolved(t *testing.T) {
	calls := 0
	a, s := newAuth(t, map[string]any{}, func(int64, string) map[string]any { calls++; return ident(`C:\a.exe`) })
	r := req(id1, "tcp", "1.1.1.1:1")
	r["pid"] = 10.5
	a.Handle(r)
	if got := s.wait(t, 1)[0]; got["allow"] != false || calls != 0 {
		t.Fatalf("%v calls=%d", got, calls)
	}
}

func TestPolicyStateTruncatesLargeRuleSets(t *testing.T) {
	rules := map[string]any{}
	for i := 0; i < 3000; i++ {
		rules[fmt.Sprintf(`C:\Program Files\Vendor%04d\Application%04d\bin\program.exe`, i, i)] = map[string]any{"outbound": "allow", "profile": "gaming"}
	}
	a, _ := newAuth(t, map[string]any{"app_rules": rules}, nil)
	st := a.PolicyState()
	if st["rules_total"] != 3000 || st["rules_truncated"] != true || len(st["rules"].(map[string]any)) >= 3000 {
		t.Fatalf("total=%v truncated=%v kept=%d", st["rules_total"], st["rules_truncated"], len(st["rules"].(map[string]any)))
	}
	small, _ := newAuth(t, map[string]any{}, nil)
	if small.PolicyState()["rules_truncated"] != false || small.PolicyState()["applies_to"] != "new_outbound_connections" {
		t.Fatalf("%v", small.PolicyState())
	}
}
