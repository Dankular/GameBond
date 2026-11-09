package nrpt

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectors struct {
	Journals []struct {
		Name  string `json:"name"`
		Token string `json:"token"`
		Text  string `json:"text"`
		OK    bool   `json:"ok"`
	} `json:"journals"`
	Hostnames []struct {
		In  string `json:"in"`
		OK  bool   `json:"ok"`
		Out string `json:"out"`
	} `json:"hostnames"`
	Resolvers []struct {
		In  string `json:"in"`
		OK  bool   `json:"ok"`
		Out string `json:"out"`
	} `json:"resolvers"`
}

func loadVectors(t *testing.T) vectors {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.NewDecoder(zr).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPythonVectors(t *testing.T) {
	v := loadVectors(t)
	dir := t.TempDir()
	for _, j := range v.Journals {
		path := filepath.Join(dir, j.Token+".json")
		if err := os.WriteFile(path, []byte(j.Text), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadJournal(path)
		if (err == nil) != j.OK {
			t.Errorf("journal %q: go ok=%v (%v), python ok=%v", j.Name, err == nil, err, j.OK)
		}
	}
	for _, h := range v.Hostnames {
		out, err := Hostname(h.In)
		if (err == nil) != h.OK || (h.OK && out != h.Out) {
			t.Errorf("hostname %q: go (%q, %v), python ok=%v %q", h.In, out, err, h.OK, h.Out)
		}
	}
	for _, r := range v.Resolvers {
		out, err := Resolver(r.In)
		if (err == nil) != r.OK || (r.OK && out != r.Out) {
			t.Errorf("resolver %q: go (%q, %v), python ok=%v %q", r.In, out, err, r.OK, r.Out)
		}
	}
	t.Logf("%d journals, %d hostnames, %d resolvers", len(v.Journals), len(v.Hostnames), len(v.Resolvers))
}

// fakeWorker emulates the PowerShell side of the protocol.
type fakeWorker struct {
	phases   []string
	rules    map[string]string // marker -> guid
	failAdd  bool
	noVerify bool
	script   string
}

func (w *fakeWorker) run(script string, stdin []byte) ([]byte, []byte, int, error) {
	w.script = script
	var req struct {
		Phase string `json:"phase"`
		State State  `json:"state"`
		Owner Process
		Path  string `json:"journal_path"`
	}
	if err := json.Unmarshal(stdin, &req); err != nil {
		return nil, nil, 0, err
	}
	w.phases = append(w.phases, req.Phase)
	if w.rules == nil {
		w.rules = map[string]string{}
	}
	reply := func(ok bool, st State, msg string) ([]byte, []byte, int, error) {
		out, _ := json.Marshal(map[string]any{"ok": ok, "state": st, "error": msg, "rollback_errors": []string{}})
		if !ok {
			return out, nil, 1, nil
		}
		return out, nil, 0, nil
	}
	switch req.Phase {
	case "activate":
		for i := range req.State.Rules {
			if w.failAdd && i == 1 {
				for m := range w.rules {
					delete(w.rules, m)
				}
				return reply(false, req.State, "boom")
			}
			g := "{00000000-0000-0000-0000-00000000000" + string(rune('0'+i)) + "}"
			req.State.Rules[i].GUID = &g
			w.rules[req.State.Rules[i].Marker] = g
			req.State.Rules[i].Verified = !w.noVerify
		}
	case "close":
		for _, r := range req.State.Rules {
			delete(w.rules, r.Marker)
		}
	}
	return reply(true, req.State, "")
}

func testHost(w *fakeWorker, live map[int]string) Host {
	return Host{
		RequireAdmin: func() error { return nil },
		Created:      func(pid int) (string, error) { return live[pid], nil },
		RunWorker:    w.run,
		PID:          4242,
	}
}

func TestScopeLifecycle(t *testing.T) {
	dir := t.TempDir()
	w := &fakeWorker{}
	s, err := New(testHost(w, map[int]string{4242: "77"}), []string{"A.example.com", "b.example.com."}, "10.77.0.2", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	active, resolver, rules := s.Status()
	if !active || resolver != "10.77.0.2" || len(rules) != 2 || rules[0].Namespace != "a.example.com" || !rules[1].Verified || len(w.rules) != 2 {
		t.Fatalf("%v %v %+v %v", active, resolver, rules, w.rules)
	}
	if _, err := ReadJournal(s.path); err != nil {
		t.Fatalf("journal on disk invalid: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path); !os.IsNotExist(err) || len(w.rules) != 0 {
		t.Fatal("close left the journal or rules behind")
	}
	if got := strings.Join(w.phases, ","); got != "activate,close" {
		t.Fatalf("phases %s", got)
	}
	if err := s.Activate(); err == nil {
		t.Fatal("activate after close")
	}
	if !strings.Contains(w.script, "Get-DnsClientNrptRule") {
		t.Fatal("worker script not passed through")
	}
}

func TestActivateFailureRollsBackAndClosesJournal(t *testing.T) {
	dir := t.TempDir()
	w := &fakeWorker{failAdd: true}
	s, _ := New(testHost(w, map[int]string{4242: "77"}), []string{"a.example.com", "b.example.com"}, "10.77.0.2", dir)
	err := s.Activate()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("%v", err)
	}
	if got := strings.Join(w.phases, ","); got != "activate,close" {
		t.Fatalf("phases %s", got)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Fatalf("journal left behind: %v", left)
	}

	w2 := &fakeWorker{noVerify: true}
	s2, _ := New(testHost(w2, map[int]string{4242: "77"}), []string{"a.example.com"}, "10.77.0.2", dir)
	if err := s2.Activate(); err == nil || !strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("unverified activation accepted: %v", err)
	}
	if len(w2.rules) != 0 {
		t.Fatal("rules not removed after unverified activation")
	}
}

func TestRecoveryOnlyAfterOwnersExit(t *testing.T) {
	dir := t.TempDir()
	dead := &fakeWorker{}
	s, _ := New(testHost(dead, map[int]string{4242: "77"}), []string{"a.example.com"}, "10.77.0.2", dir)
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	// owner still alive (same pid, same creation time): another scope must refuse
	w := &fakeWorker{}
	host := testHost(w, map[int]string{4242: "77", 1: "5"})
	host.PID = 1
	s2, _ := New(host, []string{"c.example.com"}, "10.77.0.2", dir)
	if err := s2.Activate(); err == nil || !strings.Contains(err.Error(), "live process") {
		t.Fatalf("live journal recovered: %v", err)
	}
	if len(w.phases) != 0 {
		t.Fatalf("worker ran against a live owner's journal: %v", w.phases)
	}
	// a recycled pid (different creation time) means the owner is gone
	host2 := testHost(w, map[int]string{4242: "99", 1: "5"})
	host2.PID = 1
	s3, _ := New(host2, []string{"c.example.com"}, "10.77.0.2", dir)
	if err := s3.Activate(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.phases, ","); got != "close,activate" {
		t.Fatalf("phases %s", got)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(left) != 1 {
		t.Fatalf("expected only the new scope's journal: %v", left)
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	w := &fakeWorker{}
	h := testHost(w, map[int]string{4242: "1"})
	for name, c := range map[string]struct {
		names    []string
		resolver string
	}{
		"empty":     {nil, "10.77.0.2"},
		"duplicate": {[]string{"a.example.com", "A.example.com."}, "10.77.0.2"},
		"wildcard":  {[]string{"*.example.com"}, "10.77.0.2"},
		"resolver":  {[]string{"a.example.com"}, "0.0.0.0"},
	} {
		if _, err := New(h, c.names, c.resolver, t.TempDir()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	many := make([]string, 129)
	for i := range many {
		many[i] = "h" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.com"
	}
	if _, err := New(h, many, "10.77.0.2", t.TempDir()); err == nil {
		t.Error("129 namespaces accepted")
	}
	h.RequireAdmin = func() error { return errors.New("not admin") }
	if _, err := New(h, []string{"a.example.com"}, "10.77.0.2", t.TempDir()); err == nil {
		t.Error("non-admin accepted")
	}
}

func TestActivateTwiceIsNoop(t *testing.T) {
	w := &fakeWorker{}
	s, _ := New(testHost(w, map[int]string{4242: "77"}), []string{"a.example.com"}, "10.77.0.2", t.TempDir())
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(); err != nil {
		t.Fatal(err)
	}
	if len(w.phases) != 1 {
		t.Fatalf("second Activate ran the worker again: %v", w.phases)
	}
}

func TestLiveWorkerBlocksRecovery(t *testing.T) {
	dir := t.TempDir()
	token := "0123456789abcdef01234567"
	rec := `{"version":1,"kind":"GameBond-DNS","owner":{"pid":10,"created":"1"},"worker":{"pid":11,"created":"2"},` +
		`"state":{"resolver_ip":"10.77.0.2","rules":[{"namespace":"a.example.com","marker":"GameBond-DNS-` + token + `-0","guid":null,"verified":false}]}}`
	if err := os.WriteFile(filepath.Join(dir, token+".json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &fakeWorker{}
	// owner is gone (pid 10 unknown), worker pid 11 still runs with the same creation time
	host := testHost(w, map[int]string{11: "2", 99: "5"})
	host.PID = 99
	if err := RecoverJournals(host, dir); err == nil || !strings.Contains(err.Error(), "live process") {
		t.Fatalf("live worker did not block recovery: %v", err)
	}
	host = testHost(w, map[int]string{99: "5"})
	host.PID = 99
	if err := RecoverJournals(host, dir); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.phases, ","); got != "close" {
		t.Fatalf("phases %s", got)
	}
}
