// Package nrpt is windows_dns.py: a transactional exact-host NRPT scope for the
// temporary DNS responder. Every planned random identity is journalled before
// it is created and recovered only after both owner processes exit.
//
// The PowerShell worker is the very script Python ships (scope.ps1, extracted
// from windows_dns._POWERSHELL) and receives its request on stdin.
package nrpt

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gamebond.local/nativeedge/omr"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed scope.ps1
var powershell string

// Script is the worker script.
func Script() string { return powershell }

// Error is WindowsDnsError.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }
func fail(format string, a ...any) error {
	return &Error{fmt.Sprintf(format, a...)}
}

var (
	labelRe  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	tokenRe  = regexp.MustCompile(`^[0-9a-f]{24}$`)
	guidRe   = regexp.MustCompile(`^\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$`)
	maxRules = 128
)

// Hostname is _hostname: an exact lowercase ASCII FQDN.
func Hostname(value string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(value), ".")
	if !(len(name) > 1 && len(name) <= 253) || !strings.Contains(name, ".") {
		return "", fail("DNS namespaces must be exact ASCII FQDNs, without wildcards or suffix rules")
	}
	for _, label := range strings.Split(name, ".") {
		if !labelRe.MatchString(label) {
			return "", fail("DNS namespaces must be exact ASCII FQDNs, without wildcards or suffix rules")
		}
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fail("DNS namespace must be a hostname, not an IP address")
	}
	return name, nil
}

// Resolver is _resolver: a usable IPv4 address.
func Resolver(value string) (string, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || !a.Is4() || strings.Contains(value, "%") {
		return "", fail("invalid resolver address")
	}
	if a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return "", fail("DNS resolver must be a usable IPv4 address")
	}
	return a.String(), nil
}

// Rule is one planned NRPT rule.
type Rule struct {
	Namespace string  `json:"namespace"`
	Marker    string  `json:"marker"`
	GUID      *string `json:"guid"`
	Verified  bool    `json:"verified"`
}

// State is the journalled plan.
type State struct {
	ResolverIP string `json:"resolver_ip"`
	Rules      []Rule `json:"rules"`
}

// Process identifies a process instance (pid + creation FILETIME text).
type Process struct {
	PID     int    `json:"pid"`
	Created string `json:"created"`
}

type journal struct {
	Version int      `json:"version"`
	Kind    string   `json:"kind"`
	Owner   *Process `json:"owner"`
	Worker  *Process `json:"worker"`
	State   State    `json:"state"`
}

// Host abstracts the operating system so the protocol is testable without an
// administrator session.
type Host struct {
	RequireAdmin func() error
	// Created returns the creation FILETIME text of pid ("" when it is gone).
	Created func(pid int) (string, error)
	// RunWorker runs the PowerShell worker with the JSON request on stdin.
	RunWorker func(script string, stdin []byte) (stdout, stderr []byte, exitCode int, err error)
	PID       int
}

func (h Host) live(p *Process) bool {
	if p == nil || p.PID <= 0 {
		return false
	}
	created, err := h.Created(p.PID)
	return err == nil && created != "" && created == p.Created
}

// Scope is WindowsDnsScope.
type Scope struct {
	host      Host
	state     State
	dir       string
	path      string
	owner     Process
	active    bool
	closed    bool
	randomHex func(n int) string
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// New is WindowsDnsScope(namespaces, resolver_ip, journal_dir=...).
func New(host Host, namespaces []string, resolver, journalDir string) (*Scope, error) {
	if err := host.RequireAdmin(); err != nil {
		return nil, err
	}
	var names []string
	seen := map[string]bool{}
	for _, v := range namespaces {
		n, err := Hostname(v)
		if err != nil {
			return nil, err
		}
		if len(names)+1 > maxRules {
			return nil, fail("at most 128 DNS namespaces are supported")
		}
		names = append(names, n)
		seen[n] = true
	}
	if len(names) == 0 || len(seen) != len(names) {
		return nil, fail("1..128 distinct DNS namespaces are required")
	}
	ip, err := Resolver(resolver)
	if err != nil {
		return nil, err
	}
	s := &Scope{host: host, dir: journalDir, randomHex: randomHex}
	token := s.randomHex(12)
	s.state.ResolverIP = ip
	for i, n := range names {
		s.state.Rules = append(s.state.Rules, Rule{Namespace: n, Marker: fmt.Sprintf("GameBond-DNS-%s-%d", token, i)})
	}
	s.path = filepath.Join(journalDir, token+".json")
	created, err := host.Created(host.PID)
	if err != nil {
		return nil, err
	}
	s.owner = Process{PID: host.PID, Created: created}
	return s, nil
}

func (s *Scope) saveJournal() error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(journal{Version: 1, Kind: "GameBond-DNS", Owner: &s.owner, State: s.state})
	if err != nil {
		return err
	}
	tmp := s.path[:len(s.path)-len(filepath.Ext(s.path))] + ".tmp-" + randomHex(6)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

type response struct {
	OK             *bool  `json:"ok"`
	State          *State `json:"state"`
	Error          string `json:"error"`
	RollbackErrors []any  `json:"rollback_errors"`
}

func (s *Scope) call(phase string) error {
	if err := s.saveJournal(); err != nil {
		return err
	}
	abs, err := filepath.Abs(s.path)
	if err != nil {
		return err
	}
	request, _ := json.Marshal(map[string]any{"phase": phase, "state": s.state, "owner": s.owner, "journal_path": abs})
	stdout, stderr, code, err := s.host.RunWorker(powershell, request)
	if err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if jerr := json.Unmarshal(bytes.TrimSpace(stdout), &raw); jerr != nil {
		detail := string(stderr)
		if detail == "" {
			detail = string(stdout)
		}
		return fail("DNS %s returned an invalid transcript: %s", phase, detail)
	}
	var resp response
	if json.Unmarshal(raw["ok"], new(bool)) != nil {
		return fail("DNS %s returned an invalid response", phase)
	}
	_ = json.Unmarshal(bytes.TrimSpace(stdout), &resp)
	if st, ok := raw["state"]; ok && len(st) > 0 && st[0] == '{' {
		var ns State
		if json.Unmarshal(st, &ns) == nil {
			s.state = ns
			if err := s.saveJournal(); err != nil {
				return err
			}
		}
	}
	if code != 0 || !*resp.OK {
		msg := resp.Error
		if msg == "" {
			msg = fmt.Sprintf("exit %d", code)
		}
		if len(resp.RollbackErrors) > 0 {
			var parts []string
			for _, e := range resp.RollbackErrors {
				parts = append(parts, fmt.Sprint(e))
			}
			msg += "; rollback errors: " + strings.Join(parts, "; ")
		}
		return fail("DNS %s failed: %s", phase, msg)
	}
	return nil
}

// Activate creates and verifies every rule, rolling back on failure.
func (s *Scope) Activate() error {
	if s.closed {
		return fail("DNS scope is closed")
	}
	if s.active {
		return nil
	}
	if err := recoverDir(s.host, s.dir, s.path); err != nil {
		return err
	}
	err := s.call("activate")
	if err == nil {
		for _, r := range s.state.Rules {
			if !r.Verified {
				err = fail("DNS activation did not verify every owned rule")
				break
			}
		}
	}
	if err == nil {
		s.active = true
		return nil
	}
	if cerr := s.Close(); cerr != nil {
		return fail("%v; cleanup failed: %v", err, cerr)
	}
	return err
}

// Close removes the owned rules and the journal.
func (s *Scope) Close() error {
	if s.closed {
		return nil
	}
	if _, err := os.Stat(s.path); err == nil {
		if err := s.call("close"); err != nil {
			return err
		}
		if err := os.Remove(s.path); err != nil {
			return err
		}
	}
	for i := range s.state.Rules {
		s.state.Rules[i].Verified = false
	}
	s.active, s.closed = false, true
	return nil
}

// Status is WindowsDnsScope.status.
func (s *Scope) Status() (active bool, resolver string, rules []Rule) {
	return s.active, s.state.ResolverIP, append([]Rule(nil), s.state.Rules...)
}

// ReadJournal is _read_journal.
func ReadJournal(path string) (*journal, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Size() > 128*1024 {
		return nil, fail("Refusing symlink or oversized DNS journal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &raw); err != nil {
		return nil, err
	}
	var kind string
	_ = json.Unmarshal(raw["kind"], &kind)
	vtext := strings.TrimSpace(string(raw["version"]))
	vf, verr := strconv.ParseFloat(vtext, 64)
	version := vtext == "true" || (verr == nil && vf == 1)
	var state map[string]json.RawMessage
	if !version || kind != "GameBond-DNS" ||
		json.Unmarshal(raw["state"], &state) != nil || state == nil {
		return nil, fail("Invalid DNS journal")
	}
	rdec := json.NewDecoder(bytes.NewReader(state["resolver_ip"]))
	rdec.UseNumber()
	var rany any
	if err := rdec.Decode(&rany); err != nil {
		return nil, fail("invalid resolver")
	}
	rip, err := omr.IPv4(rany)
	if err != nil {
		return nil, err
	}
	resolver, err := Resolver(rip.String())
	if err != nil {
		return nil, err
	}
	var rules []map[string]json.RawMessage
	if json.Unmarshal(state["rules"], &rules) != nil || len(rules) < 1 || len(rules) > maxRules {
		return nil, fail("Invalid DNS journal rules")
	}
	token := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if !tokenRe.MatchString(token) {
		return nil, fail("Invalid DNS journal token")
	}
	names := map[string]bool{}
	var plan State
	plan.ResolverIP = resolver
	for i, r := range rules {
		var ns, marker string
		if json.Unmarshal(r["namespace"], &ns) != nil {
			return nil, fail("Invalid DNS journal ownership fields")
		}
		name, err := Hostname(ns)
		var verified bool
		var guid *string
		guidOK := true
		if g, has := r["guid"]; has && string(g) != "null" {
			var gs string
			guidOK = json.Unmarshal(g, &gs) == nil && guidRe.MatchString(gs)
			guid = &gs
		}
		if err != nil {
			return nil, err
		}
		if name != ns || names[name] || json.Unmarshal(r["marker"], &marker) != nil ||
			marker != fmt.Sprintf("GameBond-DNS-%s-%d", token, i) ||
			!strictBool(r["verified"], &verified) || !guidOK {
			return nil, fail("Invalid DNS journal ownership fields")
		}
		names[name] = true
		plan.Rules = append(plan.Rules, Rule{Namespace: name, Marker: marker, GUID: guid, Verified: verified})
	}
	j := &journal{Version: 1, Kind: "GameBond-DNS", State: plan}
	for _, key := range []string{"owner", "worker"} {
		v, has := raw[key]
		if !has || string(v) == "null" {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(v, &m) != nil || m == nil {
			return nil, fail("Invalid DNS journal process identity")
		}
		var pid json.Number
		d := json.NewDecoder(bytes.NewReader(m["pid"]))
		d.UseNumber()
		var created string
		if err := d.Decode(&pid); err != nil {
			return nil, fail("Invalid DNS journal process identity")
		}
		n, perr := pid.Int64()
		if perr != nil || n <= 0 || json.Unmarshal(m["created"], &created) != nil {
			return nil, fail("Invalid DNS journal process identity")
		}
		p := &Process{PID: int(n), Created: created}
		if key == "owner" {
			j.Owner = p
		} else {
			j.Worker = p
		}
	}
	if j.Owner == nil {
		return nil, fail("DNS journal has no owner identity")
	}
	return j, nil
}

// CleanupJournal removes the rules of a dead owner's journal.
func CleanupJournal(host Host, path string) error {
	if err := host.RequireAdmin(); err != nil {
		return err
	}
	rec, err := ReadJournal(path)
	if err != nil {
		return err
	}
	if host.live(rec.Owner) || host.live(rec.Worker) {
		return fail("DNS journal belongs to a live process: %s", path)
	}
	created, err := host.Created(host.PID)
	if err != nil {
		return err
	}
	helper := &Scope{host: host, state: rec.State, dir: filepath.Dir(path), path: path,
		owner: Process{PID: host.PID, Created: created}, randomHex: randomHex}
	return helper.Close()
}

func recoverDir(host Host, dir, exclude string) error {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(matches)
	ex, _ := filepath.Abs(exclude)
	for _, p := range matches {
		if abs, _ := filepath.Abs(p); exclude != "" && abs == ex {
			continue
		}
		if err := CleanupJournal(host, p); err != nil {
			return err
		}
	}
	return nil
}

// RecoverJournals is recover_journals(directory).
func RecoverJournals(host Host, dir string) error { return recoverDir(host, dir, "") }

var _ = errors.New

func strictBool(raw json.RawMessage, out *bool) bool {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		*out = true
		return true
	case "false":
		*out = false
		return true
	}
	return false
}
