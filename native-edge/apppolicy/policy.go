// Package apppolicy is the Go port of gamebond/app_policy.py: validated
// per-application policies for outbound tunnel flows. It governs the SOCKS
// boundary; it is not a host firewall.
package apppolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxRules       = 4096
	MaxConfigBytes = 4 * 1024 * 1024
)

const uncPrefix = "\\\\?\\UNC\\"

// Profiles maps a configured profile to the traffic class the stack uses.
var Profiles = map[string]string{"automatic": "automatic", "gaming": "game", "streaming": "stream", "call": "call", "bulk": "bulk"}

// ErrPolicy is wrapped by every validation failure.
var ErrPolicy = errors.New("application policy")

func bad(msg string) error { return fmt.Errorf("%w: %s", ErrPolicy, msg) }

// pySpace is Python's str.isspace set: unicode.IsSpace plus the C0 separators.
func pySpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

func pyStrip(s string) string { return strings.TrimFunc(s, pySpace) }

// splitRoot is ntpath.splitroot on code points.
func splitRoot(p []rune) (drive, root, tail []rune) {
	norm := make([]rune, len(p))
	for i, r := range p {
		if r == '/' {
			r = '\\'
		}
		norm[i] = r
	}
	at := func(i int) rune {
		if i < len(norm) {
			return norm[i]
		}
		return -1
	}
	find := func(r rune, from int) int {
		for i := from; i < len(norm); i++ {
			if norm[i] == r {
				return i
			}
		}
		return -1
	}
	if at(0) == '\\' {
		if at(1) == '\\' {
			start := 2
			head := norm
			if len(head) > 8 {
				head = head[:8]
			}
			if strings.ToUpper(string(head)) == uncPrefix {
				start = 8
			}
			index := find('\\', start)
			if index == -1 {
				return p, nil, nil
			}
			index2 := find('\\', index+1)
			if index2 == -1 {
				return p, nil, nil
			}
			return p[:index2], p[index2 : index2+1], p[index2+1:]
		}
		return nil, p[:1], p[1:]
	}
	if at(1) == ':' {
		if at(2) == '\\' {
			return p[:2], p[2:3], p[3:]
		}
		return p[:2], nil, p[2:]
	}
	return nil, nil, p
}

// skipRoot mirrors the C _Py_skiproot that CPython 3.12's ntpath.normpath uses
// (it differs from the pure-Python splitroot for \\?\UNC\ paths). It
// returns the length of the root prefix and whether that prefix is rooted.
func skipRoot(p []rune) (n int, rooted bool) {
	sep := func(i int) bool { return i < len(p) && p[i] == '\\' }
	if sep(0) && sep(1) {
		if len(p) >= 8 && (p[2] == '?' || p[2] == '.') && sep(3) && string(p[4:7]) == "UNC" && sep(7) {
			return 8, true
		}
		i := 2
		for i < len(p) && p[i] != '\\' {
			i++
		}
		if i == len(p) {
			return i, false
		}
		i++
		for i < len(p) && p[i] != '\\' {
			i++
		}
		if i < len(p) {
			i++
		}
		return i, true
	}
	if sep(0) {
		return 1, true
	}
	if len(p) >= 2 && p[1] == ':' {
		if sep(2) {
			return 3, true
		}
		return 2, false
	}
	return 0, false
}

// normPath is ntpath.normpath (the C implementation in CPython 3.12).
func normPath(path string) string {
	p := []rune(strings.ReplaceAll(path, "/", "\\"))
	n, rooted := skipRoot(p)
	prefix := string(p[:n])
	comps := strings.Split(string(p[n:]), "\\")
	i := 0
	for i < len(comps) {
		switch {
		case comps[i] == "" || comps[i] == ".":
			comps = append(comps[:i], comps[i+1:]...)
		case comps[i] == "..":
			if i > 0 && comps[i-1] != ".." {
				comps = append(comps[:i-1], comps[i+1:]...)
				i--
			} else if i == 0 && rooted {
				comps = append(comps[:i], comps[i+1:]...)
			} else {
				i++
			}
		default:
			i++
		}
	}
	if prefix == "" && len(comps) == 0 {
		comps = append(comps, ".")
	}
	return prefix + strings.Join(comps, "\\")
}

// isAbs is ntpath.isabs (including its legacy "\x" behaviour).
func isAbs(s string) bool {
	r := []rune(s)
	if len(r) > 3 {
		r = r[:3]
	}
	for i := range r {
		if r[i] == '/' {
			r[i] = '\\'
		}
	}
	return (len(r) > 0 && r[0] == '\\') || (len(r) > 2 && r[1] == ':' && r[2] == '\\')
}

// normCase is ntpath.normcase on Windows: slashes to backslashes, lower case.
func normCase(s string) string {
	return strings.Map(func(r rune) rune {
		if o, ok := normcaseOverride[r]; ok {
			return o
		}
		return unicode.ToLower(r)
	}, strings.ReplaceAll(s, "/", "\\"))
}

func hasExeSuffix(p string) bool {
	r := []rune(p)
	return len(r) >= 4 && strings.ToLower(string(r[len(r)-4:])) == ".exe"
}

// CanonicalPath is canonical_path. v must be a string.
func CanonicalPath(v any) (string, error) {
	path, ok := v.(string)
	if !ok || path == "" || utf8.RuneCountInString(path) > 32768 || strings.ContainsRune(path, 0) {
		return "", bad("Choose a full executable path")
	}
	path = normPath(pyStrip(path))
	drive, _, _ := splitRoot([]rune(path))
	if len(drive) == 0 || !isAbs(path) || !hasExeSuffix(path) {
		return "", bad("Application rules require a full .exe path")
	}
	return normCase(path), nil
}

// Rule is one validated application rule.
type Rule struct{ Outbound, Profile string }

// NormalizeRule is normalize_rule; v is a decoded JSON object.
func NormalizeRule(v any) (Rule, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Rule{}, bad("Application rules support outbound and profile settings")
	}
	for k := range m {
		if k != "outbound" && k != "profile" {
			return Rule{}, bad("Application rules support outbound and profile settings")
		}
	}
	var out any = "allow"
	if x, ok := m["outbound"]; ok {
		out = x
	}
	var prof any = "automatic"
	if x, ok := m["profile"]; ok {
		prof = x
	}
	if out != "allow" && out != "block" {
		return Rule{}, bad("Outbound must be allow or block")
	}
	ps, ok := prof.(string)
	if _, known := Profiles[ps]; !ok || !known {
		return Rule{}, bad("Unknown application traffic profile")
	}
	return Rule{Outbound: out.(string), Profile: ps}, nil
}

// NormalizeRules is normalize_rules.
func NormalizeRules(v any) (map[string]Rule, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) > MaxRules {
		return nil, bad("Invalid application rule list")
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Python iterates in insertion order; acceptance cannot differ, only which error comes first
	result := make(map[string]Rule, len(m))
	for _, path := range keys {
		key, err := CanonicalPath(path)
		if err != nil {
			return nil, err
		}
		value, err := NormalizeRule(m[path])
		if err != nil {
			return nil, err
		}
		if old, dup := result[key]; dup && old != value {
			return nil, bad("Conflicting rules for the same executable")
		}
		result[key] = value
	}
	return result, nil
}

// Policy is ApplicationPolicy.
type Policy struct {
	Enabled        bool
	DefaultProfile string
	Rules          map[string]Rule
}

// New is PolicyEvaluator(config).
func New(config any) (*Policy, error) {
	m, ok := config.(map[string]any)
	if !ok {
		return nil, bad("Invalid application policy configuration")
	}
	var enabled any = true
	if x, ok := m["protection_enabled"]; ok {
		enabled = x
	}
	var def any = "automatic"
	if x, ok := m["default_app_profile"]; ok {
		def = x
	}
	var rules any = map[string]any{}
	if x, ok := m["app_rules"]; ok {
		rules = x
	}
	e, ok := enabled.(bool)
	if !ok {
		return nil, bad("Protection enabled must be a boolean")
	}
	d, ok := def.(string)
	if _, known := Profiles[d]; !ok || !known {
		return nil, bad("Unknown default application profile")
	}
	r, err := NormalizeRules(rules)
	if err != nil {
		return nil, err
	}
	return &Policy{Enabled: e, DefaultProfile: d, Rules: r}, nil
}

// Decision is the result of Authorize.
type Decision struct {
	Allow   bool
	Profile string
	Reason  string
}

// Authorize is ApplicationPolicy.authorize. application is the decoded process
// identity (an object with a "path"), or anything else when unknown.
func (p *Policy) Authorize(application, protocol, destination any) Decision {
	proto, _ := protocol.(string)
	dest, isStr := destination.(string)
	if (proto != "tcp" && proto != "udp") || !isStr || dest == "" || utf8.RuneCountInString(dest) > 512 || strings.ContainsRune(dest, 0) {
		return Decision{false, "bulk", "invalid_connection_context"}
	}
	path, havePath := "", false
	if m, ok := application.(map[string]any); ok {
		if c, err := CanonicalPath(m["path"]); err == nil {
			path, havePath = c, true
		}
	}
	if !havePath {
		return Decision{!p.Enabled, "bulk", "unverified_application"}
	}
	rule, ok := p.Rules[path]
	if !ok {
		rule = Rule{"allow", p.DefaultProfile}
	}
	allowed := !p.Enabled || rule.Outbound == "allow"
	reason := "application_allowed"
	if !p.Enabled {
		reason = "protection_disabled"
	} else if !allowed {
		reason = "application_blocked"
	}
	return Decision{allowed, Profiles[rule.Profile], reason}
}

// Snapshot is snapshot().
func (p *Policy) Snapshot() map[string]any {
	rules := make(map[string]any, len(p.Rules))
	for k, v := range p.Rules {
		rules[k] = map[string]any{"outbound": v.Outbound, "profile": v.Profile}
	}
	return map[string]any{"enabled": p.Enabled, "default_profile": p.DefaultProfile, "rules": rules,
		"scope": "outbound_tunnel_connections", "inbound": "not_exposed"}
}

// pyJSONString is json.dumps for a str (ensure_ascii).
func pyJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r < 0x20 || (r > 0x7e && r < 0x10000):
			fmt.Fprintf(&b, "\\u%04x", r)
		case r >= 0x10000:
			r -= 0x10000
			fmt.Fprintf(&b, "\\u%04x\\u%04x", 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func canonicalJSON(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		return pyJSONString(x)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = pyJSONString(k) + ":" + canonicalJSON(x[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	panic("apppolicy: unsupported snapshot value")
}

// Digest is digest(): SHA-256 of json.dumps(snapshot, sort_keys=True, separators=(',', ':')).
func (p *Policy) Digest() string {
	sum := sha256.Sum256([]byte(canonicalJSON(p.Snapshot())))
	return hex.EncodeToString(sum[:])
}
