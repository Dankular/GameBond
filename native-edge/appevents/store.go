// Package appevents is the Go port of gamebond/app_events.py's AppEventStore:
// a bounded first-use ledger of applications that really used the tunnel. It
// never infers usage from a process list; identities come from the capture
// engine's PID/birth time and are bound to a live executable by a Resolver
// (resolve_process is Windows-only and supplied by the caller).
package appevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/apppolicy"
)

// Resolver binds a native-captured PID generation to a live executable. It
// returns nil when the process cannot be verified.
type Resolver func(pid int64, createdFiletime string) map[string]any

// Options mirrors the keyword arguments of AppEventStore.
type Options struct {
	Resolver   Resolver
	Clock      func() float64 // Unix seconds
	AppLimit   int            // 1..4096, 0 = 4096
	EventLimit int            // 1..256, 0 = 256
}

type procKey struct {
	pid     int64
	created string
}

type omap[K comparable, V any] struct {
	keys []K
	m    map[K]V
}

func newOmap[K comparable, V any]() *omap[K, V] { return &omap[K, V]{m: map[K]V{}} }
func (o *omap[K, V]) len() int                  { return len(o.keys) }
func (o *omap[K, V]) get(k K) (V, bool)         { v, ok := o.m[k]; return v, ok }
func (o *omap[K, V]) remove(k K) {
	if _, ok := o.m[k]; !ok {
		return
	}
	delete(o.m, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}
func (o *omap[K, V]) set(k K, v V) { // insert or replace, moving to the end
	o.remove(k)
	o.keys = append(o.keys, k)
	o.m[k] = v
}
func (o *omap[K, V]) values() []V {
	out := make([]V, len(o.keys))
	for i, k := range o.keys {
		out[i] = o.m[k]
	}
	return out
}
func (o *omap[K, V]) popFirst() { o.remove(o.keys[0]) }

type owner struct {
	identity map[string]any
	at       float64
}

// Store is the application first-use ledger.
type Store struct {
	path       string
	resolver   Resolver
	clock      func() float64
	appLimit   int
	eventLimit int

	mu         sync.Mutex
	known      *omap[string, map[string]any]
	events     []map[string]any
	sequence   int64
	unresolved int64
	rejected   int64
	dirty      bool
	processes  *omap[procKey, map[string]any]
	traffic    *omap[procKey, map[string]any]
	skipped    int64
	authorized *omap[procKey, owner]
}

// New opens the store, loading and validating an existing history file.
func New(path string, opt Options) (*Store, error) {
	if opt.AppLimit == 0 {
		opt.AppLimit = 4096
	}
	if opt.EventLimit == 0 {
		opt.EventLimit = 256
	}
	if opt.AppLimit < 1 || opt.AppLimit > 4096 || opt.EventLimit < 1 || opt.EventLimit > 256 {
		return nil, errors.New("Invalid application history limits")
	}
	if opt.Clock == nil {
		opt.Clock = func() float64 { return float64(time.Now().UnixNano()) / 1e9 }
	}
	s := &Store{path: path, resolver: opt.Resolver, clock: opt.Clock, appLimit: opt.AppLimit, eventLimit: opt.EventLimit,
		known: newOmap[string, map[string]any](), processes: newOmap[procKey, map[string]any](), traffic: newOmap[procKey, map[string]any](),
		authorized: newOmap[procKey, owner]()}
	st, err := os.Stat(path)
	if err != nil {
		return s, nil // no history yet
	}
	if st.Size() > 4*1024*1024 {
		return nil, errors.New("Application event history is too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("application event history: %w", err)
	}
	if !equalsOne(rec["version"]) {
		return nil, errors.New("Unsupported application event history")
	}
	known, kok := listOf(rec, "applications")
	events, eok := listOf(rec, "events")
	if !kok || len(known) > opt.AppLimit || !eok || len(events) > opt.EventLimit {
		return nil, errors.New("Invalid application history bounds")
	}
	if seq, has := rec["sequence"]; has {
		v, ok := asInt(seq)
		if !ok || v < 0 {
			return nil, errors.New("Invalid application history sequence")
		}
		s.sequence = v
	}
	for _, item := range known {
		row, ok := item.(map[string]any)
		path, pok := "", false
		if ok {
			path, pok = row["path"].(string)
		}
		if !ok || !pok || !apppolicy.IsAbs(path) {
			return nil, errors.New("Invalid application identity history")
		}
		s.known.set(casefold(path), row)
	}
	var last int64
	for _, item := range events {
		e, ok := item.(map[string]any)
		id, iok := int64(0), false
		if ok {
			id, iok = asInt(e["id"])
		}
		_, aok := map[string]any(nil), false
		if ok {
			_, aok = e["application"].(map[string]any)
		}
		if !ok || !iok || !(last < id && id <= s.sequence) || e["kind"] != "new_app_tunnel_use" || !aok {
			return nil, errors.New("Invalid application event history")
		}
		last = id
	}
	for _, item := range events {
		s.events = append(s.events, item.(map[string]any))
	}
	return s, nil
}

// equalsOne is Python's `v == 1` for a decoded JSON value (1, 1.0 and true).
func equalsOne(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	f, ok := toFloat(v)
	return ok && f == 1
}

func listOf(rec map[string]any, key string) ([]any, bool) {
	v, has := rec[key]
	if !has {
		return nil, true
	}
	l, ok := v.([]any)
	return l, ok
}

// asInt reports whether v is a JSON integer (not a bool or float), like
// `type(v) is int`.
func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := strconv.ParseInt(string(n), 10, 64)
		return i, err == nil
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

func pyLen(s string) int { return len([]rune(s)) }

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Observe accepts an app_activity record produced after identity-authenticated
// tunnel success. It returns the new event, or nil.
func (s *Store) Observe(record map[string]any) map[string]any {
	reject := func() map[string]any {
		s.mu.Lock()
		s.rejected++
		s.mu.Unlock()
		return nil
	}
	dest, dok := record["destination"].(string)
	pid, pidok := asInt(record["pid"])
	created, cok := record["created_filetime"].(string)
	proof, _ := record["proof"].(string)
	protocol, _ := record["protocol"].(string)
	if record == nil || record["type"] != "app_activity" || (proof != "tcp_connect" && proof != "udp_reply") ||
		(protocol != "tcp" && protocol != "udp") || !dok || pyLen(dest) > 512 || !pidok || pid <= 0 ||
		!cok || !isDecimal(created) || pyLen(created) > 20 {
		return reject()
	}
	if (proof == "tcp_connect") != (protocol == "tcp") {
		return reject()
	}
	var identity map[string]any
	if s.resolver != nil {
		identity = s.resolver(pid, created)
	}
	if len(identity) == 0 {
		s.mu.Lock()
		if cached, ok := s.authorized.get(procKey{pid, created}); ok && s.clock()-cached.at <= 30 {
			identity = copyMap(cached.identity)
		}
		s.mu.Unlock()
	}
	if len(identity) == 0 {
		s.mu.Lock()
		s.unresolved++
		s.mu.Unlock()
		return nil
	}
	path, _ := identity["path"].(string)
	key := casefold(path)
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	ipid, _ := asInt(identity["pid"])
	icreated, _ := identity["created_filetime"].(string)
	s.processes.set(procKey{ipid, icreated}, copyMap(identity))
	for s.processes.len() > 512 {
		s.processes.popFirst()
	}
	if previous, ok := s.known.get(key); ok {
		s.known.remove(key)
		if last, _ := toFloat(previous["last_seen"]); now-last >= 60 {
			previous["last_seen"] = now
			s.dirty = true
		}
		s.known.set(key, previous)
		return nil
	}
	s.known.set(key, map[string]any{"path": identity["path"], "name": identity["name"], "first_seen": now, "last_seen": now})
	for s.known.len() > s.appLimit {
		s.known.popFirst()
	}
	s.sequence++
	event := map[string]any{"id": s.sequence, "kind": "new_app_tunnel_use", "timestamp": now, "application": identity,
		"protocol": protocol, "destination": dest, "proof": proof, "attribution": "native_capture_owner_and_tunnel_success"}
	s.events = append(s.events, event)
	if len(s.events) > s.eventLimit {
		s.events = s.events[len(s.events)-s.eventLimit:]
	}
	s.dirty = true
	return copyMap(event)
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' { // str.isdecimal also accepts other scripts; the capture engine only emits ASCII
			return false
		}
	}
	return true
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// RememberAuthorizedOwner preserves a verified owner if its process exits
// while connect completes.
func (s *Store) RememberAuthorizedOwner(identity map[string]any) {
	if len(identity) == 0 {
		return
	}
	pid, _ := asInt(identity["pid"])
	created, _ := identity["created_filetime"].(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorized.set(procKey{pid, created}, owner{copyMap(identity), s.clock()})
	for s.authorized.len() > 512 {
		s.authorized.popFirst()
	}
}

var usageFields = []string{"uploaded_bytes", "downloaded_bytes", "active_connections", "generation"}

// RecordUsage enriches counters for identities already proven by a success event.
func (s *Store) RecordUsage(record map[string]any) {
	rows, rok := record["applications"].([]any)
	s.mu.Lock()
	defer s.mu.Unlock()
	if record == nil || record["type"] != "app_metrics" || !rok || len(rows) > 64 {
		s.rejected++
		return
	}
	skipped := int64(0)
	if v, has := record["skipped_identities"]; !has {
		skipped = 0
	} else if n, ok := asInt(v); ok && n >= 0 {
		skipped = n
	} else {
		skipped = -1
	}
	if skipped >= 0 && skipped > s.skipped {
		s.skipped = skipped
	}
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			s.rejected++
			continue
		}
		pid, pok := asInt(row["pid"])
		birth, bok := row["created_filetime"].(string)
		if !pok || !bok {
			s.rejected++
			continue
		}
		key := procKey{pid, birth}
		identity, ok := s.processes.get(key)
		if !ok {
			continue
		}
		vals := map[string]int64{}
		valid := true
		for _, name := range usageFields {
			n, ok := asInt(row[name])
			if !ok || n < 0 {
				valid = false
				break
			}
			vals[name] = n
		}
		if !valid {
			s.rejected++
			continue
		}
		dests := []any{}
		if d, has := row["destinations"]; has {
			l, ok := d.([]any)
			if !ok || len(l) > 8 {
				s.rejected++
				continue
			}
			good := true
			for _, x := range l {
				if str, ok := x.(string); !ok || pyLen(str) > 512 {
					good = false
				}
			}
			if !good {
				s.rejected++
				continue
			}
			dests = append(dests, l...)
		}
		var old map[string]any
		if previous, had := s.traffic.get(key); had {
			s.traffic.remove(key)
			if g, _ := asInt(previous["generation"]); g == vals["generation"] {
				old = previous
			}
		}
		oldUp, _ := asInt(old["uploaded_bytes"])
		oldDown, _ := asInt(old["downloaded_bytes"])
		deltaUp, deltaDown := max(0, vals["uploaded_bytes"]-oldUp), max(0, vals["downloaded_bytes"]-oldDown)
		entry := copyMap(identity)
		for _, name := range usageFields {
			entry[name] = vals[name]
		}
		entry["destinations"] = dests
		if la, has := row["last_activity"]; has {
			entry["last_activity"] = la
		} else {
			entry["last_activity"] = s.clock()
		}
		s.traffic.set(key, entry)
		for s.traffic.len() > 512 {
			s.traffic.popFirst()
		}
		path, _ := identity["path"].(string)
		if known, ok := s.known.get(casefold(path)); ok && (deltaUp != 0 || deltaDown != 0) {
			u, _ := asInt(known["uploaded_bytes"])
			d, _ := asInt(known["downloaded_bytes"])
			known["uploaded_bytes"], known["downloaded_bytes"] = u+deltaUp, d+deltaDown
			known["last_seen"] = s.clock()
			s.dirty = true
		}
	}
}

// pyDumpsLen is len(json.dumps(v).encode()) as Python computes it.
func pyDumpsLen(v any) int {
	switch x := v.(type) {
	case nil:
		return 4
	case bool:
		if x {
			return 4
		}
		return 5
	case string:
		return len(apppolicy.PyJSONString(x))
	case int:
		return len(strconv.Itoa(x))
	case int64:
		return len(strconv.FormatInt(x, 10))
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			f, _ := x.Float64()
			return len(pyFloatRepr(f))
		}
		return len(x)
	case float64:
		return len(pyFloatRepr(x))
	case []any:
		n := 2
		for i, e := range x {
			if i > 0 {
				n += 2
			}
			n += pyDumpsLen(e)
		}
		return n
	case []map[string]any:
		n := 2
		for i, e := range x {
			if i > 0 {
				n += 2
			}
			n += pyDumpsLen(e)
		}
		return n
	case map[string]any:
		n := 2
		i := 0
		for k, e := range x {
			if i > 0 {
				n += 2
			}
			i++
			n += len(apppolicy.PyJSONString(k)) + 2 + pyDumpsLen(e)
		}
		return n
	}
	return len(fmt.Sprint(v))
}

// TrafficSnapshot is traffic_snapshot(limit).
func (s *Store) TrafficSnapshot(limit int) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.traffic.values()
	n := min(512, max(1, limit))
	if len(all) > n {
		all = all[len(all)-n:]
	}
	rows := make([]map[string]any, len(all))
	for i, r := range all {
		rows[i] = copyMap(r)
	}
	for pyDumpsLen(rows) > 256*1024 && len(rows) > 0 {
		rows = rows[1:]
	}
	known := s.known.values()
	if len(known) > 128 {
		known = known[len(known)-128:]
	}
	totals := make([]map[string]any, len(known))
	for i, r := range known {
		totals[i] = copyMap(r)
	}
	for pyDumpsLen(totals) > 64*1024 && len(totals) > 0 {
		totals = totals[1:]
	}
	return map[string]any{"rows": rows, "tracked_processes": s.traffic.len(), "truncated": len(rows) < s.traffic.len(),
		"skipped_identities": s.skipped, "scope": "current_tunnel_session", "known_totals": totals}
}

// Snapshot is snapshot(after, limit).
func (s *Store) Snapshot(after int64, limit int) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	selected := []map[string]any{}
	for _, e := range s.events {
		if id, _ := asInt(e["id"]); id > after {
			selected = append(selected, copyMap(e))
		}
	}
	count := min(256, max(0, limit))
	if count == 0 {
		selected = nil
	} else if len(selected) > count {
		selected = selected[len(selected)-count:]
	}
	for pyDumpsLen(selected) > 64*1024 && len(selected) > 0 {
		selected = selected[1:]
	}
	var retained any
	if len(s.events) > 0 {
		retained = s.events[0]["id"]
	}
	if selected == nil {
		selected = []map[string]any{}
	}
	return map[string]any{"latest_id": s.sequence, "events": selected, "retained_from": retained,
		"known_applications": s.known.len(), "unresolved_identities": s.unresolved, "rejected_events": s.rejected}
}

// Flush writes the history atomically if it changed.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	encoded := func() ([]byte, error) {
		return json.Marshal(map[string]any{"version": 1, "sequence": s.sequence, "applications": s.known.values(), "events": s.events})
	}
	payload, err := encoded()
	if err != nil {
		return err
	}
	for len(payload) > 4*1024*1024 && (s.known.len() > 0 || len(s.events) > 0) {
		if s.known.len() > 0 {
			s.known.popFirst()
		}
		if len(s.events) > 0 {
			s.events = s.events[1:]
		}
		if payload, err = encoded(); err != nil {
			return err
		}
	}
	tmp := s.path + "." + strconv.FormatInt(time.Now().UnixNano()&0xffffffff, 16) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	_, err = f.Write(payload)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// pyFloatRepr is Python's repr(float): shortest round-trip digits, positional
// notation for decimal exponents -4..15 and scientific otherwise.
func pyFloatRepr(x float64) string {
	if math.IsInf(x, 0) || math.IsNaN(x) {
		return "NaN" // json.dumps writes NaN/Infinity; only the length matters and these never occur
	}
	e := strconv.FormatFloat(x, 'e', -1, 64) // d.ddde±XX
	mant, expPart, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expPart)
	neg := strings.HasPrefix(mant, "-")
	digits := strings.ReplaceAll(strings.TrimPrefix(mant, "-"), ".", "")
	var out string
	switch {
	case exp >= -4 && exp < 16:
		switch {
		case exp < 0:
			out = "0." + strings.Repeat("0", -exp-1) + digits
		case len(digits) <= exp+1:
			out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		default:
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	default:
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		out += fmt.Sprintf("e%s%02d", sign, exp)
	}
	if neg {
		out = "-" + out
	}
	return out
}
