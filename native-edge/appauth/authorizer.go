// Package appauth is userspace.py's application authorization: the netstack
// asks (app_authorization_request) whether a captured process may use the
// tunnel; a worker resolves the process, evaluates the policy file and answers.
package appauth

import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"time"

	"gamebond.local/nativeedge/appevents"
	"gamebond.local/nativeedge/apppolicy"
)

const (
	maxPending = 64
	maxWorkers = 4
	maxRecent  = 32
)

// OwnerRemember is the part of appevents.Store the authorizer feeds.
type OwnerRemember interface{ RememberAuthorizedOwner(map[string]any) }

var _ OwnerRemember = (*appevents.Store)(nil)

// Authorizer answers authorization requests. Respond sends the
// app_authorization_response object back to the netstack.
type Authorizer struct {
	// Enabled mirrors "capture extension present": without it every request is
	// denied to the bulk profile, as in Python.
	Enabled    bool
	ConfigPath string
	Resolve    appevents.Resolver
	Events     OwnerRemember // may be nil (typically *appevents.Store)
	Respond    func(map[string]any) error
	Clock      func() float64

	slots   chan struct{}
	workers chan struct{}
	wg      sync.WaitGroup

	policyMu sync.Mutex
	policy   *apppolicy.Policy
	stamp    [2]int64
	stamped  bool
	state    map[string]any

	mu     sync.Mutex
	counts map[string]int
	recent []map[string]any
	closed bool
}

// Init sets the authorizer up around the initial policy configuration.
func (a *Authorizer) Init(config any) error {
	p, err := apppolicy.New(config)
	if err != nil {
		return err
	}
	a.policy = p
	a.state = policyState(p)
	a.slots = make(chan struct{}, maxPending)
	a.workers = make(chan struct{}, maxWorkers)
	a.counts = map[string]int{"allowed": 0, "denied": 0, "errors": 0}
	if a.Clock == nil {
		a.Clock = func() float64 { return float64(time.Now().UnixNano()) / 1e9 }
	}
	return nil
}

func policyState(p *apppolicy.Policy) map[string]any {
	snap := p.Snapshot()
	rules, _ := snap["rules"].(map[string]any)
	state := map[string]any{"policy_digest": p.Digest(), "rules_total": len(rules)}
	for k, v := range snap {
		state[k] = v
	}
	bounded := map[string]any{}
	size, truncated := 0, false
	for k, v := range rules {
		raw, _ := json.Marshal(map[string]any{k: v})
		size += len(raw)
		if size > 96*1024 {
			truncated = true
			break
		}
		bounded[k] = v
	}
	state["rules"], state["rules_truncated"] = bounded, truncated
	state["applies_to"], state["existing_connections"] = "new_outbound_connections", "reconnect_to_apply"
	return state
}

// PolicyState is application_policy_state.
func (a *Authorizer) PolicyState() map[string]any {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	return a.state
}

func validID(id any) (string, bool) {
	s, ok := id.(string)
	if !ok || len(s) != 24 {
		return "", false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return s, true
}

func (a *Authorizer) respond(id string, allow bool, profile string) error {
	return a.Respond(map[string]any{"type": "app_authorization_response", "id": id, "allow": allow, "profile": profile})
}

// Handle is queue_authorization: invalid ids are ignored, a disabled
// authorizer or a full queue denies to bulk, otherwise a worker decides.
func (a *Authorizer) Handle(record map[string]any) {
	id, ok := validID(record["id"])
	if !ok {
		return
	}
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if !a.Enabled || closed {
		_ = a.respond(id, false, "bulk")
		return
	}
	select {
	case a.slots <- struct{}{}:
	default:
		_ = a.respond(id, false, "bulk")
		return
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() { <-a.slots }()
		a.workers <- struct{}{}
		defer func() { <-a.workers }()
		a.authorize(id, record)
	}()
}

// Close waits for in-flight decisions and refuses new ones.
func (a *Authorizer) Close() {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	a.wg.Wait()
}

func (a *Authorizer) reload() (*apppolicy.Policy, error) {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	if a.ConfigPath != "" {
		if info, err := os.Stat(a.ConfigPath); err == nil && info.Mode().IsRegular() {
			if info.Size() > apppolicy.MaxConfigBytes {
				return nil, os.ErrInvalid
			}
			stamp := [2]int64{info.ModTime().UnixNano(), info.Size()}
			if !a.stamped || stamp != a.stamp {
				raw, err := os.ReadFile(a.ConfigPath)
				if err != nil {
					return nil, err
				}
				var config any
				if err := json.Unmarshal(raw, &config); err != nil {
					return nil, err
				}
				p, err := apppolicy.New(config)
				if err != nil {
					return nil, err
				}
				a.policy, a.stamp, a.stamped, a.state = p, stamp, true, policyState(p)
			}
		}
	}
	return a.policy, nil
}

func (a *Authorizer) authorize(id string, record map[string]any) {
	decision := apppolicy.Decision{Allow: false, Profile: "bulk", Reason: "authorization_failed"}
	var identity map[string]any
	failed := false
	func() {
		defer func() {
			if recover() != nil {
				failed = true
			}
		}()
		created, _ := record["created_filetime"].(string)
		if pid, isInt := asInt(record["pid"]); a.Resolve != nil && isInt {
			identity = a.Resolve(pid, created)
		}
		policy, err := a.reload()
		if err != nil {
			failed = true
			return
		}
		var app any
		if identity != nil {
			app = identity
		}
		d := policy.Authorize(app, record["protocol"], record["destination"])
		switch d.Profile {
		case "automatic", "bulk", "game", "call", "stream":
		default:
			failed = true
			return
		}
		decision = d
		if identity != nil && d.Allow && a.Events != nil {
			a.Events.RememberAuthorizedOwner(identity)
		}
	}()
	if failed {
		decision = apppolicy.Decision{Allow: false, Profile: "bulk", Reason: "authorization_failed"}
	}
	a.mu.Lock()
	if failed {
		a.counts["errors"]++
	}
	if decision.Allow {
		a.counts["allowed"]++
	} else {
		a.counts["denied"]++
	}
	var app any
	if identity != nil {
		app = identity
	}
	a.recent = append(a.recent, map[string]any{"timestamp": a.Clock(), "application": app,
		"captured_pid": record["pid"], "captured_created_filetime": record["created_filetime"],
		"protocol": record["protocol"], "destination": record["destination"],
		"allow": decision.Allow, "profile": decision.Profile, "reason": decision.Reason})
	if len(a.recent) > maxRecent {
		a.recent = a.recent[len(a.recent)-maxRecent:]
	}
	a.mu.Unlock()
	_ = a.respond(id, decision.Allow, decision.Profile)
}

// Snapshot is authorization_snapshot: counters plus recent decisions bounded
// to 32 KiB of JSON (oldest dropped first).
func (a *Authorizer) Snapshot() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	recent := append([]map[string]any(nil), a.recent...)
	for len(recent) > 0 {
		raw, _ := json.Marshal(recent)
		if len(raw) <= 32*1024 {
			break
		}
		recent = recent[1:]
	}
	if recent == nil {
		recent = []map[string]any{}
	}
	return map[string]any{"allowed": a.counts["allowed"], "denied": a.counts["denied"], "errors": a.counts["errors"], "recent": recent}
}

// asInt is `type(v) is int` for decoded JSON: json.Number integers and Go
// integers pass; floats and bools do not.
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
