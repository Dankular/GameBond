// Package appconfig is the validation half of gamebond/app.py load_config.
//
// Decoded JSON keeps integers as json.Number so Python's `type(x) is int`
// checks stay exact. Sections that already have their own typed Go validator
// elsewhere are NOT checked here; Result.Unchecked lists the ones present in
// the config so the caller can run those validators (currently always empty).
package appconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"unicode"

	"gamebond.local/nativeedge/appevents"
	"gamebond.local/nativeedge/lan"
	"gamebond.local/nativeedge/omr"
)

const (
	MinLinks = 1
	MaxLinks = 8
)

// Options select the platform behaviour of load_config.
type Options struct {
	Windows               bool // os.name == "nt"
	AllowUnavailableLinks bool
}

// Result is the validated configuration facts later stages need.
type Result struct {
	Config    map[string]any
	Unchecked []string // sections present but validated elsewhere
}

func bad(format string, a ...any) error { return fmt.Errorf(format, a...) }

func isInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

// number is `type(v) in (int, float)` (bool excluded) plus math.isfinite.
func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

func boolOpt(m map[string]any, key string, def bool) (bool, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	b, isBool := v.(bool)
	if !isBool {
		return false, bad("%s must be a boolean", key)
	}
	return b, nil
}

func numOpt(m map[string]any, key string, def float64) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return def, true
	}
	return number(v)
}

func hostPort(v any) (any, any, bool) {
	l, ok := v.([]any)
	if !ok || len(l) != 2 {
		return nil, nil, false
	}
	return l[0], l[1], true
}

func isLinkLocal(a netip.Addr) bool {
	b := a.As4()
	return b[0] == 169 && b[1] == 254
}

func isDigitString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// digitsValue is int(s) for a string of Unicode decimal digits, capped.
func digitsValue(s string) int {
	v := 0
	for _, r := range s {
		start := r
		for unicode.IsDigit(start - 1) {
			start--
		}
		d := int(r-start) % 10
		v = v*10 + d
		if v > 1<<20 {
			return 1 << 20
		}
	}
	return v
}

type queuePolicy struct{ priority, replicate bool }

// parseQueuePolicy is QueuePolicy(**raw).
func parseQueuePolicy(raw any) (queuePolicy, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return queuePolicy{}, bad("QueuePolicy needs an object")
	}
	var p queuePolicy
	for k := range m {
		switch k {
		case "priority", "replicate", "max_age_ms", "capacity", "retransmissions":
		default:
			return p, bad("unexpected QueuePolicy field %s", k)
		}
	}
	var ok1, ok2 bool
	if v, has := m["priority"]; has {
		p.priority, ok1 = v.(bool)
		if !ok1 {
			return p, bad("priority and replicate must be booleans")
		}
	}
	if v, has := m["replicate"]; has {
		p.replicate, ok2 = v.(bool)
		if !ok2 {
			return p, bad("priority and replicate must be booleans")
		}
	}
	if v, has := m["max_age_ms"]; has {
		// math.isfinite(True) is fine in Python; a bool is the number 1/0.
		var f float64
		switch x := v.(type) {
		case bool:
			if x {
				f = 1
			}
		default:
			var fine bool
			f, fine = number(v)
			if !fine {
				return p, bad("max_age_ms must be finite and positive")
			}
		}
		if f <= 0 {
			return p, bad("max_age_ms must be finite and positive")
		}
	}
	if v, has := m["capacity"]; has {
		if i, fine := isInt(v); !fine || i <= 0 {
			return p, bad("capacity must be a positive integer")
		}
	}
	if v, has := m["retransmissions"]; has {
		switch x := v.(type) {
		case bool:
			if x {
				return p, bad("transport retransmission is not implemented; use 0")
			}
		case json.Number:
			f, err := strconv.ParseFloat(string(x), 64)
			if err != nil || f != 0 {
				return p, bad("transport retransmission is not implemented; use 0")
			}
		default:
			return p, bad("transport retransmission is not implemented; use 0")
		}
	}
	return p, nil
}

// sessionHexLen is len(bytes.fromhex(s)); ASCII whitespace is allowed between
// bytes but never inside a pair.
func sessionHexLen(s string) (int, error) {
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			i++
			continue
		}
		if i+1 >= len(s) || !isHex(c) || !isHex(s[i+1]) {
			return 0, bad("non-hexadecimal number found in fromhex() arg")
		}
		n++
		i += 2
	}
	return n, nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func tunnelSubnetContains(client, ip netip.Addr) bool {
	a, b := client.As4(), ip.As4()
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2]
}

// Load is load_config on already-read bytes.
func Load(raw []byte, opt Options) (*Result, error) {
	config, err := omr.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, bad("config must be an object")
	}
	return Validate(config, opt)
}

// Validate is load_config on a decoded config (omr.ParseConfig).
func Validate(config map[string]any, opt Options) (*Result, error) {
	res := &Result{Config: config}
	role, _ := config["role"].(string)
	if !has(config, "role") {
		return nil, bad("role")
	}
	if err := checkSections(config, role); err != nil {
		return nil, err
	}
	if role != "client" && role != "server" {
		return nil, bad("role must be client or server")
	}

	bindList, _ := config["bind"].([]any)
	if v, ok := config["bind"]; !ok {
		return nil, bad("bind")
	} else if truthyEmpty(v) || (role == "server" && len(bindList) != 1) {
		return nil, bad("server requires one bind address")
	}
	if bindList == nil {
		return nil, bad("bind must be a list of [host, port]")
	}
	hosts := make([]any, 0, len(bindList))
	for _, b := range bindList {
		h, p, ok := hostPort(b)
		if !ok {
			return nil, bad("bind entries must be [host, port]")
		}
		if _, err := omr.IPv4(h); err != nil {
			return nil, err
		}
		if port, isI := isInt(p); !isI || port < 0 || port > 65535 {
			return nil, bad("invalid bind port")
		}
		hosts = append(hosts, h)
	}

	if role == "client" {
		if err := clientChecks(config, bindList, hosts, opt); err != nil {
			return nil, err
		}
	}

	if v, ok := config["mtu"]; ok {
		if i, isI := isInt(v); !isI || i < 1280 || i > 1400 {
			return nil, bad("inner MTU must be 1280..1400")
		}
	}
	queues := map[string]any{}
	if v, ok := config["queues"]; ok {
		m, isMap := v.(map[string]any)
		if !isMap {
			return nil, bad("queues must be an object")
		}
		queues = m
	}
	for dscp, pol := range queues {
		if !isDigitString(dscp) || digitsValue(dscp) > 63 {
			return nil, bad("DSCP must be 0..63")
		}
		if _, err := parseQueuePolicy(pol); err != nil {
			return nil, err
		}
	}
	redundant, err := boolOpt(config, "redundant_mode", true)
	if err != nil {
		return nil, err
	}
	bonding, err := boolOpt(config, "bonding_mode", false)
	if err != nil {
		return nil, err
	}
	if bonding && redundant {
		return nil, bad("bonding_mode requires redundant_mode=false; gameplay replication belongs in its DSCP queue")
	}
	initial, ok1 := numOpt(config, "bonding_initial_rate_mbps", 1)
	maxRate, ok2 := numOpt(config, "bonding_max_rate_mbps", 100)
	if !ok1 || initial <= 0 || !ok2 || maxRate <= 0 {
		return nil, bad("bonding rates must be finite and positive")
	}
	if initial > maxRate {
		return nil, bad("bonding_initial_rate_mbps must not exceed bonding_max_rate_mbps")
	}
	if f, ok := numOpt(config, "reorder_timeout_ms", 30); !ok || f < 1 || f > 200 {
		return nil, bad("reorder_timeout_ms must be finite and between 1 and 200")
	}
	for _, name := range []string{"loss_tracking", "path_mtu_discovery", "failover_replay"} {
		on, err := boolOpt(config, name, false)
		if err != nil {
			return nil, err
		}
		if on && !bonding {
			return nil, bad("%s requires bonding_mode", name)
		}
	}
	if f, ok := numOpt(config, "repair_deadline_ms", 250); !ok || f < 10 || f > 2000 {
		return nil, bad("repair_deadline_ms must be finite and between 10 and 2000")
	}
	direct, err := boolOpt(config, "direct_priority", true)
	if err != nil {
		return nil, err
	}
	if f, ok := numOpt(config, "bulk_rate_mbps", 0); !ok || f < 0 {
		return nil, bad("bulk_rate_mbps must be finite and nonnegative")
	}
	gameTruthy := false
	if v, ok := config["game_udp_ports"]; ok {
		switch x := v.(type) {
		case []any:
			for _, p := range x {
				if i, isI := isInt(p); !isI || i < 1 || i > 65535 {
					return nil, bad("game_udp_ports must contain ports 1..65535")
				}
			}
			gameTruthy = len(x) > 0
		case string:
			if x != "" {
				return nil, bad("game_udp_ports must contain ports 1..65535")
			}
		case map[string]any:
			if len(x) > 0 {
				return nil, bad("game_udp_ports must contain ports 1..65535")
			}
		default:
			return nil, bad("game_udp_ports must be a list")
		}
	}
	if gameTruthy {
		var game queuePolicy
		if raw, ok := queues["46"]; ok {
			game, _ = parseQueuePolicy(raw)
		}
		if !game.priority || !game.replicate || !direct {
			return nil, bad("game_udp_ports require direct_priority and a priority, replicated DSCP46 queue")
		}
	}
	session, isStr := config["session"].(string)
	if !isStr {
		return nil, bad("session must be hex text")
	}
	if n, err := sessionHexLen(session); err != nil || n != 16 {
		return nil, bad("session must contain 16 random bytes in hex")
	}
	clientIP, err := omr.IPv4(config["client_tunnel_ip"])
	if err != nil {
		return nil, err
	}
	if _, _, err := omr.LoadServerMode(config); err != nil {
		return nil, err
	}
	if err := lanDevices(config, role, clientIP); err != nil {
		return nil, err
	}
	if err := lanTunnelIPs(config, role, clientIP); err != nil {
		return nil, err
	}
	if v, ok := config["admin"]; ok && v != nil {
		if role != "server" {
			return nil, bad("the admin portal belongs to the server configuration")
		}
		if err := checkAdmin(v); err != nil {
			return nil, err
		}
	}
	if err := checkDNS(config, role); err != nil {
		return nil, err
	}
	return res, nil
}

func has(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// truthyEmpty reports `not value` for the bind value (empty list/str/dict,
// null, false, zero).
func truthyEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		return len(x) == 0
	case string:
		return x == ""
	case map[string]any:
		return len(x) == 0
	case bool:
		return !x
	case json.Number:
		f, _ := strconv.ParseFloat(string(x), 64)
		return f == 0
	}
	return false
}

func clientChecks(config map[string]any, bindList, hosts []any, opt Options) error {
	count := len(bindList)
	if count < MinLinks || count > MaxLinks {
		return bad("client requires %d to %d physical adapters", MinLinks, MaxLinks)
	}
	identities, hasIDs := config["interface_ids"]
	if hasIDs && identities == nil {
		hasIDs = false
	}
	stable := false
	if l, ok := identities.([]any); ok && len(l) == count {
		stable = true
		seen := map[string]bool{}
		for _, v := range l {
			s, isStr := v.(string)
			if !isStr || len([]rune(s)) != 38 || s[0] != '{' || s[len(s)-1] != '}' {
				stable = false
				break
			}
			seen[appevents.Casefold(s)] = true
		}
		stable = stable && len(seen) == count
	}
	pinned := false
	if opt.Windows {
		indices, present := config["interface_indices"]
		if !present {
			indices = []any{}
		}
		if l, ok := indices.([]any); ok && len(l) == count {
			pinned = true
			seen := map[int64]bool{}
			for _, v := range l {
				i, isI := isInt(v)
				if !isI || i <= 0 || i >= 1<<24 {
					pinned = false
					break
				}
				seen[i] = true
			}
			pinned = pinned && len(seen) == count
		}
		if !pinned {
			return bad("Windows client needs one distinct positive interface_index per selected link")
		}
	}
	if hasIDs {
		l, ok := identities.([]any)
		if !ok || len(l) != count {
			return bad("interface_ids must contain one stable adapter identifier per selected link")
		}
		present := map[string]bool{}
		n := 0
		for _, v := range l {
			s, isStr := v.(string)
			if !isStr || (s != "" && (len([]rune(s)) != 38 || s[0] != '{' || s[len(s)-1] != '}')) {
				return bad("interface_ids must contain one stable adapter identifier per selected link")
			}
			if s != "" {
				present[appevents.Casefold(s)] = true
				n++
			}
		}
		if len(present) != n {
			return bad("Selected adapter identifiers must be distinct")
		}
	}
	keys := map[string]bool{}
	live := map[string]bool{}
	liveCount := 0
	for _, h := range hosts {
		k := fmt.Sprintf("%T:%v", h, h)
		keys[k] = true
		if s, _ := h.(string); s != "0.0.0.0" {
			live[k] = true
			liveCount++
		}
	}
	repeated := len(keys) != count
	offlineOnly := opt.AllowUnavailableLinks && stable && len(live) == liveCount
	if repeated && !(offlineOnly || (stable && pinned)) {
		return bad("client requires distinct adapter IPv4 addresses or stable pinned Windows adapter identities")
	}
	for _, h := range hosts {
		ip, _ := omr.IPv4(h)
		if ip.IsUnspecified() && opt.AllowUnavailableLinks && stable {
			continue
		}
		if ip.IsUnspecified() || ip.IsLoopback() || isLinkLocal(ip) || ip.IsMulticast() {
			return bad("client paths need usable physical adapter IPv4 addresses")
		}
	}
	peer, ok := config["peer"].([]any)
	if !ok || len(peer) < 2 {
		return bad("peer must be [host, port]")
	}
	pip, err := omr.IPv4(peer[0])
	if err != nil {
		return err
	}
	if pip.IsUnspecified() || pip.IsMulticast() || isLinkLocal(pip) {
		return bad("peer must be a usable unicast IPv4 address")
	}
	if port, isI := isInt(peer[1]); !isI || port < 1 || port > 65535 {
		return bad("invalid peer port")
	}
	return nil
}

func lanDevices(config map[string]any, role string, client netip.Addr) error {
	v, ok := config["lan_devices"]
	if !ok {
		v = []any{}
	}
	l, isList := v.([]any)
	if !isList || len(l) > lan.MaxDevices {
		return bad("lan_devices must be a list of at most %d devices", lan.MaxDevices)
	}
	if len(l) > 0 && role != "client" {
		return bad("lan_devices belong to the client configuration; the server uses lan_tunnel_ips")
	}
	if err := uplinkIterables(config); err != nil {
		return err
	}
	if len(l) == 0 {
		return nil
	}
	var ids []string
	if raw, ok := config["interface_ids"].([]any); ok {
		for _, x := range raw {
			if s, isStr := x.(string); isStr && s != "" {
				ids = append(ids, s)
			}
		}
	}
	var idx []int
	if raw, ok := config["interface_indices"].([]any); ok {
		for _, x := range raw {
			if i, isI := isInt(x); isI {
				idx = append(idx, int(i))
			}
		}
	}
	enc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = lan.LoadDevices(enc, client, ids, idx)
	return err
}

func lanTunnelIPs(config map[string]any, role string, client netip.Addr) error {
	v, ok := config["lan_tunnel_ips"]
	var l []any
	if ok {
		var isList bool
		l, isList = v.([]any)
		if !isList || len(l) > 32 {
			return errors.New("lan_tunnel_ips must be a list of at most 32 addresses")
		}
	}
	seen := map[string]bool{}
	for _, a := range l {
		ip, err := omr.IPv4(a)
		if err != nil {
			return err
		}
		b := ip.As4()
		if !tunnelSubnetContains(client, ip) || b[3] == 0 || b[3] == 1 || b[3] == 255 || ip == client {
			return bad("%s is not a usable device address", ip)
		}
		seen[fmt.Sprintf("%T:%v", a, a)] = true
	}
	if len(seen) != len(l) {
		return errors.New("lan_tunnel_ips must be distinct")
	}
	if role == "client" && len(l) > 0 {
		return errors.New("lan_tunnel_ips belong to the server configuration; the client uses lan_devices")
	}
	return nil
}

// uplinkIterables reproduces the unconditional iteration load_lan_devices does
// over interface_ids (casefold of each truthy item) and interface_indices
// (set(...)): null, numbers and unhashable items fail even with no devices.
func uplinkIterables(config map[string]any) error {
	ids, has := config["interface_ids"]
	if !has {
		ids = []any{}
	}
	switch x := ids.(type) {
	case []any:
		for _, v := range x {
			if truthyEmpty(v) {
				continue
			}
			if _, isStr := v.(string); !isStr {
				return bad("interface_ids items must be strings")
			}
		}
	case string, map[string]any:
	default:
		return bad("interface_ids is not iterable")
	}
	idx, has := config["interface_indices"]
	if !has {
		idx = []any{}
	}
	switch x := idx.(type) {
	case []any:
		for _, v := range x {
			switch v.(type) {
			case []any, map[string]any:
				return bad("unhashable interface_indices item")
			}
		}
	case string, map[string]any:
	default:
		return bad("interface_indices is not iterable")
	}
	return nil
}
