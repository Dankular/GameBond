package appconfig

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// allowed reports an error when m holds a key outside names (**kwargs TypeError).
func allowed(m map[string]any, names ...string) error {
	for k := range m {
		ok := false
		for _, n := range names {
			ok = ok || k == n
		}
		if !ok {
			return bad("unexpected field %s", k)
		}
	}
	return nil
}

func oneOf(v any, options ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, o := range options {
		if s == o {
			return true
		}
	}
	return false
}

// rangeNum is `type(v) in (int,float) and isfinite and lo <= v <= hi`.
func rangeNum(v any, lo, hi float64) (float64, bool) {
	f, ok := number(v)
	return f, ok && f >= lo && f <= hi
}

// checkQoS is QoSSettings(**raw).
func checkQoS(m map[string]any) error {
	if err := allowed(m, "enabled", "loss_threshold", "jitter_threshold_ms", "recovery_seconds",
		"call_deadline_ms", "stream_deadline_ms", "game_deadline_ms", "duplicate_mbps"); err != nil {
		return err
	}
	if v, ok := m["enabled"]; ok {
		if _, isB := v.(bool); !isB {
			return bad("QoS enabled must be a boolean")
		}
	}
	vals := map[string]float64{"loss_threshold": .02, "jitter_threshold_ms": 8, "recovery_seconds": 3,
		"call_deadline_ms": 60, "stream_deadline_ms": 120, "game_deadline_ms": 20, "duplicate_mbps": 4}
	for name := range vals {
		if v, ok := m[name]; ok {
			f, fine := number(v)
			if !fine || f <= 0 {
				return bad("Invalid QoS %s", name)
			}
			vals[name] = f
		}
	}
	if vals["loss_threshold"] > 1 || vals["recovery_seconds"] > 60 || vals["duplicate_mbps"] > 1000 {
		return bad("QoS settings out of range")
	}
	for _, name := range []string{"call_deadline_ms", "stream_deadline_ms", "game_deadline_ms"} {
		if vals[name] < 1 || vals[name] > 2000 {
			return bad("QoS deadline must be 1..2000ms")
		}
	}
	return nil
}

func checkEndpoint(raw any) (string, int64, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return "", 0, bad("endpoint must be an object")
	}
	if err := allowed(m, "mode", "port", "ca_file", "server_name"); err != nil {
		return "", 0, err
	}
	mode, hasMode := m["mode"].(string)
	port, isInt64 := isInt(m["port"])
	if !hasMode || !isInt64 {
		return "", 0, bad("Invalid stream endpoint")
	}
	if !oneOf(mode, "tcp", "tls", "https") || port < 1 || port > 65535 {
		return "", 0, bad("Invalid stream endpoint")
	}
	if mode != "tcp" {
		if s, isStr := m["ca_file"].(string); !isStr || s == "" {
			return "", 0, bad("TLS/HTTPS need a trusted CA file")
		}
	}
	if v, ok := m["server_name"]; ok && v != nil {
		s, isStr := v.(string)
		if !isStr || len([]rune(s)) > 253 || strings.ContainsRune(s, 0) {
			return "", 0, bad("Invalid TLS server name")
		}
	}
	return mode, port, nil
}

// checkOuter is OuterSettings(**raw).
func checkOuter(m map[string]any) error {
	if err := allowed(m, "endpoints", "fallback_after", "recovery_interval", "queue_packets"); err != nil {
		return err
	}
	eps, ok := m["endpoints"].([]any)
	if !ok || len(eps) < 1 || len(eps) > 3 {
		return bad("Configure one to three fallback endpoints")
	}
	seen := map[string]bool{}
	for _, e := range eps {
		mode, port, err := checkEndpoint(e)
		if err != nil {
			return err
		}
		k := mode + ":" + strconv.FormatInt(port, 10)
		if seen[k] {
			return bad("Duplicate fallback endpoint")
		}
		seen[k] = true
	}
	for _, name := range []string{"fallback_after", "recovery_interval"} {
		if v, ok := m[name]; ok {
			if _, fine := rangeNum(v, .1, 300); !fine {
				return bad("Invalid carrier timer")
			}
		}
	}
	if v, ok := m["queue_packets"]; ok {
		if i, isI := isInt(v); !isI || i < 1 || i > 128 {
			return bad("Invalid carrier queue bound")
		}
	}
	return nil
}

const spaces = " \t\n\v\f\r"

// inetAton is socket.inet_aton as CPython builds it on Windows (inet_addr:
// the glibc inet_aton grammar, text after whitespace ignored, 0xFFFFFFFF only
// accepted when spelled 255.255.255.255).
func inetAton(s string) bool {
	if strings.ContainsRune(s, 0) {
		return false
	}
	var parts []uint64
	i := 0
	for {
		base := uint64(10)
		digits := 0
		if i < len(s) && s[i] == '0' {
			base = 8
			digits = 1
			i++
			if i < len(s) && (s[i] == 'x' || s[i] == 'X') {
				base = 16
				digits = 0
				i++
			}
		}
		var val uint64
	scan:
		for i < len(s) {
			c := s[i]
			d := uint64(99)
			switch {
			case c >= '0' && c <= '9':
				d = uint64(c - '0')
			case base == 16 && c >= 'a' && c <= 'f':
				d = uint64(c-'a') + 10
			case base == 16 && c >= 'A' && c <= 'F':
				d = uint64(c-'A') + 10
			}
			if d >= base {
				break scan
			}
			val = val*base + d
			if val > math.MaxUint32 {
				return false
			}
			digits++
			i++
		}
		if digits == 0 {
			return false
		}
		parts = append(parts, val)
		if i < len(s) && s[i] == '.' {
			if len(parts) == 4 {
				return false
			}
			i++
			continue
		}
		break
	}
	if i < len(s) && !strings.ContainsRune(spaces, rune(s[i])) {
		return false
	}
	last := parts[len(parts)-1]
	for _, p := range parts[:len(parts)-1] {
		if p > 255 {
			return false
		}
	}
	if last >= uint64(1)<<(8*uint(5-len(parts))) {
		return false
	}
	var addr uint64
	for k, p := range parts[:len(parts)-1] {
		addr |= p << (24 - 8*uint(k))
	}
	addr |= last
	if addr == math.MaxUint32 {
		const full = "255.255.255.255"
		return s == full
	}
	return true
}

// checkRelay is RelaySettings(**raw), returning its bind for the duplicate check.
func checkRelay(raw any) (string, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return "", bad("relay must be an object")
	}
	if err := allowed(m, "bind", "mode", "cert_file", "key_file", "max_clients"); err != nil {
		return "", err
	}
	bind, hasBind := m["bind"]
	if !hasBind {
		return "", bad("bind is required")
	}
	mode := "tls"
	if v, ok := m["mode"]; ok {
		if !oneOf(v, "tcp", "tls", "https") {
			return "", bad("Invalid relay mode")
		}
		mode = v.(string)
	}
	l, isList := bind.([]any)
	if !isList || len(l) != 2 {
		return "", bad("Invalid relay bind")
	}
	host, isStr := l[0].(string)
	if !isStr || !inetAton(host) {
		return "", bad("illegal IP address string")
	}
	if p, isI := isInt(l[1]); !isI || p < 1 || p > 65535 {
		return "", bad("Invalid relay port")
	}
	if mode != "tcp" {
		for _, k := range []string{"cert_file", "key_file"} {
			if s, isS := m[k].(string); !isS || s == "" {
				return "", bad("TLS relay requires server certificate and private key files")
			}
		}
	}
	if v, ok := m["max_clients"]; ok {
		if i, isI := isInt(v); !isI || i < 1 || i > 32 {
			return "", bad("Invalid relay client bound")
		}
	}
	enc, _ := json.Marshal(bind)
	return string(enc), nil
}

func checkLinkPolicy(m map[string]any) error {
	if err := allowed(m, "role", "upload_mbps", "download_mbps", "daily_bytes", "monthly_bytes",
		"reset_day", "overlimit", "overlimit_mbps"); err != nil {
		return err
	}
	if v, ok := m["role"]; ok && !oneOf(v, "primary", "secondary", "backup", "never") {
		return bad("Invalid link role")
	}
	for _, k := range []string{"upload_mbps", "download_mbps", "overlimit_mbps"} {
		if v, ok := m[k]; ok {
			if _, fine := rangeNum(v, 0, 10000); !fine {
				return bad("Link rates must be finite values from 0 to 10000 Mbps")
			}
		}
	}
	for _, k := range []string{"daily_bytes", "monthly_bytes"} {
		if v, ok := m[k]; ok {
			if i, isI := isInt(v); !isI || i < 0 || i > 1e16 {
				return bad("Invalid link data cap")
			}
		}
	}
	if v, ok := m["reset_day"]; ok {
		if i, isI := isInt(v); !isI || i < 1 || i > 31 {
			return bad("Billing reset day must be 1..31")
		}
	}
	if v, ok := m["overlimit"]; ok && !oneOf(v, "stop", "throttle") {
		return bad("Invalid overlimit behavior")
	}
	if m["overlimit"] == "throttle" {
		f := .2
		if v, ok := m["overlimit_mbps"]; ok {
			f, _ = number(v)
		}
		if f == 0 {
			return bad("Overlimit throttle must be positive")
		}
	}
	return nil
}

// checkSections runs the QoS, outer, relay and link-policy checks in
// load_config order.
func checkSections(config map[string]any, role string) error {
	if v, ok := config["adaptive_qos"]; ok {
		m, isMap := v.(map[string]any)
		if !isMap {
			return bad("adaptive_qos must be an object")
		}
		if err := checkQoS(m); err != nil {
			return err
		}
	}
	if v, ok := config["outer_transport"]; ok && v != nil {
		if role != "client" {
			return bad("Outer fallback belongs to the client")
		}
		m, isMap := v.(map[string]any)
		if !isMap {
			return bad("outer_transport must be an object")
		}
		if err := checkOuter(m); err != nil {
			return err
		}
	}
	if v, ok := config["stream_relays"]; ok {
		l, isList := v.([]any)
		if !isList || len(l) > 3 || (len(l) > 0 && role != "server") {
			return bad("Invalid server stream relays")
		}
		seen := map[string]bool{}
		for _, r := range l {
			b, err := checkRelay(r)
			if err != nil {
				return err
			}
			seen[b] = true
		}
		if len(seen) != len(l) {
			return bad("Duplicate relay listener")
		}
	}
	if v, ok := config["link_policies"]; ok {
		m, isMap := v.(map[string]any)
		if !isMap || len(m) > 64 {
			return bad("Invalid link policies")
		}
		for k, p := range m {
			pm, isObj := p.(map[string]any)
			if !isDigitString(k) || digitsValue(k) <= 0 || !isObj {
				return bad("Invalid link policy adapter")
			}
			if err := checkLinkPolicy(pm); err != nil {
				return err
			}
		}
	}
	return nil
}
