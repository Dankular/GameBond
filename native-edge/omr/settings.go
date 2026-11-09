// Package omr is the Go port of the OpenMPTCProuter leg. This file is
// gamebond/omr_settings.py: validated `server_type` and `omr` configuration.
package omr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Admin is a validated omr.admin login (the password is only a file reference).
type Admin struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	PasswordFile string `json:"password_file"`
	Pin          string `json:"pin"`
}

// Settings is OmrSettings.
type Settings struct {
	Server       [2]any // host string, port int
	KeyFile      string
	Admin        *Admin
	TunnelIP     string
	TunnelIPSet  bool
	RateMbps     float64
	BeatMS       int
	GamebondDSCP []int
}

// ServerHost and ServerPort are the typed view of Server.
func (s Settings) ServerHost() string { return s.Server[0].(string) }
func (s Settings) ServerPort() int    { return s.Server[1].(int) }

var pinRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// ParseConfig decodes JSON keeping integers distinguishable from floats, as
// Python's `type(x) is int` checks require.
func ParseConfig(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// isInt mirrors `type(v) is int` for decoded JSON (bool and floats excluded).
func isInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

func isNumber(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	return f, err == nil
}

// ipv4 mirrors ipaddress.IPv4Address(x): dotted quad without leading zeros,
// or an integer 0..2^32-1 (bools count as ints in Python).
func ipv4(v any) (netip.Addr, error) {
	switch x := v.(type) {
	case string:
		a, err := netip.ParseAddr(x)
		if err != nil || !a.Is4() || strings.Contains(x, "%") {
			return netip.Addr{}, fmt.Errorf("invalid IPv4 address %q", x)
		}
		return a, nil
	case bool:
		n := uint32(0)
		if x {
			n = 1
		}
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), nil
	case json.Number:
		i, ok := isInt(x)
		if !ok || i < 0 || i > math.MaxUint32 {
			return netip.Addr{}, errors.New("invalid IPv4 address")
		}
		n := uint32(i)
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), nil
	}
	return netip.Addr{}, errors.New("invalid IPv4 address")
}

func unusable(a netip.Addr) bool {
	return a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

func nonEmptyString(v any, max int) (string, bool) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" || len(([]rune(s))) > max {
		return "", false
	}
	return s, true
}

func loadAdmin(raw any, serverHost string) (*Admin, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("omr.admin needs username, password_file and pin (optional: host, port)")
	}
	for k := range m {
		switch k {
		case "host", "port", "username", "password_file", "pin":
		default:
			return nil, errors.New("omr.admin needs username, password_file and pin (optional: host, port)")
		}
	}
	for _, k := range []string{"username", "password_file", "pin"} {
		if _, ok := m[k]; !ok {
			return nil, errors.New("omr.admin needs username, password_file and pin (optional: host, port)")
		}
	}
	var hostV any = serverHost
	if h, ok := m["host"]; ok {
		hostV = h
	}
	host, err := ipv4(hostV)
	if err != nil {
		return nil, err
	}
	if unusable(host) {
		return nil, errors.New("omr.admin.host must be a usable unicast IPv4 address")
	}
	port := int64(65500)
	if p, ok := m["port"]; ok {
		pi, ok := isInt(p)
		if !ok || pi < 1 || pi > 65535 {
			return nil, errors.New("omr.admin.port must be 1..65535")
		}
		port = pi
	}
	for _, k := range []string{"username", "password_file", "pin"} {
		if _, ok := nonEmptyString(m[k], 512); !ok {
			return nil, fmt.Errorf("omr.admin.%s must be a non-empty string", k)
		}
	}
	pin := strings.TrimPrefix(strings.TrimSpace(m["pin"].(string)), "sha256//")
	if !pinRe.MatchString(pin) {
		return nil, errors.New("omr.admin.pin must be the base64 SHA-256 of the server's public key")
	}
	return &Admin{Host: host.String(), Port: int(port), Username: m["username"].(string), PasswordFile: m["password_file"].(string), Pin: pin}, nil
}

// LoadServerMode is load_server_mode: it returns the server type and the OMR
// settings (nil for "gamebond"). config comes from ParseConfig.
func LoadServerMode(config map[string]any) (string, *Settings, error) {
	mode := any("gamebond")
	if v, ok := config["server_type"]; ok {
		mode = v
	}
	modeS, isStr := mode.(string)
	if isStr && modeS == "omr" {
		return "", nil, errors.New("server_type 'omr' alone is not available yet; use 'both' (GameBond tunnel plus OMR) or 'gamebond'")
	}
	if !isStr || (modeS != "gamebond" && modeS != "both") {
		return "", nil, errors.New("server_type must be 'gamebond' or 'both'")
	}
	rawV := config["omr"]
	if modeS == "gamebond" {
		if rawV != nil {
			return "", nil, errors.New("an omr block needs server_type 'both'")
		}
		return modeS, nil, nil
	}
	if role, _ := config["role"].(string); role != "client" {
		return "", nil, errors.New("server_type 'both' belongs to the client configuration")
	}
	raw, ok := rawV.(map[string]any)
	if !ok {
		return "", nil, errors.New("omr needs server and exactly one of key_file or admin")
	}
	for k := range raw {
		switch k {
		case "server", "key_file", "admin", "tunnel_ip", "rate_mbps", "beat_ms", "gamebond_dscp":
		default:
			return "", nil, errors.New("omr needs server and exactly one of key_file or admin")
		}
	}
	_, hasKey := raw["key_file"]
	_, hasAdmin := raw["admin"]
	if _, ok := raw["server"]; !ok || hasKey == hasAdmin {
		return "", nil, errors.New("omr needs server and exactly one of key_file or admin")
	}
	srv, ok := raw["server"].([]any)
	if !ok || len(srv) != 2 {
		return "", nil, errors.New("omr.server must be [IPv4, port]")
	}
	port, ok := isInt(srv[1])
	if !ok || port < 1 || port > 65535 {
		return "", nil, errors.New("omr.server must be [IPv4, port]")
	}
	host, err := ipv4(srv[0])
	if err != nil {
		return "", nil, err
	}
	if unusable(host) {
		return "", nil, errors.New("omr.server must be a usable unicast IPv4 address")
	}
	s := &Settings{Server: [2]any{host.String(), int(port)}, TunnelIP: "10.255.254.2", RateMbps: 100, BeatMS: 100, GamebondDSCP: []int{46, 26}}
	if hasKey {
		kf, ok := raw["key_file"].(string)
		if !ok || kf == "" {
			return "", nil, errors.New("omr.key_file must name a file holding the 64-hex-character Glorytun key")
		}
		s.KeyFile = kf
	}
	if hasAdmin {
		if s.Admin, err = loadAdmin(raw["admin"], host.String()); err != nil {
			return "", nil, err
		}
	}
	var tv any = "10.255.254.2"
	if t, ok := raw["tunnel_ip"]; ok {
		tv, s.TunnelIPSet = t, true
	}
	tunnel, err := ipv4(tv)
	if err != nil {
		return "", nil, err
	}
	if unusable(tunnel) {
		return "", nil, errors.New("omr.tunnel_ip must be a unicast IPv4 address")
	}
	s.TunnelIP = tunnel.String()
	if r, ok := raw["rate_mbps"]; ok {
		f, ok := isNumber(r)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < 0.1 || f > 10000 {
			return "", nil, errors.New("omr.rate_mbps must be between 0.1 and 10000")
		}
		s.RateMbps = f
	}
	if b, ok := raw["beat_ms"]; ok {
		bi, ok := isInt(b)
		if !ok || bi < 10 || bi > 1000 {
			return "", nil, errors.New("omr.beat_ms must be 10..1000")
		}
		s.BeatMS = int(bi)
	}
	if d, ok := raw["gamebond_dscp"]; ok {
		list, ok := d.([]any)
		if !ok {
			return "", nil, errors.New("omr.gamebond_dscp must list DSCP values 0..63")
		}
		s.GamebondDSCP = s.GamebondDSCP[:0]
		for _, v := range list {
			vi, ok := isInt(v)
			if !ok || vi < 0 || vi > 63 {
				return "", nil, errors.New("omr.gamebond_dscp must list DSCP values 0..63")
			}
			s.GamebondDSCP = append(s.GamebondDSCP, int(vi))
		}
	}
	return modeS, s, nil
}
