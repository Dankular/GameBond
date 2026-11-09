package dns

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"
)

// Config is a validated DNS profile (DNSConfig in Python).
type Config struct {
	Enabled  bool
	Records  map[string]map[string][]netip.Addr // name -> "A"/"AAAA" -> addresses
	Bind     netip.AddrPort
	TTL      int
	Upstream *netip.AddrPort
	Workers  int
	Pending  int
	Timeout  time.Duration
}

type rawConfig struct {
	Enabled  *bool                          `json:"enabled"`
	Records  map[string]map[string][]string `json:"records"`
	Bind     []any                          `json:"bind"`
	TTL      *int                           `json:"ttl"`
	Upstream []any                          `json:"upstream"`
	Workers  *int                           `json:"workers"`
	Pending  *int                           `json:"pending"`
	Timeout  *float64                       `json:"timeout"`
}

// Load parses and validates a "dns" config object. null yields nil.
func Load(raw []byte) (*Config, error) {
	if string(raw) == "null" || len(raw) == 0 {
		return nil, nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, errors.New("DNS configuration must be an object")
	}
	for k := range probe {
		switch k {
		case "enabled", "records", "bind", "ttl", "upstream", "workers", "pending", "timeout":
		default:
			return nil, errors.New("unknown DNS configuration option")
		}
	}
	var r rawConfig
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid DNS configuration: %w", err)
	}
	c := &Config{Enabled: true, Bind: netip.MustParseAddrPort("10.77.0.2:53"), TTL: 15, Workers: 4, Pending: 16, Timeout: time.Second}
	if r.Enabled != nil {
		c.Enabled = *r.Enabled
	}
	if r.Bind != nil {
		if len(r.Bind) != 2 {
			return nil, errors.New("DNS bind must contain IPv4 and port")
		}
		host, _ := r.Bind[0].(string)
		port, _ := r.Bind[1].(float64)
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is4() || port != math.Trunc(port) || port < 0 || port > 65535 {
			return nil, errors.New("DNS bind must contain IPv4 and port")
		}
		if a.String() != "10.77.0.2" && !a.IsLoopback() {
			return nil, errors.New("DNS must bind only 10.77.0.2 or test loopback")
		}
		if !a.IsLoopback() && port != 53 {
			return nil, errors.New("production DNS must bind client port53; loopback tests may use ephemeral ports")
		}
		c.Bind = netip.AddrPortFrom(a, uint16(port))
	}
	if r.TTL != nil {
		c.TTL = *r.TTL
	}
	if c.TTL < 0 || c.TTL > 300 {
		return nil, errors.New("DNS TTL must be 0..300 seconds")
	}
	if r.Workers != nil {
		c.Workers = *r.Workers
	}
	if c.Workers < 1 || c.Workers > 8 {
		return nil, errors.New("DNS workers must be 1..8")
	}
	if r.Pending != nil {
		c.Pending = *r.Pending
	}
	if c.Pending < 0 || c.Pending > 32 {
		return nil, errors.New("DNS pending requests must be 0..32")
	}
	if r.Timeout != nil {
		t := *r.Timeout
		if math.IsNaN(t) || t < .05 || t > 3 {
			return nil, errors.New("DNS timeout must be finite and 0.05..3 seconds")
		}
		c.Timeout = time.Duration(t * float64(time.Second))
	}
	least := 0
	if c.Enabled {
		least = 1
	}
	if len(r.Records) < least || len(r.Records) > 64 {
		return nil, errors.New("DNS requires 1..64 exact-host overrides")
	}
	c.Records = map[string]map[string][]netip.Addr{}
	names := make([]string, 0, len(r.Records))
	for n := range r.Records {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, rawName := range names {
		name, err := NormalizeName(rawName)
		if err != nil {
			return nil, err
		}
		types := r.Records[rawName]
		if _, dup := c.Records[name]; dup || len(types) == 0 {
			return nil, errors.New("duplicate normalized hostname or empty DNS override")
		}
		c.Records[name] = map[string][]netip.Addr{}
		for kind, values := range types {
			if (kind != "A" && kind != "AAAA") || len(values) < 1 || len(values) > 16 {
				return nil, errors.New("DNS records support only 1..16 A/AAAA addresses per family")
			}
			for _, v := range values {
				a, err := netip.ParseAddr(v)
				if err != nil {
					return nil, fmt.Errorf("invalid DNS record address %q", v)
				}
				if (kind == "A") != a.Is4() {
					return nil, errors.New("DNS record address family mismatch")
				}
				c.Records[name][kind] = append(c.Records[name][kind], a)
			}
		}
	}
	if r.Upstream != nil {
		if len(r.Upstream) != 2 {
			return nil, errors.New("DNS upstream must contain public IPv4 and port")
		}
		host, _ := r.Upstream[0].(string)
		port, _ := r.Upstream[1].(float64)
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is4() || !isGlobal(a) || port != math.Trunc(port) || port < 1 || port > 65535 {
			return nil, errors.New("DNS upstream must be an explicit public IPv4 resolver")
		}
		ap := netip.AddrPortFrom(a, uint16(port))
		c.Upstream = &ap
	}
	return c, nil
}

// isGlobal approximates Python's ipaddress.is_global for IPv4.
func isGlobal(a netip.Addr) bool {
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}

// Override is the stateless in-line answer (override_response): nil means
// the query is not for a configured name and passes through unchanged.
func (c *Config) Override(packet []byte) []byte {
	q, err := ParseQuestion(packet, false)
	if err != nil || q.Class != 1 {
		return nil
	}
	rec, ok := c.Records[q.Name()]
	if !ok {
		return nil
	}
	return response(packet, &q, 0, true, c.answers(rec, q.Kind), c.TTL, false)
}

func (c *Config) answers(rec map[string][]netip.Addr, kind uint16) []answer {
	var fam string
	switch kind {
	case 1:
		fam = "A"
	case 28:
		fam = "AAAA"
	}
	var out []answer
	for _, a := range rec[fam] {
		out = append(out, answer{kind, a})
	}
	return out
}
