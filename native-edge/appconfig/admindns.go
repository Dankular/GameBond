package appconfig

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"

	"gamebond.local/nativeedge/dns"
	"gamebond.local/nativeedge/omr"
)

// checkAdmin is AdminSettings(raw) (the server's admin portal block).
func checkAdmin(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return bad("admin must be an object")
	}
	if err := allowed(m, "enabled", "bind", "password_hash", "tls_cert", "tls_key", "log_lines"); err != nil {
		return err
	}
	enabled := true
	if v, ok := m["enabled"]; ok {
		b, isB := v.(bool)
		if !isB {
			return bad("invalid admin settings")
		}
		enabled = b
	}
	var host any = "127.0.0.1"
	var port any = json.Number("8443")
	if v, ok := m["bind"]; ok {
		l, isList := v.([]any)
		if !isList || len(l) != 2 {
			return bad("admin bind must be [host, port]")
		}
		host, port = l[0], l[1]
	}
	ip, err := omr.IPv4(host)
	if err != nil {
		return err
	}
	if p, isI := isInt(port); !isI || p < 1 || p > 65535 {
		return bad("invalid admin port")
	}
	if v, ok := m["log_lines"]; ok {
		if i, isI := isInt(v); !isI || i < 10 || i > 2000 {
			return bad("invalid admin settings")
		}
	}
	if enabled {
		if h, isStr := m["password_hash"].(string); !isStr || !strings.HasPrefix(h, "scrypt$") {
			return bad("admin.password_hash is required")
		}
		if (truthyEmpty(m["tls_cert"]) || truthyEmpty(m["tls_key"])) && !ip.IsLoopback() {
			return bad("admin.tls_cert and admin.tls_key are required unless the portal binds loopback")
		}
	}
	return nil
}

var hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// hostname is windows_dns._hostname (the name is already normalised by dns.Load).
func hostname(value string) error {
	name := strings.TrimSuffix(strings.ToLower(value), ".")
	if !(len(name) > 1 && len(name) <= 253) || !strings.Contains(name, ".") {
		return bad("DNS namespaces must be exact ASCII FQDNs")
	}
	for _, label := range strings.Split(name, ".") {
		if !hostLabel.MatchString(label) {
			return bad("DNS namespaces must be exact ASCII FQDNs")
		}
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return bad("DNS namespace must be a hostname, not an IP address")
	}
	return nil
}

// checkDNS is load_dns_config plus app.load_config's client-side DNS rules.
func checkDNS(config map[string]any, role string) error {
	v, ok := config["dns"]
	if !ok || v == nil {
		return nil
	}
	enc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c, err := dns.Load(enc)
	if err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	if role != "client" {
		return bad("managed DNS overrides belong to the client configuration")
	}
	for name := range c.Records {
		if err := hostname(name); err != nil {
			return err
		}
	}
	if c.Enabled {
		client, _ := config["client_tunnel_ip"].(string)
		if c.Bind.Addr().String() != client || c.Bind.Port() != 53 {
			return bad("managed DNS must bind the client's own tunnel IPv4 address on port 53")
		}
	}
	return nil
}
