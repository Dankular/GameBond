package appconfig

import (
	"encoding/json"
	"strings"

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
