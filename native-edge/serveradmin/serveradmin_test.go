package serveradmin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"gamebond.local/nativeedge/serveradmin/fakeportal"
)

const baseConfig = `{"role":"server","mtu":1280,"reorder_timeout_ms":30.5,"queues":{"5":{"priority":true}},"lan_tunnel_ips":["10.77.0.3"],"admin":{"enabled":true}}`

func start(t *testing.T) (*fakeportal.Portal, *httptest.Server, string) {
	p := fakeportal.New("correct horse battery", baseConfig)
	srv := httptest.NewTLSServer(p.Handler())
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return p, srv, hex.EncodeToString(sum[:])
}

func TestEnsureTunnelIPsWritesValidatedMergedConfig(t *testing.T) {
	p, srv, pin := start(t)
	c, err := NewClient(srv.URL, p.Password, pin)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := c.EnsureTunnelIPs(t.Context(), []string{"10.77.0.4", "10.77.0.3", "10.77.0.10"})
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	ips, _ := TunnelIPs(p.Config)
	if strings.Join(ips, ",") != "10.77.0.3,10.77.0.4,10.77.0.10" {
		t.Fatalf("lan_tunnel_ips = %v", ips)
	}
	var doc map[string]json.RawMessage
	json.Unmarshal([]byte(p.Config), &doc)
	compact := func(raw json.RawMessage) string {
		var buf bytes.Buffer
		if err := json.Compact(&buf, raw); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if string(doc["reorder_timeout_ms"]) != "30.5" || string(doc["mtu"]) != "1280" || compact(doc["queues"]) != `{"5":{"priority":true}}` || compact(doc["admin"]) != `{"enabled":true}` {
		t.Fatalf("other settings were not carried over: %s", p.Config)
	}
	if p.Restarts != 0 {
		t.Fatal("writing the configuration must not restart the server")
	}
	if changed, err := c.EnsureTunnelIPs(t.Context(), []string{"10.77.0.4"}); err != nil || changed || p.Writes != 1 {
		t.Fatalf("a second identical request must write nothing: changed=%v err=%v writes=%d", changed, err, p.Writes)
	}
}

func TestRestartIsExplicit(t *testing.T) {
	p, srv, pin := start(t)
	c, _ := NewClient(srv.URL, p.Password, pin)
	if err := c.Restart(t.Context()); err != nil || p.Restarts != 1 {
		t.Fatalf("restart: %v (%d)", err, p.Restarts)
	}
}

func TestCertificatePin(t *testing.T) {
	p, srv, pin := start(t)
	wrong := strings.Repeat("ab", 32)
	c, _ := NewClient(srv.URL, p.Password, wrong)
	if err := c.Login(t.Context()); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a wrong pin must be refused: %v", err)
	}
	c, _ = NewClient(srv.URL, p.Password, strings.ToUpper(pin[:2])+":"+pin[2:4]+pin[4:]) // colons and case are tolerated
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("the right pin must work: %v", err)
	}
	c, _ = NewClient(srv.URL, p.Password, "") // self-signed and unpinned: the system roots do not vouch for it
	if err := c.Login(t.Context()); err == nil {
		t.Fatal("an unpinned self-signed certificate must be refused")
	}
}

func TestWrongPasswordNeverEchoed(t *testing.T) {
	p, srv, pin := start(t)
	c, _ := NewClient(srv.URL, "not the password", pin)
	err := c.Login(t.Context())
	var api *APIError
	if !errors.As(err, &api) || api.Status != 401 || strings.Contains(err.Error(), "not the password") {
		t.Fatalf("err = %v", err)
	}
	_ = p
}

func TestSessionExpiryLogsInAgain(t *testing.T) {
	p, srv, pin := start(t)
	c, _ := NewClient(srv.URL, p.Password, pin)
	if _, err := c.Config(t.Context()); err != nil {
		t.Fatal(err)
	}
	p.Lock()
	p.ExpireOne = true
	p.Unlock()
	if _, err := c.Config(t.Context()); err != nil {
		t.Fatalf("an expired session should be renewed once: %v", err)
	}
	if p.Logins != 2 {
		t.Fatalf("logins = %d", p.Logins)
	}
}

func TestRejectedConfigurationIsReportedAndNotWritten(t *testing.T) {
	p, srv, pin := start(t)
	p.RejectAs = "ValueError: lan_tunnel_ips must be distinct"
	c, _ := NewClient(srv.URL, p.Password, pin)
	_, err := c.EnsureTunnelIPs(t.Context(), []string{"10.77.0.9"})
	if err == nil || !strings.Contains(err.Error(), "must be distinct") || p.Writes != 0 {
		t.Fatalf("err=%v writes=%d", err, p.Writes)
	}
}

func TestWithTunnelIPs(t *testing.T) {
	out, changed, err := WithTunnelIPs(`{"role":"server"}`, []string{"10.77.0.7"})
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	if ips, _ := TunnelIPs(out); len(ips) != 1 || ips[0] != "10.77.0.7" {
		t.Fatalf("%v", ips)
	}
	for _, bad := range []string{"10.77.0.1", "10.77.0.2", "10.77.0.255", "10.77.1.5", "192.168.1.5", "10.77.0.05", "nope", "::1"} {
		if _, _, err := WithTunnelIPs(`{}`, []string{bad}); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	many := make([]string, 0, 33)
	for i := 3; i < 36; i++ {
		many = append(many, fmt.Sprintf("10.77.0.%d", i))
	}
	if _, _, err := WithTunnelIPs(`{}`, many); err == nil {
		t.Fatal("more than 32 addresses must be refused")
	}
	if _, _, err := WithTunnelIPs(`not json`, []string{"10.77.0.7"}); err == nil {
		t.Fatal("a damaged configuration must be refused")
	}
	same, changed, _ := WithTunnelIPs(baseConfig, []string{"10.77.0.3"})
	if changed || same != baseConfig {
		t.Fatal("an address that is already listed must leave the text untouched")
	}
}

func TestNewClientRefusesPlainHTTPAndBadPin(t *testing.T) {
	if _, err := NewClient("http://203.0.113.5:8443", "pw", ""); err == nil {
		t.Fatal("http must be refused: the password would cross the network in clear")
	}
	if _, err := NewClient("https://203.0.113.5:8443", "pw", "xyz"); err == nil {
		t.Fatal("a malformed pin must be refused")
	}
	if _, err := NewClient("https://203.0.113.5:8443", "", ""); err == nil {
		t.Fatal("an empty password must be refused")
	}
}
