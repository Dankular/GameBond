package dashboard

import (
	"strings"
	"testing"
)

func TestSecurityIsRelayedToTheServerPortal(t *testing.T) {
	s, base, p, pin, _ := portalFixture(t)
	if code, body := do(t, "GET", base+"/api/security", s.token, ""); code != 409 || !strings.Contains(body, "unconfigured") {
		t.Fatalf("with no server admin saved the page must say so: %d %s", code, body)
	}
	if code, body := saveAdmin(t, s, base, pin, portalPassword); code != 200 {
		t.Fatal(code, body)
	}
	if code, body := do(t, "GET", base+"/api/security", s.token, ""); code != 200 || !strings.Contains(body, `"mode":"off"`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := do(t, "GET", base+"/api/security/catalog", s.token, ""); code != 200 || !strings.Contains(body, `"ads"`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := do(t, "POST", base+"/api/security", s.token, `{"settings":{"ids":{"mode":"detect"}}}`); code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("%d %s", code, body)
	}
	p.Lock()
	got := p.Security
	p.Unlock()
	if got["ids"] == nil {
		t.Fatalf("the settings must reach the server unchanged: %v", got)
	}
	// Repeated calls reuse one login: the server hashes the password on every login.
	for i := 0; i < 5; i++ {
		do(t, "GET", base+"/api/security", s.token, "")
	}
	p.Lock()
	logins := p.Logins
	p.Unlock()
	if logins > 2 { // one from saving the server admin, one for the relay
		t.Fatalf("expected the portal session to be reused, got %d logins", logins)
	}

	// The server's own refusal reaches the page with its status.
	p.Lock()
	p.SecurityFail = "nftables refused the rules: syntax error"
	p.Unlock()
	code, body := do(t, "POST", base+"/api/security", s.token, `{"settings":{}}`)
	if code != 422 || !strings.Contains(body, "nftables refused") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := do(t, "POST", base+"/api/security/action", s.token, `{"action":"unblock","args":{"ip":"10.77.0.9"}}`); code != 200 {
		t.Fatal(code)
	}
	p.Lock()
	n := len(p.Actions)
	p.Unlock()
	if n != 1 {
		t.Fatalf("%d actions", n)
	}
}

func TestSecurityRelayRefusesOtherPathsMethodsAndBadBodies(t *testing.T) {
	s, base, _, pin, _ := portalFixture(t)
	saveAdmin(t, s, base, pin, portalPassword)
	if code, _ := do(t, "GET", base+"/api/security/config", s.token, ""); code != 404 {
		t.Fatalf("only the three security endpoints may be relayed: %d", code)
	}
	if code, _ := do(t, "DELETE", base+"/api/security", s.token, ""); code != 405 {
		t.Fatalf("%d", code)
	}
	if code, _ := do(t, "POST", base+"/api/security", s.token, `not json`); code != 400 {
		t.Fatalf("%d", code)
	}
	if code, _ := do(t, "GET", base+"/api/security", "wrong-token", ""); code != 403 {
		t.Fatalf("the page token must be required: %d", code)
	}
}
