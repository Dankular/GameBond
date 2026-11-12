package dashboard

import (
	"path/filepath"
	"testing"

	"gamebond.local/nativeedge/lan"
)

func TestAccessActionsAssignAddressesAndBlock(t *testing.T) {
	dir := t.TempDir()
	s := &Server{}
	access, pending := filepath.Join(dir, "lan-access.json"), filepath.Join(dir, "lan-pending.json")
	cfg := map[string]any{"client_tunnel_ip": "10.77.0.2", "lan_devices": []any{map[string]any{"tunnel_ip": "10.77.0.10"}}}
	lan.SavePending(pending, []lan.Pending{{MAC: "aa:bb:cc:00:00:01", Hostname: "Dans iPhone", Attempts: 2}})
	if err := s.applyAccess(access, pending, cfg, "mode", "", "", "ask"); err != nil {
		t.Fatal(err)
	}
	if err := s.applyAccess(access, pending, cfg, "accept", "AA:BB:CC:00:00:01", "", ""); err != nil {
		t.Fatal(err)
	}
	a := lan.LoadAccess(access)
	if a.Mode != "ask" || len(a.Accepted) != 1 || a.Accepted[0].IP != "10.77.0.11" || a.Accepted[0].Name != "Dans iPhone" {
		t.Fatalf("%+v", a)
	}
	s.applyAccess(access, pending, cfg, "decline", "aa:bb:cc:00:00:01", "", "")
	if a = lan.LoadAccess(access); len(a.Accepted) != 0 || !a.IsBlocked("aa:bb:cc:00:00:01") {
		t.Fatalf("%+v", a)
	}
	if s.applyAccess(access, pending, cfg, "mode", "", "", "bogus") == nil || s.applyAccess(access, pending, cfg, "accept", "nonsense", "", "") == nil {
		t.Fatal("bad input accepted")
	}
}
