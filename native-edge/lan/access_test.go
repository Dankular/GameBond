package lan

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func TestAccessListRulesAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lan-access.json")
	if a := LoadAccess(path); a.Mode != AccessClosed {
		t.Fatalf("default mode %q", a.Mode)
	}
	err := UpdateAccess(path, func(a *Access) error {
		a.Mode = AccessAsk
		a.Accept(AccessEntry{MAC: "aa:bb:cc:00:00:01", Name: "Laptop", IP: "10.77.0.10"})
		a.Block(AccessEntry{MAC: "aa:bb:cc:00:00:02", Name: "Stranger"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a := LoadAccess(path)
	if a.Mode != AccessAsk || !a.IsAccepted("AA:BB:CC:00:00:01") || !a.IsBlocked("aa:bb:cc:00:00:02") {
		t.Fatalf("%+v", a)
	}
	// Accepting a blocked device lifts the block; blocking an accepted device revokes it.
	UpdateAccess(path, func(a *Access) error {
		a.Accept(AccessEntry{MAC: "aa:bb:cc:00:00:02", Name: "Friend", IP: "10.77.0.11"})
		a.Block(AccessEntry{MAC: "aa:bb:cc:00:00:01"})
		return nil
	})
	a = LoadAccess(path)
	if a.IsBlocked("aa:bb:cc:00:00:02") || !a.IsAccepted("aa:bb:cc:00:00:02") || a.IsAccepted("aa:bb:cc:00:00:01") || !a.IsBlocked("aa:bb:cc:00:00:01") {
		t.Fatalf("%+v", a)
	}
}

func TestNextFreeIPAndNames(t *testing.T) {
	client := netip.MustParseAddr("10.77.0.2")
	if ip := NextFreeIP(client, []string{"10.77.0.10", "10.77.0.11"}); ip != "10.77.0.12" {
		t.Fatal(ip)
	}
	if n := DefaultDeviceName("", "aa:bb:cc:dd:ee:ff"); n != "Device ddeeff" {
		t.Fatal(n)
	}
	if n := DefaultDeviceName("Dan's <iPhone>", "x"); n != "Dans iPhone" {
		t.Fatal(n)
	}
}
