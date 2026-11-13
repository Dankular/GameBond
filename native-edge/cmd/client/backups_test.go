package main

import (
	"net/netip"
	"testing"

	"gamebond.local/nativeedge/client"
)

func TestBackupPeers(t *testing.T) {
	primary := netip.MustParseAddrPort("203.0.113.7:4434")
	got, err := backupPeers(fileConfig{PeerBackups: [][]any{{"198.51.100.9", float64(4433)}}}, primary)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddrPort("198.51.100.9:4433") {
		t.Fatalf("%v %v", got, err)
	}
	if got, err = backupPeers(fileConfig{}, primary); err != nil || len(got) != 0 {
		t.Fatalf("no backups: %v %v", got, err)
	}
	for name, list := range map[string][][]any{
		"primary":  {{"203.0.113.7", float64(4434)}},
		"twice":    {{"198.51.100.9", float64(1)}, {"198.51.100.9", float64(1)}},
		"short":    {{"198.51.100.9"}},
		"hostname": {{"example.com", float64(4433)}},
		"v6":       {{"2001:db8::1", float64(4433)}},
		"port":     {{"198.51.100.9", float64(70000)}},
		"fraction": {{"198.51.100.9", float64(4433.5)}},
		"four":     {{"198.51.100.1", float64(1)}, {"198.51.100.2", float64(1)}, {"198.51.100.3", float64(1)}, {"198.51.100.4", float64(1)}},
	} {
		if _, err := backupPeers(fileConfig{PeerBackups: list}, primary); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestExitStatusDocReportsActiveAndStandby(t *testing.T) {
	a, b := netip.MustParseAddrPort("203.0.113.7:4434"), netip.MustParseAddrPort("198.51.100.9:4433")
	doc := exitStatusDoc(client.ExitStatus{Active: b, Primary: a, Switches: 1, Probing: false,
		Servers: []client.ExitServer{{Addr: a, State: "unreachable", Failures: 1}, {Addr: b, Active: true, State: "active"}}})
	if doc["active"] != "198.51.100.9" || doc["on_backup"] != true || doc["switches"] != uint64(1) {
		t.Fatalf("%v", doc)
	}
	if s := doc["servers"].([]map[string]any); len(s) != 2 || s[0]["state"] != "unreachable" || s[1]["active"] != true {
		t.Fatalf("%v", doc["servers"])
	}
}
