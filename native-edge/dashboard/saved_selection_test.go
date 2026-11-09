package dashboard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestMissingSavedAdapterIsRetainedByIdentity(t *testing.T) {
	s, base, config := transportFixture(t)
	cfg, _ := readConfig(config)
	cfg["interface_indices"] = []int{22, 25}
	cfg["interface_ids"] = []string{uplinkGUID, spareGUID}
	cfg["interface_names"] = []string{"Ethernet", "Phone"}
	if err := writeConfig(config, cfg); err != nil {
		t.Fatal(err)
	}
	otherGUID := "{33333333-3333-3333-3333-333333333333}"
	rows := []Adapter{{Index: 22, ID: uplinkGUID, Name: "Ethernet", Up: true, Addresses: []string{"192.168.1.93"}, Gateway: "192.168.1.1"}, {Index: 25, ID: otherGUID, Name: "Other adapter", Up: true, Addresses: []string{"10.20.0.2"}, Gateway: "10.20.0.1"}}
	s.o.Adapters = func() ([]Adapter, error) { return rows, nil }
	if c, b := do(t, "GET", base+"/api/networks", s.token, ""); c != 200 || !strings.Contains(b, "Phone") || !strings.Contains(b, spareGUID) {
		t.Fatal(c, b)
	}
	selection := `[{"index":25,"id":"` + spareGUID + `"}]`
	if c, b := do(t, "PUT", base+"/api/networks", s.token, selection); c != 200 {
		t.Fatal(c, b)
	}
	cfg, _ = readConfig(config)
	raw, _ := json.Marshal(cfg["bind"])
	if string(raw) != `[["0.0.0.0",0]]` {
		t.Fatal("missing adapter bound a different NIC", cfg)
	}
	before, _ := os.ReadFile(config)
	for _, bad := range []string{`[25]`, `[{"index":25,"id":"` + otherGUID + `"},{"index":25,"id":"` + spareGUID + `"}]`, `[{"index":-1,"id":"` + spareGUID + `"}]`} {
		if c, b := do(t, "PUT", base+"/api/networks", s.token, bad); c != 422 {
			t.Fatal(bad, c, b)
		}
	}
	after, _ := os.ReadFile(config)
	if string(before) != string(after) {
		t.Fatal("rejected selection changed config")
	}
	rows = append(rows, Adapter{Index: 47, ID: spareGUID, Name: "Phone", Up: true, Addresses: []string{"172.20.10.2"}, Gateway: "172.20.10.1"})
	if c, b := do(t, "PUT", base+"/api/networks", s.token, selection); c != 200 {
		t.Fatal("stable identity failed after index change", c, b)
	}
	cfg, _ = readConfig(config)
	raw, _ = json.Marshal(cfg["interface_indices"])
	if string(raw) != `[47]` {
		t.Fatal(cfg)
	}
}

func TestApplicationRoutingModeAndLegacyList(t *testing.T) {
	s, base, config := transportFixture(t)
	if c, b := do(t, "GET", base+"/api/apps", s.token, ""); c != 200 || !strings.Contains(b, `"capture_mode":"all"`) {
		t.Fatal(c, b)
	}
	body := `{"capture_mode":"selected","cod_executables":["C:/Games/a.exe","c:/games/A.EXE"]}`
	if c, b := do(t, "PUT", base+"/api/apps", s.token, body); c != 200 {
		t.Fatal(c, b)
	}
	cfg, _ := readConfig(config)
	if cfg["capture_mode"] != "selected" || len(cfg["cod_executables"].([]any)) != 1 || cfg["bind"] == nil {
		t.Fatal(cfg)
	}
	for _, bad := range []string{`{"capture_mode":"none","cod_executables":[]}`, `{"capture_mode":"selected","cod_executables":["relative.exe"]}`, `{"capture_mode":"all","cod_executables":[],"unknown":true}`} {
		if c, b := do(t, "PUT", base+"/api/apps", s.token, bad); c != 422 {
			t.Fatal(c, b)
		}
	}
	if c, b := do(t, "PUT", base+"/api/apps", s.token, `[]`); c != 200 {
		t.Fatal(c, b)
	}
	cfg, _ = readConfig(config)
	if cfg["capture_mode"] != "selected" {
		t.Fatal("legacy list changed routing mode")
	}
}
