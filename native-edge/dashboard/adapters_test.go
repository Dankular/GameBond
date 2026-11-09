package dashboard

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestAdapterSelectionPersistsDiscoveredSettings(t *testing.T) {
	s, url, config, _ := start(t)
	rows := []Adapter{
		{Index: 22, ID: "{00000000-0000-0000-0000-000000000022}", Name: "Ethernet", Up: true, Addresses: []string{"192.168.1.93"}, Gateway: "192.168.1.1"},
		{Index: 33, ID: "{00000000-0000-0000-0000-000000000033}", Name: "Hotspot", Up: false, Addresses: []string{}},
	}
	s.o.Adapters = func() ([]Adapter, error) { return rows, nil }
	endpoint := url[:strings.Index(url, "/?t=")] + "/api/networks"
	before, _ := os.ReadFile(config)
	if c, b := do(t, "PUT", endpoint, s.token, `[33,22]`); c != 200 {
		t.Fatal(c, b)
	}
	var cfg map[string]any
	saved, _ := os.ReadFile(config)
	json.Unmarshal(saved, &cfg)
	if cfg["role"] != "client" || cfg["link_policies"] == nil {
		t.Fatal("unrelated settings lost", cfg)
	}
	b, _ := json.Marshal(cfg["bind"])
	if string(b) != `[["0.0.0.0",0],["192.168.1.93",0]]` {
		t.Fatal(string(b))
	}
	for key, want := range map[string]string{"interface_indices": `[33,22]`, "gateways": `["","192.168.1.1"]`, "interface_names": `["Hotspot","Ethernet"]`, "interface_ids": `["{00000000-0000-0000-0000-000000000033}","{00000000-0000-0000-0000-000000000022}"]`} {
		b, _ := json.Marshal(cfg[key])
		if string(b) != want {
			t.Fatalf("%s: %s", key, b)
		}
	}
	prev, _ := os.ReadFile(config + ".previous")
	if string(prev) != string(before) {
		t.Fatal("backup missing")
	}
	for _, bad := range []string{`null`, `[]`, `[22,22]`, `[22,99]`, `[22,33.5]`, `[true,33]`, `[22,33] {}`, `[1,2,3,4,5,6,7,8,9]`} {
		if c, b := do(t, "PUT", endpoint, s.token, bad); c != 422 {
			t.Fatalf("%s: %d %s", bad, c, b)
		}
	}
	rows[1].ID = ""
	if c, _ := do(t, "PUT", endpoint, s.token, `[22,33]`); c != 422 {
		t.Fatal("offline without identity accepted", c)
	}
	s.o.Adapters = func() ([]Adapter, error) { return nil, errors.New("discovery failed") }
	if c, _ := do(t, "PUT", endpoint, s.token, `[22,33]`); c != 503 {
		t.Fatal(c)
	}
	after, _ := os.ReadFile(config)
	if string(after) != string(saved) {
		t.Fatal("rejected edit changed config")
	}
}

func TestSingleAdapterSelection(t *testing.T) {
	s, url, config, _ := start(t)
	s.o.Adapters = func() ([]Adapter, error) {
		return []Adapter{{Index: 22, Name: "Ethernet", Up: true, Addresses: []string{"192.168.1.93"}, Gateway: "192.168.1.1"}}, nil
	}
	endpoint := url[:strings.Index(url, "/?t=")] + "/api/networks"
	if c, b := do(t, "PUT", endpoint, s.token, `[22]`); c != 200 {
		t.Fatal(c, b)
	}
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(raw, &cfg)
	indices, _ := json.Marshal(cfg["interface_indices"])
	bind, _ := json.Marshal(cfg["bind"])
	if string(indices) != `[22]` || string(bind) != `[["192.168.1.93",0]]` {
		t.Fatal(string(raw))
	}
}
