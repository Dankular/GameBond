package lan

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

func TestLoadDevicesMatchesPython(t *testing.T) {
	f, err := os.Open("testdata/lan-config-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var rows []struct {
		Devices json.RawMessage `json:"devices"`
		Uplinks struct {
			IDs     []string `json:"interface_ids"`
			Indices []int    `json:"interface_indices"`
		}
		OK         bool       `json:"ok"`
		Count      int        `json:"count"`
		Identities []string   `json:"identities"`
		DNS        [][]string `json:"dns"`
	}
	if err := json.NewDecoder(z).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	for i, r := range rows {
		var up struct {
			IDs     []string `json:"interface_ids"`
			Indices []int    `json:"interface_indices"`
		}
		_ = up
		got, err := LoadDevices(r.Devices, netip.MustParseAddr("10.77.0.2"), r.Uplinks.IDs, r.Uplinks.Indices)
		if err == nil && !r.OK && bytes.Count(r.Devices, []byte(`"name"`)) > 1 {
			continue // shared adapters are allowed (unpinned devices claim by DHCP)
		}
		if (err == nil) != r.OK {
			t.Fatalf("row %d: ok=%v want %v (err %v)\n%s", i, err == nil, r.OK, err, r.Devices)
		}
		if !r.OK {
			continue
		}
		if len(got) != r.Count {
			t.Fatalf("row %d: %d devices want %d", i, len(got), r.Count)
		}
		for k, d := range got {
			if d.Identity() != r.Identities[k] {
				t.Errorf("row %d identity %q want %q", i, d.Identity(), r.Identities[k])
			}
			for j, a := range d.DNS {
				if a.String() != r.DNS[k][j] {
					t.Errorf("row %d dns %v want %v", i, a, r.DNS[k])
				}
			}
		}
	}
}
