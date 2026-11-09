package nat

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestPythonVectors(t *testing.T) {
	f, err := os.Open("testdata/nat-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var scenarios []struct {
		MaxEntries int `json:"max_entries"`
		Low, High  int
		Steps      []struct {
			Dir    string
			T      float64
			Packet string
			Out    *string
			Draws  []int
		}
		Stats map[string]int
	}
	if err := json.NewDecoder(z).Decode(&scenarios); err != nil {
		t.Fatal(err)
	}
	epoch := time.Unix(100, 0)
	total := 0
	for si, sc := range scenarios {
		n, err := New(netip.MustParseAddr("10.255.254.2"), sc.MaxEntries, sc.Low, sc.High)
		if err != nil {
			t.Fatal(err)
		}
		var now time.Time
		var draws []int
		n.Now = func() time.Time { return now }
		n.Intn = func(m int) int {
			if len(draws) == 0 {
				t.Fatalf("scenario %d: unexpected port draw", si)
			}
			v := draws[0]
			draws = draws[1:]
			return v
		}
		for i, st := range sc.Steps {
			now = epoch.Add(time.Duration((st.T - 100) * float64(time.Second)))
			draws = st.Draws
			p, _ := hex.DecodeString(st.Packet)
			var got []byte
			if st.Dir == "out" {
				got = n.Outbound(p)
			} else {
				got = n.Inbound(p)
			}
			if len(draws) != 0 {
				t.Fatalf("scenario %d step %d: %d port draws unused", si, i, len(draws))
			}
			switch {
			case st.Out == nil && got != nil:
				t.Fatalf("scenario %d step %d: forwarded %x, Python dropped", si, i, got)
			case st.Out != nil && hex.EncodeToString(got) != *st.Out:
				t.Fatalf("scenario %d step %d (%s)\n got %x\nwant %s", si, i, st.Dir, got, *st.Out)
			}
			total++
		}
		s := n.Stats()
		want := sc.Stats
		got := map[string]int{"out": int(s.Out), "inn": int(s.In), "created": int(s.Created), "expired": int(s.Expired), "evicted": int(s.Evicted),
			"fragments": int(s.Fragments), "unsupported": int(s.Unsupported), "malformed": int(s.Malformed), "no_mapping": int(s.NoMapping),
			"filtered": int(s.Filtered), "port_exhausted": int(s.PortExhausted), "not_for_us": int(s.NotForUs), "icmp_errors": int(s.ICMPErrors), "active": s.Active}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("scenario %d counter %s = %d want %d", si, k, got[k], v)
			}
		}
	}
	t.Logf("%d steps", total)
}
