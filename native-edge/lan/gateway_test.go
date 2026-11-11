package lan

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"

)

type fakeIO struct{ out []string }

func (f *fakeIO) MAC() [6]byte         { return [6]byte{2, 0, 0, 0, 0, 1} }
func (f *fakeIO) Write(b []byte) error { f.out = append(f.out, hex.EncodeToString(b)); return nil }

func TestPythonVectors(t *testing.T) {
	f, err := os.Open("testdata/lan-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var v struct {
		Scenarios []struct {
			Pinned     *string  `json:"pinned"`
			DNS        bool     `json:"dns"`
			DNSServers []string `json:"dns_servers"`
			MTU        int      `json:"mtu"`
			Lease      int      `json:"lease"`
			Stale      float64  `json:"stale"`
			Steps      []struct {
				Kind   string
				T      float64
				Data   string
				Result *bool
				Frames []string
				Tunnel []string
			}
			Counters  map[string]uint64
			Leased    bool
			DeviceMAC *string `json:"device_mac"`
		}
	}
	if err := json.NewDecoder(z).Decode(&v); err != nil {
		t.Fatal(err)
	}
	epoch := time.Unix(500, 0)
	steps := 0
	for si, sc := range v.Scenarios {
		if sc.DNS {
			continue // DNS override removed
		}
		var now time.Time
		io := &fakeIO{}
		var tunnel []string
		dev := Device{Name: "Console", TunnelIP: netip.MustParseAddr("10.77.0.9")}
		for _, s := range sc.DNSServers {
			dev.DNS = append(dev.DNS, netip.MustParseAddr(s))
		}
		if sc.Pinned != nil {
			b, _ := hex.DecodeString(*sc.Pinned)
			var m [6]byte
			copy(m[:], b)
			dev.PinnedMAC = &m
		}
		cfg := Config{Device: dev, ClientIP: netip.MustParseAddr("10.77.0.2"), TunnelMTU: sc.MTU, LeaseSeconds: sc.Lease,
			StaleAfter: time.Duration(sc.Stale * float64(time.Second)), Now: func() time.Time { return now },
			OnPacket: func(p []byte) { tunnel = append(tunnel, hex.EncodeToString(p)) }}
		now = epoch
		g, err := NewGateway(cfg, io)
		if err != nil {
			t.Fatal(err)
		}
		for i, st := range sc.Steps {
			now = epoch.Add(time.Duration((st.T - 500) * float64(time.Second)))
			data, _ := hex.DecodeString(st.Data)
			io.out, tunnel = nil, nil
			var res *bool
			if st.Kind == "frame" {
				g.HandleFrame(data)
			} else {
				r := g.Deliver(data)
				res = &r
			}
			if (res == nil) != (st.Result == nil) || (res != nil && *res != *st.Result) {
				t.Fatalf("scenario %d step %d: deliver result mismatch", si, i)
			}
			if !equal(io.out, st.Frames) {
				t.Fatalf("scenario %d step %d frames\n got %v\nwant %v\ninput %s", si, i, io.out, st.Frames, st.Data)
			}
			if !equal(tunnel, st.Tunnel) {
				t.Fatalf("scenario %d step %d tunnel\n got %v\nwant %v", si, i, tunnel, st.Tunnel)
			}
			steps++
		}
		c := g.Stats()
		got := map[string]uint64{"frames_in": c.FramesIn, "frames_out": c.FramesOut, "packets_to_tunnel": c.PacketsToTunnel, "packets_from_tunnel": c.PacketsFromTunnel,
			"dhcp_offers": c.DHCPOffers, "dhcp_acks": c.DHCPAcks, "dhcp_naks": c.DHCPNaks, "arp_replies": c.ARPReplies,
			"foreign_mac_dropped": c.ForeignMACDropped, "spoofed_source_dropped": c.SpoofedSourceDropped, "local_only_dropped": c.LocalOnlyDropped,
			"ttl_expired": c.TTLExpired, "fragmented": c.Fragmented, "frag_needed_sent": c.FragNeededSent, "wrong_destination": c.WrongDestination,
			"no_device_mac": c.NoDeviceMAC, "malformed": c.Malformed, "write_errors": c.WriteErrors}
		for k, w := range sc.Counters {
			if got[k] != w {
				t.Errorf("scenario %d counter %s = %d want %d", si, k, got[k], w)
			}
		}
		if g.Leased != sc.Leased {
			t.Errorf("scenario %d leased %v want %v", si, g.Leased, sc.Leased)
		}
		m, ok := g.DeviceMAC()
		if (sc.DeviceMAC == nil) == ok || (ok && hex.EncodeToString(m[:]) != *sc.DeviceMAC) {
			t.Errorf("scenario %d device mac %x/%v want %v", si, m, ok, sc.DeviceMAC)
		}
	}
	t.Logf("%d steps", steps)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
