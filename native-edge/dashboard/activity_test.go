package dashboard

import (
	"github.com/Dankular/GameBond.Core/hwmon"
	"gamebond.local/nativeedge/uplink"
	"testing"
	"time"
)

func TestAdapterActivityUsesActualElapsedTimeAndResets(t *testing.T) {
	s := &ActivitySampler{}
	now := time.Now()
	rows := []hwmon.NamedNet{{Name: "Ethernet", NetCounter: hwmon.NetCounter{BytesRecv: 1e6, BytesSent: 2e6}}}
	adapters := []uplink.Adapter{{Name: "Ethernet", Index: 22, ID: "stable", Up: true}}
	out := s.Sample(rows, adapters, now)
	if out[0]["down_mbps"] != nil || out[0]["index"] != 22 {
		t.Fatal(out)
	}
	rows[0].BytesRecv += 2e6
	rows[0].BytesSent += 1e6
	out = s.Sample(rows, adapters, now.Add(2*time.Second))
	if out[0]["down_mbps"] != float64(8) || out[0]["up_mbps"] != float64(4) {
		t.Fatal(out)
	}
	rows[0].BytesRecv = 1
	out = s.Sample(rows, adapters, now.Add(3*time.Second))
	if out[0]["down_mbps"] != nil || out[0]["up_mbps"] != nil {
		t.Fatal("reset invented rates", out)
	}
	s.Sample(nil, adapters, now.Add(4*time.Second))
	out = s.Sample(rows, adapters, now.Add(5*time.Second))
	if out[0]["down_mbps"] != nil {
		t.Fatal("returning adapter bridged downtime", out)
	}
}
