package dashboard

import (
	"github.com/Dankular/GameBond.Core/hwmon"
	"gamebond.local/nativeedge/uplink"
	"time"
)

// ActivitySampler keeps physical-adapter counters separate from tunnel payload.
// First samples, counter resets and returning interfaces establish a baseline.
type ActivitySampler struct {
	previous map[string]hwmon.NetCounter
	last     time.Time
}

func (s *ActivitySampler) Sample(counters []hwmon.NamedNet, adapters []uplink.Adapter, now time.Time) []map[string]any {
	out := []map[string]any{}
	next := map[string]hwmon.NetCounter{}
	elapsed := now.Sub(s.last).Seconds()
	for _, c := range counters {
		next[c.Name] = c.NetCounter
		var down, up any
		if old, ok := s.previous[c.Name]; ok && !s.last.IsZero() && elapsed > 0 && c.BytesRecv >= old.BytesRecv && c.BytesSent >= old.BytesSent {
			down = float64(c.BytesRecv-old.BytesRecv) * 8 / elapsed / 1e6
			up = float64(c.BytesSent-old.BytesSent) * 8 / elapsed / 1e6
		}
		row := map[string]any{"name": c.Name, "down_mbps": down, "up_mbps": up, "received_bytes": c.BytesRecv, "sent_bytes": c.BytesSent, "observed_at": float64(now.UnixNano()) / 1e9}
		for _, a := range adapters {
			if a.Name == c.Name {
				row["index"], row["id"], row["up"], row["addresses"], row["gateway"] = a.Index, a.ID, a.Up, a.Addresses, a.Gateway
				break
			}
		}
		out = append(out, row)
	}
	s.previous, s.last = next, now
	return out
}
