package linkpolicy

import "github.com/Dankular/GameBond.Core/bond"

// Meter turns cumulative per-uplink wire counters into ledger usage and the
// operational policy each uplink should run under. It mirrors
// Runtime.meter_links: only the growth since the previous call is counted, and
// the policy handed to the transport already folds in any reached data cap.
type Meter struct {
	Ledger   *Ledger
	Keys     []string // ledger key per uplink (the Python config uses the interface index)
	Policies []Policy // configured policy per uplink
	prev     [][2]uint64
	last     []bond.PathPolicy
}

func NewMeter(l *Ledger, keys []string, policies []Policy) *Meter {
	return &Meter{Ledger: l, Keys: keys, Policies: policies, prev: make([][2]uint64, len(keys))}
}

// Update takes the cumulative (upload, download) wire bytes per uplink and
// returns the operational policies and whether they differ from the last call.
func (m *Meter) Update(wire [][2]uint64) ([]bond.PathPolicy, bool, error) {
	for i := range m.Keys {
		if i >= len(wire) {
			break
		}
		up, down := int64(0), int64(0)
		if wire[i][0] > m.prev[i][0] {
			up = int64(wire[i][0] - m.prev[i][0])
		}
		if wire[i][1] > m.prev[i][1] {
			down = int64(wire[i][1] - m.prev[i][1])
		}
		m.prev[i] = wire[i]
		if up != 0 || down != 0 {
			if err := m.Ledger.Add(m.Keys[i], up, down); err != nil {
				return nil, false, err
			}
		}
	}
	if err := m.Ledger.Save(); err != nil {
		return nil, false, err
	}
	out := make([]bond.PathPolicy, len(m.Keys))
	for i, p := range m.Policies {
		e := p.Effective(m.Ledger.Usage(m.Keys[i], p))
		role := bond.Primary
		for j, name := range Roles {
			if name == e.Role {
				role = byte(j)
			}
		}
		out[i] = bond.PathPolicy{Role: role, Blocked: e.Blocked, UploadMbps: e.UploadMbps, DownloadMbps: e.DownloadMbps}
	}
	changed := len(m.last) != len(out)
	for i := range out {
		if !changed && out[i] != m.last[i] {
			changed = true
		}
	}
	m.last = out
	return out, changed, nil
}
