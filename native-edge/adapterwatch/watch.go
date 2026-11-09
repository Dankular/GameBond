// Package adapterwatch turns "which adapters own which bind addresses right
// now" into client.UpdateUplinks input, so a daemon follows adapters that
// disappear, return or change index (python update_client_paths trigger).
package adapterwatch

import (
	"context"
	"net/netip"
	"reflect"
	"time"

	"gamebond.local/nativeedge/uplink"
)

// Lookup resolves a bind address to its adapter (uplink.InterfaceFor).
type Lookup func(netip.Addr) (index int, name string, err error)

// Slot is one configured uplink.
type Slot struct {
	Spec uplink.Spec
	// Pinned is true when the configuration fixed the adapter index; the slot
	// is then only available while that adapter still owns the address.
	Pinned bool
}

// Plan computes the specs and availability for the current adapter state.
// Slots bound to the unspecified address cannot be tracked by address, so they
// keep their spec and stay available.
func Plan(slots []Slot, lookup Lookup) (specs []uplink.Spec, available []bool) {
	specs = make([]uplink.Spec, len(slots))
	available = make([]bool, len(slots))
	for i, s := range slots {
		specs[i] = s.Spec
		if !s.Spec.Addr.IsValid() || s.Spec.Addr.IsUnspecified() {
			available[i] = true
			continue
		}
		idx, _, err := lookup(s.Spec.Addr)
		if err != nil {
			continue
		}
		if s.Pinned {
			available[i] = idx == s.Spec.InterfaceIndex
			continue
		}
		specs[i].InterfaceIndex = idx
		available[i] = true
	}
	return
}

// Updater is the part of client.Client the watcher drives.
type Updater func(specs []uplink.Spec, available []bool) error

// Run polls until ctx ends and calls update only when the plan changed.
// onError receives update failures (may be nil).
func Run(ctx context.Context, interval time.Duration, slots []Slot, lookup Lookup, update Updater, onError func(error)) {
	lastSpecs, lastAvail := Plan(slots, lookup)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		specs, avail := Plan(slots, lookup)
		if reflect.DeepEqual(specs, lastSpecs) && reflect.DeepEqual(avail, lastAvail) {
			continue
		}
		if err := update(specs, avail); err != nil {
			if onError != nil {
				onError(err)
			}
			continue // retry on the next tick
		}
		lastSpecs, lastAvail = specs, avail
	}
}
