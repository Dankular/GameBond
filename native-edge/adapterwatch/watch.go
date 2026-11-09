// Package adapterwatch turns "which adapters own which bind addresses right
// now" into client.UpdateUplinks input, so a daemon follows adapters that
// disappear, return or change index (python update_client_paths trigger).
package adapterwatch

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
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
	// Identity follows the selected Windows adapter across DHCP/index changes.
	Identity string
}

// PlanInventory resolves stable identities first; address-only configs retain
// their existing pinning behavior. Missing/offline slots never use a wildcard.
func PlanInventory(slots []Slot, adapters []uplink.Adapter, lookup Lookup) ([]uplink.Spec, []bool) {
	specs, available := Plan(slots, lookup)
	for i, slot := range slots {
		if slot.Identity == "" {
			continue
		}
		available[i] = false
		var found *uplink.Adapter
		matches := 0
		for j := range adapters {
			if strings.EqualFold(adapters[j].ID, slot.Identity) {
				found = &adapters[j]
				matches++
			}
		}
		if matches != 1 || !found.Up || found.Gateway == "" || found.Index <= 0 {
			continue
		}
		for _, address := range found.Addresses {
			ip, err := netip.ParseAddr(address)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			specs[i].Addr, specs[i].InterfaceIndex, specs[i].Interface = ip, found.Index, ""
			available[i] = true
			break
		}
	}
	return specs, available
}

// RunInventory applies the initial inventory and then follows selected stable
// identities. Discovery errors leave the current paths alone and are retried.
func RunInventory(ctx context.Context, interval time.Duration, slots []Slot, inventory func() ([]uplink.Adapter, error), lookup Lookup, update Updater, onError func(error)) {
	var lastSpecs []uplink.Spec
	var lastAvail []bool
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		rows, err := inventory()
		if err == nil {
			specs, avail := PlanInventory(slots, rows, lookup)
			if !reflect.DeepEqual(specs, lastSpecs) || !reflect.DeepEqual(avail, lastAvail) {
				err = update(specs, avail)
				if err == nil {
					lastSpecs, lastAvail = specs, avail
				}
			}
		}
		if err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
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
