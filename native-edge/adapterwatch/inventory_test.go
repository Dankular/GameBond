package adapterwatch

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"gamebond.local/nativeedge/uplink"
)

func TestInventoryFollowsIdentityFromOfflineToNewAddressAndIndex(t *testing.T) {
	slots := []Slot{{Spec: uplink.Spec{Addr: a, InterfaceIndex: 11}, Identity: "{FIRST}"}, {Spec: uplink.Spec{Addr: netip.IPv4Unspecified(), InterfaceIndex: 12}, Identity: "{SECOND}"}}
	lookup := func(netip.Addr) (int, string, error) { return 0, "", errors.New("address not present") }
	rows := []uplink.Adapter{{ID: "{first}", Index: 11, Up: true, Addresses: []string{a.String()}, Gateway: "192.168.1.1"}, {ID: "{second}", Index: 12}}
	specs, avail := PlanInventory(slots, rows, lookup)
	if !avail[0] || avail[1] || specs[1].InterfaceIndex != 12 {
		t.Fatal(specs, avail)
	}
	rows[1] = uplink.Adapter{ID: "{second}", Index: 47, Up: true, Addresses: []string{"10.0.0.9"}, Gateway: "10.0.0.1"}
	specs, avail = PlanInventory(slots, rows, lookup)
	if !avail[0] || !avail[1] || specs[1].Addr.String() != "10.0.0.9" || specs[1].InterfaceIndex != 47 {
		t.Fatal(specs, avail)
	}
	// An unrelated adapter with the old index/address must not claim the slot.
	rows[1].ID = "{unrelated}"
	_, avail = PlanInventory(slots, rows, lookup)
	if avail[1] {
		t.Fatal("followed a different adapter")
	}
	rows[1].ID = "{second}"
	rows = append(rows, rows[1])
	_, avail = PlanInventory(slots, rows, lookup)
	if avail[1] {
		t.Fatal("ambiguous identity accepted")
	}
	rows = rows[:2]
	rows[1].Gateway = ""
	_, avail = PlanInventory(slots, rows, lookup)
	if avail[1] {
		t.Fatal("adapter without gateway used")
	}
}

func TestInventoryPollRetriesDiscoveryAndUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var queries, updates atomic.Int32
	var up atomic.Bool
	observed := make(chan bool, 8)
	inventory := func() ([]uplink.Adapter, error) {
		if queries.Add(1) == 1 {
			return nil, errors.New("temporary discovery failure")
		}
		return []uplink.Adapter{{ID: "{one}", Index: 11, Up: up.Load(), Addresses: []string{a.String()}, Gateway: "192.168.1.1"}}, nil
	}
	lookup := func(netip.Addr) (int, string, error) { return 0, "", errors.New("not present") }
	update := func(_ []uplink.Spec, avail []bool) error {
		if updates.Add(1) == 1 {
			return errors.New("temporary bind failure")
		}
		observed <- avail[0]
		return nil
	}
	done := make(chan struct{})
	go func() {
		RunInventory(ctx, 10*time.Millisecond, []Slot{{Identity: "{one}", Spec: uplink.Spec{Addr: a}}}, inventory, lookup, update, nil)
		close(done)
	}()
	wait := func(want bool) {
		t.Helper()
		select {
		case got := <-observed:
			if got != want {
				t.Fatalf("available=%v want %v", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no inventory update")
		}
	}
	wait(false)
	up.Store(true)
	wait(true)
	cancel()
	<-done
	if updates.Load() != 3 {
		t.Fatal("unchanged inventory caused updates", updates.Load())
	}
}
