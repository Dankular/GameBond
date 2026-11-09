//go:build windows

package scanner

import "testing"

// Passive: reads adapters and the neighbor cache, sends nothing on the LAN.
func TestTakeInventoryOnThisHost(t *testing.T) {
	inv, err := TakeInventory()
	if err != nil {
		t.Fatal(err)
	}
	if inv.ActiveProbe || len(inv.Adapters) == 0 {
		t.Fatalf("unexpected inventory: %+v", inv.Coverage)
	}
	t.Logf("%d adapters, %d neighbors", len(inv.Adapters), len(inv.Devices))
}
