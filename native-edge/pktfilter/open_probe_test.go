package pktfilter

import "testing"

// TestRealDriverPresence only opens the device handle (no mode change) and
// logs the result; it passes either way because it depends on the host.
func TestRealDriverPresence(t *testing.T) {
	d, err := OpenDevice()
	if err != nil {
		t.Logf("driver not available: %v", err)
		return
	}
	defer d.Close()
	list := make([]byte, AdapterListBytes)
	ok, n := d.Ioctl(IoctlGetTCPIPInterfaces, list, list)
	t.Logf("driver present; list ok=%v n=%d (want %d)", ok, n, AdapterListBytes)
	for _, r := range ParseAdapterList(list) {
		t.Logf("  %s mtu %d mac %x", r.Name, r.MTU, r.MAC)
	}
}
