package dashboard

import "testing"

func TestWindowsAdapterDiscoveryReadOnly(t *testing.T) {
	rows, err := discoverAdapters()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rows {
		if a.Index <= 0 || a.Name == "" || !stableID(a.ID) {
			t.Fatalf("invalid adapter identity: %+v", a)
		}
		t.Logf("adapter %d %s up=%v IPv4=%v gateway=%s", a.Index, a.Name, a.Up, a.Addresses, a.Gateway)
	}
}
