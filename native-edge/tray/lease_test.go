//go:build windows

package tray

import "testing"

func TestLeaseSecondLaunchSignalsShow(t *testing.T) {
	root := t.TempDir()
	a, err := AcquireLease(root)
	if err != nil || !a.Owner {
		t.Fatal("first launch must own the lease", err)
	}
	defer a.Close()
	if a.ShowRequested() {
		t.Fatal("no show request yet")
	}
	b, err := AcquireLease(root)
	if err != nil || b.Owner {
		t.Fatal("second launch must not own the lease", err)
	}
	defer b.Close()
	if !a.ShowRequested() {
		t.Fatal("second launch did not signal Show")
	}
	if a.ShowRequested() {
		t.Fatal("Show request must be consumed (auto-reset event)")
	}
	other, _ := AcquireLease(t.TempDir())
	if !other.Owner {
		t.Fatal("a different workspace has its own lease")
	}
	other.Close()
}
