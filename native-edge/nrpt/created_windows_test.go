package nrpt

import (
	"os"
	"testing"
)

func TestProcessCreatedReportsOwnProcess(t *testing.T) {
	a, err := processCreated(os.Getpid())
	if err != nil || a == "" {
		t.Fatalf("%q %v", a, err)
	}
	if b, _ := processCreated(os.Getpid()); a != b {
		t.Fatal("creation time not stable")
	}
	if gone, err := processCreated(0x7ffffff0); err != nil || gone != "" {
		t.Fatalf("missing pid: %q %v", gone, err)
	}
}
