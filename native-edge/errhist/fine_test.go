package errhist

import (
	"testing"
	"time"
)

func TestViewKeepsFiveSecondSlots(t *testing.T) {
	tr := New()
	base := time.Unix(1_700_000_000, 0)
	tr.now = func() time.Time { return base }
	tr.add("link_down", 1)
	tr.now = func() time.Time { return base.Add(7 * time.Second) }
	tr.add("link_down", 2)
	fine := tr.View()["fine"].(map[string]any)
	rows := fine["minutes"].([][]uint64)
	if len(rows) != 2 {
		t.Fatalf("want two 5 s slots, got %v", rows)
	}
	if rows[1][0]-rows[0][0] != fineSeconds {
		t.Fatalf("slots %d s apart, want %d", rows[1][0]-rows[0][0], fineSeconds)
	}
	if len(tr.View()["minutes"].([][]uint64)) != 1 {
		t.Fatal("the per-minute history must still fold both into one row")
	}
}
