package errhist

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func clocked(start time.Time) (*Tracker, *time.Time) {
	t := New()
	now := start
	t.now = func() time.Time { return now }
	return t, &now
}

func rows(t *Tracker) [][]uint64 { return t.View()["minutes"].([][]uint64) }

func col(key string) int { return 1 + index[key] }

func TestFirstObservationIsOnlyABaseline(t *testing.T) {
	tr, _ := clocked(time.Unix(1_700_000_000, 0))
	tr.Observe(map[string]uint64{"socket_send_errors": 500})
	if r := rows(tr); len(r) != 0 {
		t.Fatalf("errors from before the tracker started were counted: %v", r)
	}
}

func TestDeltasLandInTheMinuteTheyHappened(t *testing.T) {
	start := time.Unix(1_700_000_040, 0)
	tr, now := clocked(start)
	tr.Observe(map[string]uint64{"socket_send_errors": 10, "malformed_frames": 0})
	*now = now.Add(5 * time.Second)
	tr.Observe(map[string]uint64{"socket_send_errors": 13, "malformed_frames": 0})
	*now = now.Add(2 * time.Minute)
	tr.Observe(map[string]uint64{"socket_send_errors": 13, "malformed_frames": 4})
	r := rows(tr)
	if len(r) != 2 || r[0][col("socket_send_errors")] != 3 || r[1][col("malformed_frames")] != 4 || r[1][col("socket_send_errors")] != 0 {
		t.Fatalf("rows: %v", r)
	}
	if r[1][0]-r[0][0] != 120 {
		t.Fatalf("minutes should be two apart: %v", r)
	}
}

func TestACounterResetCountsFromZero(t *testing.T) {
	tr, now := clocked(time.Unix(1_700_000_000, 0))
	tr.Observe(map[string]uint64{"never_arrived": 100})
	*now = now.Add(time.Second)
	tr.Observe(map[string]uint64{"never_arrived": 7}) // the client restarted its counters
	if r := rows(tr); len(r) != 1 || r[0][col("never_arrived")] != 7 {
		t.Fatalf("reset: %v", r)
	}
}

func TestUnknownKeysAreIgnored(t *testing.T) {
	tr, now := clocked(time.Unix(1_700_000_000, 0))
	tr.Observe(map[string]uint64{"made_up": 1})
	*now = now.Add(time.Second)
	tr.Observe(map[string]uint64{"made_up": 9})
	if r := rows(tr); len(r) != 0 {
		t.Fatalf("unknown kind recorded: %v", r)
	}
}

func TestLinkDownIsCountedOnTheTransitionOnly(t *testing.T) {
	tr, now := clocked(time.Unix(1_700_000_000, 0))
	tr.Links(map[int]bool{0: true, 1: false}) // link 1 was already down when we started looking
	*now = now.Add(time.Second)
	tr.Links(map[int]bool{0: true, 1: false})
	*now = now.Add(time.Second)
	tr.Links(map[int]bool{0: false, 1: false}) // link 0 just went down
	*now = now.Add(time.Second)
	tr.Links(map[int]bool{0: false, 1: false}) // and stays down
	*now = now.Add(time.Second)
	tr.Links(map[int]bool{0: true, 1: true}) // recovery is not an error
	if r := rows(tr); len(r) != 1 || r[0][col("link_down")] != 1 {
		t.Fatalf("link_down: %v", r)
	}
}

func TestHistoryIsBoundedToADay(t *testing.T) {
	tr, now := clocked(time.Unix(1_700_000_000, 0))
	tr.Observe(map[string]uint64{"socket_send_errors": 0})
	for i := 1; i <= historyMinutes+300; i++ {
		*now = now.Add(time.Minute)
		tr.Observe(map[string]uint64{"socket_send_errors": uint64(i)})
	}
	if n := len(rows(tr)); n > historyMinutes {
		t.Fatalf("%d minutes kept", n)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	tr, now := clocked(start)
	tr.Observe(map[string]uint64{"auth_errors": 0})
	*now = now.Add(time.Second)
	tr.Observe(map[string]uint64{"auth_errors": 5})
	path := filepath.Join(t.TempDir(), "e.json")
	if err := tr.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := tr.Save(path); err != nil { // unchanged: nothing to write
		t.Fatal(err)
	}
	t2, _ := clocked(*now)
	t2.Load(path)
	if r := rows(t2); len(r) != 1 || r[0][col("auth_errors")] != 5 {
		t.Fatalf("restored: %v", r)
	}
	t3, _ := clocked(now.Add(25 * time.Hour))
	t3.Load(path)
	if r := rows(t3); len(r) != 0 {
		t.Fatalf("a day-old history must be dropped: %v", r)
	}
	os.WriteFile(path, []byte("{not json"), 0o600)
	t4, _ := clocked(*now)
	t4.Load(path) // must not panic
}

func TestKindsAreUniqueAndDescribed(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range Kinds {
		if seen[k.Key] || k.Label == "" || k.Group == "" || k.Help == "" {
			t.Fatalf("bad kind %+v", k)
		}
		seen[k.Key] = true
	}
}
