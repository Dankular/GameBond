package alerting

import (
	"testing"
	"time"
)

func doc(ready ...bool) map[string]any {
	var ps []any
	for _, r := range ready {
		ps = append(ps, map[string]any{"ready": r})
	}
	return map[string]any{"state": "running", "transport": map[string]any{"paths": ps}}
}

func keys(ns []Notice) (out []string) {
	for _, n := range ns {
		k := n.Key
		if n.Resolved {
			k += "!"
		}
		out = append(out, k)
	}
	return
}

func TestNoLinksRaisesOnceAfterHoldThenResolves(t *testing.T) {
	w := NewWatcher()
	t0 := time.Unix(1000, 0)
	if n := w.Observe(t0, doc(false, false)); len(n) != 0 {
		t.Fatalf("raised before hold: %v", keys(n))
	}
	if n := w.Observe(t0.Add(6*time.Second), doc(false, false)); len(n) != 1 || n[0].Key != "no_links" || n[0].Severity != Critical {
		t.Fatalf("want no_links, got %v", keys(n))
	}
	if n := w.Observe(t0.Add(20*time.Second), doc(false, false)); len(n) != 0 {
		t.Fatalf("repeated: %v", keys(n))
	}
	if n := w.Observe(t0.Add(21*time.Second), doc(true, true)); len(n) != 1 || !n[0].Resolved {
		t.Fatalf("want recovery, got %v", keys(n))
	}
}

func TestRedundancyNeedsThirtySeconds(t *testing.T) {
	w := NewWatcher()
	t0 := time.Unix(1000, 0)
	w.Observe(t0, doc(true, false))
	if n := w.Observe(t0.Add(29*time.Second), doc(true, false)); len(n) != 0 {
		t.Fatalf("early: %v", keys(n))
	}
	if n := w.Observe(t0.Add(31*time.Second), doc(true, false)); len(n) != 1 || n[0].Key != "redundancy" {
		t.Fatalf("got %v", keys(n))
	}
	// A blip that clears before the hold never notifies.
	w2 := NewWatcher()
	w2.Observe(t0, doc(true, false))
	if n := w2.Observe(t0.Add(5*time.Second), doc(true, true)); len(n) != 0 {
		t.Fatalf("blip notified: %v", keys(n))
	}
}

func TestExitSwitchAndBackup(t *testing.T) {
	w := NewWatcher()
	t0 := time.Unix(1000, 0)
	d := doc(true)
	d["exit"] = map[string]any{"active": "10.0.0.1", "on_backup": false, "searching": false, "switches": float64(0)}
	w.Observe(t0, d)
	d["exit"] = map[string]any{"active": "10.0.0.2", "on_backup": true, "searching": false, "switches": float64(1)}
	got := keys(w.Observe(t0.Add(time.Second), d))
	if len(got) != 1 || got[0] != "exit_backup" {
		t.Fatalf("got %v", got)
	}
}

func TestAlarmClearsWhenItLeavesTheList(t *testing.T) {
	w := NewWatcher()
	t0 := time.Unix(1000, 0)
	d := doc(true)
	d["alarms"] = []any{map[string]any{"kind": "feedback-timeout", "detail": "x"}}
	w.Observe(t0, d)
	if n := w.Observe(t0.Add(31*time.Second), d); len(n) != 1 {
		t.Fatalf("got %v", keys(n))
	}
	d["alarms"] = []any{}
	if n := w.Observe(t0.Add(40*time.Second), d); len(n) != 1 || !n[0].Resolved {
		t.Fatalf("got %v", keys(n))
	}
}

func TestBurnNeedsBothWindows(t *testing.T) {
	w := NewWatcher()
	mk := func(h1, h6 float64) map[string]any {
		d := doc(true)
		d["slo"] = map[string]any{"evaluation": map[string]any{"windows": []any{
			map[string]any{"window_hours": float64(1), "delivery_burn_rate": h1},
			map[string]any{"window_hours": float64(6), "delivery_burn_rate": h6}}}}
		return d
	}
	t0 := time.Unix(1000, 0)
	if n := w.Observe(t0, mk(20, 1)); len(n) != 0 {
		t.Fatalf("fast window alone raised: %v", keys(n))
	}
	if n := w.Observe(t0.Add(time.Second), mk(20, 7)); len(n) != 1 || n[0].Key != "slo_burn" {
		t.Fatalf("got %v", keys(n))
	}
}
