package main

import (
	"reflect"
	"testing"

	"gamebond.local/nativeedge/bond"
)

func TestMTUStatusShape(t *testing.T) {
	if mtuStatus(bond.PathSnapshot{}, nil) != nil {
		t.Fatal("no discovery must report null")
	}
	p := bond.PathSnapshot{Local: 1, MTUSkips: 3, MTU: &bond.MTUStats{PathMTU: 1400, Ceiling: 1500, Confirmed: 1300, Capable: true, Rounds: 4, Acks: 2, FailedSizes: []int{1450, 1410}}}
	got := mtuStatus(p, []bool{false, true}).(map[string]any)
	want := map[string]any{"path_mtu": 1400, "ceiling": 1500, "confirmed": 1300, "capable": true, "rounds": 4, "acks": 2,
		"failed_sizes": []int{1410, 1450}, "skips": uint64(3), "df_enforced": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if mtuStatus(bond.PathSnapshot{Local: 5, MTU: &bond.MTUStats{}}, []bool{true}).(map[string]any)["df_enforced"] != false {
		t.Fatal("out-of-range slot must not enforce")
	}
}
