package main

import (
	"testing"

	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/errhist"
	"github.com/Dankular/GameBond.Core/bond"
)

// Every counter the mapping produces must be a kind the history knows, or its errors would be dropped silently.
func TestErrorCountersUseKnownKinds(t *testing.T) {
	known := map[string]bool{}
	for _, k := range errhist.Kinds {
		known[k.Key] = true
	}
	for _, k := range errhist.Recoveries {
		known[k.Key] = true
	}
	for key := range errorCounters(client.Snapshot{}, 1, true) {
		if !known[key] {
			t.Errorf("%q is not an errhist kind", key)
		}
	}
}

func TestErrorCountersValues(t *testing.T) {
	var s client.Snapshot
	s.Sender.SocketErrors, s.Reorder.Lost, s.Receiver.ReplayTooOld, s.Receiver.ReplayTooFar, s.Loop.DeliverDropped = 3, 5, 2, 4, 9
	c := errorCounters(s, 11, true)
	if c["socket_send_errors"] != 3 || c["never_arrived"] != 5 || c["replay_rejected"] != 6 || c["delivery_queue_full"] != 9 || c["os_udp_receive_errors"] != 11 {
		t.Fatalf("%v", c)
	}
	if _, ok := errorCounters(s, 0, false)["os_udp_receive_errors"]; ok {
		t.Fatal("an unavailable OS counter must be left out, not reported as zero")
	}
}

func TestLinkHealthBySlot(t *testing.T) {
	s := client.Snapshot{Paths: []bond.PathSnapshot{{Local: 0, Healthy: true}, {Local: 2, Healthy: false}}}
	if h := linkHealth(s); !h[0] || h[2] || len(h) != 2 {
		t.Fatalf("%v", h)
	}
}

func TestRecoveryCountersAndLinkCounts(t *testing.T) {
	var s client.Snapshot
	s.Sender.RepairCopies, s.Sender.SackResent, s.Sender.ParitySent, s.Receiver.FECRecovered, s.Sender.FailoverReplayed, s.Sender.FastReroutes = 1, 2, 3, 4, 5, 6
	c := errorCounters(s, 0, false)
	if c["repair_sent"] != 1 || c["resent_at_once"] != 2 || c["parity_sent"] != 3 || c["parity_recovered"] != 4 || c["failover_replayed"] != 5 || c["fast_reroutes"] != 6 {
		t.Fatalf("%v", c)
	}
	s.Paths = []bond.PathSnapshot{{Healthy: true}, {Healthy: false}, {Healthy: true}}
	if total, healthy := linkCounts(s); total != 3 || healthy != 2 {
		t.Fatalf("%d/%d", healthy, total)
	}
}
