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
