package main

import "gamebond.local/nativeedge/client"

// errorCounters maps the snapshot's cumulative counters to the error kinds the history tracks
// (package errhist). osErrors is the operating system's UDP receive error count, when it has one.
func errorCounters(s client.Snapshot, osErrors uint64, osOK bool) map[string]uint64 {
	c := map[string]uint64{
		"lost_on_wire":           s.Sender.SackLost,
		"never_arrived":          s.Reorder.Lost,
		"holes_given_up":         s.Reorder.Skipped,
		"arrived_late":           s.Reorder.Late,
		"repairs_exhausted":      s.Sender.RepairExhausted,
		"socket_send_errors":     s.Sender.SocketErrors,
		"queue_expired":          s.Queue.Expired,
		"queue_rejected":         s.Queue.Rejected,
		"delivery_queue_full":    s.Loop.DeliverDropped,
		"reorder_buffer_dropped": s.Reorder.DroppedPackets,
		"auth_errors":            s.Receiver.AuthenticationErrors,
		"malformed_frames":       s.Receiver.Malformed,
		"handshake_rejected":     s.Receiver.HandshakeRejected,
		"replay_rejected":        s.Receiver.ReplayTooOld + s.Receiver.ReplayTooFar,
		"failover_suspected":     s.Sender.FailoverSuspected,
	}
	// The mechanisms that absorb those errors, charted over them.
	c["repair_sent"] = s.Sender.RepairCopies
	c["resent_at_once"] = s.Sender.SackResent
	c["parity_sent"] = s.Sender.ParitySent
	c["parity_recovered"] = s.Receiver.FECRecovered
	c["failover_replayed"] = s.Sender.FailoverReplayed
	c["failover_recovered"] = s.Sender.FailoverRecovered
	c["fast_reroutes"] = s.Sender.FastReroutes
	if osOK {
		c["os_udp_receive_errors"] = osErrors
	}
	return c
}

// linkCounts is how many uplinks are configured and how many of them are healthy.
func linkCounts(s client.Snapshot) (total, healthy int) {
	for _, p := range s.Paths {
		total++
		if p.Healthy {
			healthy++
		}
	}
	return
}

// linkHealth is each uplink's health by slot, for the link_down transitions.
func linkHealth(s client.Snapshot) map[int]bool {
	h := make(map[int]bool, len(s.Paths))
	for _, p := range s.Paths {
		h[p.Local] = p.Healthy
	}
	return h
}
