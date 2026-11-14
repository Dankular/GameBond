package main

import "gamebond.local/nativeedge/client"

// lossCauses sorts every way a packet can fail to reach the far end into what we
// can act on. "upload" is what this side sent and the peer's selective acknowledgement
// showed dropped on a wire; "download" is what the reorder buffer gave up on; "local"
// is loss inside this machine, which no amount of redundancy on the wire can fix.
func lossCauses(s client.Snapshot) map[string]any {
	var osErrors any
	if n, ok := osUDPReceiveErrors(); ok {
		osErrors = n
	}
	return map[string]any{
		"upload": map[string]any{
			"frames_lost_on_wire": s.Sender.SackLost, "resent_at_once": s.Sender.SackResent,
			"held_for_sibling_copy": s.Sender.SackHeld, "unrecoverable_no_cache": s.Sender.SackUnrecoverable,
			"repair_copies_sent": s.Sender.RepairCopies,
			// The server asked this client to resend an upload packet and it could not: why.
			"repairs_refused": s.Sender.RepairUnavailableSent, "refused_not_cached": s.Sender.RepairNANotCached,
			"refused_too_old": s.Sender.RepairNAAged, "refused_attempts_used": s.Sender.RepairNAAttempts,
		},
		"download": map[string]any{
			"holes_given_up": s.Reorder.Skipped, "never_arrived": s.Reorder.Lost,
			"never_arrived_tcp": s.Reorder.LostTCP, "never_arrived_udp": s.Reorder.LostUDP,
			"arrived_after_deadline": s.Reorder.Late, "rebuilt_from_parity": s.Receiver.FECRecovered,
			"repairs_asked": s.Sender.RepairRequests, "repairs_exhausted": s.Sender.RepairExhausted,
		},
		"local": map[string]any{
			"delivery_queue_full": s.Loop.DeliverDropped, "socket_send_errors": s.Sender.SocketErrors,
			"queue_expired": s.Queue.Expired, "queue_rejected": s.Queue.Rejected, "wire_limited": s.Sender.WireLimited,
			"reorder_buffer_dropped": s.Reorder.DroppedPackets, "reorder_capacity_flushes": s.Reorder.CapacityFlushes,
			"os_udp_receive_errors": osErrors,
		},
	}
}
