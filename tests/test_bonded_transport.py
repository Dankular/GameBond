"""Real loopback sockets; no routes, drivers or production session."""
import queue
import secrets
import socket
import struct
import time
import unittest
import threading
import json
import heapq
from unittest import mock

from gamebond.transport import (Node, OVERHEAD, BOND_OVERHEAD, DATA, STRIPED,
                                FEEDBACK, STRIPE_HEADER, FEEDBACK_HEADER)


def handshake_without_threads(client, server):
    """Exercise the real authenticated handshake before deterministic injection."""
    from collections import deque
    pending = deque()
    exchanged = []
    original_client, original_server = client._write, server._write
    def client_write(packet, path):
        pending.append((server, 0, packet, client.addresses[path.socket_index]))
        return True
    def server_write(packet, path):
        index = client.addresses.index(path.endpoint)
        pending.append((client, index, packet, server.addresses[path.socket_index]))
        return True
    client._write, server._write = client_write, server_write
    try:
        client._probe()
        for _ in range(100):
            if not pending:
                break
            receiver, index, packet, source = pending.popleft()
            exchanged.append((receiver, index, packet, source))
            receiver._receive(index, packet, source)
        else:
            raise AssertionError("handshake failed to terminate")
        assert all(path.ready for path in client._paths.values())
        assert all(path.ready for path in server._paths.values())
        return exchanged
    finally:
        client._write, server._write = original_client, original_server


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.005)
    raise AssertionError("condition timed out")


class BondedTransportTests(unittest.TestCase):
    def test_udp_bulk_does_not_enter_tcp_repair_cache(self):
        self.start()
        self.client.send(b'opaque UDP payload',replicate=False,flow_id='udp')
        self.assertEqual(self.server.recv(1),b'opaque UDP payload')
        self.assertFalse(self.client._repair_cache)

    def test_lost_bulk_packet_is_repaired_without_duplicate_delivery(self):
        from gamebond.transport import HEADER
        self.start()
        original = self.client._write
        dropped = []
        def lose_once(packet, path):
            if HEADER.unpack_from(packet)[3] == STRIPED and not dropped:
                dropped.append(packet)
                return True
            return original(packet,path)
        self.client._write = lose_once
        def tcp(payload):
            header=bytearray(40);header[0]=0x45;header[2:4]=(40+len(payload)).to_bytes(2,'big')
            header[9]=6;header[32]=0x50
            return bytes(header)+payload
        payloads=[tcp(p) for p in (b'zero',b'one',b'two')]
        for payload in payloads:
            self.assertEqual(self.client.send(payload,replicate=False,flow_id='repair'),1)
        self.assertEqual([self.server.recv(2) for _ in range(3)],payloads)
        self.assertGreater(self.client.stats().get('repair_packets',0),0)
        # A delayed original copy after repair must remain a duplicate.
        self.server._receive(0,dropped[0],self.client.addresses[0])
        with self.assertRaises(queue.Empty):self.server.recv(.05)

    def test_low_offered_single_flow_is_weighted_instead_of_pinned_to_fast_rtt(self):
        from gamebond.bonding import PathBudget
        counts=[0,0]
        for index,path in enumerate(self.client._paths.values()):
            path.ready=True;path.last_rx=time.perf_counter();path.rtt_ms=20+index*20
            path.budget=PathBudget(100*(index+1),100*(index+1))
        self.client._write=lambda packet,path: counts.__setitem__(path.socket_index,counts[path.socket_index]+1) or True
        for _ in range(180):
            self.assertEqual(self.client.send(b'x'*1000,replicate=False,flow_id='one TCP flow'),1)
            time.sleep(.001)
        self.assertGreater(counts[0],35)
        self.assertGreater(counts[1],90)
        self.assertGreater(counts[1],counts[0])

    def setUp(self):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        options = dict(bonding_mode=True, mtu=1280 + OVERHEAD + BOND_OVERHEAD,
                       probe_interval=.05, path_timeout=.3,
                       initial_rate_mbps=2, max_rate_mbps=8)
        self.server = Node(key, "server", session, [("127.0.0.1", 0)], **options)
        self.client = Node(key, "client", session,
                           [("127.0.0.1", 0), ("127.0.0.1", 0)],
                           peer=self.server.addresses[0], **options)

    def tearDown(self):
        self.client.close()
        self.server.close()

    def start(self):
        self.server.start()
        self.client.start()
        wait_for(lambda: len(self.server.stats()["paths"]) == 2 and
                 all(p["healthy"] for p in self.client.stats()["paths"]))

    def test_one_flow_stripes_both_directions_and_feedback_is_authenticated(self):
        self.start()
        for sender, receiver in ((self.client, self.server), (self.server, self.client)):
            payloads = [struct.pack("!I", i) + b"x" * 1000 for i in range(160)]
            before = {id(p): p.transmitted for p in sender._paths.values()}
            data_paths = []
            original_write = sender._write
            def record_write(packet, path):
                from gamebond.transport import HEADER
                if HEADER.unpack_from(packet)[3] == STRIPED:
                    data_paths.append((path.socket_index, path.endpoint))
                return original_write(packet, path)
            sender._write = record_write
            for payload in payloads:
                self.assertEqual(sender.send(payload, replicate=False, flow_id="one TCP flow"), 1)
            self.assertEqual([receiver.recv(2) for _ in payloads], payloads)
            # Count data via controller rather than probes/feedback socket totals.
            sender._write = original_write
            self.assertEqual(len(set(data_paths)), 2)
            self.assertTrue(all(p.transmitted > before[id(p)] for p in sender._paths.values()))
            wait_for(lambda: sender.stats()["feedback_received"] > 0)
            self.assertEqual(sender.stats()["bonded_packets"], len(payloads))
            self.assertEqual(len(sender._stripe_flows), 1)
        self.assertEqual(self.client.stats()["auth_failures"], 0)
        self.assertEqual(self.server.stats()["receive_drops"], 0)

    def test_reordering_gap_timeout_does_not_block_immediate_game_data(self):
        handshake_without_threads(self.client, self.server)
        address = self.client.addresses[0]
        def inject(number, payload):
            packet = self.client._encode(STRIPED, STRIPE_HEADER.pack(7, number, 1) + payload)
            self.server._receive(0, packet, address)
        inject(1, b"bulk one")
        with self.assertRaises(queue.Empty):
            self.server.recv(.001)
        self.server._receive(0, self.client._encode(DATA, b"game"), address)
        self.assertEqual(self.server.recv(.1), b"game")
        inject(0, b"bulk zero")
        self.assertEqual(self.server.recv(.1), b"bulk zero")
        self.assertEqual(self.server.recv(.1), b"bulk one")
        inject(3, b"after loss")
        time.sleep(.04)
        self.server._maintenance()
        self.assertEqual(self.server.recv(.1), b"after loss")

    def test_priority_duplication_and_one_path_failure(self):
        self.start()
        self.assertEqual(self.client.send(b"game", replicate=True), 2)
        self.assertEqual(self.server.recv(1), b"game")
        with self.assertRaises(queue.Empty):
            self.server.recv(.05)
        original = self.client._write
        self.client._write = lambda packet, path: False if path.socket_index == 0 else original(packet, path)
        time.sleep(.4)
        for i in range(30):
            self.assertEqual(self.client.send(str(i).encode(), replicate=False, flow_id="bulk"), 1)
        self.assertEqual([self.server.recv(1) for _ in range(30)], [str(i).encode() for i in range(30)])
        self.assertEqual(self.server.stats()["receive_drops"], 0)

    def test_feedback_tamper_cannot_advance_controller_and_legacy_fails_closed(self):
        address = self.client.addresses[0]
        packet = self.client._encode(FEEDBACK, FEEDBACK_HEADER.pack(1, 2**63, 2**63, 0))
        bad = bytearray(packet)
        bad[-1] ^= 1
        self.server._receive(0, bytes(bad), address)
        self.assertEqual(self.server.stats()["auth_failures"], 1)
        self.assertEqual(len(self.server._paths), 0)
        handshake_without_threads(self.client, self.server)
        packet = self.client._encode(FEEDBACK, FEEDBACK_HEADER.pack(1, 2**63, 2**63, 0))
        self.server._receive(0, packet, address)
        self.assertEqual(self.server.stats()["feedback_rejected"], 1)
        legacy = Node(self.client._key, "server", self.client.session, [("127.0.0.1", 0)])
        try:
            legacy._receive(0, self.client._encode(DATA, b"new format"), address)
            self.assertEqual(len(legacy._paths), 0)
            self.assertEqual(legacy.stats()["malformed"], 1)
        finally:
            legacy.close()

    def test_inner_mtu_and_no_healthy_path(self):
        self.assertEqual(self.client.send(b"no path", replicate=False), 0)
        with self.assertRaises(ValueError):
            self.client.send(b"x" * 1281, replicate=False)
        self.start()
        self.assertEqual(self.client.send(b"x" * 1280, replicate=False), 1)
        self.assertEqual(self.server.recv(1), b"x" * 1280)

    def test_nat_rebinding_keeps_feedback_counters_and_budget_both_directions(self):
        self.start()
        for i in range(40):
            self.client.send(b"before" * 150, replicate=False, flow_id="bulk")
        for _ in range(40):
            self.server.recv(1)
        wait_for(lambda: self.client.stats()["feedback_received"] > 0)
        before = self.client.stats()["feedback_received"]
        old_address = self.client.addresses[0]
        # Keep an authenticated, not-yet-seen old-endpoint packet to verify
        # delayed arrivals cannot move the path back to its previous endpoint.
        from gamebond.transport import PROBE
        old_path = next(p for p in self.client._paths.values() if p.socket_index == 0)
        delayed = self.client._encode(PROBE, struct.pack("!Q", old_path.tx_epoch) + secrets.token_bytes(16))
        old_socket = self.client._sockets[0]
        replacement = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        replacement.bind(("127.0.0.1", 0))
        replacement.setblocking(False)
        with self.client._lock:
            self.client._sockets[0] = replacement
        # Closing a socket selected by another thread can terminate its receive
        # loop on some platforms, so retain it until the next selection cycle.
        time.sleep(.08)
        old_socket.close()
        new_address = replacement.getsockname()
        wait_for(lambda: any(p.endpoint == new_address for p in self.server._paths.values()))
        with self.server._lock:
            self.server._receive(0, delayed, old_address)
        self.assertNotIn((0, old_address), self.server._paths)
        self.assertEqual(len(self.server._paths), 2)
        for i in range(40):
            self.client.send(b"after" * 150, replicate=False, flow_id="bulk")
        self.assertEqual([self.server.recv(1) for _ in range(40)], [b"after" * 150] * 40)
        wait_for(lambda: self.client.stats()["feedback_received"] > before)
        for i in range(20):
            self.server.send(b"return" * 150, replicate=False, flow_id="return")
        self.assertEqual([self.client.recv(1) for _ in range(20)], [b"return" * 150] * 20)
        wait_for(lambda: self.server.stats()["feedback_received"] > 0)

    def test_lost_final_feedback_is_repeated_without_rejecting_duplicate_ack(self):
        self.start()
        original = self.server._write
        lost = []
        from gamebond.transport import HEADER
        def drop_first_feedback(packet, path):
            if HEADER.unpack_from(packet)[3] == FEEDBACK and not lost:
                lost.append(packet)
                return True  # A successful UDP write may still be lost in transit.
            return original(packet, path)
        self.server._write = drop_first_feedback
        self.assertEqual(self.client.send(b"last packet", replicate=False, flow_id="bulk"), 1)
        self.assertEqual(self.server.recv(1), b"last packet")
        wait_for(lambda: self.client.stats()["feedback_received"] > 0)
        self.assertEqual(len(lost), 1)
        wait_for(lambda: self.client.stats()["feedback_duplicates"] > 0)
        self.assertEqual(self.client.stats()["feedback_rejected"], 0)

    def new_client(self, receive_capacity=1024):
        return Node(self.server._key, "client", self.server.session,
                    [("127.0.0.1", 0), ("127.0.0.1", 0)],
                    peer=self.server.addresses[0], bonding_mode=True,
                    mtu=1280 + OVERHEAD + BOND_OVERHEAD, probe_interval=.05,
                    path_timeout=.3, initial_rate_mbps=2, max_rate_mbps=8,
                    receive_capacity=receive_capacity)

    def test_client_restart_renegotiates_without_server_restart_or_rekey(self):
        self.start()
        old_prefix = self.server._remote_prefix
        self.assertEqual(self.client.send(b"before", replicate=False, flow_id="bulk"), 1)
        self.assertEqual(self.server.recv(1), b"before")
        self.client.close()
        self.client = self.new_client().start()
        wait_for(lambda: self.server._remote_prefix != old_prefix and
                 len(self.server.stats()["paths"]) == 2 and
                 all(path["healthy"] for path in self.client.stats()["paths"]))
        self.assertEqual(self.server.stats()["peer_restarts"], 1)
        for sender, receiver in ((self.client, self.server), (self.server, self.client)):
            self.assertEqual(sender.send(b"after restart", replicate=False, flow_id="bulk"), 1)
            self.assertEqual(receiver.recv(1), b"after restart")

    def test_server_restart_renegotiates_and_rejects_prehandshake_data(self):
        self.start()
        old_server_prefix = self.client._remote_prefix
        stale = self.client._encode(DATA, b"captured before server restart")
        client_address = self.client.addresses[0]
        address = self.server.addresses[0]
        key, session = self.server._key, self.server.session
        self.server.close()
        self.server = Node(key, "server", session, [address], bonding_mode=True,
                           mtu=1280 + OVERHEAD + BOND_OVERHEAD, probe_interval=.05,
                           path_timeout=.3, initial_rate_mbps=2, max_rate_mbps=8).start()
        wait_for(lambda: self.client._remote_prefix != old_server_prefix and
                 len(self.server.stats()["paths"]) == 2 and
                 all(path["healthy"] for path in self.client.stats()["paths"]))
        with self.server._lock:
            self.server._receive(0, stale, client_address)
        with self.assertRaises(queue.Empty):
            self.server.recv(.05)
        for sender, receiver in ((self.client, self.server), (self.server, self.client)):
            self.assertEqual(sender.send(b"new server", replicate=False, flow_id="bulk"), 1)
            self.assertEqual(receiver.recv(1), b"new server")

    def test_replayed_old_hello_and_reset_cannot_restore_previous_client(self):
        from gamebond.transport import HEADER, HELLO, RESET
        exchanged = handshake_without_threads(self.client, self.server)
        old_packets = [row for row in exchanged if row[0] is self.server and
                       HEADER.unpack_from(row[2])[3] in (HELLO, RESET)]
        self.client.close()
        self.client = self.new_client()
        handshake_without_threads(self.client, self.server)
        current = self.server._remote_prefix
        rejected = self.server.stats()["handshake_rejected"]
        for _, index, packet, source in old_packets:
            self.server._receive(index, packet, source)
        self.assertEqual(self.server._remote_prefix, current)
        self.assertEqual(current, self.client._prefix)
        self.assertGreater(self.server.stats()["handshake_rejected"], rejected)
        self.assertTrue(all(path.ready for path in self.server._paths.values()))

    def test_unmatched_challenge_and_raw_data_cannot_pin_or_mark_healthy(self):
        from gamebond.transport import CHALLENGE, READY
        self.client._probe()  # create fresh per-path client challenges
        source = self.server.addresses[0]
        for kind in (CHALLENGE, READY):
            self.client._receive(0, self.server._encode(kind, secrets.token_bytes(32)), source)
        self.assertIsNone(self.client._remote_prefix)
        self.assertTrue(all(not path["healthy"] for path in self.client.stats()["paths"]))
        self.server._receive(0, self.client._encode(DATA, b"before proof"), self.client.addresses[0])
        self.assertIsNone(self.server._remote_prefix)
        self.assertEqual(len(self.server._paths), 0)

    def test_lost_ready_is_retried_with_consumed_reset_without_repinning(self):
        from gamebond.transport import HEADER, READY
        original = self.server._write
        lost = []
        def lose_ready(packet, path):
            if HEADER.unpack_from(packet)[3] == READY and not lost:
                lost.append(packet)
                return True
            return original(packet, path)
        self.server._write = lose_ready
        self.start()
        self.assertEqual(len(lost), 1)
        self.assertEqual(self.server.stats()["handshake_resets"], 2)
        self.assertEqual(self.server.stats()["peer_restarts"], 0)
        self.assertEqual(self.client.send(b"ready after retry", replicate=True), 2)
        self.assertEqual(self.server.recv(1), b"ready after retry")

    def feedback_with_receiver_hold(self, lost_first=False):
        """Simulate 25ms each way and a 20ms receiver ACK batching hold."""
        from gamebond.transport import HEADER
        handshake_without_threads(self.client, self.server)
        tx_path = next(path for path in self.client._paths.values() if path.socket_index == 0)
        sequence = self.client._sequence
        packet = self.client._encode(STRIPED, STRIPE_HEADER.pack(10, 0, tx_path.tx_epoch) + b"payload")
        tx_path.budget.sent(sequence, len(packet), 100.0)
        with mock.patch("gamebond.transport.time.perf_counter", return_value=100.025):
            self.server._receive(0, packet, self.client.addresses[0], received_at=100.025)
        feedback = []
        original = self.server._write
        def capture(packet, path):
            if HEADER.unpack_from(packet)[3] == FEEDBACK:
                feedback.append(packet)
            return True
        self.server._write = capture
        try:
            with mock.patch("gamebond.transport.time.perf_counter", return_value=100.045):
                self.server._maintenance()
            if lost_first:
                with mock.patch("gamebond.transport.time.perf_counter", return_value=100.1451):
                    self.server._maintenance()
            arrived = 100.1701 if lost_first else 100.070
            with mock.patch("gamebond.transport.time.perf_counter", return_value=arrived):
                self.client._receive(0, feedback[-1], self.server.addresses[0], received_at=arrived)
        finally:
            self.server._write = original
        decoded = []
        for frame in feedback:
            header = frame[:HEADER.size]
            _, _, prefix, _, transport_sequence = HEADER.unpack(header)
            cipher = self.client._cipher(prefix, "server")
            plain = cipher.decrypt(b"\0" * 4 + transport_sequence.to_bytes(8, "big"), frame[HEADER.size:], header)
            decoded.append(FEEDBACK_HEADER.unpack(plain))
        return tx_path, decoded

    def test_receiver_ack_batch_hold_is_removed_from_network_rtt(self):
        path, feedback = self.feedback_with_receiver_hold()
        self.assertEqual(len(feedback), 1)
        self.assertAlmostEqual(feedback[0][3], 20000, delta=1)
        self.assertAlmostEqual(path.budget.min_rtt, .05, places=5)
        self.assertEqual(self.client.stats()["feedback_received"], 1)

    def test_repeated_ack_uses_current_age_after_first_ack_loss(self):
        path, feedback = self.feedback_with_receiver_hold(lost_first=True)
        self.assertEqual(len(feedback), 2)
        self.assertAlmostEqual(feedback[1][3], 120100, delta=1)
        self.assertEqual(feedback[0][:3], feedback[1][:3])
        self.assertAlmostEqual(path.budget.min_rtt, .05, places=5)
        self.assertEqual(self.client.stats()["feedback_received"], 1)

    def test_feedback_delay_range_and_unknown_credit_are_rejected(self):
        handshake_without_threads(self.client, self.server)
        tx_path = next(path for path in self.client._paths.values() if path.socket_index == 0)
        for delay in (1_000_001, 0xffffffff, 1_000_000):
            packet = self.server._encode(FEEDBACK, FEEDBACK_HEADER.pack(tx_path.tx_epoch, 2**63, 9999, delay))
            self.client._receive(0, packet, self.server.addresses[0])
        self.assertEqual(self.client.stats()["feedback_received"], 0)
        self.assertEqual(self.client.stats()["feedback_rejected"], 3)
        # The previous24-byte layout is malformed under the updated protocol.
        old_layout = self.server._encode(FEEDBACK, struct.pack("!QQQ", tx_path.tx_epoch, 1, 100))
        self.client._receive(0, old_layout, self.server.addresses[0])
        self.assertEqual(self.client.stats()["malformed"], 1)

    def test_previous_bonded_wire_version_cannot_complete_a_handshake(self):
        from gamebond.transport import HELLO
        current_magic = self.client._magic
        try:
            self.client._magic = b"GB02"
            previous_version = self.client._encode(HELLO, secrets.token_bytes(16))
        finally:
            self.client._magic = current_magic
        self.server._receive(0, previous_version, self.client.addresses[0])
        self.assertIsNone(self.server._remote_prefix)
        self.assertEqual(self.server.stats()["paths"], [])
        self.assertEqual(self.server.stats()["malformed"], 1)

    def test_full_bulk_inbox_admits_5g_game_immediately_in_both_directions(self):
        key, session = self.server._key, self.server.session
        self.client.close()
        self.server.close()
        self.server = Node(key, "server", session, [("127.0.0.1", 0)], bonding_mode=True,
                           mtu=1280 + OVERHEAD + BOND_OVERHEAD, receive_capacity=4,
                           probe_interval=.05, path_timeout=.3)
        self.client = self.new_client(receive_capacity=4)
        handshake_without_threads(self.client, self.server)
        for sender, receiver in ((self.client, self.server), (self.server, self.client)):
            if sender is self.client:
                source, receive_index = self.client.addresses[1], 0
                tx_path = next(path for path in sender._paths.values() if path.socket_index == 1)
            else:
                source, receive_index = self.server.addresses[0], 1
                tx_path = sender._paths[(0, self.client.addresses[1])]
            for number in range(4):
                frame = sender._encode(STRIPED, STRIPE_HEADER.pack(20, number, tx_path.tx_epoch) + f"bulk{number}".encode())
                receiver._receive(receive_index, frame, source)
            self.assertEqual(receiver.stats()["receive_inbox"]["bulk"]["queued_packets"], 4)
            for payload in (b"game one via 5G", b"game two via 5G"):
                receiver._receive(receive_index, sender._encode(DATA, payload), source)
            # A full bulk backlog cannot force gameplay to wait for its drain.
            self.assertEqual(receiver.recv(0), b"game one via 5G")
            self.assertEqual(receiver.recv(0), b"game two via 5G")
            self.assertEqual(receiver.recv(0), b"bulk2")
            self.assertEqual(receiver.recv(0), b"bulk3")
            stats = receiver.stats()
            inbox = stats["receive_inbox"]
            self.assertEqual(stats["receive_drops"], 2)
            self.assertEqual(inbox["bulk_evicted_for_priority"], 2)
            self.assertEqual(inbox["priority_full_drops"], 0)
            self.assertEqual(inbox["priority"]["residence_samples"], 2)
            self.assertEqual(inbox["bulk"]["residence_samples"], 2)
            self.assertEqual(inbox["peak_packets"], 4)
            self.assertEqual(inbox["queued_packets"], 0)

    def test_priority_copies_charge_wire_service_without_ack_or_window_credit(self):
        handshake_without_threads(self.client, self.server)
        payload = b"urgent game"
        self.assertEqual(self.client.send(payload, replicate=True), 2)
        expected_wire = len(payload) + OVERHEAD + 28
        stats = self.client.stats()
        self.assertEqual(stats["priority_tx_packets"], 2)
        self.assertEqual(stats["priority_tx_wire_bytes"], 2 * expected_wire)
        for path in stats["paths"]:
            self.assertEqual(path["priority_tx_packets"], 1)
            self.assertEqual(path["priority_tx_wire_bytes"], expected_wire)
            self.assertEqual(path["bonding"]["priority_wire_bytes"], expected_wire)
            self.assertEqual(path["bonding"]["priority_wire_packets"], 1)
            self.assertEqual(path["bonding"]["pending_packets"], 0)
            self.assertEqual(path["bonding"]["inflight_bytes"], 0)
            self.assertEqual(path["bonding"]["sent_bytes"], 0)
            self.assertGreater(path["bonding"]["next_send"], 0)

    def test_first_and_duplicate_path_copies_are_distinct_from_replay_age_drops(self):
        from gamebond.transport import PROBE, REPLAY_WINDOW
        handshake_without_threads(self.client, self.server)
        starlink, phone = self.client.addresses
        starlink_path = self.server._paths[(0, starlink)]
        original_health_time = starlink_path.last_rx
        first = self.client._encode(DATA, b"seen priority")
        unseen = self.client._encode(DATA, b"unseen delayed priority")
        self.server._receive(0, first, phone)
        self.server._receive(0, first, starlink)
        self.assertEqual(starlink_path.last_rx, original_health_time)
        # A valid high sequence models other authenticated traffic advancing
        # the shared replay window; the delayed DATA was never seen before.
        self.client._sequence += REPLAY_WINDOW
        phone_path = next(path for path in self.client._paths.values() if path.socket_index == 1)
        advance = self.client._encode(PROBE, struct.pack("!Q", phone_path.tx_epoch) + secrets.token_bytes(16))
        self.server._receive(0, advance, phone)
        self.server._receive(0, unseen, starlink)
        stats = self.server.stats()
        self.assertEqual(stats["duplicates"], 2)  # historical aggregate retained
        self.assertEqual(stats["duplicate_copies"], 1)
        self.assertEqual(stats["replay_too_old_drops"], 1)
        self.assertEqual(stats["priority_rx_first_packets"], 1)
        self.assertEqual(stats["priority_rx_duplicate_packets"], 1)
        self.assertEqual(stats["priority_rx_too_old_packets"], 1)
        self.assertEqual(starlink_path.priority_rx_first_packets, 0)
        self.assertEqual(starlink_path.priority_rx_duplicate_packets, 1)
        self.assertEqual(starlink_path.priority_rx_too_old_packets, 1)
        self.assertEqual(starlink_path.last_rx, original_health_time)
        self.assertEqual(self.server._paths[(0, phone)].priority_rx_first_packets, 1)
        self.assertEqual(self.server.recv(0), b"seen priority")
        with self.assertRaises(queue.Empty):
            self.server.recv(0)

    def test_continuous_bidirectional_game_with_bulk_and_ten_second_blackhole(self):
        """Actual UDP loopback; synthetic network-loss injection, no host links changed."""
        self._continuous_game_case()

    def test_fullsize_game_survives_asymmetric_delays_and_ten_second_blackhole(self):
        """Full1280-byte game payloads; synthetic phone30ms one-way plus jitter."""
        self._continuous_game_case(asymmetric=True)

    def _continuous_game_case(self, asymmetric=False):
        self.start()
        from gamebond.transport import HEADER
        game = struct.Struct("!cIQ")
        bulk_stop, consumer_stop = threading.Event(), threading.Event()
        blackout = {"active": False}
        records = {"up": [], "down": []}
        attempted = {"up": 0, "down": 0}
        injected = {"client": 0, "server": 0}
        errors = []
        original_client, original_server = self.client._write, self.server._write
        starlink_address = self.client.addresses[0]
        relay_condition, relay_stop = threading.Condition(), threading.Event()
        relay_jobs, relay_order = [], [0]
        def schedule(sender, original, packet, path, starlink):
            sequence = HEADER.unpack_from(packet)[4]
            delay = (.005 + (sequence % 3) * .001) if starlink else (.03 + ((sequence % 5) - 2) * .002)
            with relay_condition:
                relay_order[0] += 1
                heapq.heappush(relay_jobs, (time.perf_counter() + delay, relay_order[0], sender,
                                           original, packet, path, starlink))
                relay_condition.notify()
            return True
        def client_write(packet, path):
            if blackout["active"] and path.socket_index == 0:
                injected["client"] += 1
                return True  # A successful UDP write can be blackholed downstream.
            if asymmetric:
                return schedule(self.client, original_client, packet, path, path.socket_index == 0)
            return original_client(packet, path)
        def server_write(packet, path):
            if blackout["active"] and path.endpoint == starlink_address:
                injected["server"] += 1
                return True
            if asymmetric:
                return schedule(self.server, original_server, packet, path, path.endpoint == starlink_address)
            return original_server(packet, path)
        self.client._write, self.server._write = client_write, server_write
        def relay():
            while not relay_stop.is_set():
                with relay_condition:
                    while not relay_jobs and not relay_stop.is_set():
                        relay_condition.wait(.02)
                    if relay_stop.is_set():
                        return
                    delay = relay_jobs[0][0] - time.perf_counter()
                    if delay > 0:
                        relay_condition.wait(delay)
                        continue
                    _, _, sender, original, packet, path, starlink = heapq.heappop(relay_jobs)
                if blackout["active"] and starlink:
                    injected[sender.role] += 1
                    continue
                # This test shim models downstream propagation after a write;
                # serialize actual socket/counter access with the node as usual.
                with sender._lock:
                    original(packet, path)
        def consume(node, direction):
            while not consumer_stop.is_set():
                try:
                    packet = node.recv(.02)
                except queue.Empty:
                    continue
                received = time.perf_counter_ns()
                if len(packet) >= game.size and packet[:1] == b"G":
                    _, sequence, sent = game.unpack_from(packet)
                    records[direction].append((sequence, received, (received - sent) / 1e6))
                else:
                    # Deliberately slow bulk injection creates a real full RX
                    # backlog; game must jump ahead rather than wait behind it.
                    time.sleep(.025 if asymmetric else .015)
        def bulk(node):
            while not bulk_stop.is_set():
                node.send(b"B" + b"x" * 1000, replicate=False, flow_id="continuous bulk")
        def guarded(function, *args):
            try:
                function(*args)
            except Exception as exc:
                errors.append(repr(exc))
                bulk_stop.set()
                consumer_stop.set()
        workers = [threading.Thread(target=guarded, args=(consume, self.server, "up"), daemon=True),
                   threading.Thread(target=guarded, args=(consume, self.client, "down"), daemon=True),
                   threading.Thread(target=guarded, args=(bulk, self.client), daemon=True),
                   threading.Thread(target=guarded, args=(bulk, self.server), daemon=True)]
        relay_worker = threading.Thread(target=guarded, args=(relay,), daemon=True) if asymmetric else None
        if relay_worker is not None:
            relay_worker.start()
        for worker in workers:
            worker.start()
        outage_started = outage_finished = None
        start = time.perf_counter()
        try:
            for sequence in range(660):  # 0.5s baseline,10s outage,0.5s recovery at60Hz.
                deadline = start + sequence / 60
                delay = deadline - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
                elapsed = time.perf_counter() - start
                active = .5 <= elapsed < 10.5
                if active and not blackout["active"]:
                    outage_started = time.perf_counter()
                elif not active and blackout["active"]:
                    outage_finished = time.perf_counter()
                blackout["active"] = active
                for sender, direction in ((self.client, "up"), (self.server, "down")):
                    attempted[direction] += 1
                    payload = game.pack(b"G", sequence, time.perf_counter_ns())
                    if asymmetric:
                        payload += b"g" * (1280 - len(payload))
                    self.assertGreater(sender.send(payload, replicate=True), 0)
            bulk_stop.set()
            for worker in workers[2:]:
                worker.join(1)
            time.sleep(.3)
        finally:
            blackout["active"] = False
            bulk_stop.set()
            consumer_stop.set()
            for worker in workers:
                worker.join(1)
            relay_stop.set()
            with relay_condition:
                relay_condition.notify_all()
            if relay_worker is not None:
                relay_worker.join(1)
            self.client._write, self.server._write = original_client, original_server
        metrics = {"measurement": "UDP loopback synthetic10s path blackhole with concurrent bulk",
                   "outage_seconds": outage_finished - outage_started,
                   "injected_drops": injected, "directions": {}, "receiver_qos": {},
                   "regression_limits_ms": {"max_latency": 100, "p95_latency": 75 if asymmetric else 40, "max_interarrival": 100},
                   "limitations": ["Real loopback UDP with synthetic loss; physical 5G/Starlink links were not tested.",
                                   "Includes a deliberately slow bulk consumer and host scheduling jitter; limits are regression tolerances, not a CoD interpolation threshold."],
                   "game_payload_bytes": 1280 if asymmetric else game.size,
                   "synthetic_one_way_delay_ms": {"starlink": "5..7", "phone": "26..34"} if asymmetric else None}
        for direction in ("up", "down"):
            rows = records[direction]
            latencies = sorted(row[2] for row in rows)
            gaps = [(rows[index][1] - rows[index - 1][1]) / 1e6 for index in range(1, len(rows))]
            metrics["directions"][direction] = {
                "sent": attempted[direction], "received": len(rows),
                "max_latency_ms": max(latencies), "p95_latency_ms": latencies[int((len(latencies) - 1) * .95)],
                "max_interarrival_ms": max(gaps),
                "out_of_order_deliveries": sum(rows[index][0] < rows[index - 1][0] for index in range(1, len(rows)))}
            self.assertEqual(len(rows), attempted[direction], metrics)
            self.assertEqual(len({row[0] for row in rows}), attempted[direction], metrics)
            self.assertLess(max(latencies), 100, metrics)
            self.assertLess(latencies[int((len(latencies) - 1) * .95)], 75 if asymmetric else 40, metrics)
            self.assertLess(max(gaps), 100, metrics)
        self.assertFalse(errors, errors)
        self.assertGreater(injected["client"], 0)
        self.assertGreater(injected["server"], 0)
        for node in (self.client, self.server):
            inbox = node.stats()["receive_inbox"]
            metrics["receiver_qos"][node.role] = {
                "bulk_full_drops": inbox["bulk_full_drops"],
                "bulk_evicted_for_priority": inbox["bulk_evicted_for_priority"],
                "priority_full_drops": inbox["priority_full_drops"],
                "priority_max_residence_ms": inbox["priority"]["max_residence_ms"],
                "bulk_max_residence_ms": inbox["bulk"]["max_residence_ms"],
                "peak_packets": inbox["peak_packets"]}
            self.assertEqual(inbox["priority_full_drops"], 0, inbox)
            self.assertGreater(inbox["bulk_full_drops"] + inbox["bulk_evicted_for_priority"], 0, inbox)
        self.continuity_metrics = metrics
        print("Gameplay continuity regression: " + json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
