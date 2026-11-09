"""Replicated-copy accounting, deadline-aware repair and per-path MTU search.

Real loopback sockets and threads; packets are dropped by wrapping the client's
``_write``. Nothing here measures a physical link.
"""
import queue
import secrets
import struct
import time
import unittest
from unittest import mock

from gamebond import path_quality
from gamebond.transport import (Node, OVERHEAD, BOND_OVERHEAD, HEADER, DATA, DATA_COPY,
                                STRIPED, MTU_PROBE)
from test_bonded_transport import wait_for


def tcp(payload):
    header = bytearray(40)
    header[0] = 0x45
    header[2:4] = (40 + len(payload)).to_bytes(2, "big")
    header[9] = 6
    header[32] = 0x50
    return bytes(header) + payload


class DataPlaneQualityTests(unittest.TestCase):
    def build(self, client_options=None, server_options=None):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        base = dict(bonding_mode=True, mtu=1280 + OVERHEAD + BOND_OVERHEAD,
                    probe_interval=.05, path_timeout=.3, initial_rate_mbps=2, max_rate_mbps=8)
        self.server = Node(key, "server", session, [("127.0.0.1", 0)], **base, **(server_options or {}))
        self.client = Node(key, "client", session, [("127.0.0.1", 0), ("127.0.0.1", 0)],
                           peer=self.server.addresses[0], **base, **(client_options or {}))
        self.addCleanup(self.client.close)
        self.addCleanup(self.server.close)
        self.server.start()
        self.client.start()
        wait_for(lambda: len(self.server.stats()["paths"]) == 2 and
                 all(p["healthy"] for p in self.client.stats()["paths"]))

    def server_path(self, client_index):
        address = self.client.addresses[client_index]
        return next(p for p in self.server.stats()["paths"] if tuple(p["remote"]) == tuple(address))

    def drop(self, predicate):
        original = self.client._write
        self.client._write = lambda packet, path: True if predicate(packet, path) else original(packet, path)

    # ---- replicated-copy ledger -------------------------------------------------
    def test_copies_on_both_paths_are_seen_and_reported_back(self):
        self.build(client_options=dict(loss_tracking=True))
        for n in range(30):
            self.client.send(struct.pack("!I", n) + b"g" * 100, replicate=True)
            time.sleep(.005)
        for _ in range(30):
            self.server.recv(1)
        wait_for(lambda: all(self.server_path(i)["copy_quality"]["seen"] >= 25 for i in (0, 1)))
        for i in (0, 1):
            self.assertEqual(self.server_path(i)["copy_quality"]["missed"], 0)
        # The receiver's view reaches the sender, which is who must act on it.
        wait_for(lambda: all((p["peer_copy_quality"] or {}).get("seen", 0) >= 25
                             for p in self.client.stats()["paths"]))

    def test_a_path_that_loses_copies_is_identified_and_game_data_still_arrives(self):
        self.build(client_options=dict(loss_tracking=True))
        self.drop(lambda packet, path: HEADER.unpack_from(packet)[3] == DATA_COPY and path.socket_index == 1)
        sent = 40
        for n in range(sent):
            self.client.send(struct.pack("!I", n) + b"g" * 100, replicate=True)
            time.sleep(.005)
        got = sorted(struct.unpack("!I", self.server.recv(1)[:4])[0] for _ in range(sent))
        self.assertEqual(got, list(range(sent)))  # zero application loss
        wait_for(lambda: self.server_path(1)["copy_quality"]["missed"] >= sent - 2)
        self.assertEqual(self.server_path(0)["copy_quality"]["missed"], 0)
        wait_for(lambda: (self.client.stats()["paths"][1]["peer_copy_quality"] or {}).get("missed", 0) >= sent - 2)
        self.assertEqual((self.client.stats()["paths"][0]["peer_copy_quality"] or {}).get("missed", 0), 0)

    def test_a_late_copy_is_reclassified_not_left_as_loss(self):
        self.build(client_options=dict(loss_tracking=True))
        held = []
        original = self.client._write
        def hold(packet, path):
            if HEADER.unpack_from(packet)[3] == DATA_COPY and path.socket_index == 1:
                held.append((packet, path))
                return True
            return original(packet, path)
        self.client._write = hold
        for n in range(10):
            self.client.send(b"p%d" % n, replicate=True)
        wait_for(lambda: self.server_path(1)["copy_quality"]["missed"] >= 10)
        self.client._write = original
        for packet, path in held:
            original(packet, path)
        wait_for(lambda: self.server_path(1)["copy_quality"]["late"] >= 10)
        self.assertEqual(self.server_path(1)["copy_quality"]["missed"], 0)
        self.assertIsNotNone(self.server_path(1)["copy_quality"]["lag_ms"])

    def test_untracked_sender_uses_plain_data_and_leaves_ledger_empty(self):
        self.build()
        kinds = []
        original = self.client._write
        self.client._write = lambda packet, path: (kinds.append(HEADER.unpack_from(packet)[3]), original(packet, path))[1]
        self.client.send(b"x" * 50, replicate=True)
        self.server.recv(1)
        self.assertIn(DATA, kinds)
        self.assertNotIn(DATA_COPY, kinds)
        time.sleep(.15)
        self.assertTrue(all(self.server_path(i)["copy_quality"]["seen"] == 0 for i in (0, 1)))

    # ---- deadline-aware repair --------------------------------------------------
    def send_flow_with_first_lost(self):
        dropped = []
        original = self.client._write
        def lose_first(packet, path):
            if HEADER.unpack_from(packet)[3] == STRIPED and not dropped:
                dropped.append(packet)
                return True
            return original(packet, path)
        self.client._write = lose_first
        payloads = [tcp(p) for p in (b"zero", b"one", b"two")]
        for payload in payloads:
            self.assertEqual(self.client.send(payload, replicate=False, flow_id="repair"), 1)
        return payloads

    def test_repair_that_cannot_beat_its_deadline_is_not_requested(self):
        self.build(server_options=dict(repair_deadline=.01))
        wait_for(lambda: all(p.rtt_ms is not None for p in self.server._paths.values()))
        self.send_flow_with_first_lost()
        wait_for(lambda: self.server.stats().get("repair_skipped_deadline", 0) >= 1)
        time.sleep(.1)
        self.assertEqual(self.server.stats().get("repair_requests", 0), 0)
        self.assertEqual(self.client.stats().get("repair_packets", 0), 0)

    def test_repair_inside_the_deadline_is_requested_and_counted_in_time(self):
        self.build()
        wait_for(lambda: all(p.rtt_ms is not None for p in self.server._paths.values()))
        payloads = self.send_flow_with_first_lost()
        self.assertEqual([self.server.recv(2) for _ in range(3)], payloads)
        self.assertGreater(self.client.stats().get("repair_packets", 0), 0)
        self.assertEqual(self.server.stats().get("repair_skipped_deadline", 0), 0)
        wait_for(lambda: self.server.stats().get("gap_filled_in_time", 0)
                 + self.server.stats().get("gap_filled_late", 0) >= 1)

    def test_unrepairable_gap_gets_an_explicit_unavailable_reply(self):
        self.build()
        wait_for(lambda: all(p.rtt_ms is not None for p in self.server._paths.values()))
        # Make every repair request unanswerable: the sender has forgotten the packet.
        original = self.client._write
        dropped = []
        def lose_first(packet, path):
            if HEADER.unpack_from(packet)[3] == STRIPED and not dropped:
                dropped.append(packet)
                return True
            return original(packet, path)
        self.client._write = lose_first
        for payload in [tcp(p) for p in (b"zero", b"one", b"two")]:
            self.client.send(payload, replicate=False, flow_id="gone")
            with self.client._lock:
                self.client._repair_cache.clear()
        wait_for(lambda: self.client.stats().get("repair_unavailable_sent", 0) >= 1)
        wait_for(lambda: self.server.stats().get("repair_unavailable", 0) >= 1)
        key = next(k for k, v in self.server._repair_asked.items() if v[1] == 99)
        self.assertIsNotNone(key)  # given up on: not asked again

    # ---- per-path MTU -----------------------------------------------------------
    def test_each_path_gets_its_own_mtu_and_oversize_copies_avoid_the_small_path(self):
        with mock.patch.object(path_quality, "MTU_ROUND_SECONDS", .05):
            self.build(client_options=dict(path_mtu_discovery=True))
            # Path 1's link carries at most a 1250-byte datagram (DF set: larger is dropped).
            self.drop(lambda packet, path: path.socket_index == 1 and len(packet) > 1250)
            wait_for(lambda: self.client.stats()["paths"][1]["mtu"]["path_mtu"] == 1232, timeout=8)
        paths = self.client.stats()["paths"]
        self.assertEqual(paths[0]["mtu"]["path_mtu"], self.client.mtu)
        self.assertEqual(paths[1]["mtu"]["path_mtu"], 1232)
        self.assertTrue(paths[1]["mtu"]["capable"])
        before = self.client.stats().get("mtu_path_skips", 0)
        big = b"G" * (1280 - 1)  # complete datagram well over 1232 bytes
        self.assertEqual(self.client.send(big, replicate=True), 1)  # only the large-MTU path
        self.assertGreater(self.client.stats()["mtu_path_skips"], before)
        self.assertEqual(self.server.recv(1), big)
        small = b"s" * 200
        self.assertEqual(self.client.send(small, replicate=True), 2)

    def test_peer_that_never_answers_mtu_probes_keeps_the_configured_mtu(self):
        with mock.patch.object(path_quality, "MTU_ROUND_SECONDS", .05):
            self.build(client_options=dict(path_mtu_discovery=True))
            self.drop(lambda packet, path: HEADER.unpack_from(packet)[3] == MTU_PROBE)
            time.sleep(1.0)  # several rounds, all sizes struck out
        for path in self.client.stats()["paths"]:
            self.assertEqual(path["mtu"]["path_mtu"], self.client.mtu)
            self.assertFalse(path["mtu"]["capable"])

    def test_options_require_bonding_and_valid_values(self):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        for bad in (dict(loss_tracking=True), dict(path_mtu_discovery=True),
                    dict(bonding_mode=True, repair_deadline=0), dict(bonding_mode=True, loss_tracking="yes")):
            with self.assertRaises(ValueError):
                Node(key, "server", session, [("127.0.0.1", 0)], **bad)


if __name__ == "__main__":
    unittest.main()
