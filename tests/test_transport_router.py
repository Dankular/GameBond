import queue
import struct
import threading
import time
import unittest

from gamebond.nat import Nat
from gamebond.transport_router import GAMEBOND, OMR, TransportRouter
from test_nat import EXT, udp, verify


class FakeGameBond:
    def __init__(self):
        self.sent, self.inbox, self.healthy, self.closed = [], queue.Queue(), True, False
        self.links = []

    def send(self, payload, replicate=True, flow_id=None, *, urgent=False):
        self.sent.append((payload, replicate, flow_id, urgent))
        return 2 if replicate else 1

    def recv(self, timeout=None):
        return self.inbox.get(timeout=timeout)

    def stats(self):
        return dict(paths=[dict(healthy=self.healthy, enabled=True, rtt_ms=20)], counters=1)

    def update_client_paths(self, *args):
        self.links.append(args)
        return []

    def close(self):
        self.closed = True


class FakeOmr:
    def __init__(self):
        self.sent, self.inbox, self.ready, self.closed = [], queue.Queue(), True, False

    def send(self, packet):
        self.sent.append(packet)
        return True

    def recv(self, timeout=None):
        return self.inbox.get(timeout=timeout)

    def stats(self):
        return dict(ready=self.ready, tunnel_mtu=1450)

    def close(self):
        self.closed = True


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.gb, self.omr, self.clock = FakeGameBond(), FakeOmr(), Clock()
        self.router = TransportRouter(self.gb, self.omr, Nat(EXT), ready_ttl=0, clock=self.clock)
        self.addCleanup(self.router.close)

    def test_game_and_call_classes_use_gamebond_everything_else_uses_omr_through_the_nat(self):
        game = udp("10.77.0.3", "203.0.113.9", 3074, 3074)
        bulk = udp("10.77.0.3", "198.51.100.5", 40000, 443)
        self.assertEqual(self.router.send(game, replicate=True, flow_id="g", urgent=True, dscp=46), 2)
        self.assertEqual(self.router.send(bulk, replicate=False, flow_id="b", dscp=0), 1)
        self.assertEqual(self.gb.sent, [(game, True, "g", True)])                  # GameBond leg untouched: own address, replicated
        self.assertEqual(len(self.omr.sent), 1)
        src, dst, _ = verify(self.omr.sent[0])
        self.assertEqual((src, dst), (EXT, "198.51.100.5"))                        # OMR leg rewritten to the OMR tunnel address

    def test_a_flow_stays_on_its_transport(self):
        packet = udp("10.77.0.3", "198.51.100.5", 40000, 443)
        self.router.send(packet, replicate=False, flow_id="f", dscp=0)
        self.router.send(packet, replicate=False, flow_id="f", dscp=46)             # same flow, now marked as gameplay
        self.assertEqual((len(self.omr.sent), len(self.gb.sent)), (2, 0))

    def test_flow_moves_when_its_transport_goes_down_and_stays_moved(self):
        packet = udp("10.77.0.3", "198.51.100.5", 40000, 443)
        self.router.send(packet, replicate=False, flow_id="f", dscp=0)
        self.omr.ready = False
        self.router.send(packet, replicate=False, flow_id="f", dscp=0)
        self.assertEqual((len(self.omr.sent), len(self.gb.sent)), (1, 1))
        self.omr.ready = True
        self.router.send(packet, replicate=False, flow_id="f", dscp=0)              # sticky on its new transport
        self.assertEqual(len(self.gb.sent), 2)
        self.assertEqual(self.router.counts["fallbacks"], 1)

    def test_gameplay_falls_back_to_omr_when_the_gamebond_tunnel_is_down(self):
        self.gb.healthy = False
        packet = udp("10.77.0.3", "203.0.113.9", 3074, 3074)
        self.router.send(packet, replicate=True, flow_id="g", urgent=True, dscp=46)
        self.assertEqual((len(self.gb.sent), len(self.omr.sent)), (0, 1))

    def test_idle_flow_is_decided_afresh(self):
        packet = udp("10.77.0.3", "198.51.100.5", 40000, 443)
        self.router.send(packet, replicate=False, flow_id="f", dscp=0)
        self.clock.now += 121
        self.omr.ready = False
        self.router.send(packet, replicate=False, flow_id="f", dscp=0)
        self.assertEqual(len(self.gb.sent), 1)

    def test_inbound_from_both_transports_is_merged_and_omr_is_translated_back(self):
        out = self.router.send(udp("10.77.0.3", "198.51.100.5", 40000, 443), replicate=False, flow_id="b", dscp=0)
        self.assertEqual(out, 1)
        ext_port = struct.unpack_from("!H", self.omr.sent[0], 20)[0]
        self.router.start()
        self.omr.inbox.put(udp("198.51.100.5", EXT, 443, ext_port, b"from-omr"))
        self.omr.inbox.put(udp("198.51.100.5", EXT, 443, 59999, b"unsolicited"))     # no mapping: dropped
        self.gb.inbox.put(udp("203.0.113.9", "10.77.0.3", 3074, 3074, b"from-gamebond"))
        got = [self.router.recv(timeout=3), self.router.recv(timeout=3)]
        payloads = sorted(p[28:] for p in got)
        self.assertEqual(payloads, [b"from-gamebond", b"from-omr"])
        omr_packet = next(p for p in got if p.endswith(b"from-omr"))
        self.assertEqual(verify(omr_packet)[:2], ("198.51.100.5", "10.77.0.3"))
        with self.assertRaises(queue.Empty):
            self.router.recv(timeout=0.2)
        self.assertEqual(self.router.counts["recv_nat_dropped"], 1)

    def test_unsupported_packets_are_dropped_by_the_nat_not_sent(self):
        gre = bytes.fromhex("4500001c000000004000") + b"\0\0" + bytes([10, 77, 0, 3, 1, 1, 1, 1]) + b"\0" * 8
        gre = gre[:9] + b"\x2f" + gre[10:]
        self.assertEqual(self.router.send(gre, replicate=False, flow_id="x", dscp=0), 0)
        self.assertEqual((self.omr.sent, self.router.counts["nat_dropped"]), ([], 1))

    def test_node_surface_is_delegated_and_stats_combine_both(self):
        self.router.update_client_paths([("1.2.3.4", 0)], [5], [True])
        self.assertEqual(self.gb.links, [([("1.2.3.4", 0)], [5], [True])])
        stats = self.router.stats()
        self.assertEqual((stats["counters"], stats["omr"]["tunnel_mtu"]), (1, 1450))
        self.assertTrue(stats["router"]["gamebond_ready"] and stats["router"]["omr_ready"])

    def test_close_closes_both_even_if_one_fails(self):
        self.omr.close = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        self.router.close()
        self.assertTrue(self.gb.closed)


if __name__ == "__main__":
    unittest.main()
