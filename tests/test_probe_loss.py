"""Early probe-loss declaration; deterministic clock, no sockets carry traffic."""
import secrets
import unittest
from unittest import mock

from gamebond.transport import Node, OVERHEAD, BOND_OVERHEAD, PONG
from tests.test_bonded_transport import handshake_without_threads


class ProbeLossTests(unittest.TestCase):
    def setUp(self):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        options = dict(bonding_mode=True, mtu=1280 + OVERHEAD + BOND_OVERHEAD,
                       probe_interval=.25, path_timeout=2.0)
        self.server = Node(key, "server", session, [("127.0.0.1", 0)], **options)
        self.client = Node(key, "client", session,
                           [("127.0.0.1", 0), ("127.0.0.1", 0)],
                           peer=self.server.addresses[0], **options)
        handshake_without_threads(self.client, self.server)
        self.client._pending.clear()
        self.client._lost_probes.clear()
        for path in self.client._paths.values():
            path.probe_sent = path.probe_acked = path.probe_lost = 0
            path.probe_lost_early = path.probe_late = 0
            path.probe_acked_sent_at = -1.0
            path.rtt_ms = None
            path.rtt_jitter_ms = 0.0
        self.client._write = lambda packet, path: True
        self.clock = [1000.0]
        patcher = mock.patch("gamebond.transport.time.perf_counter", lambda: self.clock[0])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.client.close)
        self.addCleanup(self.server.close)
        self.paths = list(self.client._paths.values())
        self.a, self.b = self.paths[0], self.paths[1]

    def tokens(self, path):
        identity = (path.socket_index, path.endpoint)
        return [t for t, (_, who) in self.client._pending.items() if who == identity]

    def reply(self, path, token):
        packet = self.server._encode(PONG, token)
        self.client._receive(path.socket_index, packet, self.server.addresses[0])

    def probe_round(self, at):
        self.clock[0] = at
        for path in self.paths:
            path.last_rx = at  # handshake stamped the real clock; keep paths live
        before ={id(p): set(self.tokens(p)) for p in self.paths}
        self.client._probe()
        return {id(p): (set(self.tokens(p)) - before[id(p)]).pop() for p in self.paths}

    def test_overtaken_probe_is_lost_before_path_timeout(self):
        first = self.probe_round(1000.0)
        second = self.probe_round(1000.25)
        self.clock[0] = 1000.26
        self.reply(self.a, second[id(self.a)])
        self.clock[0] = 1000.30
        self.client._probe()
        self.assertEqual((self.a.probe_lost, self.a.probe_lost_early), (1, 1))
        # No later probe was answered on b, so only the full timeout applies.
        self.assertEqual((self.b.probe_lost, self.b.probe_lost_early), (0, 0))
        self.assertIn(first[id(self.b)], self.client._pending)
        # Probes sent at 1000.00, 1000.25 and 1000.30 all pass the 2 s timeout.
        self.clock[0] = 1002.30
        self.client._probe()
        self.assertEqual((self.b.probe_lost, self.b.probe_lost_early), (3, 0))

    def test_late_reply_is_reclassified_and_still_counts_as_jitter(self):
        first = self.probe_round(1000.0)
        second = self.probe_round(1000.25)
        self.clock[0] = 1000.26
        self.reply(self.a, second[id(self.a)])
        self.clock[0] = 1000.30
        self.client._probe()
        self.assertEqual(self.a.probe_lost, 1)
        jitter = self.a.rtt_jitter_ms
        self.clock[0] = 1000.40
        self.reply(self.a, first[id(self.a)])
        self.assertEqual((self.a.probe_lost, self.a.probe_late), (0, 1))
        self.assertGreater(self.a.rtt_jitter_ms, jitter)

    def test_recent_probe_is_not_declared_lost_inside_the_guard(self):
        self.probe_round(1000.0)
        second = self.probe_round(1000.05)  # unusually tight spacing
        self.clock[0] = 1000.06
        self.reply(self.a, second[id(self.a)])
        self.clock[0] = 1000.07
        self.client._probe()
        self.assertEqual(self.a.probe_lost, 0)

    def test_foreign_or_replayed_reply_cannot_reclassify(self):
        first = self.probe_round(1000.0)
        second = self.probe_round(1000.25)
        self.clock[0] = 1000.26
        self.reply(self.a, second[id(self.a)])
        self.clock[0] = 1000.30
        self.client._probe()
        # A reply for path a's probe delivered on path b must not count.
        self.clock[0] = 1000.40
        self.reply(self.b, first[id(self.a)])
        self.assertEqual((self.a.probe_lost, self.a.probe_late), (1, 0))


if __name__ == "__main__":
    unittest.main()
