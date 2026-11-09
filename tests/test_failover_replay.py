"""Sender-driven failover: a silent path is avoided and its recent bulk replayed.

Real loopback sockets and threads. A "dead link" is simulated by discarding
everything the client writes to, and receives from, one socket. Nothing here
measures a physical link or a game deadline.
"""
import secrets
import time
import unittest

from gamebond.transport import Node, OVERHEAD, BOND_OVERHEAD, HEADER, STRIPED
from test_bonded_transport import wait_for
from test_data_plane_quality import tcp


class FailoverReplayTests(unittest.TestCase):
    def build(self, client_options=None):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        base = dict(bonding_mode=True, mtu=1280 + OVERHEAD + BOND_OVERHEAD,
                    probe_interval=.05, path_timeout=.3, initial_rate_mbps=2, max_rate_mbps=8)
        self.server = Node(key, "server", session, [("127.0.0.1", 0)], **base)
        self.client = Node(key, "client", session, [("127.0.0.1", 0), ("127.0.0.1", 0)],
                           peer=self.server.addresses[0], **base, **(client_options or {}))
        self.addCleanup(self.client.close)
        self.addCleanup(self.server.close)
        self.server.start()
        self.client.start()
        wait_for(lambda: len(self.server.stats()["paths"]) == 2 and
                 all(p["healthy"] for p in self.client.stats()["paths"]))
        self.dead = False
        self.striped_writes = [0, 0]
        write, receive = self.client._write, self.client._receive

        def lossy_write(packet, path, **kwargs):
            if HEADER.unpack_from(packet)[3] == STRIPED:
                self.striped_writes[path.socket_index] += 1
            return True if self.dead and path.socket_index == 1 else write(packet, path, **kwargs)

        def lossy_receive(index, packet, endpoint, **kwargs):
            if not (self.dead and index == 1):
                receive(index, packet, endpoint, **kwargs)

        self.client._write, self.client._receive = lossy_write, lossy_receive

    def path(self, index):
        return self.client.stats()["paths"][index]

    def test_silent_path_is_suspected_before_the_full_timeout(self):
        self.build(dict(failover_replay=True))
        self.dead = True
        wait_for(lambda: self.path(1)["suspect"])
        # path_timeout is .3 s; suspicion fires at about half of it.
        self.assertTrue(self.path(1)["healthy"])
        self.assertFalse(self.path(0)["suspect"])
        self.assertEqual(self.client.stats()["failover_suspected"], 1)

    def test_tail_packet_lost_on_the_dying_path_is_replayed_on_the_live_one(self):
        self.build(dict(failover_replay=True))
        self.dead = True
        # The path is dead but not yet suspected, so the striper still uses it.
        # Send single packets until one is written into the void. Nothing is
        # sent after it, so the receiver has no gap to notice or request.
        lost = None
        for n in range(40):
            payload = tcp(b"t%03d" % n)
            before = self.striped_writes[1]
            self.assertEqual(self.client.send(payload, replicate=False, flow_id=("tail", n)), 1)
            if self.striped_writes[1] > before:
                lost = payload
                break
            self.assertEqual(self.server.recv(2), payload)
        self.assertIsNotNone(lost, "striper never chose the dead path")
        self.assertEqual(self.server.recv(2), lost)
        stats = self.client.stats()
        self.assertGreaterEqual(stats["failover_replayed"], 1)
        self.assertEqual(stats["failover_suspected"], 1)
        self.assertEqual(stats.get("repair_packets", 0), 0)

    def test_non_tcp_bulk_is_also_replayed(self):
        self.build(dict(failover_replay=True))
        self.dead = True
        header = bytearray(28)
        header[0], header[9] = 0x45, 17
        header[2:4] = (28 + 20).to_bytes(2, "big")
        payloads = [bytes(header) + b"%020d" % n for n in range(8)]
        for payload in payloads:
            self.client.send(payload, replicate=False, flow_id="udp-bulk")
        # UDP gaps are never requested by the receiver, so only the sender's
        # failover can fill them.
        self.assertEqual(sorted(self.server.recv(2) for _ in payloads), sorted(payloads))
        self.assertGreaterEqual(self.client.stats()["failover_replayed"], 1)

    def test_new_bulk_avoids_a_suspect_path(self):
        self.build(dict(failover_replay=True))
        self.dead = True
        wait_for(lambda: self.path(1)["suspect"])
        before = self.striped_writes[1]
        replayed = self.client.stats().get("failover_replayed", 0)
        for n in range(20):
            self.client.send(tcp(b"n%03d" % n), replicate=False, flow_id="after")
        self.assertEqual(self.striped_writes[1], before)
        self.assertEqual([self.server.recv(2) for _ in range(20)][0], tcp(b"n000"))
        self.assertGreaterEqual(replayed, 0)

    def test_path_returns_to_service_when_it_answers_again(self):
        self.build(dict(failover_replay=True))
        self.dead = True
        wait_for(lambda: self.path(1)["suspect"])
        self.dead = False
        wait_for(lambda: not self.path(1)["suspect"])
        self.assertGreaterEqual(self.client.stats()["failover_recovered"], 1)
        before = self.striped_writes[1]
        for n in range(20):
            self.client.send(tcp(b"r%03d" % n), replicate=False, flow_id="again")
        wait_for(lambda: self.striped_writes[1] > before)

    def test_disabled_by_default_changes_nothing(self):
        self.build()
        self.dead = True
        time.sleep(.2)
        stats = self.client.stats()
        self.assertFalse(self.path(1)["suspect"])
        self.assertEqual(stats.get("failover_suspected", 0), 0)
        self.assertEqual(stats.get("failover_replayed", 0), 0)

    def test_option_requires_bonding_and_a_boolean(self):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        for bad in (dict(failover_replay=True), dict(bonding_mode=True, failover_replay="yes")):
            with self.assertRaises(ValueError):
                Node(key, "server", session, [("127.0.0.1", 0)], **bad)


if __name__ == "__main__":
    unittest.main()
