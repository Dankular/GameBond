"""Bad-link handling on the OMR leg: fast failure detection, spike demotion with hysteresis, hot standby, adapter changes."""
import struct
import time
import unittest

try:
    import nacl  # noqa: F401
except ImportError:
    raise unittest.SkipTest("PyNaCl not installed (pip install 'gamebond[omr]')")

from gamebond.omr_glorytun import DEGRADED, MudClient, READY, RUNNING
from mud_peer import MudPeer
from test_omr_glorytun import KEY, ip_packet, wait_for

A, B = "127.0.0.1", "127.0.0.2"


class Steering(unittest.TestCase):
    def open(self, locals_=(A, B), **kw):
        self.peer = MudPeer(KEY)
        options = dict(beat_ms=20, recovery_seconds=0.6)
        options.update(kw)
        self.client = MudClient(KEY, self.peer.address, list(locals_), **options).start()
        self.addCleanup(self.client.close)
        self.addCleanup(self.peer.close)
        self.assertTrue(wait_for(lambda: self.client.ready and all(p.status == RUNNING for p in self.client.paths if p.enabled)),
                        self.client.stats())
        return self.client, self.peer

    def pump(self, seconds, urgent=True):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.client.send(ip_packet(b"u" * 30), urgent=urgent)
            time.sleep(0.004)

    def path_tx(self, ip):
        """Data packets only: a failed path is still probed every beat to notice its recovery."""
        return next(p.data_tx for p in self.client.paths if p.local_ip == ip)

    def test_a_dead_link_stops_carrying_urgent_traffic_within_a_fraction_of_a_second(self):
        client, peer = self.open()
        self.pump(0.3)
        peer.blocked.add(B)                                              # link B dies
        self.pump(0.45)                                                  # detection window (2 missed beats at 20 ms, plus slack)
        before = self.path_tx(B)
        self.pump(1.0)
        # After detection no urgent packet may go to the dead link (only its control probes may).
        urgent_to_dead = self.path_tx(B) - before
        self.assertEqual(urgent_to_dead, 0, urgent_to_dead)              # none of ~250 urgent packets went to the dead link
        self.assertGreater(self.path_tx(A), 100)

    def test_latency_spike_demotes_the_slow_link_for_both_directions_then_restores_it(self):
        client, peer = self.open()
        peer.delays[B] = 0.12                                            # link B becomes slow (120 ms extra each way back)
        self.assertTrue(wait_for(lambda: next(p for p in client.paths if p.local_ip == B).demoted, 6), client.stats())
        slow = next(p for p in client.paths if p.local_ip == B)
        self.assertEqual(slow.pref, slow.base_pref + 2)
        # The server side sees the worse preference and stops sending downstream on that link.
        self.assertTrue(wait_for(lambda: peer.paths[(B, slow.sock.getsockname()[1])]["pref"] == slow.base_pref + 2, 3))
        base = dict(peer.arrivals)
        sent_before = {r: p["sent_data"] for r, p in peer.paths.items()}
        for _ in range(60):
            peer.send(ip_packet(b"d" * 30))
            time.sleep(0.003)
        slow_remote = (B, slow.sock.getsockname()[1])
        self.assertEqual(peer.paths[slow_remote]["sent_data"] - sent_before[slow_remote], 0)
        self.assertGreaterEqual(sum(p["sent_data"] for p in peer.paths.values()) - sum(sent_before.values()), 50)
        # Upstream urgent traffic also avoids it.
        before = self.path_tx(B)
        self.pump(0.6)
        self.assertEqual(self.path_tx(B) - before, 0)
        # Recovery needs a sustained healthy period, not one good sample.
        peer.delays.pop(B)
        self.assertTrue(wait_for(lambda: not slow.demoted, 8), client.stats())
        self.assertEqual(slow.pref, slow.base_pref)
        self.assertGreaterEqual(client.errors["demotions"], 1)

    def test_a_single_link_or_all_links_degrading_is_never_demoted(self):
        client, peer = self.open()
        peer.delays[A] = 0.1
        peer.delays[B] = 0.1
        time.sleep(1.5)
        self.assertFalse(any(p.demoted for p in client.paths))          # nothing better to prefer: keep both, do not strand traffic
        solo_peer = MudPeer(KEY)
        self.addCleanup(solo_peer.close)
        solo = MudClient(KEY, solo_peer.address, [A], beat_ms=20).start()
        self.addCleanup(solo.close)
        self.assertTrue(wait_for(lambda: solo.ready))
        solo_peer.delays[A] = 0.15
        time.sleep(1.2)
        self.assertFalse(solo.paths[0].demoted)

    def test_backup_role_is_a_probed_hot_standby_that_takes_over_when_the_primary_dies(self):
        client, peer = self.open()
        client.set_roles(["primary", "backup"])
        backup = client.paths[1]
        self.assertEqual(backup.pref, 125)
        self.assertTrue(wait_for(lambda: backup.status == READY, 3), client.stats())
        probes, data = backup.tx.total, backup.data_tx
        self.pump(0.5)
        self.assertGreater(backup.tx.total - probes, 0)                  # probed while idle: its quality stays known
        self.assertEqual(backup.data_tx - data, 0)                       # but carries no data
        self.assertTrue(backup.rtt.setup)
        peer.blocked.add(A)                                              # primary dies
        self.assertTrue(wait_for(lambda: backup.status == RUNNING, 6), client.stats())
        while not peer.inbox.empty():
            peer.inbox.get()                                             # earlier traffic from before the failure
        packet = ip_packet(b"takeover")
        self.assertTrue(wait_for(lambda: client.send(packet, urgent=True)))
        self.assertEqual(peer.inbox.get(timeout=3), packet)

    def test_role_never_removes_a_link_and_restoring_it_brings_it_back(self):
        client, _ = self.open()
        client.set_roles(["primary", "never"])
        self.assertFalse(client.paths[1].enabled)
        self.assertTrue(client.ready)
        client.set_roles(["primary", "primary"])
        self.assertTrue(wait_for(lambda: client.paths[1].enabled and client.paths[1].status == RUNNING, 6), client.stats())

    def test_adapter_changes_rebind_only_the_affected_slot_and_pin_the_interface(self):
        pinned = []
        client, peer = self.open(interface_indices=[11, 12], pin=lambda sock, index: pinned.append(index))
        self.assertEqual(pinned, [11, 12])
        untouched = client.paths[0].sock
        errors = client.update_paths([A, B], [11, 12], [True, False])    # the second adapter vanished
        self.assertEqual(errors, [])
        self.assertFalse(client.paths[1].enabled)
        self.assertEqual(client.paths[1].reason, "adapter unavailable")
        self.assertIs(client.paths[0].sock, untouched)
        self.assertTrue(client.ready)                                    # the other link keeps the session up
        packet = ip_packet(b"one-link")
        self.assertTrue(wait_for(lambda: client.send(packet)))
        self.assertEqual(peer.inbox.get(timeout=3), packet)
        pinned.clear()
        client.update_paths([A, "127.0.0.3"], [11, 14], [True, True])    # it came back with a new address and index
        self.assertEqual(pinned, [14])                                    # only the changed slot is pinned again
        self.assertTrue(wait_for(lambda: client.paths[1].enabled and client.paths[1].status == RUNNING, 6), client.stats())
        self.assertEqual(client.paths[1].local_ip, "127.0.0.3")
        with self.assertRaises(ValueError):
            client.update_paths([A], None, None)

    def test_link_speed_limits_cap_our_sending_and_are_advertised_for_the_servers_sending(self):
        client, peer = self.open(rate_mbps=100)
        client.set_rates([20, 0], [50, 0])
        self.assertEqual(client.paths[0].tx.rate, 20 * 125_000)
        self.assertEqual(client.paths[1].tx.rate, 100 * 125_000)                    # 0 means the configured default, not zero
        remote = lambda p: (p.local_ip, p.sock.getsockname()[1])
        self.assertTrue(wait_for(lambda: peer.paths[remote(client.paths[0])]["max_rate"] == 50 * 125_000, 3))
        self.assertEqual(peer.paths[remote(client.paths[1])]["max_rate"], 100 * 125_000)
        with self.assertRaises(ValueError):
            client.set_rates([1], [1])
        with self.assertRaises(ValueError):
            client.set_rates([-1, 0], [0, 0])

    def test_a_pin_failure_disables_the_slot_and_reports_it_instead_of_failing(self):
        def failing(sock, index):
            raise OSError("no such interface")
        peer = MudPeer(KEY)
        self.addCleanup(peer.close)
        client = MudClient(KEY, peer.address, [A, B], beat_ms=20, interface_indices=[1, 2], pin=failing).start()
        self.addCleanup(client.close)
        self.assertEqual([p.enabled for p in client.paths], [False, False])
        self.assertIn("no such interface", client.paths[0].reason)
        self.assertFalse(client.ready)


if __name__ == "__main__":
    unittest.main()
