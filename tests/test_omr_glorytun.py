import os
import struct
import time
import unittest

try:
    import nacl  # noqa: F401
except ImportError:  # the OMR transport is an optional extra
    raise unittest.SkipTest("PyNaCl not installed (pip install 'gamebond[omr]')")

from gamebond.omr_glorytun import (Clock, KeyExchange, MSG_SIZE, Msg, MudClient, PKT_MIN, RUNNING, parse_key, seal,
                                   unseal)
from mud_peer import MudPeer

KEY = bytes(range(32))


def ip_packet(payload=b"x" * 20, protocol=17, size=None):
    body = payload if size is None else bytes(size - 20)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, protocol, 0, bytes([10, 255, 254, 2]), bytes([8, 8, 8, 8])) + body


def wait_for(condition, timeout=6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return False


class PrimitiveTests(unittest.TestCase):
    def test_key_parsing(self):
        self.assertEqual(parse_key("00" * 31 + "FF"), bytes(31) + b"\xff")
        for bad in ("zz" * 32, "00" * 31, ""):
            with self.assertRaises(ValueError):
                parse_key(bad)

    def test_packet_layout_overhead_and_tamper_detection(self):
        header = (123456 << 1).to_bytes(6, "little")
        wire = seal(KEY, header, b"payload")
        self.assertEqual((wire[:6], len(wire)), (header, 6 + len(b"payload") + 16))
        self.assertEqual(unseal(KEY, wire), b"payload")
        for mutated in (wire[:-1] + bytes([wire[-1] ^ 1]), bytes([wire[0] ^ 2]) + wire[1:]):   # tag, header (nonce and AAD)
            self.assertIsNone(unseal(KEY, mutated))
        self.assertIsNone(unseal(bytes(32), wire))

    def test_control_message_is_exactly_125_bytes_and_round_trips(self):
        msg = Msg(sent_time=0x010203040506, pkey=bytes(range(100, 132)), tx=(1, 2), rx=(3, 4), fw=(5, 6), max_rate=12_500_000,
                  beat=100_000, mtu=1472, pref=1, loss=7, fixed_rate=1, loss_limit=255, addr=("203.0.113.9", 65001))
        raw = msg.pack()
        self.assertEqual(len(raw), MSG_SIZE)
        # struct mud_addr at offset 107: v4-mapped IPv6 (10 zero bytes, ff ff, the IPv4 address) then the network-order port
        self.assertEqual(raw[107:117], bytes(10))
        self.assertEqual(raw[117:119], b"\xff\xff")
        self.assertEqual(raw[119:123], bytes([203, 0, 113, 9]))
        self.assertEqual(raw[123:125], struct.pack("!H", 65001))
        self.assertEqual(Msg.unpack(raw), msg)

    def test_session_keys_are_complementary_and_depend_on_the_private_key(self):
        a, b = KeyExchange(KEY), KeyExchange(KEY)
        a.rotate_if_due(1000)
        b.rotate_if_due(1000)
        self.assertTrue(a.derive(b.local) and b.derive(a.local))
        self.assertEqual((a.next[0], a.next[1]), (b.next[1], b.next[0]))       # my encrypt key is your decrypt key
        c = KeyExchange(bytes(32))
        c.rotate_if_due(1000)
        c.secret, c.local = a.secret, a.local
        c.derive(b.local)
        self.assertNotEqual(c.next, a.next)
        self.assertFalse(a.derive(bytes(32)))                                   # low-order point rejected


class SessionTests(unittest.TestCase):
    def open(self, *, locals_=("127.0.0.1",), mtu_limit=1500, beat_ms=20, key=KEY, peer_clock=None, **kw):
        self.peer = MudPeer(KEY, clock=peer_clock, mtu_limit=mtu_limit)
        self.client = MudClient(key, self.peer.address, list(locals_), beat_ms=beat_ms, **kw).start()
        self.addCleanup(self.client.close)
        self.addCleanup(self.peer.close)
        return self.client, self.peer

    def test_handshake_finds_the_mtu_and_carries_data_both_ways(self):
        client, peer = self.open()
        self.assertTrue(wait_for(lambda: client.ready), client.stats())
        self.assertEqual(client.tunnel_mtu, 1450)                                  # MTU_MAX - overhead, nothing smaller on the path
        packet = ip_packet(b"hello")
        self.assertTrue(wait_for(lambda: client.send(packet)))
        self.assertEqual(peer.inbox.get(timeout=3), packet)
        self.assertTrue(wait_for(lambda: peer.send(ip_packet(b"reply"))))
        self.assertEqual(client.recv(timeout=3), ip_packet(b"reply"))
        self.assertEqual(client.paths[0].status, RUNNING)

    def test_mtu_search_converges_below_a_limited_path(self):
        client, _ = self.open(mtu_limit=1222)
        self.assertTrue(wait_for(lambda: client.ready, 15), client.stats())
        self.assertEqual(client.tunnel_mtu, 1222 - PKT_MIN)

    def test_oversized_packets_are_refused_not_fragmented(self):
        client, _ = self.open(mtu_limit=1100)
        self.assertTrue(wait_for(lambda: client.ready, 15))
        self.assertFalse(client.send(ip_packet(size=client.tunnel_mtu + 1)))

    def test_two_local_addresses_form_one_session_and_both_carry_traffic(self):
        client, peer = self.open(locals_=("127.0.0.1", "127.0.0.2"))
        self.assertTrue(wait_for(lambda: client.ready and all(p.status == RUNNING for p in client.paths)), client.stats())
        sent = 0
        deadline = time.monotonic() + 5
        while sent < 200 and time.monotonic() < deadline:
            sent += client.send(ip_packet(os.urandom(40)))
            time.sleep(0.002)
        self.assertGreaterEqual(sent, 100)
        self.assertTrue(wait_for(lambda: peer.inbox.qsize() >= sent - 5))
        self.assertEqual(len(peer.paths), 2)                                       # the server saw two distinct source paths
        used = [p.tx.total for p in client.paths]
        self.assertTrue(all(count > 10 for count in used), used)                   # weighted striping, not one path

    def test_wrong_key_never_becomes_ready_and_is_counted(self):
        client, peer = self.open(key=bytes(32))
        time.sleep(0.6)
        self.assertFalse(client.ready)
        self.assertGreater(peer.errors["decrypt"], 0)
        self.assertFalse(client.send(ip_packet()))

    def test_clock_skew_beyond_the_tolerance_is_rejected(self):
        class Skewed(Clock):
            def now(self):
                return super().now() + 11 * 60 * 1_000_000
        client, peer = self.open(peer_clock=Skewed())
        time.sleep(0.6)
        self.assertFalse(client.ready)
        self.assertGreater(peer.errors["clocksync"], 0)

    def test_client_key_rotation_keeps_traffic_flowing(self):
        client, peer = self.open()
        self.assertTrue(wait_for(lambda: client.ready))
        self.assertTrue(wait_for(lambda: client.send(ip_packet(b"before"))))
        self.assertEqual(peer.inbox.get(timeout=3), ip_packet(b"before"))
        with client.lock:
            client.kx.time = 0                                                     # force the hourly rotation now
        time.sleep(0.4)
        self.assertTrue(wait_for(lambda: client.send(ip_packet(b"after"))))
        self.assertEqual(peer.inbox.get(timeout=3), ip_packet(b"after"))
        self.assertTrue(wait_for(lambda: peer.send(ip_packet(b"down"))))
        self.assertEqual(client.recv(timeout=3), ip_packet(b"down"))

    def test_garbage_and_replayed_datagrams_do_not_disturb_the_session(self):
        client, peer = self.open()
        self.assertTrue(wait_for(lambda: client.ready))
        import socket
        raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for junk in (b"", b"\0" * 10, os.urandom(60), os.urandom(1400)):
            raw.sendto(junk, client.paths[0].sock.getsockname())
        raw.close()
        time.sleep(0.2)
        self.assertTrue(client.ready)
        self.assertTrue(wait_for(lambda: client.send(ip_packet(b"still"))))
        self.assertEqual(peer.inbox.get(timeout=3), ip_packet(b"still"))


if __name__ == "__main__":
    unittest.main()


class ProbeToolTests(unittest.TestCase):
    def test_probe_builds_valid_icmp_echo_and_recognises_a_reply(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("probe", os.path.join(os.path.dirname(__file__), "..", "tools", "probe_omr_glorytun.py"))
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        packet = probe.icmp_echo("10.255.254.2", "10.255.254.1", 0x6742, 3)
        self.assertEqual(probe.checksum(packet[:20]), 0)                    # valid IP header
        self.assertEqual(probe.checksum(packet[20:]), 0)                    # valid ICMP checksum
        reply = bytearray(packet)
        reply[20] = 0
        self.assertTrue(probe.is_echo_reply(bytes(reply), 0x6742))
        self.assertFalse(probe.is_echo_reply(bytes(reply), 1))
        self.assertFalse(probe.is_echo_reply(packet, 0x6742))               # an echo request is not a reply
