import struct
import unittest

from gamebond.nat import Nat, checksum

EXT = "10.255.254.2"


def ip(text):
    return bytes(int(p) for p in text.split("."))


def full_ip_header(src, dst, proto, payload, ident=1, flags=0):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags, 64, proto, 0, ip(src), ip(dst))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def l4_checksum(src, dst, proto, segment):
    return checksum(ip(src) + ip(dst) + struct.pack("!BBH", 0, proto, len(segment)) + segment)


def udp(src, dst, sport, dport, data=b"hello", checksum_on=True):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    if checksum_on:
        seg = seg[:6] + struct.pack("!H", l4_checksum(src, dst, 17, seg) or 0xFFFF) + seg[8:]
    return full_ip_header(src, dst, 17, seg)


def tcp(src, dst, sport, dport, flags=0x10, data=b"data"):
    seg = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 65535, 0, 0) + data
    seg = seg[:16] + struct.pack("!H", l4_checksum(src, dst, 6, seg)) + seg[18:]
    return full_ip_header(src, dst, 6, seg)


def icmp_echo(src, dst, ident, kind=8, seq=1):
    body = struct.pack("!BBHHH", kind, 0, 0, ident, seq) + b"ping"
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return full_ip_header(src, dst, 1, body)


def verify(packet):
    """Independent full verification: header checksum and transport checksum recomputed from scratch."""
    ihl = (packet[0] & 15) * 4
    assert checksum(packet[:ihl]) == 0, "bad IP header checksum"
    src, dst = ".".join(map(str, packet[12:16])), ".".join(map(str, packet[16:20]))
    seg = packet[ihl:]
    if packet[9] == 6:
        assert l4_checksum(src, dst, 6, seg) == 0, "bad TCP checksum"
    elif packet[9] == 17 and struct.unpack_from("!H", seg, 6)[0]:
        assert l4_checksum(src, dst, 17, seg) == 0, "bad UDP checksum"
    elif packet[9] == 1:
        assert checksum(seg) == 0, "bad ICMP checksum"
    return src, dst, seg


class FakeClock:
    now = 1000.0

    def __call__(self):
        return self.now


class NatTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.nat = Nat(EXT, clock=self.clock)

    def test_udp_round_trip_rewrites_both_ways_with_valid_checksums_and_preserves_port(self):
        out = self.nat.outbound(udp("10.77.0.3", "203.0.113.9", 3074, 3074))
        src, dst, seg = verify(out)
        self.assertEqual((src, dst, struct.unpack_from("!HH", seg)), (EXT, "203.0.113.9", (3074, 3074)))   # port preserved
        back = self.nat.inbound(udp("203.0.113.9", EXT, 3074, 3074, b"reply"))
        src, dst, seg = verify(back)
        self.assertEqual((src, dst, struct.unpack_from("!HH", seg)), ("203.0.113.9", "10.77.0.3", (3074, 3074)))
        self.assertEqual(seg[8:], b"reply")

    def test_tcp_round_trip_and_state_machine_timeouts(self):
        out = self.nat.outbound(tcp("10.77.0.2", "198.51.100.7", 50000, 443, flags=0x02))
        verify(out)
        reply = self.nat.inbound(tcp("198.51.100.7", EXT, 443, 50000, flags=0x12))
        self.assertEqual(verify(reply)[1], "10.77.0.2")
        self.nat.outbound(tcp("10.77.0.2", "198.51.100.7", 50000, 443, flags=0x10))          # established
        self.clock.now += 3600
        self.assertIsNotNone(self.nat.inbound(tcp("198.51.100.7", EXT, 443, 50000)))          # still alive after an hour
        self.nat.outbound(tcp("10.77.0.2", "198.51.100.7", 50000, 443, flags=0x11))          # FIN
        self.clock.now += 31
        self.assertIsNone(self.nat.inbound(tcp("198.51.100.7", EXT, 443, 50000)))             # closing entries age out fast

    def test_two_hosts_using_the_same_source_port_get_distinct_external_ports(self):
        a = self.nat.outbound(udp("10.77.0.2", "203.0.113.9", 5000, 3074))
        b = self.nat.outbound(udp("10.77.0.3", "203.0.113.9", 5000, 3074))
        port_a, port_b = (struct.unpack_from("!H", verify(p)[2])[0] for p in (a, b))
        self.assertEqual(port_a, 5000)
        self.assertNotEqual(port_b, 5000)
        self.assertGreaterEqual(port_b, 20000)
        # Each reply reaches the right host.
        self.assertEqual(verify(self.nat.inbound(udp("203.0.113.9", EXT, 3074, port_a)))[1], "10.77.0.2")
        self.assertEqual(verify(self.nat.inbound(udp("203.0.113.9", EXT, 3074, port_b)))[1], "10.77.0.3")

    def test_port_restricted_cone_accepts_only_contacted_remotes_but_one_mapping_serves_all_of_them(self):
        first = self.nat.outbound(udp("10.77.0.3", "203.0.113.9", 4000, 3074))
        self.nat.outbound(udp("10.77.0.3", "198.51.100.5", 4000, 5000))
        port = struct.unpack_from("!H", verify(first)[2])[0]
        self.assertEqual(self.nat.outbound(udp("10.77.0.3", "192.0.2.1", 4000, 1))[20:22], struct.pack("!H", port))  # same mapping
        self.assertIsNotNone(self.nat.inbound(udp("198.51.100.5", EXT, 5000, port)))                                 # peer we contacted
        self.assertIsNone(self.nat.inbound(udp("198.51.100.5", EXT, 5001, port)))                                    # wrong remote port
        self.assertIsNone(self.nat.inbound(udp("198.51.100.99", EXT, 5000, port)))                                   # unknown remote
        self.assertEqual(self.nat.stats()["filtered"], 2)

    def test_unsolicited_and_misaddressed_packets_are_dropped(self):
        self.assertIsNone(self.nat.inbound(udp("203.0.113.9", EXT, 1, 22222)))
        self.assertIsNone(self.nat.inbound(udp("203.0.113.9", "10.255.254.9", 1, 2)))
        self.assertEqual((self.nat.stats()["no_mapping"], self.nat.stats()["not_for_us"]), (1, 1))

    def test_udp_without_checksum_stays_without_checksum(self):
        out = self.nat.outbound(udp("10.77.0.3", "203.0.113.9", 4000, 53, checksum_on=False))
        self.assertEqual(struct.unpack_from("!H", out, 26)[0], 0)
        verify(out)

    def test_icmp_echo_is_translated_by_identifier(self):
        out = self.nat.outbound(icmp_echo("10.77.0.3", "8.8.8.8", 0x1234))
        verify(out)
        reply = self.nat.inbound(icmp_echo("8.8.8.8", EXT, struct.unpack_from("!H", out, 24)[0], kind=0))
        src, dst, seg = verify(reply)
        self.assertEqual((dst, struct.unpack_from("!H", seg, 4)[0]), ("10.77.0.3", 0x1234))

    def test_icmp_fragmentation_needed_for_a_known_flow_is_translated_including_the_quote(self):
        out = self.nat.outbound(udp("10.77.0.3", "203.0.113.9", 4000, 3074, b"x" * 100))
        quoted = out[:28]
        error = struct.pack("!BBHHH", 3, 4, 0, 0, 1280) + quoted
        error = error[:2] + struct.pack("!H", checksum(error)) + error[4:]
        translated = self.nat.inbound(full_ip_header("198.51.100.1", EXT, 1, error))
        self.assertIsNotNone(translated)
        _, dst, seg = verify(translated)
        self.assertEqual(dst, "10.77.0.3")
        quote = seg[8:]
        self.assertEqual((bytes(quote[12:16]), struct.unpack_from("!H", quote, 20)[0]), (ip("10.77.0.3"), 4000))
        self.assertEqual(checksum(quote[:20]), 0)
        # An error quoting a destination we never contacted is refused.
        stranger = struct.pack("!BBHHH", 3, 4, 0, 0, 1280) + quoted[:16] + ip("192.0.2.77") + quoted[20:]
        stranger = stranger[:2] + struct.pack("!H", checksum(stranger)) + stranger[4:]
        self.assertIsNone(self.nat.inbound(full_ip_header("198.51.100.1", EXT, 1, stranger)))

    def test_fragments_other_protocols_and_garbage_are_dropped_and_counted(self):
        self.assertIsNone(self.nat.outbound(full_ip_header("10.77.0.3", "1.1.1.1", 17, b"\0" * 16, flags=0x2000)))   # MF
        self.assertIsNone(self.nat.outbound(full_ip_header("10.77.0.3", "1.1.1.1", 47, b"\0" * 16)))               # GRE
        self.assertIsNone(self.nat.outbound(b"\x45\0"))
        self.assertIsNone(self.nat.outbound(icmp_echo("10.77.0.3", "1.1.1.1", 1, kind=13)))
        stats = self.nat.stats()
        self.assertEqual((stats["fragments"], stats["unsupported"], stats["malformed"]), (1, 2, 1))

    def test_idle_mappings_expire_and_the_table_is_bounded(self):
        self.nat.outbound(udp("10.77.0.3", "203.0.113.9", 4000, 3074))
        self.clock.now += 121
        self.assertIsNone(self.nat.inbound(udp("203.0.113.9", EXT, 3074, 4000)))
        self.assertEqual(self.nat.stats()["active"], 0)
        small = Nat(EXT, max_entries=3, clock=self.clock)
        for port in range(2000, 2010):
            small.outbound(udp("10.77.0.3", "203.0.113.9", port, 9))
        self.assertEqual(small.stats()["active"], 3)
        self.assertEqual(small.stats()["evicted"], 7)

    def test_incremental_checksums_match_a_full_recompute_for_many_random_packets(self):
        import os
        for index in range(300):
            proto_udp = index % 2
            src, port = f"10.77.0.{2 + index % 3}", 1024 + (os.urandom(2)[0] << 8 | os.urandom(1)[0]) % 40000
            data = os.urandom(1 + index % 200)
            packet = udp(src, "198.51.100.8", port, 443, data) if proto_udp else tcp(src, "198.51.100.8", port, 443, data=data)
            out = self.nat.outbound(packet)
            verify(out)
            ext_port = struct.unpack_from("!H", out, 20)[0]
            reply = udp("198.51.100.8", EXT, 443, ext_port, data) if proto_udp else tcp("198.51.100.8", EXT, 443, ext_port, data=data)
            verify(self.nat.inbound(reply))

    def test_port_rewrites_in_both_directions_keep_every_checksum_valid(self):
        """Force collisions so the external port differs from the internal one, for TCP and UDP, both ways."""
        import os
        for index in range(200):
            port = 3000 + index
            first = udp("10.77.0.2", "198.51.100.8", port, 443) if index % 2 else tcp("10.77.0.2", "198.51.100.8", port, 443)
            self.nat.outbound(first)                                              # host .2 takes the port
            data = os.urandom(1 + index % 150)
            second = udp("10.77.0.3", "198.51.100.8", port, 443, data) if index % 2 else tcp("10.77.0.3", "198.51.100.8", port, 443, data=data)
            out = self.nat.outbound(second)
            _, _, seg = verify(out)
            ext = struct.unpack_from("!H", seg)[0]
            self.assertNotEqual(ext, port)
            reply = udp("198.51.100.8", EXT, 443, ext, data) if index % 2 else tcp("198.51.100.8", EXT, 443, ext, data=data)
            back = self.nat.inbound(reply)
            _, dst, seg = verify(back)
            self.assertEqual((dst, struct.unpack_from("!H", seg, 2)[0]), ("10.77.0.3", port))


if __name__ == "__main__":
    unittest.main()
