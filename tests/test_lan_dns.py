import struct
import unittest

from gamebond.dns import DNSConfig, override_response
from gamebond.frame_io import MemoryFrameIO
from gamebond.lan_gateway import LanDevice, LanGateway
from test_lan_gateway import CLIENT_IP, GW_MAC, PS_IP, PS_MAC, csum, dhcp_request, eth, ipv4, ip
from test_lan_runtime import DEVICE, make_runtime

OVERRIDE_IP = "192.0.2.55"


def query(name, kind=1, txid=0x1234, edns=False):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    body = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 1 if edns else 0) + labels + b"\0" + struct.pack("!HH", kind, 1)
    if edns:
        body += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return body


def udp_dns(src, dst, payload, sport=50000, dport=53):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ipv4(src, dst, 17, seg)


def answers(response):
    _, flags, qd, an, *_ = struct.unpack("!HHHHHH", response[:12])
    return flags, an, response[-4:] if an else b""


class OverrideTests(unittest.TestCase):
    def setUp(self):
        self.config = DNSConfig(records={"login.example.net": {"A": [OVERRIDE_IP], "AAAA": ["2001:db8::5"]}}, bind=("10.77.0.2", 53))

    def test_configured_name_gets_authoritative_answer(self):
        response = override_response(self.config, query("Login.Example.net"))
        flags, count, rdata = answers(response)
        self.assertEqual((response[:2], flags & 0x8400, flags & 15, count, rdata), (b"\x12\x34", 0x8400, 0, 1, bytes([192, 0, 2, 55])))

    def test_other_types_of_a_configured_name_are_empty_not_forwarded(self):
        response = override_response(self.config, query("login.example.net", kind=16))     # TXT
        self.assertEqual((answers(response)[0] & 15, answers(response)[1]), (0, 0))

    def test_unconfigured_malformed_and_non_internet_class_pass_through(self):
        self.assertIsNone(override_response(self.config, query("other.example.org")))
        self.assertIsNone(override_response(self.config, b"\x00" * 5))
        chaos = bytearray(query("login.example.net"))
        chaos[-1] = 3
        self.assertIsNone(override_response(self.config, bytes(chaos)))


class GatewayDnsTests(unittest.TestCase):
    def setUp(self):
        self.wire, self.console = MemoryFrameIO.pair(GW_MAC, PS_MAC)
        self.up = []
        config = DNSConfig(records={"login.example.net": {"A": [OVERRIDE_IP]}}, bind=("10.77.0.2", 53))
        self.gw = LanGateway(LanDevice(name="PS5", tunnel_ip=PS_IP, interface_name="eth9"), self.wire, self.up.append,
                             client_tunnel_ip=CLIENT_IP, dns_override=lambda q: override_response(config, q))
        self.gw.handle_frame(dhcp_request(3, requested=PS_IP, server="10.77.0.1"))
        while not self.console.inbox.empty():
            self.console.inbox.get()

    def ask(self, payload, resolver="8.8.8.8", **kw):
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp_dns(PS_IP, resolver, payload, **kw)))

    def test_override_is_answered_locally_as_the_resolver_the_device_asked(self):
        self.ask(query("login.example.net"), resolver="9.9.9.9", sport=44444)
        self.assertEqual(self.up, [])                          # never left the workstation
        frame = self.console.inbox.get_nowait()
        packet = frame[14:]
        self.assertEqual((packet[12:16], packet[16:20]), (ip("9.9.9.9"), ip(PS_IP)))   # spoofed from the asked server
        self.assertEqual(csum(packet[:20]), 0)
        sport, dport = struct.unpack("!HH", packet[20:24])
        self.assertEqual((sport, dport), (53, 44444))
        pseudo = packet[12:20] + struct.pack("!BBH", 0, 17, struct.unpack("!H", packet[24:26])[0])
        self.assertEqual(csum(pseudo + packet[20:20 + struct.unpack("!H", packet[24:26])[0]]), 0)   # valid UDP checksum
        self.assertEqual(answers(packet[28:])[2], bytes([192, 0, 2, 55]))
        self.assertEqual(self.gw.counters.dns_overridden, 1)

    def test_everything_else_is_forwarded_unchanged_through_the_tunnel(self):
        self.ask(query("www.example.org"))
        self.assertEqual(len(self.up), 1)
        self.assertEqual(self.up[0][16:20], ip("8.8.8.8"))
        self.assertTrue(self.console.inbox.empty())
        self.assertEqual(self.gw.counters.dns_overridden, 0)

    def test_non_dns_udp_and_fragments_are_not_inspected(self):
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp_dns(PS_IP, "8.8.8.8", query("login.example.net"), dport=5353)))
        fragment = ipv4(PS_IP, "8.8.8.8", 17, struct.pack("!HHHH", 1, 53, 8 + 29, 0) + query("login.example.net"), flags=0x2000)
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, fragment))
        self.assertEqual(len(self.up), 2)
        self.assertEqual(self.gw.counters.dns_overridden, 0)

    def test_a_failing_resolver_never_blocks_traffic(self):
        self.gw.dns_override = lambda q: 1 / 0
        self.ask(query("login.example.net"))
        self.assertEqual(len(self.up), 1)

    def test_gateway_without_override_is_unchanged(self):
        self.gw.dns_override = None
        self.ask(query("login.example.net"))
        self.assertEqual(len(self.up), 1)


class RuntimeDnsTests(unittest.TestCase):
    def runtime(self, dns):
        extra = dict(lan_devices=[dict(DEVICE)])
        if dns is not None:
            extra["dns"] = dns
        return make_runtime(**extra)

    def test_override_active_only_when_enabled(self):
        profile = dict(enabled=True, bind=[CLIENT_IP, 53], records={"login.example.net": {"A": [OVERRIDE_IP]}})
        self.assertIsNotNone(self.runtime(profile).dns_override())
        self.assertIsNone(self.runtime(dict(profile, enabled=False)).dns_override())
        self.assertIsNone(self.runtime(None).dns_override())

    def test_status_reports_scope_and_counts_only_when_applied(self):
        runtime = self.runtime(dict(enabled=True, bind=[CLIENT_IP, 53], records={"login.example.net": {"A": [OVERRIDE_IP]}}))
        self.assertIsNone(runtime.dns_status())                       # no device up yet
        gateway = type("G", (), dict(alive=True, counters=type("C", (), dict(dns_overridden=3))()))()
        runtime.lan_gateways = {"PS5": gateway}
        self.assertEqual(runtime.dns_status(), dict(scope="connected_devices", overrides=3))
        self.assertIsNone(self.runtime(None).dns_status())


if __name__ == "__main__":
    unittest.main()
