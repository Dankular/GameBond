import ipaddress
import struct
import unittest

from gamebond.frame_io import MemoryFrameIO
from gamebond.lan_gateway import (LanDevice, LanGateway, clamp_tcp_mss, fragment_ipv4, load_lan_devices,
                                  load_lan_tunnel_ips, parse_ipv4)

GW_MAC = bytes.fromhex("02aabbccdd01")
PS_MAC = bytes.fromhex("021122334455")
OTHER_MAC = bytes.fromhex("02deadbeef99")
BCAST = b"\xff" * 6
GW_IP, PS_IP, CLIENT_IP = "10.77.0.1", "10.77.0.3", "10.77.0.2"


def ip(text):
    return ipaddress.IPv4Address(text).packed


def csum(data):
    """Independent RFC 1071 checksum for verifying the module's output."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64, flags=0, ident=1):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags, ttl, proto, 0, ip(src), ip(dst))
    return header[:10] + struct.pack("!H", csum(header)) + header[12:] + payload


def udp(src, dst, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    return ipv4(src, dst, 17, seg)


def tcp_syn(src, dst, mss, ack=False):
    options = b"\x02\x04" + struct.pack("!H", mss) + b"\x01\x03\x03\x08"  # MSS, NOP, wscale
    flags = 0x12 if ack else 0x02
    segment = struct.pack("!HHIIBBHHH", 40000, 443, 1, 0, (5 + len(options) // 4) << 4, flags, 65535, 0, 0) + options
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", csum(pseudo + segment)) + segment[18:]
    return ipv4(src, dst, 6, segment)


def eth(dst, src, ethertype, payload):
    frame = dst + src + struct.pack("!H", ethertype) + payload
    return frame + b"\0" * max(0, 60 - len(frame))


def dhcp_request(kind, mac=PS_MAC, requested=None, server=None, xid=b"\x12\x34\x56\x78"):
    body = struct.pack("!BBBB4sH2s4s4s4s4s", 1, 1, 6, 0, xid, 0, b"\x80\x00", b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4)
    body += mac + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63" + bytes([53, 1, kind])
    if requested:
        body += bytes([50, 4]) + ip(requested)
    if server:
        body += bytes([54, 4]) + ip(server)
    body += b"\xff"
    seg = struct.pack("!HHHH", 68, 67, 8 + len(body), 0) + body
    return eth(BCAST, mac, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, seg))


def arp(op, sender_mac, sender_ip, target_ip, dst=BCAST):
    body = b"\x00\x01\x08\x00\x06\x04" + struct.pack("!H", op) + sender_mac + ip(sender_ip) + b"\0" * 6 + ip(target_ip)
    return eth(dst, sender_mac, 0x0806, body)


def dhcp_options(frame):
    payload = frame[14 + 20 + 8:]
    options, index = {}, 240
    while payload[index] != 255:
        options[payload[index]] = payload[index + 2:index + 2 + payload[index + 1]]
        index += 2 + payload[index + 1]
    return payload, options


class GatewayCase(unittest.TestCase):
    def setUp(self):
        self.wire, self.device_side = MemoryFrameIO.pair(GW_MAC, PS_MAC)
        self.up = []
        self.now = [1000.0]
        self.device = LanDevice(name="PS5", tunnel_ip=PS_IP, interface_name="eth9")
        self.gw = LanGateway(self.device, self.wire, self.up.append, client_tunnel_ip=CLIENT_IP, clock=lambda: self.now[0])

    def sent(self):
        frames = []
        while not self.device_side.inbox.empty():
            frames.append(self.device_side.inbox.get())
        return frames

    def lease(self):
        self.gw.handle_frame(dhcp_request(1))
        self.gw.handle_frame(dhcp_request(3, requested=PS_IP, server=GW_IP))
        self.sent()


class DhcpTests(GatewayCase):
    def test_discover_gets_offer_with_own_tunnel_address(self):
        self.gw.handle_frame(dhcp_request(1))
        (frame,) = self.sent()
        payload, options = dhcp_options(frame)
        self.assertEqual(frame[:6], BCAST)
        self.assertEqual(frame[6:12], GW_MAC)
        self.assertEqual(options[53], b"\x02")
        self.assertEqual(payload[16:20], ip(PS_IP))          # yiaddr
        self.assertEqual(payload[4:8], b"\x12\x34\x56\x78")  # xid echoed
        self.assertEqual(options[54], ip(GW_IP))
        self.assertEqual(options[3], ip(GW_IP))              # router
        self.assertEqual(options[1], ip("255.255.255.0"))
        self.assertEqual(options[6], ip("1.1.1.1") + ip("8.8.8.8"))
        self.assertEqual(struct.unpack("!H", options[26])[0], 1280)
        self.assertEqual(csum(frame[14:34]), 0)               # valid IP header checksum

    def test_request_is_acked_and_marks_leased(self):
        self.gw.handle_frame(dhcp_request(3, requested=PS_IP, server=GW_IP))
        (frame,) = self.sent()
        self.assertEqual(dhcp_options(frame)[1][53], b"\x05")
        self.assertTrue(self.gw.leased)

    def test_request_for_other_address_is_nak(self):
        self.gw.handle_frame(dhcp_request(3, requested="10.77.0.50"))
        (frame,) = self.sent()
        self.assertEqual(dhcp_options(frame)[1][53], b"\x06")
        self.assertFalse(self.gw.leased)

    def test_request_choosing_another_server_is_ignored(self):
        self.gw.handle_frame(dhcp_request(3, requested=PS_IP, server="192.168.1.1"))
        self.assertEqual(self.sent(), [])

    def test_second_device_cannot_take_the_lease(self):
        self.gw.handle_frame(dhcp_request(1))
        self.sent()
        self.gw.handle_frame(dhcp_request(1, mac=OTHER_MAC))
        self.assertEqual(self.sent(), [])
        self.assertEqual(self.gw.counters.foreign_mac_dropped, 1)

    def test_replacement_device_accepted_after_silence(self):
        self.gw.handle_frame(dhcp_request(1))
        self.sent()
        self.now[0] += 121
        self.gw.handle_frame(dhcp_request(1, mac=OTHER_MAC))
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.gw.device_mac, OTHER_MAC)

    def test_pinned_mac_is_never_replaced(self):
        device = LanDevice(name="PS5", tunnel_ip=PS_IP, interface_name="eth9", device_mac="02:11:22:33:44:55")
        gw = LanGateway(device, self.wire, self.up.append, client_tunnel_ip=CLIENT_IP, clock=lambda: self.now[0])
        self.now[0] += 10000
        gw.handle_frame(dhcp_request(1, mac=OTHER_MAC))
        self.assertEqual(self.sent(), [])


class ArpTests(GatewayCase):
    def test_answers_for_gateway_and_other_tunnel_addresses(self):
        for target in (GW_IP, CLIENT_IP, "10.77.0.77"):
            self.gw.handle_frame(arp(1, PS_MAC, PS_IP, target))
        replies = self.sent()
        self.assertEqual(len(replies), 3)
        for frame in replies:
            self.assertEqual(frame[:6], PS_MAC)
            self.assertEqual(frame[20:22], b"\x00\x02")
            self.assertEqual(frame[22:28], GW_MAC)  # proxy ARP: our MAC for any tunnel address

    def test_does_not_answer_for_devices_own_address_or_outside_subnet(self):
        self.gw.handle_frame(arp(1, PS_MAC, "0.0.0.0", PS_IP))   # duplicate-address probe
        self.gw.handle_frame(arp(1, PS_MAC, PS_IP, PS_IP))       # gratuitous
        self.gw.handle_frame(arp(1, PS_MAC, PS_IP, "192.168.1.1"))
        self.assertEqual(self.sent(), [])

    def test_arp_with_foreign_sender_ip_is_dropped(self):
        self.gw.handle_frame(arp(1, PS_MAC, "10.77.0.9", GW_IP))
        self.assertEqual(self.sent(), [])
        self.assertEqual(self.gw.counters.spoofed_source_dropped, 1)


class ForwardingTests(GatewayCase):
    def test_device_packet_reaches_tunnel_with_decremented_ttl(self):
        self.lease()
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp(PS_IP, "8.8.4.4", 5000, 53, b"x" * 20)))
        (packet,) = self.up
        self.assertEqual(packet[8], 63)
        self.assertEqual(csum(packet[:20]), 0)
        self.assertEqual(packet[12:16], ip(PS_IP))
        self.assertEqual(len(packet), 20 + 8 + 20)  # Ethernet padding stripped

    def test_spoofed_source_and_foreign_mac_are_dropped(self):
        self.lease()
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp(CLIENT_IP, "8.8.4.4", 1, 2, b"a")))
        self.gw.handle_frame(eth(GW_MAC, OTHER_MAC, 0x0800, udp(PS_IP, "8.8.4.4", 1, 2, b"a")))
        self.assertEqual(self.up, [])
        self.assertEqual((self.gw.counters.spoofed_source_dropped, self.gw.counters.foreign_mac_dropped), (1, 1))

    def test_multicast_broadcast_and_local_are_not_forwarded(self):
        self.lease()
        for dst in ("239.255.255.250", "255.255.255.255", "10.77.0.255", "127.0.0.1"):
            self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp(PS_IP, dst, 1900, 1900, b"x")))
        self.assertEqual(self.up, [])
        self.assertEqual(self.gw.counters.local_only_dropped, 4)

    def test_expiring_ttl_is_not_forwarded(self):
        self.lease()
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, ipv4(PS_IP, "8.8.8.8", 17, b"\0" * 8, ttl=1)))
        self.assertEqual(self.up, [])
        self.assertEqual(self.gw.counters.ttl_expired, 1)

    def test_oversized_packet_without_df_is_fragmented_and_reassembles(self):
        self.lease()
        data = bytes(range(256)) * 5  # 1280 bytes UDP payload -> 1308-byte packet
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp(PS_IP, "8.8.4.4", 7, 9, data)))
        self.assertGreater(len(self.up), 1)
        rebuilt = b""
        for index, piece in enumerate(self.up):
            self.assertLessEqual(len(piece), 1280)
            self.assertEqual(csum(piece[:20]), 0)
            field = struct.unpack("!H", piece[6:8])[0]
            self.assertEqual((field & 0x1FFF) * 8, len(rebuilt))
            self.assertEqual(bool(field & 0x2000), index < len(self.up) - 1)
            rebuilt += piece[20:]
        self.assertEqual(rebuilt[8:], data)

    def test_oversized_packet_with_df_gets_icmp_fragmentation_needed(self):
        self.lease()
        big = ipv4(PS_IP, "8.8.4.4", 17, b"\0" * 1400, flags=0x4000)
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, big))
        self.assertEqual(self.up, [])
        (frame,) = self.sent()
        icmp = frame[14 + 20:]
        self.assertEqual(frame[14 + 9], 1)
        self.assertEqual((icmp[0], icmp[1]), (3, 4))
        self.assertEqual(struct.unpack("!H", icmp[6:8])[0], 1280)
        self.assertEqual(csum(icmp), 0)
        self.assertEqual(frame[14 + 16:14 + 20], ip(PS_IP))

    def test_syn_mss_is_clamped_in_both_directions_with_valid_checksum(self):
        self.lease()
        self.gw.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, tcp_syn(PS_IP, "93.184.216.34", 1460)))
        (out,) = self.up
        header = 20
        self.assertEqual(struct.unpack("!H", out[header + 22:header + 24])[0], 1240)
        segment = out[header:]
        self.assertEqual(csum(ip(PS_IP) + ip("93.184.216.34") + struct.pack("!BBH", 0, 6, len(segment)) + segment), 0)
        self.assertTrue(self.gw.deliver(tcp_syn("93.184.216.34", PS_IP, 1460, ack=True)))
        (frame,) = self.sent()
        self.assertEqual(struct.unpack("!H", frame[14 + 42:14 + 44])[0], 1240)

    def test_small_mss_is_left_untouched(self):
        packet = tcp_syn(PS_IP, "1.2.3.4", 1000)
        self.assertIs(clamp_tcp_mss(packet, 1240), packet)


class DeliveryTests(GatewayCase):
    def test_tunnel_packet_is_framed_for_the_device(self):
        self.lease()
        packet = udp("8.8.4.4", PS_IP, 53, 5000, b"answer")
        self.assertTrue(self.gw.deliver(packet))
        (frame,) = self.sent()
        self.assertEqual((frame[:6], frame[6:12], frame[12:14]), (PS_MAC, GW_MAC, b"\x08\x00"))
        inner = frame[14:14 + 20 + 8 + 6]
        self.assertEqual(inner[8], 63)
        self.assertEqual(csum(inner[:20]), 0)

    def test_wrong_destination_and_unknown_mac_are_counted_not_sent(self):
        self.assertFalse(self.gw.deliver(udp("8.8.4.4", PS_IP, 1, 2, b"x")))  # device never seen
        self.assertEqual(self.gw.counters.no_device_mac, 1)
        self.lease()
        self.assertFalse(self.gw.deliver(udp("8.8.4.4", CLIENT_IP, 1, 2, b"x")))
        self.assertEqual(self.gw.counters.wrong_destination, 1)
        self.assertEqual(self.sent(), [])

    def test_threaded_reader_forwards_frames(self):
        import time
        self.gw.start()
        try:
            self.device_side.write(dhcp_request(3, requested=PS_IP, server=GW_IP))
            self.device_side.write(eth(GW_MAC, PS_MAC, 0x0800, udp(PS_IP, "9.9.9.9", 1, 2, b"hi")))
            deadline = time.monotonic() + 3
            while not self.up and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(self.up), 1)
            self.assertTrue(self.gw.stats()["leased"])
        finally:
            self.gw.close()


class ConfigTests(unittest.TestCase):
    def config(self, **extra):
        return dict(role="client", client_tunnel_ip=CLIENT_IP, interface_ids=["{00000001-1111-1111-1111-000000000001}"],
                    interface_indices=[10], **extra)

    def device(self, **over):
        row = dict(name="PS5", tunnel_ip=PS_IP, interface_id="{AAAAAAAA-1111-1111-1111-000000000009}", interface_index=14)
        row.update(over)
        return row

    def test_valid_device_loads(self):
        (device,) = load_lan_devices(self.config(lan_devices=[self.device()]))
        self.assertEqual((device.name, device.tunnel_ip), ("PS5", PS_IP))

    def test_rejects_reserved_foreign_and_duplicate_addresses(self):
        for address in ("10.77.0.0", "10.77.0.1", CLIENT_IP, "10.77.0.255", "10.78.0.3", "nope"):
            with self.assertRaises(ValueError, msg=address):
                load_lan_devices(self.config(lan_devices=[self.device(tunnel_ip=address)]))
        with self.assertRaises(ValueError):
            load_lan_devices(self.config(lan_devices=[self.device(), self.device(name="Xbox", interface_id="{AAAAAAAA-1111-1111-1111-00000000000A}")]))

    def test_rejects_uplink_adapter_and_unknown_fields_and_bad_mac(self):
        with self.assertRaises(ValueError):
            load_lan_devices(self.config(lan_devices=[self.device(interface_id="{00000001-1111-1111-1111-000000000001}")]))
        with self.assertRaises(ValueError):
            load_lan_devices(self.config(lan_devices=[self.device(surprise=1)]))
        with self.assertRaises(ValueError):
            load_lan_devices(self.config(lan_devices=[self.device(device_mac="zz")]))
        with self.assertRaises(ValueError):
            load_lan_devices(self.config(lan_devices=[self.device(interface_id="not-a-guid")]))

    def test_server_ip_list_validation(self):
        base = dict(client_tunnel_ip=CLIENT_IP)
        self.assertEqual(load_lan_tunnel_ips(dict(base, lan_tunnel_ips=[PS_IP, "10.77.0.4"])), [PS_IP, "10.77.0.4"])
        for bad in ([CLIENT_IP], ["10.77.0.1"], [PS_IP, PS_IP], ["192.168.0.5"]):
            with self.assertRaises(ValueError):
                load_lan_tunnel_ips(dict(base, lan_tunnel_ips=bad))

    def test_parse_ipv4_rejects_truncated(self):
        self.assertIsNone(parse_ipv4(udp(PS_IP, "1.1.1.1", 1, 2, b"abc")[:25]))
        self.assertEqual(fragment_ipv4(ipv4(PS_IP, "1.1.1.1", 17, b"\0" * 16), 1280)[0][2:4], struct.pack("!H", 36))


if __name__ == "__main__":
    unittest.main()
