"""Real AF_PACKET I/O against a kernel TAP device; skipped without root and /dev/net/tun."""
import fcntl
import os
import select
import socket
import struct
import sys
import time
import unittest

from gamebond.frame_io import LinuxFrameIO, linux_interfaces
from gamebond.lan_gateway import LanDevice, LanGateway
from test_lan_gateway import PS_IP, PS_MAC, GW_IP, CLIENT_IP, arp, dhcp_options, dhcp_request, eth, udp

NAME = b"gbtest0"


def make_tap():
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", NAME, 0x0002 | 0x1000) + bytes(22))  # IFF_TAP | IFF_NO_PI
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, struct.pack("16sH", NAME, 0) + bytes(22))[:18])[1]
        fcntl.ioctl(s, 0x8914, struct.pack("16sH", NAME, flags | 1) + bytes(22))
    return fd


def read_matching(fd, predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if select.select([fd], [], [], 0.1)[0]:
            frame = os.read(fd, 4096)
            if predicate(frame):
                return frame
    return None


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0
                     and os.path.exists("/dev/net/tun"), "needs Linux root and /dev/net/tun")
class LinuxRawIoTests(unittest.TestCase):
    def setUp(self):
        self.fd = make_tap()
        self.io = LinuxFrameIO(NAME.decode())
        self.up = []
        device = LanDevice(name="PS5", tunnel_ip=PS_IP, interface_name=NAME.decode())
        self.gw = LanGateway(device, self.io, self.up.append, client_tunnel_ip=CLIENT_IP).start()

    def tearDown(self):
        self.gw.close()
        os.close(self.fd)

    def test_dhcp_arp_and_forwarding_over_a_real_interface(self):
        os.write(self.fd, dhcp_request(1))
        offer = read_matching(self.fd, lambda f: f[:6] == b"\xff" * 6 and f[6:12] == self.io.mac and len(f) > 280)
        self.assertIsNotNone(offer, "no DHCP offer on the wire")
        payload, options = dhcp_options(offer)
        self.assertEqual((options[53], payload[16:20]), (b"\x02", socket.inet_aton(PS_IP)))
        os.write(self.fd, dhcp_request(3, requested=PS_IP, server=GW_IP))
        self.assertIsNotNone(read_matching(self.fd, lambda f: len(f) > 280 and f[6:12] == self.io.mac))
        os.write(self.fd, arp(1, PS_MAC, PS_IP, GW_IP))
        reply = read_matching(self.fd, lambda f: f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02")
        self.assertIsNotNone(reply)
        self.assertEqual(reply[22:28], self.io.mac)
        os.write(self.fd, eth(self.io.mac, PS_MAC, 0x0800, udp(PS_IP, "9.9.9.9", 1111, 2222, b"payload")))
        deadline = time.monotonic() + 3
        while not self.up and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(self.up), 1)
        self.assertTrue(self.up[0].endswith(b"payload"))
        self.assertTrue(self.gw.deliver(udp("9.9.9.9", PS_IP, 2222, 1111, b"reply")))
        self.assertIsNotNone(read_matching(self.fd, lambda f: f[12:14] == b"\x08\x00" and f.rstrip(b"\0").endswith(b"reply")))

    def test_own_transmissions_are_not_read_back(self):
        os.write(self.fd, dhcp_request(1))
        read_matching(self.fd, lambda f: len(f) > 280)
        time.sleep(0.4)
        # Only the single DISCOVER may have been counted as inbound from the device
        # (the kernel adds IPv6 chatter, which is ignored as non-IPv4/ARP).
        self.assertEqual(self.gw.counters.dhcp_offers, 1)

    def test_candidate_listing_excludes_loopback_and_virtual_interfaces(self):
        names = [row["name"] for row in linux_interfaces()]
        self.assertNotIn("lo", names)
        self.assertNotIn(NAME.decode(), names)  # a TAP has no backing hardware device


if __name__ == "__main__":
    unittest.main()
