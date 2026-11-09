"""PS5-side frames -> LanGateway -> Runtime -> encrypted Node over loopback -> server app.run -> back."""
import contextlib
import io
import queue
import secrets
import struct
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from gamebond import app
from gamebond.frame_io import MemoryFrameIO
from gamebond.lan_gateway import parse_ipv4
from gamebond.transport import Node
from test_app import FakeTun, base_config, ipv4
from test_lan_gateway import GW_MAC, PS_MAC, arp, dhcp_options, dhcp_request, eth, udp
from test_lan_runtime import DEVICE, make_runtime

PS5 = "10.70.0.3"
PC = "10.70.0.2"


class EndToEnd(unittest.TestCase):
    def setUp(self):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        self.tun, nodes, self.stop = FakeTun(), [], threading.Event()
        config = base_config()
        config.pop("interface_indices")
        config.update(role="server", bind=[["127.0.0.1", 0]], session=session.hex(), lan_tunnel_ips=[PS5])
        config.pop("peer")

        def factory(*args, **kwargs):
            nodes.append(Node(*args, **kwargs))
            return nodes[-1]

        directory = tempfile.TemporaryDirectory()
        key_path = Path(directory.name) / "key.bin"
        key_path.write_bytes(key)
        signals = types.SimpleNamespace(SIGINT=2, SIGTERM=15, signal=lambda *_: None)
        patches = [patch.object(app, "open_tun", return_value=self.tun), patch.object(app, "Node", side_effect=factory),
                   patch.object(app, "signal", signals)]
        for p in patches:
            p.start()

        def serve():
            with contextlib.redirect_stdout(io.StringIO()):
                app.run(config, key_path, stop_event=self.stop)
        threading.Thread(target=serve, daemon=True).start()
        deadline = time.monotonic() + 3
        while not nodes and time.monotonic() < deadline:
            time.sleep(0.01)

        # Client side: the real Runtime send/receive code with a real Node, no ProxiFyre/netstack.
        runtime = make_runtime(lan_devices=[dict(DEVICE, tunnel_ip=PS5)], client_tunnel_ip=PC, game_udp_ports=[])
        runtime.node = Node(key, "client", session, [("127.0.0.1", 0)], nodes[0].addresses[0]).start()
        deadline = time.monotonic() + 3
        while not (runtime.node.stats()["paths"] and runtime.node.stats()["paths"][0]["healthy"]) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.to_pc_stack = []
        runtime.stack = types.SimpleNamespace(stdin=types.SimpleNamespace(write=self.to_pc_stack.append, flush=lambda: None))
        self.far_end = []
        runtime.lan_opener = lambda device: self.far_end.append(MemoryFrameIO.pair(GW_MAC, PS_MAC)) or self.far_end[-1][0]
        for target in (runtime.send_bulk, runtime.receive):
            threading.Thread(target=target, daemon=True).start()
        self.runtime = runtime
        with contextlib.redirect_stdout(io.StringIO()):
            runtime.maintain_lan()
        self.console = self.far_end[0][1]

        def cleanup():
            runtime.stop.set()
            self.stop.set()
            for gateway in runtime.lan_gateways.values():
                gateway.close()
            runtime.node.close()
            time.sleep(0.2)
            for p in patches:
                p.stop()
            directory.cleanup()
        self.addCleanup(cleanup)

    def frames_to_console(self, predicate, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                frame = self.console.inbox.get(timeout=0.1)
            except queue.Empty:
                continue
            if predicate(frame):
                return frame
        return None

    def test_console_joins_gets_own_address_and_exchanges_traffic_with_the_internet_side(self):
        # 1. The console boots: DHCP, then ARP for its gateway.
        self.console.write(dhcp_request(1))
        offer = self.frames_to_console(lambda f: len(f) > 280)
        self.assertEqual(dhcp_options(offer)[0][16:20], bytes([10, 70, 0, 3]))
        self.console.write(dhcp_request(3, requested=PS5, server="10.70.0.1"))
        self.assertIsNotNone(self.frames_to_console(lambda f: len(f) > 280))
        self.console.write(arp(1, PS_MAC, PS5, "10.70.0.1"))
        self.assertIsNotNone(self.frames_to_console(lambda f: f[12:14] == b"\x08\x06"))
        # 2. Console -> internet: the VPS-side TUN sees the packet from the console's own tunnel address.
        self.console.write(eth(GW_MAC, PS_MAC, 0x0800, udp(PS5, "198.51.100.7", 40000, 3074, b"hello-from-ps5")))
        arrived = self.tun.injected.get(timeout=3)
        _, proto, src, dst, total = parse_ipv4(arrived)
        self.assertEqual((src, dst, proto), (bytes([10, 70, 0, 3]), bytes([198, 51, 100, 7]), 17))
        self.assertTrue(arrived.endswith(b"hello-from-ps5"))
        # 3. Internet -> console: routed by destination address back out the USB-side adapter, not into the PC's netstack.
        self.tun.capture.put(ipv4("198.51.100.7", PS5, sport=3074, dport=40000, payload=b"reply-to-ps5"))
        frame = self.frames_to_console(lambda f: f[12:14] == b"\x08\x00" and f.rstrip(b"\0").endswith(b"reply-to-ps5"))
        self.assertIsNotNone(frame)
        self.assertEqual((frame[:6], frame[6:12]), (PS_MAC, GW_MAC))
        self.assertEqual(self.to_pc_stack, [])
        # 4. The PC's own address still goes to its netstack, unaffected.
        self.tun.capture.put(ipv4("198.51.100.7", PC, sport=443, dport=50000, payload=b"reply-to-pc"))
        deadline = time.monotonic() + 3
        while not self.to_pc_stack and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(len(self.to_pc_stack), 1)
        self.assertIn(b"reply-to-pc", self.to_pc_stack[0])
        # 5. The server refuses a packet whose source is neither the PC nor a configured console address.
        self.runtime.node.send(ipv4("10.70.0.99", "198.51.100.7"))
        with self.assertRaises(queue.Empty):
            self.tun.injected.get(timeout=0.3)


if __name__ == "__main__":
    unittest.main()
