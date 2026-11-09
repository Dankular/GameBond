"""PS5 -> LanGateway -> Runtime -> TransportRouter -> {GameBond tunnel -> app.run server | NAT -> Glorytun UDP -> OMR peer}."""
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

try:
    import nacl  # noqa: F401
except ImportError:
    raise unittest.SkipTest("PyNaCl not installed (pip install 'gamebond[omr]')")

from gamebond import app
from gamebond.frame_io import MemoryFrameIO
from gamebond.nat import Nat
from gamebond.transport import Node
from gamebond.transport_router import TransportRouter
from gamebond.omr_glorytun import MudClient
from mud_peer import MudPeer
from test_app import FakeTun, base_config, ipv4
from test_lan_gateway import GW_MAC, PS_MAC, dhcp_request, eth, udp as lan_udp
from test_lan_runtime import DEVICE, make_runtime
from test_nat import udp as valid_udp, verify

PS5, PC, OMR_ADDR = "10.70.0.3", "10.70.0.2", "10.255.254.2"
GLORYTUN_KEY = bytes(range(32))


def wait_for(condition, timeout=6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


class SideBySide(unittest.TestCase):
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
        self.assertTrue(wait_for(lambda: nodes))
        gamebond = Node(key, "client", session, [("127.0.0.1", 0)], nodes[0].addresses[0]).start()
        self.assertTrue(wait_for(lambda: gamebond.stats()["paths"] and gamebond.stats()["paths"][0]["healthy"]))

        self.omr_peer = MudPeer(GLORYTUN_KEY)                      # stands in for the OMR server's Glorytun UDP
        omr = MudClient(GLORYTUN_KEY, self.omr_peer.address, ["127.0.0.1"], beat_ms=20).start()
        self.assertTrue(wait_for(lambda: omr.ready))

        runtime = make_runtime(lan_devices=[dict(DEVICE, tunnel_ip=PS5)], client_tunnel_ip=PC, game_udp_ports=[3075])
        self.router = TransportRouter(gamebond, omr, Nat(OMR_ADDR), ready_ttl=0.05).start()
        runtime.node = self.router
        self.to_pc_stack = []
        runtime.stack = types.SimpleNamespace(stdin=types.SimpleNamespace(write=self.to_pc_stack.append, flush=lambda: None))
        self.far_end = []
        runtime.lan_opener = lambda device: self.far_end.append(MemoryFrameIO.pair(GW_MAC, PS_MAC)) or self.far_end[-1][0]
        for target in (runtime.send_bulk, runtime.receive):
            threading.Thread(target=target, daemon=True).start()
        with contextlib.redirect_stdout(io.StringIO()):
            runtime.maintain_lan()
        self.runtime, self.console = runtime, self.far_end[0][1]
        self.console.write(dhcp_request(3, requested=PS5, server="10.70.0.1"))
        time.sleep(0.1)
        while not self.console.inbox.empty():
            self.console.inbox.get()

        def cleanup():
            runtime.stop.set()
            self.stop.set()
            for gateway in runtime.lan_gateways.values():
                gateway.close()
            self.router.close()
            self.omr_peer.close()
            time.sleep(0.2)
            for p in patches:
                p.stop()
            directory.cleanup()
        self.addCleanup(cleanup)

    def ps5_sends(self, dst, sport, dport, data):
        self.console.write(eth(GW_MAC, PS_MAC, 0x0800, lan_udp(PS5, dst, sport, dport, data)))

    def console_frame(self, tail, timeout=4.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                frame = self.console.inbox.get(timeout=0.1)
            except queue.Empty:
                continue
            if frame[12:14] == b"\x08\x00" and frame.rstrip(b"\0").endswith(tail):
                return frame
        return None

    def test_gameplay_rides_the_gamebond_tunnel_and_bulk_rides_omr_through_the_nat(self):
        # Gameplay (UDP 3075 -> DSCP 46): GameBond tunnel, original tunnel address, nothing on the OMR leg.
        self.ps5_sends("203.0.113.9", 3075, 3075, b"game-tick")
        arrived = self.tun.injected.get(timeout=4)
        self.assertEqual((arrived[12:16], arrived[1] >> 2), (bytes([10, 70, 0, 3]), 46))
        self.assertTrue(arrived.endswith(b"game-tick"))
        self.assertTrue(self.omr_peer.inbox.empty())
        # Bulk: OMR leg, source rewritten to the OMR tunnel address, valid checksums, nothing on the GameBond leg.
        self.ps5_sends("198.51.100.5", 40000, 443, b"bulk-data")
        packet = self.omr_peer.inbox.get(timeout=4)
        src, dst, seg = verify(packet)
        self.assertEqual((src, dst), (OMR_ADDR, "198.51.100.5"))
        self.assertTrue(seg.endswith(b"bulk-data"))
        with self.assertRaises(queue.Empty):
            self.tun.injected.get(timeout=0.3)
        # Returns: OMR reply is un-NATed and framed for the PS5; the GameBond reply goes straight to it.
        ext_port = struct.unpack_from("!H", packet, 20)[0]
        self.assertTrue(wait_for(lambda: self.omr_peer.send(ipv4("198.51.100.5", OMR_ADDR, sport=443, dport=ext_port, payload=b"bulk-reply"))))
        frame = self.console_frame(b"bulk-reply")
        self.assertIsNotNone(frame)
        self.assertEqual(verify(frame[14:14 + struct.unpack_from("!H", frame, 16)[0]])[1], PS5)
        self.tun.capture.put(ipv4("203.0.113.9", PS5, sport=3075, dport=3075, payload=b"game-reply"))
        self.assertIsNotNone(self.console_frame(b"game-reply"))
        self.assertEqual(self.to_pc_stack, [])

    def test_the_workstations_own_bulk_traffic_also_uses_omr_and_returns_to_its_stack(self):
        self.runtime.send_outbound(valid_udp(PC, "198.51.100.8", 50000, 443, b"pc-bulk"))
        packet = self.omr_peer.inbox.get(timeout=4)
        self.assertEqual(verify(packet)[0], OMR_ADDR)
        ext_port = struct.unpack_from("!H", packet, 20)[0]
        self.assertTrue(wait_for(lambda: self.omr_peer.send(valid_udp("198.51.100.8", OMR_ADDR, 443, ext_port, b"pc-reply"))))
        self.assertTrue(wait_for(lambda: self.to_pc_stack))
        self.assertIn(b"pc-reply", self.to_pc_stack[0])
        self.assertEqual(struct.unpack_from("!H", self.to_pc_stack[0], 3 + 22)[0], 50000)     # port restored for the stack

    def test_bulk_falls_back_to_the_gamebond_tunnel_when_omr_dies_and_gameplay_is_unaffected(self):
        self.omr_peer.close()
        self.assertTrue(wait_for(lambda: not self.router.omr.ready, 6))
        self.ps5_sends("198.51.100.5", 40001, 443, b"bulk-after-omr-loss")
        arrived = self.tun.injected.get(timeout=4)
        self.assertEqual(arrived[12:16], bytes([10, 70, 0, 3]))                            # original address: the GameBond leg, no NAT
        self.assertTrue(arrived.endswith(b"bulk-after-omr-loss"))
        self.ps5_sends("203.0.113.9", 3075, 3075, b"game-after-omr-loss")
        self.assertTrue(self.tun.injected.get(timeout=4).endswith(b"game-after-omr-loss"))
        self.assertGreaterEqual(self.router.counts["fallbacks"], 1)


if __name__ == "__main__":
    unittest.main()
