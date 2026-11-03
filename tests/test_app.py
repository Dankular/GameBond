"""Configuration checks and a packet-only runtime test; no routes or drivers."""
import contextlib
import copy
import io
import json
from pathlib import Path
import queue
import secrets
import struct
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
from unittest.mock import Mock

from gamebond import app
from gamebond.transport import Node


def base_config():
    return {
        "role": "client", "bind": [["192.168.8.2", 0], ["192.168.9.2", 0]],
        "interface_indices": [12, 18], "peer": ["203.0.113.10", 4433],
        "session": "12" * 16, "client_tunnel_ip": "10.70.0.2", "mtu": 1280,
        "queues": {"46": {"priority": True, "replicate": True,
                            "max_age_ms": 20, "capacity": 64,
                            "retransmissions": 0}},
    }


class ConfigTests(unittest.TestCase):
    def validate(self, config, platform="nt"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            # Replace only app's os reference, leaving pathlib's host OS intact.
            with patch.object(app, "os", types.SimpleNamespace(name=platform)):
                return app.load_config(path)

    def test_valid_windows_client_and_linux_client(self):
        config = base_config()
        self.assertEqual(self.validate(config)["bind"], config["bind"])
        config.pop("interface_indices")
        self.assertEqual(self.validate(config, "posix")["role"], "client")

    def test_windows_requires_distinct_positive_interface_indices(self):
        for indices in (None, [], [12], [12, 12], [0, 12], [-1, 12], ["12", 18]):
            with self.subTest(indices=indices):
                config = base_config()
                if indices is None:
                    config.pop("interface_indices")
                else:
                    config["interface_indices"] = indices
                with self.assertRaises(ValueError):
                    self.validate(config)

    def test_client_requires_two_distinct_usable_ipv4_paths(self):
        for paths in (("192.168.8.2",), ("192.168.8.2", "192.168.8.2"),
                      ("0.0.0.0", "192.168.8.2"), ("127.0.0.1", "192.168.8.2"),
                      ("169.254.2.3", "192.168.8.2"), ("::1", "192.168.8.2")):
            with self.subTest(paths=paths):
                config = base_config()
                config["bind"] = [[host, 0] for host in paths]
                with self.assertRaises(ValueError):
                    self.validate(config, "posix")

    def test_server_does_not_need_client_physical_interfaces(self):
        config = base_config()
        config.update(role="server", bind=[["0.0.0.0", 4433]])
        config.pop("peer")
        config.pop("interface_indices")
        self.assertEqual(self.validate(config)["role"], "server")

    def test_rejects_unsupported_retransmissions(self):
        config = base_config()
        config["queues"]["46"]["retransmissions"] = 2
        with self.assertRaisesRegex(ValueError, "retransmission"):
            self.validate(config)

    def test_bonding_is_opt_in_and_requires_selective_replication(self):
        config = base_config()
        self.assertFalse(self.validate(config).get("bonding_mode", False))
        config["bonding_mode"] = True
        with self.assertRaisesRegex(ValueError, "redundant_mode=false"):
            self.validate(config)
        config["redundant_mode"] = False
        self.assertTrue(self.validate(config)["bonding_mode"])
        config["redundant_mode"] = True
        with self.assertRaisesRegex(ValueError, "redundant_mode=false"):
            self.validate(config)

    def test_configured_game_ports_cannot_silently_use_bulk_or_single_copy(self):
        for change in ({"priority": False}, {"replicate": False}):
            config = base_config()
            config["game_udp_ports"] = [3075]
            config["queues"]["46"].update(change)
            with self.assertRaisesRegex(ValueError, "priority, replicated"):
                self.validate(config)
        config = base_config()
        config.update(game_udp_ports=[3075], direct_priority=False)
        with self.assertRaisesRegex(ValueError, "direct_priority"):
            self.validate(config)

    def test_bonding_rates_and_reordering_reject_nonfinite_or_ambiguous_values(self):
        changes = (
            {"bonding_mode": 1}, {"bonding_mode": "true"},
            {"bonding_initial_rate_mbps": 0}, {"bonding_initial_rate_mbps": -1},
            {"bonding_initial_rate_mbps": True}, {"bonding_initial_rate_mbps": float("nan")},
            {"bonding_max_rate_mbps": 0}, {"bonding_max_rate_mbps": float("inf")},
            {"bonding_max_rate_mbps": "100"},
            {"bonding_initial_rate_mbps": 5, "bonding_max_rate_mbps": 4},
            {"reorder_timeout_ms": 0}, {"reorder_timeout_ms": 201},
            {"reorder_timeout_ms": float("nan")}, {"reorder_timeout_ms": True},
        )
        for change in changes:
            with self.subTest(change=change):
                config = base_config()
                config.update(change)
                with self.assertRaises(ValueError):
                    self.validate(config)
        for timeout in (1, 30, 200):
            config = base_config()
            config.update(bonding_mode=True, redundant_mode=False, reorder_timeout_ms=timeout,
                          bonding_initial_rate_mbps=.5, bonding_max_rate_mbps=.5)
            self.assertEqual(self.validate(config)["reorder_timeout_ms"], timeout)

    def test_role_endpoint_ports_mtu_and_session_constraints(self):
        changes = (
            {"role": "unknown"}, {"peer": ["vps.example", 4433]},
            {"peer": ["203.0.113.10", 0]}, {"peer": ["203.0.113.10", 65536]},
            {"bind": [["192.168.8.2", -1], ["192.168.9.2", 0]]},
            {"mtu": 1279}, {"mtu": 1401}, {"mtu": "1280"},
            {"session": "12" * 15}, {"session": "not-hex"},
            {"client_tunnel_ip": "::1"},
        )
        for change in changes:
            with self.subTest(change=change):
                config = base_config()
                config.update(copy.deepcopy(change))
                with self.assertRaises(ValueError):
                    self.validate(config)

    def test_dns_is_client_only_and_uses_its_own_tunnel_address(self):
        config = base_config()
        config['client_tunnel_ip'] = '10.77.0.2'
        config['dns'] = {'records': {'private.example': {'A': ['127.0.0.1']}}}
        self.assertIn('dns', self.validate(config))
        config['client_tunnel_ip'] = '10.70.0.2'
        with self.assertRaisesRegex(ValueError, 'own tunnel'):
            self.validate(config)
        config.update(role='server', bind=[['0.0.0.0', 4433]])
        with self.assertRaisesRegex(ValueError, 'client configuration'):
            self.validate(config)


def ipv4(source, destination, *, dscp=0, sport=3000, dport=4000, payload=b"test"):
    import ipaddress
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + len(udp),
                       0, 0, 64, 17, 0, ipaddress.IPv4Address(source).packed,
                       ipaddress.IPv4Address(destination).packed) + udp


class FakeTun:
    name = "test-packet-device"

    def __init__(self):
        self.capture = queue.Queue()
        self.injected = queue.Queue()
        self.closed = False

    def read(self, timeout):
        try:
            item = self.capture.get(timeout=timeout)
        except queue.Empty:
            return None
        if isinstance(item, Exception):
            raise item
        return item

    def write(self, packet):
        self.injected.put(bytes(packet))

    def close(self):
        self.closed = True


class RuntimeTests(unittest.TestCase):
    def test_external_stop_during_path_startup_cleans_up_without_timeout_error(self):
        stop, tun = threading.Event(), FakeTun()
        node, network, ready = Mock(), Mock(), Mock()
        node.start.side_effect = stop.set
        node.stats.return_value = {"paths": []}
        config = base_config()
        signals = types.SimpleNamespace(SIGINT=2, SIGTERM=15, signal=lambda *_: None)
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.bin"
            key.write_bytes(secrets.token_bytes(32))
            with (patch.object(app, "os", types.SimpleNamespace(name="nt")),
                  patch.object(app, "open_tun", return_value=tun),
                  patch.object(app, "Node", return_value=node),
                  patch.object(app, "signal", signals),
                  patch("gamebond.windows_network.WindowsNetwork", return_value=network),
                  patch("gamebond.windows_dns.recover_journals"),
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertIsNone(app.run(config, key, configure=True, stop_event=stop, on_ready=ready))
        network.prepare.assert_called_once()
        network.activate.assert_not_called()
        network.close.assert_called_once()
        node.close.assert_called_once()
        ready.assert_not_called()
        self.assertTrue(tun.closed)

    def test_fake_tun_round_trip_real_loopback_transport_and_spoof_rejection(self):
        self.round_trip(bonding=False)

    def test_bonded_fake_tun_round_trip_keeps_gameplay_redundant_and_carries_full_mtu_bulk(self):
        self.round_trip(bonding=True)

    def round_trip(self, *, bonding):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        wire_mtu = 1280 + app.OVERHEAD + (app.BOND_OVERHEAD if bonding else 0)
        server = Node(key, "server", session, [("127.0.0.1", 0)],
                      mtu=wire_mtu, bonding_mode=bonding).start()
        tun = FakeTun()
        failures, nodes = [], []
        config = base_config()
        # Loopback is a test harness only: production load_config rejects it.
        config.update(bind=[["127.0.0.1", 0], ["127.0.0.1", 0]],
                      peer=list(server.addresses[0]), session=session.hex())
        if bonding:
            config.update(bonding_mode=True, redundant_mode=False)
        config.pop("interface_indices")

        def factory(*args, **kwargs):
            # OS interface pinning is deliberately outside this loopback test.
            kwargs.pop("interface_indices", None)
            node = Node(*args, **kwargs)
            nodes.append(node)
            return node

        def invoke(path):
            try:
                app.run(config, path)
            except Exception as exc:
                failures.append(exc)

        signals = types.SimpleNamespace(SIGINT=2, SIGTERM=15, signal=lambda *_: None)
        thread = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "key.bin"
                path.write_bytes(key)
                with (patch.object(app, "open_tun", return_value=tun),
                      patch.object(app, "Node", side_effect=factory),
                      patch.object(app, "signal", signals),
                      contextlib.redirect_stdout(io.StringIO())):
                    thread = threading.Thread(target=invoke, args=(path,), daemon=True)
                    thread.start()
                    deadline = time.monotonic() + 3
                    while len(server.stats()["paths"]) < 2 and time.monotonic() < deadline:
                        if failures:
                            raise failures[0]
                        time.sleep(.01)
                    self.assertEqual(len(server.stats()["paths"]), 2)
                    outgoing = ipv4("10.70.0.2", "198.51.100.1", dscp=46)
                    tun.capture.put(outgoing)
                    self.assertEqual(server.recv(1), outgoing)
                    with self.assertRaises(queue.Empty):
                        server.recv(.05)
                    reply = ipv4("198.51.100.1", "10.70.0.2", sport=4000, dport=3000)
                    server.send(reply)
                    self.assertEqual(tun.injected.get(timeout=1), reply)
                    with self.assertRaises(queue.Empty):
                        tun.injected.get(timeout=.05)
                    if bonding:
                        bulk = ipv4("10.70.0.2", "198.51.100.2", sport=5000, dport=6000,
                                    payload=b"x" * 1252)
                        tun.capture.put(bulk)
                        self.assertEqual(server.recv(1), bulk)
                        bulk_reply = ipv4("198.51.100.2", "10.70.0.2", sport=6000, dport=5000,
                                          payload=b"y" * 1252)
                        server.send(bulk_reply, replicate=False, flow_id=("bulk-response",))
                        self.assertEqual(tun.injected.get(timeout=1), bulk_reply)
                        self.assertTrue(nodes[0].stats()["bonding_mode"])
                    # Authenticated does not mean the inner destination is allowed.
                    server.send(ipv4("198.51.100.1", "10.70.0.3"))
                    with self.assertRaises(queue.Empty):
                        tun.injected.get(timeout=.1)
                    # Local TUN source spoofing also must not enter the transport.
                    tun.capture.put(ipv4("10.70.0.3", "198.51.100.1"))
                    with self.assertRaises(queue.Empty):
                        server.recv(.1)
                    tun.capture.put(OSError("intentional fake TUN shutdown"))
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
            self.assertTrue(tun.closed)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], RuntimeError)
            self.assertIsInstance(failures[0].__cause__, OSError)
        finally:
            if thread is not None and thread.is_alive():
                tun.capture.put(OSError("cleanup"))
                thread.join(3)
            for node in nodes:
                node.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
