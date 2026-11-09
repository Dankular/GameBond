"""Server accepts and routes back to configured LAN-device tunnel addresses only."""
import contextlib
import io
import json
import queue
import secrets
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from gamebond import app
from gamebond.transport import Node
from test_app import FakeTun, base_config, ipv4


class ServerLanAddressTests(unittest.TestCase):
    def run_server(self, lan_ips):
        key, session = secrets.token_bytes(32), secrets.token_bytes(16)
        tun, nodes, stop = FakeTun(), [], threading.Event()
        config = base_config()
        config.pop("interface_indices")
        config.update(role="server", bind=[["127.0.0.1", 0]], session=session.hex(), lan_tunnel_ips=lan_ips)
        config.pop("peer")

        def factory(*args, **kwargs):
            node = Node(*args, **kwargs)
            nodes.append(node)
            return node

        signals = types.SimpleNamespace(SIGINT=2, SIGTERM=15, signal=lambda *_: None)
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "key.bin"
        path.write_bytes(key)
        patches = [patch.object(app, "open_tun", return_value=tun), patch.object(app, "Node", side_effect=factory),
                   patch.object(app, "signal", signals)]
        for p in patches:
            p.start()
        def invoke():
            with contextlib.redirect_stdout(io.StringIO()):
                app.run(config, path, stop_event=stop)

        thread = threading.Thread(target=invoke, daemon=True)
        thread.start()
        deadline = time.monotonic() + 3
        while not nodes and time.monotonic() < deadline:
            time.sleep(0.01)
        client = Node(key, "client", session, [("127.0.0.1", 0)], nodes[0].addresses[0]).start()
        deadline = time.monotonic() + 3
        while not (client.stats()["paths"] and client.stats()["paths"][0]["healthy"]) and time.monotonic() < deadline:
            time.sleep(0.02)

        def cleanup():
            stop.set()
            thread.join(3)
            client.close()
            for p in patches:
                p.stop()
            directory.cleanup()
        self.addCleanup(cleanup)
        return tun, client

    def test_configured_device_address_passes_both_directions_and_others_do_not(self):
        tun, client = self.run_server(["10.70.0.3"])
        for source in ("10.70.0.2", "10.70.0.3"):
            packet = ipv4(source, "198.51.100.1")
            client.send(packet)
            self.assertEqual(tun.injected.get(timeout=2), packet)
        client.send(ipv4("10.70.0.9", "198.51.100.1"))
        with self.assertRaises(queue.Empty):
            tun.injected.get(timeout=0.2)
        for destination in ("10.70.0.2", "10.70.0.3"):
            reply = ipv4("198.51.100.1", destination, sport=53, dport=4000)
            tun.capture.put(reply)
            self.assertEqual(client.recv(2), reply)
        tun.capture.put(ipv4("198.51.100.1", "10.70.0.9"))
        with self.assertRaises(queue.Empty):
            client.recv(0.2)

    def test_without_lan_addresses_only_the_single_client_is_allowed(self):
        tun, client = self.run_server([])
        client.send(ipv4("10.70.0.3", "198.51.100.1"))
        with self.assertRaises(queue.Empty):
            tun.injected.get(timeout=0.2)


class ConfigIntegrationTests(unittest.TestCase):
    def load(self, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "c.json"
            path.write_text(json.dumps(config))
            with patch.object(app, "os", types.SimpleNamespace(name="nt")):
                return app.load_config(path)

    def test_client_lan_devices_validated_and_rejected_by_legacy_runner(self):
        config = base_config()
        config["lan_devices"] = [dict(name="PS5", tunnel_ip="10.70.0.3", interface_id="{AAAAAAAA-1111-1111-1111-000000000009}")]
        self.load(config)
        with self.assertRaisesRegex(ValueError, "userspace runtime"):
            app.run(config, "unused")
        config["lan_devices"][0]["tunnel_ip"] = "10.70.0.2"
        with self.assertRaises(ValueError):
            self.load(config)

    def test_roles_cannot_swap_lan_settings(self):
        config = base_config()
        config["lan_tunnel_ips"] = ["10.70.0.3"]
        with self.assertRaisesRegex(ValueError, "server configuration"):
            self.load(config)


if __name__ == "__main__":
    unittest.main()
