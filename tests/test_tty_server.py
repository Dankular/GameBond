"""Real local TCP log relay tests; no TUN devices, routes or administrator calls."""
import io
import contextlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from gamebond.tty_server import LogRelay, Ring, attach, connect, ensure_server, read_metadata, control
from gamebond.windows_launcher import AsyncPublisher, Tee
from gamebond import windows_launcher


class RelayTests(unittest.TestCase):
    def relay(self, **kwargs):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        relay = LogRelay(Path(directory.name) / "relay.json", **kwargs).start()
        self.addCleanup(relay.close)
        return relay, read_metadata(relay.metadata)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 2
        while not predicate() and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertTrue(predicate())

    def test_authenticated_replay_tail_live_copy_and_nonadmin_ensure_reuse(self):
        relay, record = self.relay()
        self.assertEqual(ensure_server(relay.metadata)["port"], record["port"])
        with connect(record, "publish") as publisher:
            publisher.sendall(b"old\ncurrent\n")
            self.wait_for(lambda: relay.counts["published_bytes"] == 12)
            with connect(record, "attach", tail=1) as reader:
                self.assertEqual(reader.recv(4096), b"current\n")
                publisher.sendall(b"live\n")
                self.assertEqual(reader.recv(4096), b"live\n")
        output = io.BytesIO()
        attach(relay.metadata, tail=2, duration=.05, output=output)
        self.assertEqual(output.getvalue(), b"current\nlive\n")
        self.assertNotIn(record["token"].encode(), output.getvalue())

    def test_wrong_token_and_command_role_are_rejected_before_receiving_logs(self):
        relay, record = self.relay()
        with self.assertRaises((ConnectionError, OSError)):
            connect({**record, "token": "0" * 64}, "attach")
        with self.assertRaises((ConnectionError, OSError)):
            connect(record, "command")
        self.wait_for(lambda: relay.counts["auth_rejected"] == 2)

    def test_attachment_input_is_closed_and_never_reaches_publisher(self):
        relay, record = self.relay()
        with connect(record, "publish") as publisher, connect(record, "attach", tail=0) as reader:
            reader.sendall(b"stop gamebond\n")
            self.assertEqual(reader.recv(100), b"")
            self.wait_for(lambda: relay.counts["input_rejected"] == 1)
            publisher.settimeout(.05)
            with self.assertRaises(socket.timeout):
                publisher.recv(100)
            self.assertEqual(relay.ring.size, 0)

    def test_eight_attachments_are_supported_and_ninth_is_refused(self):
        relay, record = self.relay()
        readers = []
        try:
            for _ in range(8):
                readers.append(connect(record, "attach", tail=0))
            with self.assertRaises((ConnectionError, OSError)):
                connect(record, "attach", tail=0)
            self.assertEqual(sum(c["role"] == "attach" for c in relay.clients.values()), 8)
        finally:
            for reader in readers:
                reader.close()

    def test_reader_backpressure_disconnect_does_not_block_publisher_or_grow_ring(self):
        relay, record = self.relay(reader_limit=64, ring_limit=256)
        with connect(record, "attach", tail=0) as reader, connect(record, "publish") as publisher:
            publisher.sendall(b"x" * 4096)
            self.wait_for(lambda: relay.counts["slow_readers"] == 1)
            self.assertEqual(reader.recv(100), b"")
            publisher.sendall(b"still receiving\n")
            self.wait_for(lambda: relay.counts["published_bytes"] == 4112)
            self.assertLessEqual(relay.ring.size, 256)

    def test_console_tee_publishes_asynchronously_and_preserves_console(self):
        relay, record = self.relay()
        publisher = AsyncPublisher(record).start()
        self.addCleanup(publisher.close)
        console = io.StringIO()
        tee = Tee(console, publisher)
        self.assertEqual(tee.write("stats one\n"), 10)
        tee.flush()
        self.assertEqual(console.getvalue(), "stats one\n")
        self.wait_for(lambda: relay.counts["published_bytes"] == 10)
        with connect(record, "attach", tail=1) as reader:
            self.assertEqual(reader.recv(100), b"stats one\n")

    def test_full_publisher_queue_drops_without_waiting_for_network(self):
        publisher = AsyncPublisher({}, capacity=2)
        start = time.monotonic()
        for _ in range(10000):
            publisher.write("sample\n")
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(publisher.pending.qsize(), 2)
        self.assertEqual(publisher.dropped, 9998)

    def test_ring_is_bounded_even_for_a_single_oversized_write(self):
        ring = Ring(10)
        ring.append(b"first\n")
        ring.append(b"0123456789last\n")
        self.assertEqual(ring.size, 10)
        self.assertEqual(ring.tail(1), b"56789last\n")

    def test_launcher_cleanup_error_is_relayed_and_prevents_tunnel_start(self):
        relay, record = self.relay()
        console, errors = io.StringIO(), io.StringIO()
        with (patch.object(windows_launcher.app, "load_config", return_value={"bonding_mode": False}),
              patch.object(windows_launcher.app, "run") as run,
              patch.object(windows_launcher, "ensure_server", return_value=record),
              patch.object(windows_launcher, "cleanup_legacy", side_effect=RuntimeError("cleanup fixture failure")),
              patch.object(windows_launcher.sys, "argv", ["launcher", "--config", "client.json", "--key", "key", "--configure", "--once"]),
              patch.object(windows_launcher.sys, "stdin", io.StringIO()),
              contextlib.redirect_stdout(console), contextlib.redirect_stderr(errors)):
            self.assertEqual(windows_launcher.launch(), 1)
            run.assert_not_called()
        self.assertIn("cleanup fixture failure", errors.getvalue())
        self.wait_for(lambda: b"cleanup fixture failure" in relay.ring.tail(100))
        output = io.BytesIO()
        attach(relay.metadata, tail=100, duration=.05, output=output)
        self.assertIn(b"cleanup fixture failure", output.getvalue())
        self.assertNotIn(record["token"].encode(), output.getvalue())

    def test_stop_restart_are_cooperative_and_complete_after_cleanup_and_readiness(self):
        relay, record = self.relay()
        owner = windows_launcher.ControlOwner(record).start()
        events, failures, reload_after = [], [], []

        def fake_app(config, key, *, configure, stop_event, on_ready):
            number = sum(event.startswith("started") for event in events) + 1
            events.append(f"started{number}")
            on_ready()
            stop_event.wait(5)
            events.append(f"cleaned{number}")

        def run():
            try:
                windows_launcher.supervise({}, "fixed-key-path", False, owner,
                    reload_on_restart=True, config_path="fixed-config")
            except Exception as exc:
                failures.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        try:
            with (patch.object(windows_launcher.app, "run", side_effect=fake_app),
                  patch.object(windows_launcher.app, "load_config", return_value={}) as load,
                  patch.object(windows_launcher, "reload_runtime", side_effect=lambda: reload_after.append(events[-1]))):
                thread.start()
                self.wait_for(lambda: relay.owner_state == "running")
                transcript = io.StringIO()
                result = control("restart", relay.metadata, timeout=3, output=transcript)
                self.assertTrue(result["ok"])
                self.assertEqual(result["state"], "running")
                self.assertEqual(events[:3], ["started1", "cleaned1", "started2"])
                self.assertIn('"complete": false', transcript.getvalue())
                result = control("stop", relay.metadata, timeout=3, output=io.StringIO())
                self.assertTrue(result["ok"])
                self.assertEqual(result["state"], "stopped")
                self.assertEqual(events[-1], "cleaned2")
                self.assertTrue(thread.is_alive())
                status = control("status", relay.metadata, output=io.StringIO())
                self.assertEqual(status["state"], "stopped")
                self.assertIsInstance(status["owner_pid"], int)
                result = control("restart", relay.metadata, timeout=3, output=io.StringIO())
                self.assertTrue(result["ok"])
                self.assertEqual(result["state"], "running")
                self.assertEqual(events[-1], "started3")
                control("stop", relay.metadata, timeout=3, output=io.StringIO())
                self.assertEqual(events[-1], "cleaned3")
                self.assertFalse(failures)
                self.assertEqual(reload_after, ["cleaned1", "cleaned2"])
                self.assertEqual(load.call_count, 3)
        finally:
            owner.close()
            thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_control_without_owner_fails_and_arbitrary_commands_are_rejected(self):
        relay, _ = self.relay()
        result = control("stop", relay.metadata, output=io.StringIO())
        self.assertFalse(result["ok"])
        self.assertTrue(result["complete"])
        with self.assertRaises(ValueError):
            control("powershell.exe", relay.metadata)

    def test_initially_stopped_supervisor_waits_for_authenticated_restart(self):
        relay, record = self.relay()
        owner = windows_launcher.ControlOwner(record).start()
        cleaned = threading.Event()

        def fake_app(config, key, *, configure, stop_event, on_ready):
            on_ready()
            stop_event.wait(5)
            cleaned.set()

        with patch.object(windows_launcher.app, "run", side_effect=fake_app) as run:
            thread = threading.Thread(target=windows_launcher.supervise,
                args=({}, "fixed-key", False, owner), kwargs={"initially_stopped": True}, daemon=True)
            try:
                thread.start()
                self.wait_for(lambda: relay.owner_state == "stopped")
                result = control("status", relay.metadata, output=io.StringIO())
                self.assertEqual(result["state"], "stopped")
                run.assert_not_called()
                self.assertFalse(cleaned.is_set())
                result = control("restart", relay.metadata, timeout=3, output=io.StringIO())
                self.assertEqual(result["state"], "running")
                self.assertTrue(result["ok"])
                run.assert_called_once()
                result = control("stop", relay.metadata, timeout=3, output=io.StringIO())
                self.assertEqual(result["state"], "stopped")
                self.assertTrue(cleaned.is_set())
                self.assertTrue(thread.is_alive())
            finally:
                owner.close()
                thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_second_owner_is_refused_before_a_second_app_can_start(self):
        relay, record = self.relay()
        owner = windows_launcher.ControlOwner(record).start()
        self.addCleanup(owner.close)
        rejected = windows_launcher.ControlOwner(record)
        with self.assertRaisesRegex(RuntimeError, "exclusive control owner slot"):
            rejected.start(timeout=.1)
        self.assertFalse(rejected.registered.is_set())
        with (patch.object(windows_launcher.app, "load_config", return_value={}),
              patch.object(windows_launcher.app, "run") as run,
              patch.object(windows_launcher, "ensure_server", return_value=record),
              patch.object(windows_launcher, "ControlOwner", return_value=rejected),
              patch.object(rejected, "start", side_effect=RuntimeError("owner slot denied")),
              patch.object(windows_launcher.sys, "argv", ["launcher", "--config", "c", "--key", "k", "--once"]),
              patch.object(windows_launcher.sys, "stdin", io.StringIO()),
              contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
            self.assertEqual(windows_launcher.launch(), 1)
            run.assert_not_called()
        self.wait_for(lambda: b"owner slot denied" in relay.ring.tail(100))


if __name__ == "__main__":
    unittest.main()
