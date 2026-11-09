import contextlib
import io
import tempfile
import time
import unittest
from pathlib import Path

try:
    import nacl  # noqa: F401
except ImportError:
    raise unittest.SkipTest("PyNaCl not installed (pip install 'gamebond[omr]')")

from gamebond.omr_admin import learn_pin
from gamebond.omr_settings import OmrSettings
from gamebond.transport_router import TransportRouter
from mud_peer import MudPeer
from test_omr_admin import FakeOmrAdmin, KEY_HEX
from test_omr_glorytun import wait_for
from test_lan_runtime import make_runtime
from test_transport_router import FakeGameBond

PASSWORD = "s3cret"


class OmrRuntimeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)
        quiet = contextlib.redirect_stdout(io.StringIO())
        self.output = quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        self.admin = FakeOmrAdmin(self.dir)
        self.addCleanup(self.admin.close)
        self.peer = MudPeer(bytes.fromhex(KEY_HEX))
        self.addCleanup(self.peer.close)
        (self.dir / "pass.txt").write_text(PASSWORD + "\n")                       # a trailing newline must not matter
        self.pin = learn_pin("127.0.0.1", self.admin.port)

    def runtime(self, *, pin=None, password_file="pass.txt", tunnel_ip=None, username="openmptcprouter"):
        # Built directly: the production validator (rightly) refuses loopback servers, which these tests use.
        settings = OmrSettings(server=self.peer.address, admin=dict(host="127.0.0.1", port=self.admin.port, username=username,
                                                                    password_file=str(self.dir / password_file), pin=pin or self.pin),
                               tunnel_ip=tunnel_ip or "10.255.254.2", tunnel_ip_set=bool(tunnel_ip), beat_ms=20)
        runtime = make_runtime(bind=[["127.0.0.1", 0]], interface_indices=[7], path_availability=[True])
        runtime.server_type, runtime.omr_settings = "both", settings
        runtime.omr_error, runtime.omr_retry_at, runtime.omr_blocked = None, 0, False
        runtime.node = FakeGameBond()
        self.addCleanup(lambda: runtime.node.close() if isinstance(runtime.node, TransportRouter) else None)
        return runtime

    def test_key_and_tunnel_address_come_from_the_admin_api_and_the_leg_comes_up(self):
        runtime = self.runtime()
        runtime.maintain_omr()
        self.assertIsInstance(runtime.node, TransportRouter)
        self.assertEqual(runtime.node.nat.external.hex(), "0afffe02")            # 10.255.254.2 from /config
        self.assertTrue(wait_for(lambda: runtime.node.omr.ready), runtime.node.omr.stats())
        self.assertEqual(runtime.omr_status(), dict(mode="both", active=True, error=None, blocked=False))
        self.assertEqual(self.admin.logins, [("openmptcprouter", PASSWORD)])
        self.assertTrue(runtime.node.omr.paths[0].index in (None, 7))             # pinning only on Windows

    def test_the_servers_tunnel_address_is_used_unless_the_user_fixed_one(self):
        self.admin.config = {"glorytun": {"key": KEY_HEX, "udp": {"client_ip": "10.255.254.9"}, "chacha": True}}
        first = self.runtime()
        first.maintain_omr()
        self.assertEqual(first.node.nat.external.hex(), "0afffe09")
        second = self.runtime(tunnel_ip="10.255.254.77")
        second.maintain_omr()
        self.assertEqual(second.node.nat.external.hex(), "0afffe4d")

    def test_a_refused_login_is_attempted_once_and_never_retried(self):
        runtime = self.runtime(username="wrong")
        runtime.maintain_omr()
        self.assertFalse(isinstance(runtime.node, TransportRouter))
        self.assertTrue(runtime.omr_status()["blocked"])
        self.assertIn("Not retrying", runtime.omr_error)
        runtime.omr_retry_at = 0
        runtime.maintain_omr()
        runtime.omr_retry_at = 0
        runtime.maintain_omr()
        self.assertEqual(len(self.admin.logins), 1)                                # the server bans an address after six failures

    def test_a_wrong_certificate_pin_fails_safely_without_sending_credentials_and_retries_later(self):
        runtime = self.runtime(pin="A" * 43 + "=")
        runtime.maintain_omr()
        self.assertFalse(isinstance(runtime.node, TransportRouter))
        self.assertIn("does not match the pin", runtime.omr_error)
        self.assertFalse(runtime.omr_status()["blocked"])
        self.assertEqual(self.admin.logins, [])
        before = runtime.omr_retry_at
        runtime.maintain_omr()                                                      # inside the 30 s window: nothing happens
        self.assertEqual(runtime.omr_retry_at, before)

    def test_an_unreachable_admin_api_never_stops_the_main_tunnel_and_recovers_when_it_returns(self):
        runtime = self.runtime()
        original = runtime.node
        self.admin.close()
        runtime.maintain_omr()
        self.assertIs(runtime.node, original)                                       # still the plain GameBond node
        self.assertTrue(runtime.omr_error)
        self.assertFalse(runtime.omr_status()["active"])
        self.assertFalse(runtime.omr_status()["blocked"])

    def test_missing_password_file_is_reported_not_raised(self):
        runtime = self.runtime(password_file="absent.txt")
        runtime.maintain_omr()
        self.assertIn("absent.txt", runtime.omr_error)
        self.assertEqual(self.admin.logins, [])

    def test_plain_gamebond_mode_does_nothing(self):
        runtime = make_runtime()
        runtime.server_type, runtime.omr_error, runtime.omr_retry_at, runtime.omr_blocked = "gamebond", None, 0, False
        runtime.node = FakeGameBond()
        runtime.maintain_omr()
        self.assertIsNone(runtime.omr_status())


if __name__ == "__main__":
    unittest.main()
