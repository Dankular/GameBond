import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import nacl  # noqa: F401
except ImportError:
    raise unittest.SkipTest("PyNaCl not installed (pip install 'gamebond[omr]')")

from PyQt5.QtWidgets import QApplication

from gamebond.glass_settings import OmrDialog, omr_status_text
from gamebond.omr_admin import learn_pin
from test_omr_admin import FakeOmrAdmin

PIN = "A" * 43 + "="


def base_config(**extra):
    return dict(role="client", client_tunnel_ip="10.77.0.2", interface_names=["Starlink", "5G"], **extra)


class OmrDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)
        self.path = self.dir / "client.json"
        self.write(base_config())

    def write(self, config):
        self.path.write_text(json.dumps(config))

    def dialog(self, runtime=None):
        with patch("gamebond.glass_settings.CONFIG", self.path):
            dialog = OmrDialog(runtime)
        self.addCleanup(lambda: (dialog.reject(), dialog.deleteLater(), self.app.processEvents()))
        return dialog

    def save(self, dialog):
        saver = lambda server_type, omr: __import__("gamebond.widget_data", fromlist=["x"]).save_omr_settings(server_type, omr, self.path)
        password = lambda text, path=None: str(self.dir / "omr.pass") if (self.dir / "omr.pass").write_text(text.strip() + "\n") else ""
        with patch("gamebond.glass_settings.save_omr_settings", saver), patch("gamebond.glass_settings.write_omr_password", password):
            return dialog.write_config()

    def wait(self, condition, seconds=5):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if condition():
                return True
            time.sleep(0.01)
        return False

    def test_defaults_show_gamebond_only_with_the_omr_fields_disabled(self):
        dialog = self.dialog()
        self.assertEqual(dialog.mode.currentIndex(), 0)
        self.assertFalse(dialog.server.isEnabled())
        dialog.mode.setCurrentIndex(1)
        self.assertTrue(dialog.server.isEnabled() and dialog.pin.isEnabled())
        dialog.use_key.setChecked(True)
        self.assertTrue(dialog.key_file.isEnabled())
        self.assertFalse(dialog.pin.isEnabled() or dialog.password.isEnabled())

    def test_saving_admin_login_stores_the_password_in_a_file_and_never_in_the_config(self):
        dialog = self.dialog()
        dialog.mode.setCurrentIndex(1)
        dialog.server.setText("203.0.113.10")
        dialog.username.setText("openmptcprouter")
        dialog.password.setText("hunter2")
        dialog.pin.setText("sha256//" + PIN)
        config = self.save(dialog)
        self.assertEqual(config["server_type"], "both")
        self.assertEqual(config["omr"]["server"], ["203.0.113.10", 65001])
        self.assertEqual(config["omr"]["admin"]["pin"], "sha256//" + PIN)
        self.assertEqual((self.dir / "omr.pass").read_text().strip(), "hunter2")
        self.assertNotIn("hunter2", self.path.read_text())
        # Reopening keeps the stored login and shows that a password is already saved.
        again = self.dialog()
        self.assertEqual((again.mode.currentIndex(), again.server.text(), again.username.text()), (1, "203.0.113.10", "openmptcprouter"))
        self.assertIn("saved", again.password.placeholderText())

    def test_saving_with_a_key_file_and_custom_classes(self):
        dialog = self.dialog()
        dialog.mode.setCurrentIndex(1)
        dialog.use_key.setChecked(True)
        dialog.server.setText("203.0.113.10")
        dialog.key_file.setText("secrets/glorytun.key")
        dialog.dscp.setText("46; 34")
        dialog.tunnel_ip.setText("10.255.254.9")
        config = self.save(dialog)
        self.assertEqual((config["omr"]["key_file"], config["omr"]["gamebond_dscp"], config["omr"]["tunnel_ip"]),
                         ("secrets/glorytun.key", [46, 34], "10.255.254.9"))

    def test_switching_back_to_gamebond_only_keeps_the_settings_as_a_draft(self):
        dialog = self.dialog()
        dialog.mode.setCurrentIndex(1)
        dialog.use_key.setChecked(True)
        dialog.server.setText("203.0.113.10")
        dialog.key_file.setText("k.key")
        self.save(dialog)
        off = self.dialog()
        off.mode.setCurrentIndex(0)
        config = self.save(off)
        self.assertEqual(config["server_type"], "gamebond")
        self.assertNotIn("omr", config)
        self.assertEqual(config["omr_draft"]["server"], ["203.0.113.10", 65001])
        back = self.dialog()                                                      # the draft refills the form
        self.assertEqual(back.server.text(), "203.0.113.10")

    def test_invalid_input_is_reported_and_nothing_is_written(self):
        dialog = self.dialog()
        dialog.mode.setCurrentIndex(1)
        dialog.use_key.setChecked(True)
        dialog.server.setText("not-an-address")
        dialog.key_file.setText("k.key")
        before = self.path.read_text()
        with self.assertRaises(ValueError):
            self.save(dialog)
        self.assertEqual(self.path.read_text(), before)
        dialog.server.setText("203.0.113.10")
        dialog.dscp.setText("46, abc")
        with self.assertRaisesRegex(ValueError, "numbers"):
            self.save(dialog)

    def test_pin_is_read_from_the_server_and_only_adopted_after_confirmation(self):
        server = FakeOmrAdmin(self.dir)
        self.addCleanup(server.close)
        dialog = self.dialog()
        dialog.mode.setCurrentIndex(1)
        dialog.server.setText("127.0.0.1")
        dialog.admin_port.setValue(server.port)
        with patch.object(dialog, "confirm_pin", return_value=False):
            dialog.learn_pin()
            self.assertTrue(self.wait(lambda: "not accepted" in dialog.feedback.text()))
        self.assertEqual(dialog.pin.text(), "")
        with patch.object(dialog, "confirm_pin", return_value=True):
            dialog.learn_pin()
            self.assertTrue(self.wait(lambda: dialog.pin.text() != ""))
        self.assertEqual(dialog.pin.text(), learn_pin("127.0.0.1", server.port))
        self.assertEqual(server.requests, [])                                      # no HTTP data was sent while learning

    def test_login_test_reports_success_without_revealing_the_key_and_failure_clearly(self):
        server = FakeOmrAdmin(self.dir)
        self.addCleanup(server.close)
        dialog = self.dialog()
        dialog.mode.setCurrentIndex(1)
        dialog.server.setText("127.0.0.1")
        dialog.admin_port.setValue(server.port)
        dialog.pin.setText(learn_pin("127.0.0.1", server.port))
        dialog.password.setText("s3cret")
        dialog.test_login()
        self.assertTrue(self.wait(lambda: "Login works" in dialog.feedback.text()), dialog.feedback.text())
        self.assertIn("10.255.254.2", dialog.feedback.text())
        self.assertNotIn("ABAB", dialog.feedback.text())
        dialog.password.setText("wrong")
        dialog.test_login()
        self.assertTrue(self.wait(lambda: "refused" in dialog.feedback.text()), dialog.feedback.text())
        dialog.pin.setText("")
        dialog.test_login()
        self.assertIn("pin", dialog.feedback.text())

    def test_status_text_for_every_state(self):
        self.assertIn("not running", omr_status_text(None))
        self.assertIn("GameBond only", omr_status_text(dict(omr=None)))
        down = omr_status_text(dict(omr=dict(active=False, error="cannot read the server certificate", blocked=False),
                                    transport=dict(paths=[dict(healthy=True), dict(healthy=False)])))
        self.assertIn("1 of 2 links healthy", down)
        self.assertIn("cannot read the server certificate", down)
        self.assertIn("retrying every 30 seconds", down)
        self.assertIn("will not be retried", omr_status_text(dict(omr=dict(active=False, error="refused", blocked=True), transport={})))
        up = omr_status_text(dict(omr=dict(active=True, error=None, blocked=False), transport=dict(
            paths=[dict(healthy=True)], router=dict(sent_gamebond=5, sent_omr=90, fallbacks=1, nat=dict(active=4)),
            omr=dict(ready=True, tunnel_mtu=1450, paths=[
                dict(slot=0, enabled=True, status=6, rtt_ms=31.2, jitter_ms=2.14, role="primary", demoted=False, bad=False, reason=""),
                dict(slot=1, enabled=True, status=5, rtt_ms=80.0, jitter_ms=20.0, role="primary", demoted=True, bad=True, reason="jitter"),
                dict(slot=2, enabled=False, reason="adapter unavailable")]))), names=["Starlink", "5G"])
        for text in ("ready, MTU 1450", "Starlink: active, RTT 31 ms", "5G: standby", "demoted, server steered away", "Link 3: off (adapter unavailable)",
                     "5 packets via GameBond, 90 via OMR, 1 fallbacks; 4 NAT mappings"):
            self.assertIn(text, up)


if __name__ == "__main__":
    unittest.main()
