"""Mock PowerShell responses only: these tests never execute a network cmdlet."""
import copy
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pathlib import Path
from gamebond.windows_network import (WindowsNetwork, WindowsNetworkError, _POWERSHELL,
                                      cleanup_journal, recover_journals)


def config():
    return {"role": "client", "bind": [["192.168.8.2", 0], ["192.168.9.2", 0]],
            "interface_indices": [12, 18], "gateways": ["192.168.8.1", "192.168.9.1"],
            "peer": ["203.0.113.10", 4433], "client_tunnel_ip": "10.77.0.2",
            "tun_name": "GameBond", "mtu": 1280}


class Transcript:
    """Retain server-side identities and simulate operational failures."""

    def __init__(self, fail_phase=None, cleanup_failure=False):
        self.fail_phase = fail_phase
        self.cleanup_failure = cleanup_failure
        self.requests = []
        self.state = None

    def __call__(self, command, **kwargs):
        request = json.loads(kwargs["input"])
        self.requests.append((command, kwargs, request))
        phase = request["phase"]
        if phase == "preflight":
            self.state = {"tun_index": 42, "tun_guid": "owned-adapter-guid",
                          "old_mtu": 1500, "config": request["config"],
                          "routes": [{"prefix": request["config"]["peer"][0] + "/32",
                                      "metric": request["metric"], "added": False}],
                          "qos": request["qos"], "address_added": False}
        else:
            # The next phase must carry exactly the last returned identities.
            if request["state"] != self.state:
                raise AssertionError("caller lost ownership state between phases")
        if phase == "prepare":
            self.state["routes"][0]["added"] = True
            self.state["address_added"] = True
        if phase == self.fail_phase or (phase == "close" and self.cleanup_failure):
            response = {"ok": False, "state": self.state,
                        "error": "CIM provider refused operation", "rollback_errors": ["route still in use"]}
            return subprocess.CompletedProcess(command, 1, json.dumps(response), "")
        if phase == "close":
            self.state["routes"][0]["added"] = False
            self.state["address_added"] = False
        return subprocess.CompletedProcess(command, 0, json.dumps({"ok": True, "state": self.state}), "")


class WindowsNetworkTests(unittest.TestCase):
    def helper(self, **kwargs):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with patch("gamebond.windows_network._require_windows_admin"):
            return WindowsNetwork(config(), journal_dir=directory.name, **kwargs)

    def test_staged_lifecycle_keeps_routes_unactivated_until_caller_requests(self):
        transcript = Transcript()
        helper = self.helper()
        with patch("gamebond.windows_network.subprocess.run", side_effect=transcript):
            helper.prepare()
            self.assertEqual([r[2]["phase"] for r in transcript.requests], ["preflight", "prepare"])
            helper.prepare()  # Duplicate calls must not add duplicate routes.
            helper.activate()
            helper.activate()
            helper.close()
            helper.close()
        self.assertEqual([r[2]["phase"] for r in transcript.requests],
                         ["preflight", "prepare", "activate", "close"])
        self.assertFalse(transcript.state["routes"][0]["added"])

    def test_configuration_stays_in_stdin_and_cannot_become_powershell_code(self):
        path = r"C:\Call of Duty\cod'$(Get-Process)`;.exe"
        transcript = Transcript()
        helper = self.helper(cod_executables=[path])
        with patch("gamebond.windows_network.subprocess.run", side_effect=transcript):
            helper.prepare()
            helper.close()
        for command, kwargs, _ in transcript.requests:
            self.assertEqual(command[-1], _POWERSHELL)
            self.assertNotIn(path, command[-1])
            self.assertNotIn("-ExecutionPolicy", command)
            self.assertFalse(kwargs.get("shell", False))
            self.assertGreater(kwargs["creationflags"], 0)
        self.assertEqual(transcript.requests[0][2]["qos"][0]["path"], path)
        self.assertNotIn("session", transcript.requests[0][2]["config"])

    def test_partial_prepare_failure_retains_ownership_and_cleans_up(self):
        transcript = Transcript(fail_phase="prepare")
        helper = self.helper()
        with patch("gamebond.windows_network.subprocess.run", side_effect=transcript):
            with self.assertRaisesRegex(WindowsNetworkError, "rollback errors: route still in use"):
                helper.prepare()
        self.assertEqual([r[2]["phase"] for r in transcript.requests], ["preflight", "prepare", "close"])
        self.assertFalse(transcript.state["address_added"])

    def test_activation_and_cleanup_errors_are_both_reported_then_close_can_retry(self):
        transcript = Transcript(fail_phase="activate", cleanup_failure=True)
        helper = self.helper()
        with patch("gamebond.windows_network.subprocess.run", side_effect=transcript):
            helper.prepare()
            with self.assertRaisesRegex(WindowsNetworkError, "activate failed:.*cleanup failed:.*close failed"):
                helper.activate()
            transcript.cleanup_failure = False
            helper.close()
        self.assertFalse(transcript.state["address_added"])

    def test_preflight_permission_failure_never_attempts_mutations(self):
        helper = self.helper()
        failure = subprocess.CompletedProcess([], 1, json.dumps(
            {"ok": False, "state": None, "error": "Access is denied", "rollback_errors": []}), "")
        with patch("gamebond.windows_network.subprocess.run", return_value=failure) as runner:
            with self.assertRaisesRegex(WindowsNetworkError, "Access is denied"):
                helper.prepare()
        self.assertEqual(runner.call_count, 1)

    def test_malformed_transcript_and_nonzero_exit_are_not_success(self):
        for result in (subprocess.CompletedProcess([], 0, "not JSON", "provider diagnostic"),
                       subprocess.CompletedProcess([], 2, '{"ok":true,"state":null}', "provider diagnostic")):
            with self.subTest(result=result):
                helper = self.helper()
                with patch("gamebond.windows_network.subprocess.run", return_value=result):
                    with self.assertRaisesRegex(WindowsNetworkError, "provider diagnostic"):
                        helper.prepare()

    def test_activation_requires_preparation_and_closed_helper_cannot_restart(self):
        helper = self.helper()
        with self.assertRaisesRegex(WindowsNetworkError, "prepare"):
            helper.activate()
        helper.close()
        with self.assertRaisesRegex(WindowsNetworkError, "closed"):
            helper.prepare()

    def test_input_validation_rejects_duplicate_paths_and_ambiguous_gateways(self):
        for change in ({"gateways": ["192.168.8.1"]}, {"interface_indices": [12, 12]},
                       {"bind": [["0.0.0.0", 0], ["192.168.9.2", 0]]},
                       {"peer": ["203.0.113.10", True]}, {"client_tunnel_ip": "10.77.0.3"}):
            with self.subTest(change=change), patch("gamebond.windows_network._require_windows_admin"):
                current = copy.deepcopy(config())
                current.update(change)
                with self.assertRaises(ValueError):
                    WindowsNetwork(current)
        with patch("gamebond.windows_network._require_windows_admin"):
            with self.assertRaisesRegex(ValueError, "distinct"):
                WindowsNetwork(config(), cod_executables=[r"C:\Games\cod.exe", r"c:\games\COD.exe"])

    def test_journal_persists_partial_ownership_and_is_removed_after_cleanup(self):
        transcript = Transcript(cleanup_failure=True)
        helper = self.helper()
        with patch("gamebond.windows_network.subprocess.run", side_effect=transcript):
            helper.prepare()
            record = json.loads(helper._journal_path.read_text())
            self.assertTrue(record["state"]["address_added"])
            self.assertTrue(record["state"]["routes"][0]["added"])
            with self.assertRaises(WindowsNetworkError):
                helper.close()
            self.assertTrue(helper._journal_path.exists())
            transcript.cleanup_failure = False
            helper.close()
            self.assertFalse(helper._journal_path.exists())

    def test_recovery_refuses_live_owner_or_hidden_worker_even_after_parent_exits(self):
        helper = self.helper()
        for live_field in ("owner", "worker"):
            with self.subTest(live_field=live_field):
                record = {"version": 1, "state": {"routes": [], "qos": []},
                          "owner": None, "worker": None}
                record[live_field] = {"pid": 123, "created": "creation-token"}
                helper._journal_path.write_text(json.dumps(record))
                with patch("gamebond.windows_network._require_windows_admin"), \
                     patch("gamebond.windows_network._process_created", return_value="creation-token"), \
                     patch("gamebond.windows_network.subprocess.run") as runner:
                    with self.assertRaisesRegex(WindowsNetworkError, "live process"):
                        cleanup_journal(helper._journal_path)
                    runner.assert_not_called()

    def test_recovery_accepts_reused_pid_with_different_creation_and_removes_only_record(self):
        helper = self.helper()
        record = {"version": 1, "state": {"routes": [], "qos": []},
                  "owner": {"pid": 123, "created": "old-creation"}, "worker": None}
        helper._journal_path.write_text(json.dumps(record))
        result = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "state": record["state"]}), "")
        with patch("gamebond.windows_network._require_windows_admin"), \
             patch("gamebond.windows_network._process_created", return_value="new-creation"), \
             patch("gamebond.windows_network.subprocess.run", return_value=result) as runner:
            cleanup_journal(helper._journal_path)
        self.assertEqual(json.loads(runner.call_args.kwargs["input"])["phase"], "close")
        self.assertFalse(helper._journal_path.exists())

    def test_invalid_recovery_scope_stops_before_any_cmdlet(self):
        helper = self.helper()
        record = {"version": 1, "state": {"routes": [{"prefix": "0.0.0.0/0"}], "qos": []}}
        helper._journal_path.write_text(json.dumps(record))
        with patch("gamebond.windows_network._require_windows_admin"), \
             patch("gamebond.windows_network.subprocess.run") as runner:
            with self.assertRaisesRegex(WindowsNetworkError, "unexpected route"):
                recover_journals(helper._journal_dir)
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
