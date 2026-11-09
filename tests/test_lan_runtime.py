"""Userspace runtime wiring for LAN devices, without ProxiFyre, drivers or a network stack."""
import contextlib
import io
import threading
import time
import unittest
from collections import OrderedDict
from unittest.mock import MagicMock

from gamebond.adaptive_qos import AdaptiveQoS, QoSSettings
from gamebond.frame_io import FrameIOError, MemoryFrameIO
from gamebond.lan_gateway import LanDevice, load_lan_devices
from gamebond.policy import Classifier, PriorityScheduler, QueuePolicy
from gamebond.userspace import Runtime
from test_lan_gateway import GW_MAC, PS_IP, PS_MAC, CLIENT_IP, dhcp_request, eth, udp

DEVICE = dict(name="PS5", tunnel_ip=PS_IP, interface_id="{AAAAAAAA-1111-1111-1111-000000000009}")


def make_runtime(**config):
    runtime = object.__new__(Runtime)
    runtime.config = dict(role="client", client_tunnel_ip=CLIENT_IP, mtu=1280, game_udp_ports=[3075],
                          interface_ids=[], interface_indices=[])
    runtime.config.update(config)
    runtime.classify_lock = threading.Lock()
    runtime.flow_profiles = OrderedDict()
    runtime.classifier = Classifier({46: QueuePolicy(priority=True, replicate=True, max_age_ms=20, capacity=64, retransmissions=0),
                                     0: QueuePolicy(priority=False, replicate=False, max_age_ms=100, capacity=256, retransmissions=0)})
    runtime.qos = AdaptiveQoS(QoSSettings())
    runtime.node = MagicMock()
    runtime.node.stats.return_value = {"paths": []}
    runtime.scheduler = PriorityScheduler(capacity=64)
    runtime.counts = dict(tagged_game_udp=0, bulk_enqueued=0, malformed=0, injected=0)
    runtime.stop = threading.Event()
    runtime.stack_write_lock = threading.Lock()
    runtime.stack = MagicMock()
    runtime.lan_devices = load_lan_devices(runtime.config)
    runtime.lan_gateways, runtime.lan_by_ip, runtime.lan_errors, runtime.lan_retry_at = {}, {}, {}, {}
    return runtime


class LanRuntimeTests(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        self.runtime = make_runtime(lan_devices=[dict(DEVICE)])
        self.ends = []

        def opener(device):
            wire, far = MemoryFrameIO.pair(GW_MAC, PS_MAC)
            self.ends.append(far)
            return wire
        self.runtime.lan_opener = opener
        self.addCleanup(lambda: [g.close() for g in self.runtime.lan_gateways.values()])

    def bring_up(self):
        self.runtime.maintain_lan()
        return self.runtime.lan_gateways["PS5"]

    def test_device_traffic_takes_the_normal_classification_path(self):
        gateway = self.bring_up()
        gateway.handle_frame(dhcp_request(3, requested=PS_IP, server="10.77.0.1"))
        gateway.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp(PS_IP, "203.0.113.5", 3075, 3075, b"game")))   # game UDP -> DSCP46
        gateway.handle_frame(eth(GW_MAC, PS_MAC, 0x0800, udp(PS_IP, "203.0.113.5", 9000, 9001, b"bulk")))
        self.assertEqual(self.runtime.node.send.call_count, 1)
        sent = self.runtime.node.send.call_args
        self.assertEqual(sent.args[0][1] >> 2, 46)           # marked as gameplay
        self.assertTrue(sent.kwargs["replicate"])
        self.assertEqual(self.runtime.counts["bulk_enqueued"], 1)
        self.assertEqual(self.runtime.scheduler.pop(0.1).packet[12:16], bytes([10, 77, 0, 3]))

    def test_inbound_packets_route_by_destination_address(self):
        gateway = self.bring_up()
        gateway.handle_frame(dhcp_request(3, requested=PS_IP, server="10.77.0.1"))
        self.ends[0].inbox.queue.clear()
        for_ps5 = udp("203.0.113.5", PS_IP, 1, 2, b"for-ps5")
        for_pc = udp("203.0.113.5", CLIENT_IP, 1, 2, b"for-pc")
        pending = [for_ps5, for_pc]

        def recv(timeout):
            item = pending.pop(0)
            if not pending:
                self.runtime.stop.set()
            return item
        self.runtime.node.recv.side_effect = recv
        self.runtime.receive()
        frames = list(self.ends[0].inbox.queue)
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].rstrip(b"\0").endswith(b"for-ps5"))
        self.runtime.stack.stdin.write.assert_called_once()          # the PC's own packet still reaches netstack
        self.assertIn(b"for-pc", self.runtime.stack.stdin.write.call_args.args[0])
        self.assertEqual(self.runtime.counts["lan_delivered"], 1)

    def test_missing_adapter_does_not_fail_and_is_retried(self):
        attempts = []

        def failing(device):
            attempts.append(time.monotonic())
            raise FrameIOError("adapter not present")
        self.runtime.lan_opener = failing
        self.runtime.maintain_lan()
        self.runtime.maintain_lan()                      # inside the retry window: no second attempt
        self.assertEqual(len(attempts), 1)
        self.assertEqual(self.runtime.lan_status()[0]["error"], "adapter not present")
        self.assertFalse(self.runtime.lan_status()[0]["up"])
        self.runtime.lan_retry_at["PS5"] = 0
        self.runtime.lan_opener = lambda device: MemoryFrameIO.pair(GW_MAC, PS_MAC)[0]
        self.runtime.maintain_lan()
        self.assertTrue(self.runtime.lan_status()[0]["up"])
        self.assertIn(bytes([10, 77, 0, 3]), self.runtime.lan_by_ip)

    def test_unplugged_adapter_is_unrouted_then_restarted(self):
        gateway = self.bring_up()
        self.ends[0].peer.close()                        # the wire end errors on its next read
        deadline = time.monotonic() + 3
        while gateway.alive and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(gateway.alive)
        self.runtime.lan_retry_at["PS5"] = 0
        self.runtime.maintain_lan()
        self.assertIsNot(self.runtime.lan_gateways["PS5"], gateway)
        self.assertTrue(self.runtime.lan_gateways["PS5"].alive)
        self.assertEqual(len(self.ends), 2)

    def test_no_devices_configured_changes_nothing(self):
        runtime = make_runtime()
        runtime.maintain_lan()
        self.assertEqual((runtime.lan_status(), runtime.lan_by_ip), ([], {}))


if __name__ == "__main__":
    unittest.main()
