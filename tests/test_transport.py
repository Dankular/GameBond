import queue
import secrets
import socket
import struct
import time
import unittest
from unittest import mock

from gamebond.transport import DATA, HEADER, FLOW_CACHE_CAPACITY, Node, ReplayWindow


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError("condition timed out")


class ReplayTests(unittest.TestCase):
    def test_reordering_duplicates_and_bounded_old_packets(self):
        window = ReplayWindow(8)
        self.assertTrue(window.accept(4))
        self.assertTrue(window.accept(2))
        self.assertFalse(window.accept(4))
        self.assertTrue(window.accept(20))
        self.assertFalse(window.accept(2))
        self.assertTrue(window.accept(19))
        self.assertFalse(window.accept(19))


class TransportTests(unittest.TestCase):
    def test_bulk_reorder_budget_tracks_skew_and_jitter_with_a_hard_bound(self):
        paths=list(self.client._paths.values())
        for path,rtt,jitter in zip(paths,(50,90),(5,10)):
            path.ready=True;path.rtt_ms=rtt;path.rtt_jitter_ms=jitter
        self.client._update_reorder_budget()
        self.assertAlmostEqual(self.client._reorder.timeout,.115)
        paths[1].rtt_ms=2000;paths[1].rtt_jitter_ms=500
        self.client._update_reorder_budget()
        self.assertEqual(self.client._reorder.timeout,.2)
        paths[1].ready=False
        self.client._update_reorder_budget()
        self.assertEqual(self.client._reorder.timeout,.03)

    def setUp(self):
        self.key, self.session = secrets.token_bytes(32), secrets.token_bytes(16)
        self.server = Node(self.key, "server", self.session, [("127.0.0.1", 0)],
                           probe_interval=.05, path_timeout=.3)
        self.client = Node(self.key, "client", self.session,
                           [("127.0.0.1", 0), ("127.0.0.1", 0)],
                           peer=self.server.addresses[0], probe_interval=.05,
                           path_timeout=.3)

    def tearDown(self):
        self.client.close()
        self.server.close()

    def test_duplicate_delivery_both_directions_and_each_link_outage(self):
        self.server.start()
        self.client.start()
        wait_for(lambda: len(self.server.stats()["paths"]) == 2)
        self.assertEqual(self.client.send(b"upstream"), 2)
        self.assertEqual(self.server.recv(1), b"upstream")
        with self.assertRaises(queue.Empty):
            self.server.recv(.1)
        self.assertEqual(self.server.send(b"downstream"), 2)
        self.assertEqual(self.client.recv(1), b"downstream")
        with self.assertRaises(queue.Empty):
            self.client.recv(.1)
        # Simulate each direction of each physical path becoming a blackhole.
        # The UDP sockets and surviving path remain real loopback sockets.
        client_write, server_write = self.client._write, self.server._write
        for disabled in (0, 1):
            disabled_address = self.client.addresses[disabled]
            self.client._write = lambda packet, path: (
                False if path.socket_index == disabled else client_write(packet, path))
            self.server._write = lambda packet, path: (
                False if path.endpoint == disabled_address else server_write(packet, path))
            time.sleep(.4)
            packet = f"up-{disabled}".encode()
            self.assertEqual(self.client.send(packet), 1)
            self.assertEqual(self.server.recv(1), packet)
            packet = f"down-{disabled}".encode()
            self.assertEqual(self.server.send(packet), 1)
            self.assertEqual(self.client.recv(1), packet)
            self.client._write, self.server._write = client_write, server_write
            wait_for(lambda: all(p["healthy"] for p in self.server.stats()["paths"]))
        self.assertGreater(self.client.stats()["duplicates"], 0)
        self.assertGreater(self.server.stats()["duplicates"], 0)
        wait_for(lambda: all(p["rtt_ms"] is not None for p in self.client.stats()["paths"]))

    def test_authentication_before_replay_or_path_learning(self):
        packet = self.client._encode(DATA, b"valid")
        bad = bytearray(packet)
        # Forge a very high sequence; authentication must fail before window advance.
        bad[HEADER.size - 8:HEADER.size] = struct.pack("!Q", 2**63)
        address = self.client.addresses[0]
        self.server._receive(0, bytes(bad), address)
        self.assertEqual(self.server._replay.highest, -1)
        self.assertEqual(len(self.server._paths), 0)
        self.server._receive(0, packet, address)
        self.assertEqual(self.server.recv(.1), b"valid")
        self.server._receive(0, packet, address)
        with self.assertRaises(queue.Empty):
            self.server.recv(.05)
        self.assertEqual(self.server.stats()["auth_failures"], 1)
        self.assertEqual(self.server.stats()["duplicates"], 1)

    def test_wrong_key_and_session_rejected(self):
        for key, session in ((secrets.token_bytes(32), self.session),
                             (self.key, secrets.token_bytes(16))):
            other = Node(key, "client", session, [("127.0.0.1", 0)],
                         peer=self.server.addresses[0])
            try:
                self.server._receive(0, other._encode(DATA, b"wrong"), other.addresses[0])
            finally:
                other.close()
        self.assertEqual(len(self.server._paths), 0)
        with self.assertRaises(queue.Empty):
            self.server.recv(.05)

    def test_nonce_domains_directions_and_payload_limit(self):
        same_sequence_client = self.client._encode(DATA, b"same")
        same_sequence_server = self.server._encode(DATA, b"same")
        self.assertNotEqual(same_sequence_client, same_sequence_server)
        self.assertEqual(len(self.client._encode(DATA, b"x" * self.client.max_payload)), self.client.mtu)
        with self.assertRaises(ValueError):
            self.client.send(b"x" * (self.client.max_payload + 1))

    def test_receive_queue_bounded(self):
        small = Node(self.key, "server", self.session, [("127.0.0.1", 0)], receive_capacity=1)
        try:
            for payload in (b"one", b"two"):
                small._receive(0, self.client._encode(DATA, payload), self.client.addresses[0])
            self.assertEqual(small.recv(.1), b"one")
            self.assertEqual(small.stats()["receive_drops"], 1)
        finally:
            small.close()

    def test_unreplicated_send_falls_back_after_immediate_send_error(self):
        attempted = []
        def write(packet, path):
            attempted.append(path.socket_index)
            return path.socket_index == 1
        self.client._write = write
        self.assertEqual(self.client.send(b"fallback", replicate=False), 1)
        self.assertEqual(attempted, [0, 1])

    def test_invalid_mtu_and_interface_configuration(self):
        for mtu in (-1, 0, 60, 65508):
            with self.assertRaises(ValueError):
                Node(self.key, "server", self.session, [("127.0.0.1", 0)], mtu=mtu)
        for indices in ([], [0], [-1], [True], [2**24], [1, 2]):
            with self.assertRaises(ValueError):
                Node(self.key, "server", self.session, [("127.0.0.1", 0)], interface_indices=indices)

    def test_windows_interface_option_has_network_byte_order(self):
        fake_socket = mock.Mock()
        with mock.patch("gamebond.transport.sys.platform", "win32"), mock.patch(
                "gamebond.transport.socket.socket", return_value=fake_socket):
            node = Node(self.key, "server", self.session, [("192.0.2.1", 0)], interface_indices=[257])
            try:
                fake_socket.setsockopt.assert_has_calls([
                    mock.call(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536),
                    mock.call(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024),
                    mock.call(socket.IPPROTO_IP, getattr(socket, "IP_UNICAST_IF", 31), b"\0\0\x01\x01")])
                fake_socket.bind.assert_called_once_with(("192.0.2.1", 0))
            finally:
                node.close()

    def test_windows_interface_failure_identifies_source_and_closes_socket(self):
        fake_socket = mock.Mock()
        def set_option(level, option, value):
            if level == socket.IPPROTO_IP:
                raise OSError(10022, "An invalid argument was supplied")
        fake_socket.setsockopt.side_effect = set_option
        with mock.patch("gamebond.transport.sys.platform", "win32"), mock.patch(
                "gamebond.transport.socket.socket", return_value=fake_socket):
            with self.assertRaisesRegex(OSError, "192.0.2.1.*index 57") as raised:
                Node(self.key, "server", self.session, [("192.0.2.1", 0)], interface_indices=[57])
        self.assertIsInstance(raised.exception.__cause__, OSError)
        fake_socket.close.assert_called_once()
        fake_socket.bind.assert_not_called()

    def test_stale_peer_and_replays_do_not_report_healthy(self):
        self.assertTrue(all(not p["healthy"] for p in self.client.stats()["paths"]))
        packet = self.client._encode(DATA, b"once")
        address = self.client.addresses[0]
        self.server._receive(0, packet, address)
        self.assertTrue(self.server.stats()["paths"][0]["healthy"])
        time.sleep(.35)
        self.server._receive(0, packet, address)
        self.assertFalse(self.server.stats()["paths"][0]["healthy"])
        self.assertEqual(self.server.send(b"expired"), 0)

    def test_reordered_data_delivered_without_waiting_for_missing_sequence(self):
        packets = [self.client._encode(DATA, str(i).encode()) for i in range(4)]
        for index in (3, 1, 0, 2, 3):
            self.server._receive(0, packets[index], self.client.addresses[0])
        self.assertEqual([self.server.recv(.1) for _ in range(4)], [b"3", b"1", b"0", b"2"])
        with self.assertRaises(queue.Empty):
            self.server.recv(.05)

    def test_socket_send_buffer_requested_and_reported(self):
        self.assertEqual(self.client.stats()["requested_send_buffer_bytes"], 65536)
        self.assertTrue(all(path["actual_send_buffer_bytes"] > 0 for path in self.client.stats()["paths"]))
        for capacity in (0, -1, True, 4095, 1048577):
            with self.assertRaises(ValueError):
                Node(self.key, "server", self.session, [("127.0.0.1", 0)], send_buffer_bytes=capacity)

    def test_nonblocking_buffer_error_does_not_prevent_other_duplicate(self):
        real_socket = self.client._sockets[0]
        class BlockedSocket:
            def sendto(self, *args):
                raise BlockingIOError("synthetic send-buffer exhaustion")
            def __getattr__(self, name):
                return getattr(real_socket, name)
        self.client._sockets[0] = BlockedSocket()
        self.server.start()
        self.assertEqual(self.client.send(b"surviving duplicate"), 1)
        self.assertEqual(self.server.recv(1), b"surviving duplicate")
        self.assertEqual(self.client.stats()["socket_errors"], 1)
        self.assertEqual(self.client.stats()["paths"][0]["errors"], 1)

    def test_flow_affinity_sticks_until_path_failure_then_falls_back(self):
        paths = list(self.client._paths.values())
        for path, rtt in zip(paths, (10, 20)):
            path.last_rx, path.rtt_ms = time.perf_counter(), rtt
        attempts = []
        failing = set()
        def write(packet, path):
            attempts.append(path.socket_index)
            return path.socket_index not in failing
        self.client._write = write
        flow = ("tcp", "10.77.0.2", 45000, "192.0.2.1", 443)
        self.assertEqual(self.client.send(b"one", replicate=False, flow_id=flow), 1)
        self.assertEqual(attempts[-1], 0)
        paths[1].rtt_ms = 1
        self.client.send(b"two", replicate=False, flow_id=flow)
        self.assertEqual(attempts[-1], 0)  # RTT changes do not migrate an established flow.
        self.client.send(b"new flow", replicate=False, flow_id=("other",))
        self.assertEqual(attempts[-1], 1)
        paths[0].last_rx = time.perf_counter() - 3
        self.client.send(b"stale primary", replicate=False, flow_id=flow)
        self.assertEqual(attempts[-1], 1)
        paths[0].last_rx, paths[0].rtt_ms = time.perf_counter(), .1
        failing.add(1)
        attempts.clear()
        self.client.send(b"socket error", replicate=False, flow_id=flow)
        self.assertEqual(attempts, [1, 0])
        failing.clear()
        paths[1].rtt_ms = .01
        self.client.send(b"updated affinity", replicate=False, flow_id=flow)
        self.assertEqual(attempts[-1], 0)
        attempts.clear()
        self.assertEqual(self.client.send(b"game", replicate=True, flow_id=flow), 2)
        self.assertEqual(set(attempts), {0, 1})

    def test_affinity_cache_is_bounded_and_idle_flows_expire(self):
        paths = list(self.client._paths.values())
        for path in paths:
            path.last_rx, path.rtt_ms = 10, path.socket_index + 1
        self.client._write = lambda packet, path: True
        with mock.patch("gamebond.transport.time.perf_counter", return_value=10):
            for flow in range(FLOW_CACHE_CAPACITY + 1):
                self.client.send(b"bulk", replicate=False, flow_id=flow)
            self.assertEqual(len(self.client._flow_paths), FLOW_CACHE_CAPACITY)
            self.assertNotIn(0, self.client._flow_paths)
            self.assertIn(FLOW_CACHE_CAPACITY, self.client._flow_paths)
        for path in paths:
            path.last_rx = 131
        paths[1].rtt_ms = .1
        attempted = []
        self.client._write = lambda packet, path: attempted.append(path.socket_index) or True
        with mock.patch("gamebond.transport.time.perf_counter", return_value=131):
            self.client.send(b"after idle", replicate=False, flow_id=FLOW_CACHE_CAPACITY)
        self.assertEqual(len(self.client._flow_paths), 1)
        self.assertEqual(attempted, [1])

    def test_wire_and_payload_bytes_count_duplicate_overhead(self):
        packet = self.client._encode(DATA, b"payload")
        address = self.client.addresses[0]
        self.server._receive(0, packet, address)
        self.server._receive(0, packet, address)
        stats = self.server.stats()
        self.assertEqual(stats["rx_bytes"], len(packet) * 2)
        self.assertEqual(stats["paths"][0]["rx_bytes"], len(packet) * 2)
        self.assertEqual(stats["rx_payload_bytes"], 7)
        self.assertEqual(stats["rx_packets"], 1)
        self.client.send(b"payload", replicate=True)
        stats = self.client.stats()
        self.assertEqual(stats["tx_bytes"], len(packet) * 2)
        self.assertEqual(sum(p["tx_bytes"] for p in stats["paths"]), len(packet) * 2)
        self.assertEqual(stats["tx_payload_bytes"], 7)

    def test_receive_buffer_requested_reported_and_validated(self):
        stats = self.client.stats()
        self.assertEqual(stats["requested_receive_buffer_bytes"], 4 * 1024 * 1024)
        self.assertTrue(all(path["actual_receive_buffer_bytes"] > 0 for path in stats["paths"]))
        for capacity in (0, -1, True, 1279, 16 * 1024 * 1024 + 1):
            with self.assertRaises(ValueError):
                Node(self.key, "server", self.session, [("127.0.0.1", 0)], receive_buffer_bytes=capacity)

    def test_linux_server_receive_buffer_force_is_socket_local_and_optional(self):
        fake_socket = mock.Mock()
        fake_socket.getsockopt.return_value = 212992
        fake_socket.getsockname.return_value = ("127.0.0.1", 1)
        def set_option(level, option, value):
            if option == getattr(socket, "SO_RCVBUFFORCE", 33):
                raise PermissionError("CAP_NET_ADMIN unavailable")
        fake_socket.setsockopt.side_effect = set_option
        with mock.patch("gamebond.transport.sys.platform", "linux"), mock.patch(
                "gamebond.transport.socket.socket", return_value=fake_socket):
            node = Node(self.key, "server", self.session, [("127.0.0.1", 0)],
                        peer=("127.0.0.1", 2))
            try:
                fake_socket.setsockopt.assert_any_call(socket.SOL_SOCKET,
                    getattr(socket, "SO_RCVBUFFORCE", 33), 4 * 1024 * 1024)
                path = node.stats()["paths"][0]
                self.assertEqual(path["actual_receive_buffer_bytes"], 212992)
                self.assertIn("CAP_NET_ADMIN", path["receive_buffer_force_error"])
            finally:
                node.close()
        fake_socket.reset_mock(side_effect=False)
        with mock.patch("gamebond.transport.sys.platform", "linux"), mock.patch(
                "gamebond.transport.socket.socket", return_value=fake_socket):
            node = Node(self.key, "client", self.session, [("127.0.0.1", 0)], peer=("127.0.0.1", 2))
            try:
                self.assertFalse(any(call.args[1] == getattr(socket, "SO_RCVBUFFORCE", 33)
                                     for call in fake_socket.setsockopt.call_args_list))
            finally:
                node.close()


if __name__ == "__main__":
    unittest.main()
