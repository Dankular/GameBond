"""Marshalling and call-sequence tests for the Windows Packet Filter backend.

The driver is a fake that follows the semantics read from wiresock/ndisapi; these tests do not prove the
real driver accepts the calls. They catch layout mistakes against that source and logic errors in our code.
"""
import ctypes
import queue
import unittest

from gamebond import windows_packet_filter as w
from gamebond.frame_io import FrameIOError

GUID = "{AAAAAAAA-1111-1111-1111-000000000009}"
OTHER = "{BBBBBBBB-2222-2222-2222-00000000000A}"
MAC = bytes.fromhex("021122334455")
HANDLE = 0x1122334455667788


class FakeNdisrd:
    """Implements the documented driver behavior over real ctypes buffers."""

    def __init__(self, adapters=((GUID, MAC, HANDLE),)):
        self.adapters = list(adapters)
        self.inbox = queue.Queue()
        self.sent, self.mode, self.event, self.log = [], None, None, []
        self.signaled = False
        self.closed_events = []

    def ioctl(self, code, request=None, response=None):
        self.log.append(code)
        if code == w.IOCTL_GET_TCPIP_INTERFACES:
            listing = response
            listing.count = len(self.adapters)
            for index, (guid, mac, handle) in enumerate(self.adapters):
                name = ("\\DEVICE\\" + guid).encode()
                for position, byte in enumerate(name + b"\0"):
                    listing.names[index][position] = byte
                listing.handles[index] = handle
                for position, byte in enumerate(mac):
                    listing.addresses[index][position] = byte
                listing.mtus[index] = 1500
            return True, ctypes.sizeof(listing)
        if code == w.IOCTL_SET_ADAPTER_MODE:
            self.mode = (request.adapter, request.flags)
            return True, 0
        if code == w.IOCTL_SET_EVENT:
            self.event = (request.adapter, request.event)
            return True, 0
        if code == w.IOCTL_FLUSH_ADAPTER_QUEUE:
            self.inbox = queue.Queue()
            return True, 0
        if code == w.IOCTL_READ_PACKET:
            try:
                flags, frame = self.inbox.get_nowait()
            except queue.Empty:
                return False, 0
            buffer = ctypes.cast(request.buffer, ctypes.POINTER(w.IntermediateBuffer)).contents
            buffer.device_flags, buffer.length = flags, len(frame)
            ctypes.memmove(ctypes.addressof(buffer.data), frame, len(frame))
            return True, ctypes.sizeof(request)
        if code == w.IOCTL_SEND_PACKET_TO_ADAPTER:
            buffer = ctypes.cast(request.buffer, ctypes.POINTER(w.IntermediateBuffer)).contents
            self.sent.append((request.adapter, ctypes.string_at(ctypes.addressof(buffer.data), buffer.length)))
            return True, 0
        raise AssertionError(f"unexpected IOCTL {code:#x}")

    def create_event(self):
        return 0xE1

    def wait(self, event, milliseconds):
        return False

    def reset_event(self, event):
        self.signaled = False

    def close_event(self, event):
        self.closed_events.append(event)

    def close(self):
        raise AssertionError("an injected driver must not be closed by the IO object")


def frame(size=60, fill=1):
    return bytes([fill]) * size


class LayoutTests(unittest.TestCase):
    def test_structure_sizes_and_offsets_match_the_upstream_headers(self):
        self.assertEqual(ctypes.sizeof(w.TcpAdapterList), 4 + 32 * 256 + 32 * 8 + 32 * 4 + 32 * 6 + 32 * 2)
        self.assertEqual(w.TcpAdapterList.handles.offset, 4 + 32 * 256)
        self.assertEqual(w.TcpAdapterList.mtus.offset, 4 + 32 * 256 + 32 * 8 + 32 * 4 + 32 * 6)
        self.assertEqual(ctypes.sizeof(w.EthRequest), 16)
        self.assertEqual(ctypes.sizeof(w.AdapterMode), 12)
        self.assertEqual(ctypes.sizeof(w.AdapterEvent), 16)
        self.assertEqual(w.IntermediateBuffer.device_flags.offset, 16)  # after the 16-byte HANDLE/LIST_ENTRY union
        self.assertEqual(w.IntermediateBuffer.length.offset, 20)
        self.assertEqual(w.IntermediateBuffer.data.offset, 52)          # 16 + 4*5 + 4*4 reserved

    def test_ioctl_codes_follow_ctl_code_formula(self):
        self.assertEqual(w.IOCTL_GET_TCPIP_INTERFACES, 0x83000000 + 4 * 0x831)
        self.assertEqual(w.IOCTL_READ_PACKET, 0x83000000 + 4 * 0x834)
        self.assertEqual(w.IOCTL_SET_EVENT, 0x83000000 + 4 * 0x837)
        self.assertEqual(len({w.IOCTL_GET_TCPIP_INTERFACES, w.IOCTL_SEND_PACKET_TO_ADAPTER, w.IOCTL_READ_PACKET,
                              w.IOCTL_SET_ADAPTER_MODE, w.IOCTL_FLUSH_ADAPTER_QUEUE, w.IOCTL_SET_EVENT}), 6)


class IoTests(unittest.TestCase):
    def open(self, **kwargs):
        self.driver = FakeNdisrd(**kwargs)
        io = w.WindowsPacketFilterIO(GUID, driver=self.driver)
        self.addCleanup(io.close)
        return io

    def test_opens_matching_adapter_in_tunnel_mode_with_event_registered(self):
        io = self.open(adapters=((OTHER, bytes(6), 7), (GUID, MAC, HANDLE)))
        self.assertEqual((io.mac, io.mtu), (MAC, 1500))
        self.assertEqual(self.driver.mode, (HANDLE, 3))
        self.assertEqual(self.driver.event, (HANDLE, 0xE1))

    def test_guid_match_is_case_insensitive(self):
        self.driver = FakeNdisrd()
        io = w.WindowsPacketFilterIO(GUID.lower(), driver=self.driver)
        io.close()

    def test_missing_adapter_fails_cleanly_without_changing_any_mode(self):
        driver = FakeNdisrd(adapters=((OTHER, bytes(6), 7),))
        with self.assertRaisesRegex(FrameIOError, "not bound"):
            w.WindowsPacketFilterIO(GUID, driver=driver)
        self.assertNotIn(w.IOCTL_SET_ADAPTER_MODE, driver.log)

    def test_received_frames_are_returned_and_windows_own_sends_are_discarded(self):
        io = self.open()
        self.driver.inbox.put((w.PACKET_FLAG_ON_SEND, frame(70, 9)))     # Windows DHCP probe etc.
        self.driver.inbox.put((w.PACKET_FLAG_ON_RECEIVE, frame(90, 5)))
        self.assertEqual(io.read(0.01), frame(90, 5))
        self.assertIsNone(io.read(0.01))
        self.assertEqual(self.driver.sent, [])                          # nothing from Windows reached the wire

    def test_runt_and_oversized_frames_are_dropped(self):
        io = self.open()
        self.driver.inbox.put((w.PACKET_FLAG_ON_RECEIVE, frame(10)))
        self.driver.inbox.put((w.PACKET_FLAG_ON_RECEIVE, frame(60, 2)))
        self.assertEqual(io.read(0.01), frame(60, 2))

    def test_write_sends_exact_frame_to_the_adapter(self):
        io = self.open()
        data = bytes(range(256)) * 5 + b"tail"
        io.write(data)
        self.assertEqual(self.driver.sent, [(HANDLE, data)])
        with self.assertRaises(ValueError):
            io.write(b"short")

    def test_removed_adapter_is_detected_when_idle(self):
        io = self.open()
        io._next_presence_check = 0
        self.driver.adapters = []
        with self.assertRaisesRegex(FrameIOError, "removed"):
            io.read(0.01)

    def test_replugged_adapter_with_new_handle_is_treated_as_removed(self):
        io = self.open()
        io._next_presence_check = 0
        self.driver.adapters = [(GUID, MAC, HANDLE + 1)]
        with self.assertRaises(FrameIOError):
            io.read(0.01)

    def test_close_restores_passthrough_flushes_and_releases_event(self):
        io = self.open()
        io.close()
        self.assertEqual(self.driver.mode, (HANDLE, 0))
        self.assertEqual(self.driver.closed_events, [0xE1])
        with self.assertRaises(FrameIOError):
            io.read(0.01)
        io.close()  # idempotent

    def test_signaled_event_triggers_a_second_drain(self):
        io = self.open()
        calls = []

        def wait(event, milliseconds):
            calls.append(milliseconds)
            self.driver.inbox.put((w.PACKET_FLAG_ON_RECEIVE, frame(64, 3)))
            return True
        self.driver.wait = wait
        self.assertEqual(io.read(0.25), frame(64, 3))
        self.assertEqual(calls, [250])


class WiringTests(unittest.TestCase):
    def test_open_frame_io_selects_the_windows_backend(self):
        import sys
        from unittest.mock import patch
        from gamebond import frame_io
        from gamebond.lan_gateway import LanDevice
        device = LanDevice(name="PS5", tunnel_ip="10.77.0.3", interface_id=GUID)
        sentinel = object()
        with patch.object(sys, "platform", "win32"), patch.object(w, "WindowsPacketFilterIO", return_value=sentinel) as opener:
            self.assertIs(frame_io.open_frame_io(device), sentinel)
        opener.assert_called_once_with(GUID)

    def test_driver_class_refuses_to_run_off_windows(self):
        with self.assertRaisesRegex(FrameIOError, "only on Windows"):
            w.NdisrdDriver()


if __name__ == "__main__":
    unittest.main()
