"""Raw Ethernet frame I/O on Windows through the Windows Packet Filter (NDISRD) driver.

Struct layouts, IOCTL numbering and the call sequence follow wiresock/ndisapi
(`include/Common.h`, `ndisapi/ndisapi.cpp`, the PassThru examples) as read on
2026-11-09. They were NOT exercised against the real driver or hardware in the
environment this was written in: the unit tests drive a fake that implements
the documented semantics. Validate on a Windows machine before relying on it.

The adapter is switched to tunnel mode (`MSTCP_FLAG_SENT_TUNNEL | RECV_TUNNEL`):
frames arriving from the wire are delivered to GameBond instead of Windows, and
anything Windows itself tries to send out that adapter (for example DHCP
discovery) is discarded, so the Windows stack never talks to the console.
Requires a 64-bit Python and the already-installed driver (no elevation was
required for packet capture per the upstream 'remove unnecessary elevation'
change; this was not verified here).
"""
from __future__ import annotations

import ctypes
import sys
import threading
import time

from .frame_io import FrameIOError

FILE_DEVICE_NDISRD = 0x8300
NDISRD_IOCTL_INDEX = 0x830
ADAPTER_LIST_SIZE = 32
ADAPTER_NAME_SIZE = 256
ETHER_ADDR_LENGTH = 6
# Driver is built with 1514 or (JUMBO_FRAME_SUPPORTED) 9014; always allocate the larger so a
# jumbo build can never write past our buffer. Field offsets do not depend on this size.
MAX_FRAME_BUFFER = 9014
MSTCP_FLAG_SENT_TUNNEL = 0x1
MSTCP_FLAG_RECV_TUNNEL = 0x2
TUNNEL_MODE = MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL
PACKET_FLAG_ON_SEND = 0x1
PACKET_FLAG_ON_RECEIVE = 0x2
DEVICE_PATH = r"\\.\NDISRD"


def ctl_code(offset: int) -> int:
    """CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX + offset, METHOD_BUFFERED, FILE_ANY_ACCESS)."""
    return (FILE_DEVICE_NDISRD << 16) | ((NDISRD_IOCTL_INDEX + offset) << 2)


IOCTL_GET_TCPIP_INTERFACES = ctl_code(1)
IOCTL_SEND_PACKET_TO_ADAPTER = ctl_code(2)
IOCTL_READ_PACKET = ctl_code(4)
IOCTL_SET_ADAPTER_MODE = ctl_code(5)
IOCTL_FLUSH_ADAPTER_QUEUE = ctl_code(6)
IOCTL_SET_EVENT = ctl_code(7)


class TcpAdapterList(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("count", ctypes.c_uint32),
                ("names", (ctypes.c_ubyte * ADAPTER_NAME_SIZE) * ADAPTER_LIST_SIZE),
                ("handles", ctypes.c_uint64 * ADAPTER_LIST_SIZE),
                ("mediums", ctypes.c_uint32 * ADAPTER_LIST_SIZE),
                ("addresses", (ctypes.c_ubyte * ETHER_ADDR_LENGTH) * ADAPTER_LIST_SIZE),
                ("mtus", ctypes.c_uint16 * ADAPTER_LIST_SIZE)]


class IntermediateBuffer(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("link", ctypes.c_uint64 * 2),  # union of HANDLE / LIST_ENTRY: 16 bytes on x64
                ("device_flags", ctypes.c_uint32), ("length", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("q8021", ctypes.c_uint32), ("filter_id", ctypes.c_uint32),
                ("reserved", ctypes.c_uint32 * 4),
                ("data", ctypes.c_ubyte * MAX_FRAME_BUFFER)]


class EthRequest(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("adapter", ctypes.c_uint64), ("buffer", ctypes.c_uint64)]


class AdapterMode(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("adapter", ctypes.c_uint64), ("flags", ctypes.c_uint32)]


class AdapterEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("adapter", ctypes.c_uint64), ("event", ctypes.c_uint64)]


def adapter_rows(listing: TcpAdapterList) -> list[dict]:
    rows = []
    for index in range(min(listing.count, ADAPTER_LIST_SIZE)):
        raw = bytes(listing.names[index]).split(b"\0", 1)[0]
        rows.append(dict(name=raw.decode("ascii", "replace"), handle=listing.handles[index],
                         mac=bytes(listing.addresses[index]), mtu=listing.mtus[index]))
    return rows


def match_adapter(rows: list[dict], interface_id: str) -> dict | None:
    """Driver names are `\\DEVICE\\<service name>`; for NICs the service name is the adapter GUID."""
    wanted = ("\\device\\" + interface_id).casefold()
    return next((row for row in rows if row["name"].casefold() == wanted), None)


class NdisrdDriver:
    """Win32 access to \\\\.\\NDISRD with one overlapped event per calling thread."""

    def __init__(self):
        if sys.platform != "win32":
            raise FrameIOError("The Windows Packet Filter driver exists only on Windows")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise FrameIOError("LAN devices need 64-bit Python (the driver structures are 64-bit)")
        from ctypes import wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        self._k = k
        handle, dword, pointer = wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, dword, dword, pointer, dword, dword, handle]
        k.CreateFileW.restype = handle
        k.DeviceIoControl.argtypes = [handle, dword, pointer, dword, pointer, dword, ctypes.POINTER(dword), pointer]
        k.DeviceIoControl.restype = wintypes.BOOL
        k.GetOverlappedResult.argtypes = [handle, pointer, ctypes.POINTER(dword), wintypes.BOOL]
        k.GetOverlappedResult.restype = wintypes.BOOL
        k.CreateEventW.argtypes = [pointer, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateEventW.restype = handle
        k.WaitForSingleObject.argtypes = [handle, dword]
        k.WaitForSingleObject.restype = dword
        k.ResetEvent.argtypes = [handle]
        k.ResetEvent.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [handle]
        k.CloseHandle.restype = wintypes.BOOL

        class Overlapped(ctypes.Structure):
            _fields_ = [("internal", ctypes.c_size_t), ("internal_high", ctypes.c_size_t),
                        ("offset", dword), ("offset_high", dword), ("event", handle)]
        self._Overlapped = Overlapped
        self._local = threading.local()
        # FILE_FLAG_OVERLAPPED = 0x40000000, share read|write, OPEN_EXISTING, no access rights needed.
        self._device = k.CreateFileW(DEVICE_PATH, 0, 3, None, 3, 0x40000000, None)
        if not self._device or self._device == 0xFFFFFFFFFFFFFFFF:  # NULL or INVALID_HANDLE_VALUE
            raise FrameIOError("Windows Packet Filter driver is not available: " + str(ctypes.WinError(ctypes.get_last_error())))

    def _thread_event(self):
        event = getattr(self._local, "event", None)
        if event is None:
            event = self._k.CreateEventW(None, True, False, None)
            if not event:
                raise FrameIOError(str(ctypes.WinError(ctypes.get_last_error())))
            self._local.event = event
        return event

    def ioctl(self, code, request=None, response=None):
        """Synchronous IOCTL. Returns (ok, bytes_returned)."""
        k = self._k
        overlapped = self._Overlapped()
        overlapped.event = self._thread_event()
        returned = ctypes.c_uint32(0)
        in_ptr = ctypes.addressof(request) if request is not None else None
        in_size = ctypes.sizeof(request) if request is not None else 0
        out_ptr = ctypes.addressof(response) if response is not None else None
        out_size = ctypes.sizeof(response) if response is not None else 0
        ok = k.DeviceIoControl(self._device, code, in_ptr, in_size, out_ptr, out_size, ctypes.byref(returned), ctypes.byref(overlapped))
        if not ok and ctypes.get_last_error() == 997:  # ERROR_IO_PENDING
            returned.value = 0
            ok = k.GetOverlappedResult(self._device, ctypes.byref(overlapped), ctypes.byref(returned), True)
        return bool(ok), returned.value

    def create_event(self):
        event = self._k.CreateEventW(None, True, False, None)
        if not event:
            raise FrameIOError(str(ctypes.WinError(ctypes.get_last_error())))
        return event

    def wait(self, event, milliseconds: int) -> bool:
        result = self._k.WaitForSingleObject(event, milliseconds)
        if result == 0xFFFFFFFF:
            raise FrameIOError(str(ctypes.WinError(ctypes.get_last_error())))
        return result == 0  # WAIT_OBJECT_0; 258 is WAIT_TIMEOUT

    def reset_event(self, event) -> None:
        self._k.ResetEvent(event)

    def close_event(self, event) -> None:
        self._k.CloseHandle(event)

    def close(self) -> None:
        event = getattr(self._local, "event", None)
        if event:
            self._k.CloseHandle(event)
            self._local.event = None
        self._k.CloseHandle(self._device)


class WindowsPacketFilterIO:
    """Frame I/O for one adapter, identified by its Windows adapter GUID."""

    PRESENCE_CHECK_SECONDS = 1.0

    def __init__(self, interface_id: str, driver=None):
        if not interface_id:
            raise FrameIOError("LAN devices on Windows need interface_id (the adapter GUID)")
        self.driver = driver or NdisrdDriver()
        self._owns_driver = driver is None
        self._local = threading.local()
        self._closed = False
        self._event = None
        self._handle = None
        self.interface_id = interface_id
        try:
            row = self._find_adapter()
            if row is None:
                raise FrameIOError(f"Adapter {interface_id} is not bound to TCP/IP or is not visible to the packet driver")
            self._handle, self.mac, self.mtu = row["handle"], row["mac"], row["mtu"]
            self._set_mode(TUNNEL_MODE)
            self._event = self.driver.create_event()
            request = AdapterEvent(self._handle, int(self._event))
            ok, _ = self.driver.ioctl(IOCTL_SET_EVENT, request)
            if not ok:
                raise FrameIOError("Packet driver rejected the packet-event registration")
            self._flush()
        except BaseException:
            self.close()
            raise
        self._next_presence_check = time.monotonic() + self.PRESENCE_CHECK_SECONDS

    # driver helpers
    def _find_adapter(self):
        listing = TcpAdapterList()
        ok, size = self.driver.ioctl(IOCTL_GET_TCPIP_INTERFACES, listing, listing)
        if not ok or size != ctypes.sizeof(listing):
            raise FrameIOError("Packet driver could not list TCP/IP adapters")
        return match_adapter(adapter_rows(listing), self.interface_id)

    def _set_mode(self, flags: int) -> None:
        ok, _ = self.driver.ioctl(IOCTL_SET_ADAPTER_MODE, AdapterMode(self._handle, flags))
        if not ok:
            raise FrameIOError("Packet driver rejected the adapter mode change")

    def _flush(self) -> None:
        self.driver.ioctl(IOCTL_FLUSH_ADAPTER_QUEUE, ctypes.c_uint64(self._handle))

    def _buffer(self):
        buffer = getattr(self._local, "buffer", None)
        if buffer is None:
            buffer = self._local.buffer = IntermediateBuffer()
        return buffer

    # frame I/O
    def _read_one(self):
        """One queued frame from the wire, or None when the queue is empty."""
        buffer = self._buffer()
        while True:
            ctypes.memset(ctypes.addressof(buffer), 0, IntermediateBuffer.data.offset)
            request = EthRequest(self._handle, ctypes.addressof(buffer))
            ok, size = self.driver.ioctl(IOCTL_READ_PACKET, request, request)
            if not ok or size != ctypes.sizeof(request):
                return None
            if buffer.device_flags & PACKET_FLAG_ON_SEND:
                continue  # Windows' own transmission toward this adapter: isolated, never put on the wire
            if 14 <= buffer.length <= MAX_FRAME_BUFFER:
                return ctypes.string_at(ctypes.addressof(buffer) + IntermediateBuffer.data.offset, buffer.length)

    def read(self, timeout: float = 0.25):
        if self._closed:
            raise FrameIOError("adapter closed")
        frame = self._read_one()
        if frame is not None:
            return frame
        if self.driver.wait(self._event, max(1, int(timeout * 1000))):
            self.driver.reset_event(self._event)  # reset before draining so a later arrival re-signals
            return self._read_one()
        now = time.monotonic()
        if now >= self._next_presence_check:
            self._next_presence_check = now + self.PRESENCE_CHECK_SECONDS
            row = self._find_adapter()
            if row is None or row["handle"] != self._handle:
                raise FrameIOError("Adapter was removed or is no longer bound to TCP/IP")
        return None

    def write(self, frame: bytes) -> None:
        if self._closed:
            raise FrameIOError("adapter closed")
        if not 14 <= len(frame) <= MAX_FRAME_BUFFER:
            raise ValueError("invalid Ethernet frame size")
        buffer = self._buffer()
        ctypes.memset(ctypes.addressof(buffer), 0, IntermediateBuffer.data.offset)
        buffer.length = len(frame)
        ctypes.memmove(ctypes.addressof(buffer) + IntermediateBuffer.data.offset, frame, len(frame))
        ok, _ = self.driver.ioctl(IOCTL_SEND_PACKET_TO_ADAPTER, EthRequest(self._handle, ctypes.addressof(buffer)))
        if not ok:
            raise FrameIOError("Packet driver refused the frame")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._handle is not None:
            try:  # restore pass-through and drop anything still queued (mirrors the upstream release())
                self._set_mode(0)
                self._flush()
            except (OSError, ValueError):
                pass
        if self._event is not None:
            self.driver.close_event(self._event)
            self._event = None
        if self._owns_driver:
            self.driver.close()
