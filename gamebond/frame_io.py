"""Raw Ethernet frame I/O for a device-facing adapter.

Every backend exposes: `mac` (six bytes), `read(timeout) -> bytes | None`,
`write(frame)`, and `close()`. `read` returns only frames received from the
wire, never frames this process transmitted.
"""
from __future__ import annotations

import os
import queue
import socket
import sys
import threading


class FrameIOError(OSError):
    pass


class MemoryFrameIO:
    """In-process endpoint pair for tests: frames written here appear on the peer."""

    def __init__(self, mac: bytes):
        self.mac = bytes(mac)
        self.inbox: queue.Queue = queue.Queue()
        self.peer: "MemoryFrameIO | None" = None
        self.sent: list[bytes] = []
        self.closed = False

    @classmethod
    def pair(cls, mac_a: bytes, mac_b: bytes):
        a, b = cls(mac_a), cls(mac_b)
        a.peer, b.peer = b, a
        return a, b

    def read(self, timeout: float = 0.25):
        if self.closed:
            raise FrameIOError("adapter closed")
        try:
            return self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def write(self, frame: bytes) -> None:
        if self.closed:
            raise FrameIOError("adapter closed")
        self.sent.append(bytes(frame))
        if self.peer is not None:
            self.peer.inbox.put(bytes(frame))

    def close(self) -> None:
        self.closed = True


class LinuxFrameIO:
    """AF_PACKET raw socket bound to one interface (requires CAP_NET_RAW)."""

    def __init__(self, interface: str):
        if not hasattr(socket, "AF_PACKET"):
            raise FrameIOError("AF_PACKET is not available on this platform")
        self.interface = interface
        self._lock = threading.Lock()
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
            self._sock.bind((interface, 0))
        except OSError as exc:
            raise FrameIOError(f"cannot open raw socket on {interface}: {exc}") from exc
        self.mac = bytes(self._sock.getsockname()[4][:6])
        self._sock.settimeout(0.25)

    def read(self, timeout: float = 0.25):
        sock = self._sock
        if sock.fileno() < 0:
            raise FrameIOError("adapter closed")
        sock.settimeout(min(max(timeout, 0.0), 0.25) or 0.001)
        try:
            frame, address = sock.recvfrom(65535)
        except socket.timeout:
            return None
        except OSError as exc:
            raise FrameIOError(str(exc)) from exc
        if address[2] == socket.PACKET_OUTGOING:  # our own transmission echoed back
            return None
        return frame

    def write(self, frame: bytes) -> None:
        with self._lock:
            self._sock.send(frame)

    def close(self) -> None:
        self._sock.close()


def open_frame_io(device):
    """Open raw frame access for a `LanDevice` on this platform."""
    if sys.platform.startswith("linux"):
        if not device.interface_name:
            raise FrameIOError("Linux LAN devices need interface_name")
        return LinuxFrameIO(device.interface_name)
    if sys.platform == "win32":
        from .windows_packet_filter import WindowsPacketFilterIO
        return WindowsPacketFilterIO(device.interface_id)
    raise FrameIOError(f"LAN devices are unsupported on {sys.platform}")


def _read(path: str) -> str:
    with open(path, encoding="ascii") as handle:
        return handle.read().strip()


def linux_interfaces() -> list[dict]:
    """Candidate device-facing adapters on Linux, flagging USB-attached ones."""
    rows = []
    base = "/sys/class/net"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return rows
    for name in names:
        path = os.path.join(base, name)
        if name == "lo" or not os.path.exists(os.path.join(path, "device")):
            continue  # virtual interface
        try:
            mac = _read(os.path.join(path, "address"))
            state = _read(os.path.join(path, "operstate"))
            real = os.path.realpath(os.path.join(path, "device"))
        except OSError:
            continue
        rows.append(dict(name=name, mac=mac, up=state == "up", usb="/usb" in real, id="", index=0))
    return rows
