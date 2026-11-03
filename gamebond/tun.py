"""Packet-only TUN devices. Address, MTU and route configuration is external.

API references: WireGuard/wintun api/wintun.h and README.md;
https://docs.kernel.org/networking/tuntap.html.
Creating a device requires Administrator/CAP_NET_ADMIN. No installed Speedify
adapter is opened or modified. Stop packet workers before calling close().
"""

from __future__ import annotations

import ctypes
import math
import os
from pathlib import Path
import sys
import threading


def _timeout(value: float) -> float:
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ValueError("timeout must be finite and nonnegative")
    # A close request never waits behind a long driver event wait.
    return min(value, 0.25)


def _validate(name: str, mtu: int) -> None:
    if not isinstance(name, str) or not name or "\0" in name:
        raise ValueError("a nonempty adapter name without NUL is required")
    if name.casefold() in {"speedify", "speedify virtual adapter"}:
        raise ValueError("choose a separate GameBond adapter name")
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 1280 <= mtu <= 65535:
        raise ValueError("mtu must be an integer between 1280 and 65535")


class LinuxTun:
    """Linux raw-IP TUN, one reader and one writer supported concurrently."""

    def __init__(self, name: str, mtu: int = 1280):
        _validate(name, mtu)
        import fcntl
        import struct

        encoded = name.encode("ascii")
        if len(encoded) > 15 or "/" in name or "%" in name:
            raise ValueError("Linux adapter name must be ASCII and at most 15 bytes")
        self.mtu = mtu
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            # Linux struct ifreq is 40 bytes on 64-bit and 32 on 32-bit.
            request = struct.pack("16sH", encoded, 0x0001 | 0x1000)
            request += bytes((40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 32) - len(request))
            result = fcntl.ioctl(self._fd, 0x400454CA, request)  # TUNSETIFF
            self.name = result[:16].split(b"\0", 1)[0].decode("ascii")
        except BaseException:
            os.close(self._fd)
            self._fd = -1
            raise

    def read(self, timeout: float = 0.25) -> bytes | None:
        import select

        wait = _timeout(timeout)
        with self._read_lock:
            if self._fd < 0:
                raise RuntimeError("TUN is closed")
            if not select.select([self._fd], [], [], wait)[0]:
                return None
            try:
                packet = os.read(self._fd, 65535)
            except BlockingIOError:
                return None
            if not packet:
                raise EOFError("TUN device closed")
            return packet

    def write(self, packet: bytes) -> None:
        packet = bytes(packet)
        if not packet or len(packet) > self.mtu:
            raise ValueError("packet size must be between 1 and tunnel MTU")
        with self._write_lock:
            if self._fd < 0:
                raise RuntimeError("TUN is closed")
            size = os.write(self._fd, packet)
            if size != len(packet):
                raise OSError("partial TUN packet write")

    def close(self) -> None:
        with self._read_lock, self._write_lock:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1


class WindowsTun:
    """Wintun adapter with explicit DLL path and correctly sized native handles."""

    def __init__(self, name: str, mtu: int = 1280, dll_path: str | None = None):
        _validate(name, mtu)
        if sys.platform != "win32":
            raise OSError("Wintun is supported only on Windows")
        if not dll_path or not Path(dll_path).is_absolute():
            raise ValueError("an absolute path to a trusted signed wintun.dll is required")
        path = Path(dll_path).resolve(strict=True)
        if path.name.casefold() != "wintun.dll":
            raise ValueError("dll_path must identify wintun.dll")
        self.name = name
        self.mtu = mtu
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._adapter = None
        self._session = None
        self._event = None
        # Search dependencies only beside this DLL and in System32, never CWD.
        self._dll = ctypes.WinDLL(str(path), use_last_error=True, winmode=0x100 | 0x800)
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
        pointer = ctypes.c_void_p
        dword = ctypes.c_uint32
        self._bind("WintunCreateAdapter", pointer, [ctypes.c_wchar_p, ctypes.c_wchar_p, pointer])
        self._bind("WintunCloseAdapter", None, [pointer])
        self._bind("WintunStartSession", pointer, [pointer, dword])
        self._bind("WintunEndSession", None, [pointer])
        self._bind("WintunGetReadWaitEvent", pointer, [pointer])
        self._bind("WintunReceivePacket", pointer, [pointer, ctypes.POINTER(dword)])
        self._bind("WintunReleaseReceivePacket", None, [pointer, pointer])
        self._bind("WintunAllocateSendPacket", pointer, [pointer, dword])
        self._bind("WintunSendPacket", None, [pointer, pointer])
        self._kernel.WaitForSingleObject.argtypes = [pointer, dword]
        self._kernel.WaitForSingleObject.restype = dword
        try:
            self._adapter = self._dll.WintunCreateAdapter(name, "GameBond", None)
            if not self._adapter:
                raise ctypes.WinError(ctypes.get_last_error())
            self._session = self._dll.WintunStartSession(self._adapter, 0x400000)
            if not self._session:
                raise ctypes.WinError(ctypes.get_last_error())
            self._event = self._dll.WintunGetReadWaitEvent(self._session)
            if not self._event:
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.close()
            raise

    def _bind(self, name, result, arguments):
        function = getattr(self._dll, name)
        function.restype = result
        function.argtypes = arguments

    def _receive(self) -> bytes | None:
        size = ctypes.c_uint32()
        pointer = self._dll.WintunReceivePacket(self._session, ctypes.byref(size))
        if not pointer:
            error = ctypes.get_last_error()
            if error == 259:  # ERROR_NO_MORE_ITEMS
                return None
            raise ctypes.WinError(error)
        try:
            if not size.value or size.value > 65535:
                raise ValueError("invalid Wintun IP packet size")
            return ctypes.string_at(pointer, size.value)
        finally:
            self._dll.WintunReleaseReceivePacket(self._session, pointer)

    def read(self, timeout: float = 0.25) -> bytes | None:
        wait = _timeout(timeout)
        with self._read_lock:
            if not self._session:
                raise RuntimeError("TUN is closed")
            packet = self._receive()
            if packet is not None or wait == 0:
                return packet
            result = self._kernel.WaitForSingleObject(self._event, math.ceil(wait * 1000))
            if result == 258:  # WAIT_TIMEOUT
                return None
            if result != 0:  # WAIT_OBJECT_0
                if result == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
                raise OSError(f"unexpected Wintun wait result: {result}")
            return self._receive()

    def write(self, packet: bytes) -> None:
        packet = bytes(packet)
        if not packet or len(packet) > self.mtu:
            raise ValueError("packet size must be between 1 and tunnel MTU")
        with self._write_lock:
            if not self._session:
                raise RuntimeError("TUN is closed")
            pointer = self._dll.WintunAllocateSendPacket(self._session, len(packet))
            if not pointer:
                raise ctypes.WinError(ctypes.get_last_error())
            # Every successfully allocated packet must be sent, in allocation order.
            ctypes.memmove(pointer, packet, len(packet))
            self._dll.WintunSendPacket(self._session, pointer)

    def close(self) -> None:
        with self._read_lock, self._write_lock:
            if self._session:
                self._dll.WintunEndSession(self._session)
                self._session = None
                self._event = None  # Owned by session; do not CloseHandle.
            if self._adapter:
                self._dll.WintunCloseAdapter(self._adapter)
                self._adapter = None


def open_tun(name: str, mtu: int = 1280, dll_path: str | None = None):
    """Create a separate packet device; caller must configure address/up/MTU.

    This function intentionally installs no routes or NAT rules and does not set
    an IP address. Windows requires a trusted architecture-matching signed DLL.
    """
    _validate(name, mtu)
    if sys.platform == "win32":
        return WindowsTun(name, mtu, dll_path)
    if sys.platform.startswith("linux"):
        return LinuxTun(name, mtu)
    raise OSError(f"unsupported TUN platform: {sys.platform}")
