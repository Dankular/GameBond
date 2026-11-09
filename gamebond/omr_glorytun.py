"""Client for the Glorytun UDP ("mud") bonding protocol used by OpenMPTCProuter servers.

Implemented from the sources OMR's server installs: github.com/ysurac/glorytun at
2310047 with angt/mud e991dc9 (`mud.c`, `mud.h`, `src/bind.c`, `src/path.c`), read on
2026-11-09. Client side only, ChaCha20-Poly1305 only (what OMR runs), IPv4 only.

It carries raw IP packets, aggregates several local source addresses to one server
and stripes per packet by configured rate. Like the original it has NO sequence
numbers and NO reordering, and it cannot replicate packets, so GameBond's replicated
gameplay queue and reorder buffer do not apply on this path.

STATUS: written from the source, not yet exercised against the real glorytun binary.
`tests/test_omr_glorytun.py` runs against a Python peer written from the same reading,
which proves internal consistency and the documented behavior, not interoperability.
"""
from __future__ import annotations

import hashlib
import os
import queue
import selectors
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

try:
    from nacl import bindings as _sodium
    from nacl.exceptions import CryptoError
except ImportError as exc:  # pragma: no cover - exercised only without the optional dependency
    raise ImportError("The OMR transport needs PyNaCl (libsodium): pip install 'gamebond[omr]'") from exc

TIME_SIZE, KEY_SIZE, MAC_SIZE = 6, 32, 16
PKT_MIN = TIME_SIZE + MAC_SIZE           # 22 bytes of overhead
PKT_MAX = 1500
MTU_MIN, MTU_MAX = 576 + PKT_MIN, 1450 + PKT_MIN
MSG_SIZE = 125
MSG_SENT_MAX = 5
ONE_MSEC, ONE_SEC = 1000, 1_000_000
ONE_MIN = 60 * ONE_SEC
TIME_MASK = (1 << (TIME_SIZE * 8)) - 2   # microseconds, bit 0 reserved as the "control message" mark
KEEPALIVE, TIME_TOLERANCE, KX_TIMEOUT = 25 * ONE_SEC, 10 * ONE_MIN, 60 * ONE_MIN

ROLE_PREF = {"primary": 1, "secondary": 1, "backup": 125}   # "never" disables the path
DEMOTION = 2                                                 # added to a degrading path's preference
# path status (mud.h)
DELETING, PROBING, DEGRADED, LOSSY, WAITING, READY, RUNNING = range(7)


def tmask(value: int) -> int:
    return value & TIME_MASK


def parse_key(text: str) -> bytes:
    """Glorytun keyfile: 64 hex characters (case-insensitive) giving 32 bytes."""
    text = text.strip()
    if len(text) != 64:
        raise ValueError("Glorytun key must be 64 hexadecimal characters")
    return bytes.fromhex(text)


def _store(value: int, size: int) -> bytes:
    return (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def _load(raw: bytes) -> int:
    return int.from_bytes(raw, "little")


# --- crypto --------------------------------------------------------------------------------

def seal(key: bytes, header: bytes, plaintext: bytes) -> bytes:
    """[6B time][ciphertext][16B tag]; the time is both the AAD and the zero-padded 8-byte nonce."""
    return header + _sodium.crypto_aead_chacha20poly1305_encrypt(plaintext, header, header + b"\0\0", key)


def unseal(key: bytes, packet: bytes) -> bytes | None:
    header = packet[:TIME_SIZE]
    try:
        return _sodium.crypto_aead_chacha20poly1305_decrypt(packet[TIME_SIZE:], header, header + b"\0\0", key)
    except CryptoError:
        return None


def _hash_key(private: bytes, secret: bytes, pk0: bytes, pk1: bytes) -> bytes:
    state = hashlib.blake2b(digest_size=KEY_SIZE, key=private)
    state.update(secret + pk0 + pk1)
    return state.digest()


class KeyExchange:
    """Private (pre-shared) key plus rotating ephemeral X25519 session keys (mud_keyx)."""

    def __init__(self, private: bytes):
        self.private = (private, private)
        self.current = self.next = self.last = self.private   # (encrypt, decrypt)
        self.secret = self.local = None
        self.remote = bytes(KEY_SIZE)
        self.time = 0
        self.use_next = False

    def rotate_if_due(self, now: int, timeout: int = KX_TIMEOUT) -> bool:
        if self.time and tmask(now - self.time) < timeout:
            return False
        while True:
            secret = os.urandom(KEY_SIZE)
            local = _sodium.crypto_scalarmult_base(secret)
            try:  # the original rejects a keypair whose product with a fixed test point is all zero
                _sodium.crypto_scalarmult(bytes.fromhex(
                    "9bf414900feff82d11326e3d99ce96b94f793101abafe303591acdddb0fbe349"), local)
                break
            except (RuntimeError, ValueError):
                continue
        self.secret, self.local, self.time = secret, local, now
        return True

    def derive(self, remote: bytes) -> bool:
        if self.secret is None:
            return False
        try:
            shared = _sodium.crypto_scalarmult(self.secret, remote)
        except (RuntimeError, ValueError):
            return False
        key = self.private[0]
        self.next = (_hash_key(key, shared, remote, self.local), _hash_key(key, shared, self.local, remote))
        self.remote = remote
        return True

    def encrypt(self, now: int, plaintext: bytes) -> bytes:
        keys = self.next if self.use_next else self.current
        return seal(keys[0], _store(now, TIME_SIZE), plaintext)

    def decrypt(self, packet: bytes) -> bytes | None:
        plain = unseal(self.current[1], packet)
        if plain is not None:
            return plain
        plain = unseal(self.next[1], packet)
        if plain is not None:
            self.last, self.current, self.use_next = self.current, self.next, False
            return plain
        return unseal(self.last[1], packet) or unseal(self.private[1], packet)


# --- control message (struct mud_msg, 125 bytes, little endian) -------------------------------

@dataclass
class Msg:
    sent_time: int = 0
    aes: int = 0
    pkey: bytes = bytes(KEY_SIZE)
    tx: tuple = (0, 0)       # (bytes, total)
    rx: tuple = (0, 0)
    fw: tuple = (0, 0)
    max_rate: int = 0
    beat: int = 0
    mtu: int = 0
    pref: int = 0
    loss: int = 0
    fixed_rate: int = 0
    loss_limit: int = 0
    addr: tuple = ("0.0.0.0", 0)   # the receiver's address as the sender sees it

    def pack(self) -> bytes:
        ip, port = self.addr
        out = (_store(self.sent_time, 6) + bytes([self.aes]) + self.pkey
               + b"".join(_store(v, 8) for pair in (self.tx, self.rx, self.fw) for v in pair)
               + _store(self.max_rate, 8) + _store(self.beat, 6) + _store(self.mtu, 2)
               + bytes([self.pref, self.loss, self.fixed_rate, self.loss_limit])
               + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack("!H", port))
        assert len(out) == MSG_SIZE
        return out

    @classmethod
    def unpack(cls, raw: bytes) -> "Msg":
        if len(raw) < MSG_SIZE:
            raise ValueError("short control message")
        pairs = [(_load(raw[o:o + 8]), _load(raw[o + 8:o + 16])) for o in (39, 55, 71)]
        return cls(_load(raw[0:6]), raw[6], bytes(raw[7:39]), pairs[0], pairs[1], pairs[2],
                   _load(raw[87:95]), _load(raw[95:101]), _load(raw[101:103]),
                   raw[103], raw[104], raw[105], raw[106],
                   (socket.inet_ntoa(raw[119:123]), struct.unpack("!H", raw[123:125])[0]))


# --- clock ---------------------------------------------------------------------------------------

class Clock:
    """Unix microseconds with bit 0 cleared, advanced by the monotonic clock (mud_now)."""

    def __init__(self):
        mono = time.monotonic_ns() // 1000
        self.base = max(0, time.time_ns() // 1000 - mono)

    def now(self) -> int:
        return tmask(self.base + time.monotonic_ns() // 1000)


# --- paths ------------------------------------------------------------------------------------

@dataclass
class _Stat:
    val: int = 0
    var: int = 0
    setup: bool = False

    def update(self, value: int) -> None:
        if self.setup:
            self.var = ((self.var << 1) + self.var + abs(self.val - value)) >> 2
            self.val = ((self.val << 3) - self.val + value) >> 3
        else:
            self.setup, self.var, self.val = True, value >> 1, value


@dataclass
class _Dir:
    total: int = 0
    bytes: int = 0
    time: int = 0
    rate: int = 0
    loss: int = 0


@dataclass
class _MsgState:
    time: int = 0
    sent: int = 0
    set: bool = False
    tx_time: int = 0
    rx_time: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_total: int = 0
    rx_total: int = 0
    tx_acc: int = 0
    rx_acc: int = 0


@dataclass
class Path:
    local_ip: str
    sock: socket.socket | None
    remote: tuple
    tx_max_rate: int           # bytes per second
    rx_max_rate: int
    pref: int = 1
    beat: int = 100 * ONE_MSEC
    fixed_rate: int = 1
    loss_limit: int = 255
    status: int = PROBING
    idle: int = 0
    tx: _Dir = field(default_factory=_Dir)
    rx: _Dir = field(default_factory=_Dir)
    rtt: _Stat = field(default_factory=_Stat)
    msg: _MsgState = field(default_factory=_MsgState)
    mtu_min: int = 0
    mtu_max: int = 0
    mtu_probe: int = 0
    mtu_last: int = 0
    mtu_ok: int = 0
    slot: int = 0
    index: int | None = None       # Windows interface index used to pin the socket
    enabled: bool = True           # False: adapter missing or role "never"
    role: str = "primary"
    base_pref: int = 1
    demoted: bool = False          # advertised with a worse preference so the server also avoids it
    bad_since: float = 0.0
    good_since: float = 0.0
    bad: bool = False
    base_rtt: float | None = None
    reason: str = ""
    data_tx: int = 0               # data packets (not control probes) sent on this path

    def update_mtu(self, size: int) -> None:
        if not self.mtu_probe:
            if not self.mtu_last:
                self.mtu_min, self.mtu_max, self.mtu_probe = MTU_MIN, MTU_MAX, MTU_MAX
            return
        if size:
            if self.mtu_min > size or self.mtu_max < size:
                return
            self.mtu_min, self.mtu_last = size + 1, size
        else:
            self.mtu_max = self.mtu_probe - 1
        self.mtu_probe = 0 if self.mtu_min > self.mtu_max else (self.mtu_min + self.mtu_max) >> 1


def windows_pin(sock: socket.socket, index: int) -> None:
    """Pin a socket's outgoing interface (Winsock IP_UNICAST_IF takes a DWORD in network byte order)."""
    if not hasattr(socket, "IP_UNICAST_IF") and os.name != "nt":
        raise OSError("interface pinning is supported on Windows only")
    sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_UNICAST_IF", 31), struct.pack("=I", socket.htonl(index)))


class MudClient:
    """One Glorytun UDP session from several local addresses to one server."""

    def __init__(self, key: bytes, server: tuple, local_ips: list[str], *, rate_mbps: float = 100.0,
                 prefs: list[int] | None = None, beat_ms: int = 100, clock: Clock | None = None,
                 interface_indices: list[int] | None = None, available: list[bool] | None = None,
                 roles: list[str] | None = None, pin=None, jitter_threshold_ms: float = 8.0,
                 demote_after: float = 0.3, recovery_seconds: float = 3.0):
        if len(key) != KEY_SIZE or not local_ips:
            raise ValueError("a 32-byte key and at least one local address are required")
        self.server = (server[0], int(server[1]))
        self.threads: list[threading.Thread] = []
        self.paths: list[Path] = []
        self.clock = clock or Clock()
        self.kx = KeyExchange(key)
        self.lock = threading.RLock()
        self.inbox: "queue.Queue[bytes]" = queue.Queue(maxsize=4096)
        self.stop = threading.Event()
        self.pref = 0
        self.rate = 0
        self.mtu = 0
        self.window = 0
        self.window_time = self.clock.now()
        self.pin = pin if pin is not None else windows_pin
        self.beat = beat_ms * ONE_MSEC
        self.rate_bps = int(rate_mbps * 1_000_000 / 8)
        self.jitter_threshold_ms, self.demote_after, self.recovery_seconds = jitter_threshold_ms, demote_after, recovery_seconds
        self.last_assess = 0.0
        self.pause = False
        self.sel_lock = threading.Lock()
        self.last_recv_time = 0
        self.errors = dict(decrypt=0, clocksync=0, keyx=0, malformed=0, dropped_window=0, no_path=0)
        count = len(local_ips)
        for name, value in (("interface_indices", interface_indices), ("available", available), ("roles", roles), ("prefs", prefs)):
            if value is not None and len(value) != count:
                raise ValueError(f"{name} must have one entry per local address")
        self.selector = selectors.DefaultSelector()
        try:
            for slot, ip in enumerate(local_ips):
                up = True if available is None else bool(available[slot])
                role = roles[slot] if roles else "primary"
                if role not in ROLE_PREF and role != "never":
                    raise ValueError("unknown link role " + role)
                path = self._new_path(slot, ip, interface_indices[slot] if interface_indices else None, up, role,
                                      prefs[slot] if prefs else None)
                self.paths.append(path)
        except BaseException:
            self.close()
            raise

    def _new_path(self, slot: int, ip: str, index, up: bool, role: str, pref=None) -> Path:
        """A path for one uplink slot. Missing adapters and role "never" get no socket and carry no traffic."""
        enabled = up and role != "never" and ip not in ("", "0.0.0.0")
        sock = None
        reason = "" if enabled else ("role never" if role == "never" else "adapter unavailable")
        if enabled:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                if index is not None:
                    self.pin(sock, index)            # same Winsock IP_UNICAST_IF pinning the GameBond transport uses
                sock.bind((ip, 0))
            except OSError as exc:
                if sock is not None:
                    sock.close()
                sock, enabled, reason = None, False, str(exc)
        base = pref if pref is not None else ROLE_PREF.get(role, 1)
        path = Path(ip, sock, self.server, self.rate_bps, self.rate_bps, pref=base, beat=self.beat,
                    idle=self.clock.now(), slot=slot, index=index, enabled=enabled, role=role, base_pref=base, reason=reason)
        path.tx.rate = self.rate_bps                # fixed rate: tx.rate == tx_max_rate
        if sock is not None:
            self.selector.register(sock, selectors.EVENT_READ, path)
        return path

    def update_paths(self, local_ips: list[str], interface_indices: list[int] | None = None,
                     available: list[bool] | None = None) -> list[dict]:
        """Follow adapter changes: rebind only slots whose address, interface or availability changed."""
        if len(local_ips) != len(self.paths):
            raise ValueError("path slots must remain stable")
        errors = []
        self.pause = True
        try:
            with self.sel_lock, self.lock:
                for slot, ip in enumerate(local_ips):
                    old = self.paths[slot]
                    index = interface_indices[slot] if interface_indices else None
                    up = True if available is None else bool(available[slot])
                    wanted = up and old.role != "never" and ip not in ("", "0.0.0.0")
                    if ip == old.local_ip and index == old.index and wanted == old.enabled:
                        continue
                    if old.sock is not None:
                        try:
                            self.selector.unregister(old.sock)
                        except (KeyError, ValueError):
                            pass
                        old.sock.close()
                    custom = old.base_pref if old.base_pref != ROLE_PREF.get(old.role) else None
                    fresh = self._new_path(slot, ip, index, up, old.role, custom)
                    for name in ("total", "bytes"):                       # keep usage counters across a rebind
                        setattr(fresh.tx, name, getattr(old.tx, name))
                        setattr(fresh.rx, name, getattr(old.rx, name))
                    if wanted and not fresh.enabled:
                        errors.append(dict(slot=slot, error=fresh.reason))
                    self.paths[slot] = fresh
                self.errors["rebinds"] = self.errors.get("rebinds", 0) + 1
        finally:
            self.pause = False
        return errors

    def set_roles(self, roles: list[str]) -> None:
        """Link roles from GameBond's link controls: primary and secondary aggregate, backup is hot standby, never is off."""
        if len(roles) != len(self.paths) or any(r not in ROLE_PREF and r != "never" for r in roles):
            raise ValueError("one valid role per path is required")
        with self.lock:
            for path, role in zip(self.paths, roles):
                if role == path.role:
                    continue
                path.role = role
                path.base_pref = ROLE_PREF.get(role, path.base_pref)
                if role == "never" and path.enabled:
                    path.enabled, path.reason = False, "role never"
                elif role != "never" and not path.enabled and path.reason == "role never":
                    path.enabled, path.reason = path.sock is not None, ""
                path.pref = path.base_pref + (DEMOTION if path.demoted else 0)

    def set_rates(self, upload_mbps: list[float], download_mbps: list[float]) -> None:
        """Per-link speed limits (0 = unlimited). Upload caps what we send; download is advertised so the server
        sends no faster than that toward us (the server copies it from every control message)."""
        if len(upload_mbps) != len(self.paths) or len(download_mbps) != len(self.paths):
            raise ValueError("one limit per path is required")
        with self.lock:
            for path, up, down in zip(self.paths, upload_mbps, download_mbps):
                if up < 0 or down < 0:
                    raise ValueError("limits must not be negative")
                path.tx_max_rate = int(up * 125_000) if up else self.rate_bps
                path.rx_max_rate = int(down * 125_000) if down else self.rate_bps
                path.tx.rate = min(path.tx.rate or path.tx_max_rate, path.tx_max_rate) if path.fixed_rate == 0 else path.tx_max_rate

    # lifecycle
    def start(self) -> "MudClient":
        self.kx.rotate_if_due(self.clock.now())
        for target in (self._reader, self._timer):
            thread = threading.Thread(target=target, daemon=True, name="gamebond-omr-" + target.__name__)
            thread.start()
            self.threads.append(thread)
        return self

    def close(self) -> None:
        self.stop.set()
        for thread in self.threads:
            thread.join(2)
        for path in self.paths:
            if path.sock is None:
                continue
            try:
                self.selector.unregister(path.sock)
            except (KeyError, ValueError):
                pass
            path.sock.close()
        self.selector.close()

    @property
    def tunnel_mtu(self) -> int:
        return self.mtu - PKT_MIN if self.mtu else 0

    @property
    def ready(self) -> bool:
        return self.rate > 0 and self.tunnel_mtu > 0

    def stats(self) -> dict:
        with self.lock:
            return dict(ready=self.ready, tunnel_mtu=self.tunnel_mtu, errors=dict(self.errors), paths=[
                dict(slot=p.slot, local=p.local_ip, enabled=p.enabled, reason=p.reason, role=p.role, status=p.status,
                     mtu=p.mtu_ok, rtt_ms=p.rtt.val / 1000, jitter_ms=p.rtt.var / 1000, pref=p.pref, demoted=p.demoted,
                     bad=p.bad, tx_bytes=p.tx.bytes, rx_bytes=p.rx.bytes, tx_packets=p.tx.total, rx_packets=p.rx.total,
                     data_tx=p.data_tx, loss=p.tx.loss) for p in self.paths])

    # data plane
    def send(self, packet: bytes, urgent: bool = False) -> bool:
        """Encrypt and send one IP packet. Normal traffic is striped by rate weight; urgent traffic uses the
        single best path (lowest predicted latency, not suspect) so a degrading link never carries it.
        False if not ready or throttled."""
        if not packet:
            return False
        with self.lock:
            if self.window < 1500:
                self.errors["dropped_window"] += 1
                return False
            if self.mtu and len(packet) + PKT_MIN > self.mtu:
                return False
            now = self.clock.now()
            wire = self.kx.encrypt(now, bytes(packet))
            cursor = struct.unpack("<H", wire[-2:])[0]
            path = self._best_path() if urgent else self._select_path(cursor)
            if path is None:
                self.errors["no_path"] += 1
                return False
            path.idle = now
            path.data_tx += 1
            self._send_path(path, now, wire)
            return True

    def recv(self, timeout: float | None = None) -> bytes:
        return self.inbox.get(timeout=timeout)

    @staticmethod
    def predicted_ms(path: Path) -> float:
        """Same shape as GameBond's own estimate: half the round trip plus twice the jitter."""
        return path.rtt.val / 2000 + 2 * path.rtt.var / 1000 if path.rtt.setup else 1000.0

    def _best_path(self) -> Path | None:
        usable = [p for p in self.paths if p.enabled and p.status == RUNNING]
        if not usable:
            return None
        usable.sort(key=lambda p: (p.bad or p.msg.sent >= 2, self.predicted_ms(p)))
        return usable[0]

    def _select_path(self, cursor: int) -> Path | None:
        k = (cursor * self.rate) >> 16
        for path in self.paths:
            if path.status != RUNNING or not path.enabled:
                continue
            if k < path.tx.rate:
                return path
            k -= path.tx.rate
        return None

    def _send_path(self, path: Path, now: int, wire: bytes) -> None:
        try:
            path.sock.sendto(wire, path.remote)
        except OSError:
            pass  # a path that cannot send is handled by its own timeouts
        path.tx.total += 1
        path.tx.bytes += len(wire)
        path.tx.time = now
        self.window = self.window - len(wire) if self.window > len(wire) else 0

    # control plane
    def _send_msg(self, path: Path, now: int, sent_time: int, fw_bytes: int, fw_total: int, size: int) -> None:
        size = min(max(size, PKT_MIN + MSG_SIZE), PKT_MAX)
        message = Msg(sent_time=sent_time, aes=0, pkey=self.kx.local or bytes(KEY_SIZE),
                      tx=(path.tx.bytes, path.tx.total), rx=(path.rx.bytes, path.rx.total), fw=(fw_bytes, fw_total),
                      max_rate=path.rx_max_rate, beat=path.beat,
                      mtu=0 if path.mtu_probe else path.mtu_last,
                      pref=path.pref, loss=min(path.tx.loss, 255), fixed_rate=path.fixed_rate,
                      loss_limit=path.loss_limit, addr=path.remote)
        plain = message.pack().ljust(size - PKT_MIN, b"\0")
        self._send_path(path, now, seal(self.kx.private[0], _store(now | 1, TIME_SIZE), plain))

    def _recv_msg(self, path: Path, now: int, header_time: int, size: int, plain: bytes) -> None:
        message = Msg.unpack(plain)
        if not message.sent_time:
            return  # the server never initiates; only echoes of our probes are meaningful
        path.rtt.update(tmask(now - message.sent_time))
        tx_bytes, tx_total = message.fw
        rx_bytes, rx_total = message.rx
        m = path.msg
        if (message.sent_time > m.tx_time and tx_bytes > m.tx_bytes and header_time > m.rx_time and rx_bytes > m.rx_bytes):
            if m.set and path.status > PROBING:
                self._update_rl(path, tmask(message.sent_time - m.tx_time), tx_bytes - m.tx_bytes, tx_total - m.tx_total,
                                tmask(header_time - m.rx_time), rx_bytes - m.rx_bytes, rx_total - m.rx_total)
            m.tx_time, m.rx_time, m.tx_bytes, m.rx_bytes = message.sent_time, header_time, tx_bytes, rx_bytes
            m.tx_total, m.rx_total, m.set = tx_total, rx_total, True
        path.rx.loss = message.loss
        m.sent = 0
        path.update_mtu(size)
        if path.mtu_last and path.mtu_last == message.mtu:
            path.mtu_ok = path.mtu_last
        if message.pkey != self.kx.remote:
            if not self.kx.derive(message.pkey):
                self.errors["keyx"] += 1
                return
        else:
            self.kx.use_next = True   # the peer has echoed our key: switch to the session keys
        self._send_msg(path, now, header_time, message.tx[0], message.tx[1], size)

    def _update_rl(self, path: Path, tx_dt: int, tx_bytes: int, tx_pkt: int, rx_dt: int, rx_bytes: int, rx_pkt: int) -> None:
        m = path.msg
        if rx_dt and rx_dt > tx_dt + (tx_dt >> 3):
            if not path.fixed_rate:
                path.tx.rate = (7 * rx_bytes * ONE_SEC) // (8 * rx_dt)
        else:
            tx_acc, rx_acc = m.tx_acc + tx_pkt, m.rx_acc + rx_pkt
            if tx_acc > 1000:
                if tx_acc >= rx_acc:
                    path.tx.loss = (tx_acc - rx_acc) * 255 // tx_acc
                m.tx_acc, m.rx_acc = tx_acc - (tx_acc >> 4), rx_acc - (rx_acc >> 4)
            else:
                m.tx_acc, m.rx_acc = tx_acc, rx_acc
            if not path.fixed_rate:
                path.tx.rate += path.tx.rate // 10
        path.tx.rate = min(path.tx.rate, path.tx_max_rate)

    def _reader(self) -> None:
        while not self.stop.is_set():
            if self.pause:                       # update_paths is swapping sockets
                time.sleep(0.002)
                continue
            with self.sel_lock:
                try:
                    events = self.selector.select(0.02)
                except (OSError, ValueError):
                    events = []
            for key, _ in events:
                path = key.data
                for _ in range(64):
                    if path.sock is None:
                        break
                    try:
                        packet, address = path.sock.recvfrom(PKT_MAX)
                    except (BlockingIOError, InterruptedError, OSError):
                        break
                    with self.lock:
                        if path in self.paths:
                            self._on_packet(path, address, packet)

    def _on_packet(self, path: Path, address: tuple, packet: bytes) -> None:
        if not path.enabled or len(packet) <= PKT_MIN or address != path.remote:
            return
        now = self.clock.now()
        header_time = _load(packet[:TIME_SIZE])
        if tmask(now - header_time) > TIME_TOLERANCE and tmask(header_time - now) > TIME_TOLERANCE:
            self.errors["clocksync"] += 1
            return
        is_msg = bool(header_time & 1)
        plain = unseal(self.kx.private[1], packet) if is_msg else self.kx.decrypt(packet)
        if plain is None or (is_msg and len(plain) < MSG_SIZE):
            self.errors["decrypt"] += 1
            return
        if is_msg:
            self._recv_msg(path, now, header_time, len(packet), plain)
        else:
            path.idle = now
            if len(plain) >= 20 and plain[0] >> 4 in (4, 6):
                try:
                    self.inbox.put_nowait(plain)
                except queue.Full:
                    self.errors["malformed"] += 1
            else:
                self.errors["malformed"] += 1
        path.rx.total += 1
        path.rx.time = now
        path.rx.bytes += len(packet)
        self.last_recv_time = now

    # periodic work (mud_update)
    def _timer(self) -> None:
        while not self.stop.wait(0.005):
            with self.lock:
                self._update()

    def _path_update(self, path: Path) -> bool:
        if path.msg.sent >= MSG_SENT_MAX:
            if path.mtu_probe:
                path.update_mtu(0)
                path.msg.sent = 0
            else:
                path.msg.sent = MSG_SENT_MAX
                path.status = DEGRADED
                return False
        if not path.mtu_ok:
            path.status = PROBING
            return False
        if path.tx.loss > path.loss_limit or path.rx.loss > path.loss_limit:
            path.status = LOSSY
            return False
        if path.pref > self.pref:
            path.status = READY
        elif path.status != RUNNING:
            path.status, path.idle = RUNNING, self.clock.now()
        return True

    def _path_track(self, path: Path, now: int) -> int:
        timeout = path.beat
        if path.status == RUNNING:
            if tmask(now - path.idle) >= ONE_SEC:
                timeout = KEEPALIVE
        elif path.status == READY:
            # Beyond the original: keep a hot standby (or a demoted path) measured and alive with a cheap probe,
            # so its quality is known and its recovery is noticed.
            timeout = max(path.beat, 250 * ONE_MSEC)
        elif path.status not in (DEGRADED, LOSSY, PROBING):
            return now
        if not path.msg.time or tmask(now - path.msg.time) >= timeout:
            path.msg.sent += 1
            path.msg.time = now
            self._send_msg(path, now, 0, 0, 0, path.mtu_probe)
            now = self.clock.now()
        return now

    def _assess(self, now_s: float) -> None:
        """Judge each path (missed echoes, RTT spike against its own baseline, jitter, loss) with hysteresis and
        advertise a worse preference for a degrading path whenever a better one exists. The server copies the
        preference from every control message, so it stops sending downstream on that path too."""
        if now_s - self.last_assess < 0.05:
            return
        elapsed, self.last_assess = now_s - self.last_assess if self.last_assess else 0.05, now_s
        for path in self.paths:
            if not path.enabled:
                path.bad = False
                continue
            rtt, jitter = path.rtt.val / 1000, path.rtt.var / 1000
            known = path.rtt.setup and path.mtu_ok
            if known:
                path.base_rtt = rtt if path.base_rtt is None else min(rtt, path.base_rtt + 0.5 * elapsed)   # relearns over time
            spike = known and rtt > 2 * (path.base_rtt or rtt) + 20
            reasons = [name for name, hit in (("missed", path.msg.sent >= 2), ("latency", spike),
                       ("jitter", known and jitter > self.jitter_threshold_ms), ("loss", path.tx.loss > 5)) if hit]
            path.bad, path.reason = bool(reasons), ",".join(reasons)
            if path.bad:
                path.bad_since = path.bad_since or now_s
                path.good_since = 0.0
            else:
                path.good_since = path.good_since or now_s
                path.bad_since = 0.0
        for path in self.paths:
            if not path.enabled:
                continue
            other_good = any(o is not path and o.enabled and not o.bad and o.mtu_ok for o in self.paths)
            if not path.demoted and path.bad and other_good and now_s - path.bad_since >= self.demote_after:
                path.demoted, path.pref = True, path.base_pref + DEMOTION
                self.errors["demotions"] = self.errors.get("demotions", 0) + 1
            elif path.demoted and not path.bad and now_s - path.good_since >= self.recovery_seconds:
                path.demoted, path.pref = False, path.base_pref
            elif path.demoted and path.bad and not other_good:
                path.demoted, path.pref = False, path.base_pref   # nothing better to prefer: do not strand the traffic

    def _update(self) -> None:
        self._assess(time.monotonic())
        now = self.clock.now()
        self.kx.rotate_if_due(now)
        pref, next_pref, rate, mtu = 255, 255, 0, 0
        active = [p for p in self.paths if p.enabled]
        for path in self.paths:
            if not path.enabled:
                path.status = PROBING
        for path in active:
            if self._path_update(path):
                if next_pref > path.pref > self.pref:
                    next_pref = path.pref
                pref = min(pref, path.pref)
                if path.status == RUNNING:
                    rate += path.tx.rate
            if path.mtu_ok and (not mtu or mtu > path.mtu_ok):
                mtu = path.mtu_ok
            now = self._path_track(path, now)
        if rate:
            self.pref = pref
        else:
            self.pref = next_pref
            for path in active:
                if self._path_update(path) and path.status == RUNNING:
                    rate += path.tx.rate
        self.rate, self.mtu = rate, mtu
        elapsed = tmask(now - self.window_time)
        if elapsed > ONE_MSEC:
            self.window += self.rate * elapsed // ONE_SEC
            self.window_time = now
        self.window = min(self.window, self.rate * 100 * ONE_MSEC // ONE_SEC)
