"""Experimental authenticated UDP multipath transport, independent of Speedify.

One Node pair represents one configured session. Distribute the 16-byte session
and 32-byte PSK over a trusted channel. GB03 authenticates process restarts with
fresh challenge proofs before changing the peer's random encryption domain.
Legacy GB01 still requires both ends to restart with a fresh session. This PSK
protocol provides no forward secrecy or compatibility with another VPN.
"""
from __future__ import annotations

import hmac
import queue
import secrets
import select
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from collections import OrderedDict, deque
import math

from .link_limits import MAX_LINKS
from .bonding import PathBudget
from .reorder import ReorderBuffer
from .path_quality import CopyLedger, MtuProber
from .policy import parse_packet,is_tcp_control
from .link_policy import (WirePacer, validate_state, encode_state, decode_state,
                          POLICY_HEADER, POLICY_ACK_HEADER)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HEADER = struct.Struct("!4s16s16sBQ")
MAGIC = b"GB01"
DATA, PROBE, PONG = 1, 2, 3
STRIPED, FEEDBACK = 4, 5
HELLO, CHALLENGE, RESET, READY = 6, 7, 8, 9
REPAIR = 10
LINK_POLICY, LINK_POLICY_ACK = 11, 12
# Receivers always accept these in bonded mode; senders emit them only when the
# matching option is on (or, for REPAIR_NA, in answer to a REPAIR request).
DATA_COPY, MTU_PROBE, MTU_ACK, REPAIR_NA, COPY_REPORT = 13, 14, 15, 16, 17
DATA_KINDS = (DATA, DATA_COPY)
MTU_PROBE_HEADER = struct.Struct('!QI')  # nonce, claimed datagram size
COPY_REPORT_HEADER = struct.Struct('!QQQ')  # cumulative seen, missed, late
COPY_REPORT_INTERVAL = .5
REPAIR_HEADER = struct.Struct('!QQ')
HANDSHAKE_TIMEOUT = 2.0
HANDSHAKE_CAPACITY = 8
STRIPE_HEADER = struct.Struct("!QQQ")  # flow, flow sequence, sender path epoch
FEEDBACK_HEADER = struct.Struct("!QQQI")  # path epoch, sequence, received bytes, receiver hold microseconds
MAX_ACK_DELAY_US = 1_000_000

def _repairable(payload):
    try:
        info = parse_packet(payload)
        return info.protocol == 6 and not info.fragmented
    except ValueError:
        return False
BOND_OVERHEAD = STRIPE_HEADER.size
BOND_MAGIC = b"GB03"
OVERHEAD = HEADER.size + 16
REPLAY_WINDOW = 8192
FLOW_CACHE_CAPACITY = 8192
FLOW_IDLE_TIMEOUT = 120.0


def _enable_df(sock) -> bool:
    """Set don't-fragment so an oversize datagram fails instead of fragmenting.

    Returns False when the platform call is unavailable; MTU probe answers then
    prove delivery but not absence of IP fragmentation.
    """
    try:
        if sys.platform == "win32":
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_DONTFRAGMENT", 14), 1)
        elif sys.platform.startswith("linux"):
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10),
                            getattr(socket, "IP_PMTUDISC_DO", 2))
        else:
            return False
        return True
    except OSError:
        return False


class _PriorityInbox:
    """Bounded packet inbox; authenticated DATA precedes reordered bulk.

    Both classes retain FIFO order. A priority admission can evict the oldest
    bulk payload, but never another priority payload. The condition owns only
    inbox state and never acquires Node's crypto/state lock.
    """

    def __init__(self, capacity):
        self.capacity = capacity
        self._priority, self._bulk = deque(), deque()
        self._condition = threading.Condition()
        self._closed = False
        self._bytes = {"priority": 0, "bulk": 0}
        self._counts = {name: 0 for name in (
            "priority_admitted", "bulk_admitted", "priority_dequeued", "bulk_dequeued",
            "priority_full_drops", "bulk_full_drops", "bulk_evicted_for_priority",
            "priority_reset_drops", "bulk_reset_drops", "peak_packets")}
        self._residence = {kind: {"samples": 0, "total_seconds": 0.0, "max_seconds": 0.0}
                           for kind in ("priority", "bulk")}

    def put_nowait(self, payload, *, priority=False):
        """Return True if admission evicted bulk; otherwise False or queue.Full."""
        kind = "priority" if priority else "bulk"
        with self._condition:
            evicted = False
            if self._closed:
                self._counts[kind + "_full_drops"] += 1
                raise queue.Full
            if len(self._priority) + len(self._bulk) >= self.capacity:
                if priority and self._bulk:
                    old_payload, _ = self._bulk.popleft()
                    self._bytes["bulk"] -= len(old_payload)
                    self._counts["bulk_evicted_for_priority"] += 1
                    evicted = True
                else:
                    self._counts[kind + "_full_drops"] += 1
                    raise queue.Full
            target = self._priority if priority else self._bulk
            target.append((payload, time.perf_counter()))
            self._bytes[kind] += len(payload)
            self._counts[kind + "_admitted"] += 1
            self._counts["peak_packets"] = max(self._counts["peak_packets"], len(self._priority) + len(self._bulk))
            self._condition.notify()
            return evicted

    def get(self, block=True, timeout=None):
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be nonnegative")
        with self._condition:
            deadline = None if timeout is None else time.perf_counter() + timeout
            while not self._priority and not self._bulk:
                if not block or self._closed:
                    raise queue.Empty
                remaining = None if deadline is None else deadline - time.perf_counter()
                if remaining is not None and remaining <= 0:
                    raise queue.Empty
                self._condition.wait(remaining)
            kind = "priority" if self._priority else "bulk"
            payload, queued_at = (self._priority if self._priority else self._bulk).popleft()
            self._bytes[kind] -= len(payload)
            self._counts[kind + "_dequeued"] += 1
            residence = max(0.0, time.perf_counter() - queued_at)
            sample = self._residence[kind]
            sample["samples"] += 1
            sample["total_seconds"] += residence
            sample["max_seconds"] = max(sample["max_seconds"], residence)
            return payload

    def get_nowait(self):
        return self.get(block=False)

    def clear(self):
        with self._condition:
            removed = len(self._priority) + len(self._bulk)
            for kind, target in (("priority", self._priority), ("bulk", self._bulk)):
                self._counts[kind + "_reset_drops"] += len(target)
                target.clear()
                self._bytes[kind] = 0
            return removed

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    def stats(self):
        with self._condition:
            now = time.perf_counter()
            result = {**self._counts, "capacity_packets": self.capacity,
                      "queued_packets": len(self._priority) + len(self._bulk)}
            for kind, target in (("priority", self._priority), ("bulk", self._bulk)):
                residence = self._residence[kind]
                result[kind] = {
                    "queued_packets": len(target), "queued_bytes": self._bytes[kind],
                    "oldest_age_ms": max(0.0, now - target[0][1]) * 1000 if target else 0.0,
                    "residence_samples": residence["samples"],
                    "mean_residence_ms": residence["total_seconds"] * 1000 / residence["samples"] if residence["samples"] else 0.0,
                    "max_residence_ms": residence["max_seconds"] * 1000,
                }
            return result


class ReplayWindow:
    """Bounded bitmap accepting reordered packets once, without waiting for gaps."""

    def __init__(self, width: int = REPLAY_WINDOW):
        self.width = width
        self.highest = -1
        self.bits = 0

    def accept(self, sequence: int) -> bool:
        if sequence > self.highest:
            shift = sequence - self.highest
            self.bits = ((self.bits << shift) | 1) & ((1 << self.width) - 1) if shift < self.width else 1
            self.highest = sequence
            return True
        age = self.highest - sequence
        if age >= self.width or self.bits & (1 << age):
            return False
        self.bits |= 1 << age
        return True


@dataclass
class _Path:
    available: bool = field(default=True,init=False)
    probe_sent: int = field(default=0,init=False)
    probe_acked: int = field(default=0,init=False)
    probe_lost: int = field(default=0,init=False)
    probe_lost_early: int = field(default=0,init=False)
    probe_late: int = field(default=0,init=False)
    probe_acked_sent_at: float = field(default=-1.0,init=False)
    copy_seen: int = field(default=0,init=False)
    copy_missed: int = field(default=0,init=False)
    copy_late: int = field(default=0,init=False)
    copy_lag_ms: float | None = field(default=None,init=False)
    copy_reported: tuple = field(default=(0,0,0),init=False)
    last_copy_report: float = field(default=0.0,init=False)
    peer_copy: tuple | None = field(default=None,init=False)
    mtu_prober: MtuProber | None = field(default=None,init=False)
    mtu_skips: int = field(default=0,init=False)
    socket_index: int
    endpoint: tuple[str, int]
    last_rx: float = 0.0
    rtt_ms: float | None = None
    rtt_jitter_ms: float = 0.0
    bulk_finish: float = 0.0
    bulk_filtered: bool = False
    link_state: dict | None = None
    wire_pacer: WirePacer = field(default_factory=WirePacer)
    policy_revision: int = 0
    policy_confirmed: bool = True
    last_policy_sent: float = -1
    rx_wire_packets: int = 0
    remote_wire_tx: int = 0
    remote_wire_epoch: int | None = None
    remote_wire_offset: int = 0
    received: int = 0
    transmitted: int = 0
    errors: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    budget: PathBudget | None = None
    stripe_rx_bytes: int = 0
    stripe_rx_highest: int = -1
    stripe_rx_highest_at: float | None = None
    feedback_due: bool = False
    last_feedback: float = 0.0
    tx_epoch: int = 0
    rx_epoch: int | None = None
    accepted_feedback: tuple[int, int] | None = None
    last_sequence: int = -1
    ready: bool = False
    hello_nonce: bytes | None = None
    hello_started: float = 0.0
    server_nonce: bytes | None = None
    challenge_prefix: bytes | None = None
    confirmation: bytes | None = None
    confirmation_expires: float = 0.0
    priority_tx_packets: int = 0
    priority_tx_wire_bytes: int = 0
    priority_rx_first_packets: int = 0
    priority_rx_duplicate_packets: int = 0
    priority_rx_too_old_packets: int = 0


class Node:
    """Threaded single-peer IPv4 transport.

    Client bind addresses must be concrete addresses belonging to the physical
    links. On Windows ``interface_indices`` pins each outgoing socket to its
    corresponding physical interface. Without it, routing remains the caller's
    responsibility. Server paths are learned only from fresh authenticated
    packets. ``mtu`` bounds the complete UDP payload, not the outer IP packet.
    Replicated data uses immediate first-arrival delivery. Opt-in bonding stripes
    nonreplicated packets with per-path feedback/pacing and bounded per-flow
    reordering and bounded recent bulk repair. Replicated priority data is never
    retransmitted or held for repair.
    Each socket requests a bounded SO_SNDBUF and uses nonblocking send calls;
    queue exhaustion drops that copy while other paths are still attempted.
    OS buffer accounting can differ from the request. The original conservative
    AIMD controller in bonded mode cannot guarantee modem/router queue bounds.
    """

    def __init__(self, key: bytes, role: str, session: bytes,
                 bind: list[tuple[str, int]], peer: tuple[str, int] | None = None,
                 *, mtu: int = 1280, probe_interval: float = .25,
                 path_timeout: float = 2.0, receive_capacity: int = 1024,
                 interface_indices: list[int] | None = None,
                 send_buffer_bytes: int = 65536,
                 receive_buffer_bytes: int = 4 * 1024 * 1024,
                 bonding_mode: bool = False, initial_rate_mbps: float = 1,
                 max_rate_mbps: float = 100, reorder_timeout: float = .03,
                 link_states: list[dict] | None = None, path_availability: list[bool] | None = None,
                 outer_transport: dict | None = None,
                 loss_tracking: bool = False, path_mtu_discovery: bool = False,
                 repair_deadline: float = .25):
        if len(key) != 32 or len(session) != 16:
            raise ValueError("key must be 32 bytes and session must be 16 bytes")
        if role not in ("client", "server"):
            raise ValueError("role must be client or server")
        if not bind or len(bind) > MAX_LINKS:
            raise ValueError("one to eight bind addresses required")
        if role == "client" and peer is None:
            raise ValueError("client requires a numeric IPv4 peer")
        if not OVERHEAD + 16 <= mtu <= 65507 or probe_interval <= 0 or path_timeout <= probe_interval:
            raise ValueError("invalid MTU or probe timing")
        if type(receive_capacity) is not int or receive_capacity <= 0:
            raise ValueError("receive_capacity must be a positive integer")
        if type(bonding_mode) is not bool:
            raise ValueError("bonding_mode must be a boolean")
        if type(loss_tracking) is not bool or type(path_mtu_discovery) is not bool:
            raise ValueError("loss_tracking and path_mtu_discovery must be booleans")
        if (type(repair_deadline) not in (int, float) or not math.isfinite(repair_deadline)
                or not .01 <= repair_deadline <= 2):
            raise ValueError("repair_deadline must be between 0.01 and 2 seconds")
        if (loss_tracking or path_mtu_discovery) and not bonding_mode:
            raise ValueError("loss_tracking and path_mtu_discovery require bonding_mode")
        if any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0
               for v in (initial_rate_mbps, max_rate_mbps, reorder_timeout)) or initial_rate_mbps > max_rate_mbps:
            raise ValueError("invalid bonding rates or reorder timeout")
        if bonding_mode and (mtu < OVERHEAD + BOND_OVERHEAD + 16 or not .001 <= reorder_timeout <= .2):
            raise ValueError("invalid bonding MTU or reorder timeout")
        if type(send_buffer_bytes) is not int or not max(4096, mtu) <= send_buffer_bytes <= 1048576:
            raise ValueError("send_buffer_bytes must be an integer between max(4096, mtu) and 1048576")
        if type(receive_buffer_bytes) is not int or not mtu <= receive_buffer_bytes <= 16 * 1024 * 1024:
            raise ValueError("receive_buffer_bytes must be an integer between mtu and 16777216")
        if interface_indices is not None:
            if len(interface_indices) != len(bind) or any(
                    type(index) is not int or not 0 < index < (1 << 24)
                    for index in interface_indices):
                raise ValueError("one positive 24-bit interface index per bind address required")
            if sys.platform != "win32":
                raise ValueError("interface_indices pinning is supported on Windows only")
        if peer:
            socket.inet_aton(peer[0])
        self.role, self.session, self.mtu = role, bytes(session), mtu
        self._peer=tuple(peer) if peer else None
        self._outer_settings=None;self._udp_recovery={}
        if outer_transport is not None:
            from .outer_transport import OuterSettings
            if role!='client' or not bonding_mode:raise ValueError('Outer fallback requires a bonded client')
            self._outer_settings=OuterSettings(**outer_transport)
        if link_states is not None and (role!='client' or not bonding_mode or len(link_states)!=len(bind)):
            raise ValueError('One client link state per physical path is required')
        self._link_states=[validate_state(s) for s in link_states] if link_states is not None else None
        self._policy_enabled=link_states is not None
        self._policy_revision=1
        self.bonding_mode = bonding_mode
        self._magic = BOND_MAGIC if bonding_mode else MAGIC
        self._initial_rate_mbps, self._max_rate_mbps = initial_rate_mbps, max_rate_mbps
        self._reorder = ReorderBuffer(timeout=reorder_timeout,allow_late=True)
        self._reorder_timeout = reorder_timeout
        self._stripe_flows: OrderedDict[object, tuple[int, int, float]] = OrderedDict()
        self._bulk_clock = 0.0
        self._repair_cache = OrderedDict()
        self._repair_requests = OrderedDict()
        self._repair_asked = OrderedDict()
        self._repair_next_request = 0.0
        self._repair_deadline = float(repair_deadline)
        self._loss_tracking = loss_tracking
        self._mtu_enabled = path_mtu_discovery
        self._df_enforced = {}
        self._copy_ledger = CopyLedger()
        self.probe_interval, self.path_timeout = probe_interval, path_timeout
        self._key = bytes(key)
        self._prefix = secrets.token_bytes(16)
        self._remote_prefix: bytes | None = None
        self._tx = self._cipher(self._prefix, role)
        self._rx: ChaCha20Poly1305 | None = None
        self._sequence = 0
        self._replay = ReplayWindow()
        self._receive_floor = 0
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._received = _PriorityInbox(receive_capacity)
        self._sockets: list[socket.socket] = []
        self._paths: dict[tuple[int, tuple[str, int]], _Path] = {}
        self._pending: dict[bytes, tuple[float, tuple[int, tuple[str, int]]]] = {}
        # Probes declared lost before path_timeout because a later probe on the
        # same path was answered. A reply that still arrives is a late sample,
        # not a loss, and must keep feeding the RTT/jitter estimate.
        self._lost_probes: dict[bytes, tuple[float, tuple[int, tuple[str, int]]]] = {}
        self._flow_paths: OrderedDict[object, tuple[tuple[int, tuple[str, int]], float]] = OrderedDict()
        self._challenges: OrderedDict[tuple[int, tuple[str, int], bytes], tuple[bytes, bytes, float]] = OrderedDict()
        self._counts = dict(tx_packets=0, tx_copies=0, rx_packets=0,
                            duplicates=0, auth_failures=0, malformed=0,
                            receive_drops=0, socket_errors=0, tx_bytes=0,
                            rx_bytes=0, tx_payload_bytes=0, rx_payload_bytes=0,
                            bonded_packets=0, bonding_deadline_drops=0,
                            feedback_received=0, feedback_rejected=0, feedback_duplicates=0,
                            handshake_hellos=0, handshake_challenges=0,
                            handshake_resets=0, handshake_ready=0,
                            handshake_rejected=0, peer_restarts=0, restart_discarded=0,
                            priority_tx_packets=0, priority_tx_wire_bytes=0,
                            priority_rx_first_packets=0, priority_rx_duplicate_packets=0,
                            priority_rx_too_old_packets=0, duplicate_copies=0,
                            replay_too_old_drops=0, replay_floor_drops=0)
        self._closed = False
        self._interface_indices = list(interface_indices) if interface_indices is not None else None
        self._bind_specs=list(bind)
        self._path_availability=list(path_availability) if path_availability is not None else [True]*len(bind)
        if len(self._path_availability)!=len(bind) or any(type(v) is not bool for v in self._path_availability):
            raise ValueError('One availability flag per path is required')
        self.send_buffer_bytes = send_buffer_bytes
        self.receive_buffer_bytes = receive_buffer_bytes
        self._receive_buffer_force_errors: dict[int, str] = {}
        try:
            for index, (host, port) in enumerate(bind):
                if not self._path_availability[index]:
                    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                    sock.bind(('127.0.0.1',0));sock.setblocking(False);self._sockets.append(sock)
                    continue
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buffer_bytes)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer_bytes)
                    # Linux reports twice SO_RCVBUF for kernel bookkeeping.
                    # A server container with CAP_NET_ADMIN can override its
                    # own socket's rmem_max clamp. Never change a host sysctl.
                    if (sys.platform.startswith("linux") and role == "server" and
                            sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) < 2 * receive_buffer_bytes):
                        try:
                            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_RCVBUFFORCE", 33), receive_buffer_bytes)
                        except OSError as exc:
                            self._receive_buffer_force_errors[index] = str(exc)
                    if interface_indices is not None:
                        # Winsock IP_UNICAST_IF takes a DWORD in network order.
                        # Packing the htonl result as a native unsigned DWORD
                        # also works for indices whose converted sign bit is set.
                        # https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
                        value = struct.pack("=I", socket.htonl(interface_indices[index]))
                        try:
                            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_UNICAST_IF", 31), value)
                        except OSError as exc:
                            raise OSError(
                                f"Cannot pin source {host} to Windows interface index "
                                f"{interface_indices[index]}: {exc}. Adapter indices can change; "
                                "check Get-NetIPAddress -AddressFamily IPv4 and update "
                                "interface_indices to match each configured bind address."
                            ) from exc
                    sock.bind((host, port))
                    sock.setblocking(False)
                    if path_mtu_discovery:
                        self._df_enforced[index] = _enable_df(sock)
                except Exception:
                    sock.close()
                    if path_availability is None:raise
                    self._path_availability[index]=False
                    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                    sock.bind(('127.0.0.1',0));sock.setblocking(False)
                self._sockets.append(self._wrap_carrier(sock,index))
            if peer:
                for index in range(len(self._sockets)):
                    self._paths[(index, peer)] = self._new_path(index, peer)
        except Exception:
            self.close()
            raise

    def _cipher(self, prefix: bytes, role: str) -> ChaCha20Poly1305:
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=self.session,
                   info=b"gamebond-v1/" + role.encode("ascii") + b"/" + prefix).derive(self._key)
        return ChaCha20Poly1305(key)

    def _wrap_carrier(self,sock,index):
        if self._outer_settings is None or not self._path_availability[index]:return sock
        from .outer_transport import CarrierSocket
        return CarrierSocket(sock,self._peer,self._key,self.session,self._outer_settings,
                             self._interface_indices[index] if self._interface_indices else None)

    def _new_path(self, index, endpoint):
        path = _Path(index, endpoint, budget=PathBudget(
            initial_rate_mbps=self._initial_rate_mbps, max_rate_mbps=self._max_rate_mbps),
            tx_epoch=secrets.randbits(64), ready=not self.bonding_mode)
        path.available=self._path_availability[index]
        if self._mtu_enabled:
            path.mtu_prober = MtuProber(self.mtu, min(548, self.mtu))
        if self._link_states is not None:
            path.link_state=dict(self._link_states[index]);path.policy_revision=self._policy_revision
            path.policy_confirmed=False
            path.wire_pacer.set_rate(path.link_state['upload_mbps'],time.perf_counter())
        return path

    def update_client_paths(self,bind,interface_indices=None,available=None):
        """Rebind changed physical paths, retaining the peer session and other sockets."""
        if self.role!='client' or len(bind)!=len(self._sockets):raise ValueError('Client path slots must remain stable')
        available=[True]*len(bind) if available is None else list(available)
        if len(available)!=len(bind) or any(type(v) is not bool for v in available):raise ValueError('Invalid path availability')
        if interface_indices is not None and (len(interface_indices)!=len(bind) or any(type(i) is not int or not 0<i<(1<<24) for i in interface_indices)):
            raise ValueError('Invalid physical interface indices')
        errors=[]
        with self._lock:
            if self._closed:return errors
            for index,spec in enumerate(bind):
                spec=tuple(spec);socket.inet_aton(spec[0])
                old_index=self._interface_indices[index] if self._interface_indices else None
                new_index=interface_indices[index] if interface_indices else None
                if spec==tuple(self._bind_specs[index]) and old_index==new_index and available[index]==self._path_availability[index]:continue
                sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                live=available[index]
                try:
                    sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,self.send_buffer_bytes)
                    sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,self.receive_buffer_bytes)
                    if live and new_index is not None:
                        sock.setsockopt(socket.IPPROTO_IP,getattr(socket,'IP_UNICAST_IF',31),struct.pack('=I',socket.htonl(new_index)))
                    sock.bind(spec if live else ('127.0.0.1',0));sock.setblocking(False)
                except OSError as exc:
                    sock.close();errors.append(dict(slot=index,error=str(exc)));live=False
                    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.setblocking(False)
                previous=self._sockets[index]
                self._path_availability[index]=live;self._bind_specs[index]=spec
                # The new interface index is needed by the carrier TCP socket.
                if self._interface_indices is not None:self._interface_indices[index]=new_index
                self._sockets[index]=self._wrap_carrier(sock,index)
                self._udp_recovery.pop(index,None)
                for identity,path in list(self._paths.items()):
                    if path.socket_index!=index:continue
                    fresh=self._new_path(index,path.endpoint)
                    for name in ('tx_bytes','rx_bytes','transmitted','received','rx_wire_packets'):
                        setattr(fresh,name,getattr(path,name))
                    fresh.remote_wire_offset=path.remote_wire_offset+path.remote_wire_tx
                    self._paths[identity]=fresh
                self._pending={token:value for token,value in self._pending.items() if value[1][0]!=index}
                self._lost_probes={token:value for token,value in self._lost_probes.items() if value[1][0]!=index}
                previous.close()
                self._counts['path_rebinds']=self._counts.get('path_rebinds',0)+1
            self._interface_indices=list(interface_indices) if interface_indices is not None else None
            self._probe()
        return errors

    def set_link_states(self,states):
        if self.role!='client' or len(states)!=len(self._sockets):raise ValueError('Invalid client link states')
        states=[validate_state(s) for s in states]
        with self._lock:
            if states==self._link_states:return
            self._link_states=states;self._policy_enabled=True;self._policy_revision+=1
            for path in self._paths.values():
                path.link_state=dict(states[path.socket_index]);path.policy_revision=self._policy_revision
                path.policy_confirmed=False;path.last_policy_sent=-1
                path.wire_pacer.set_rate(path.link_state['upload_mbps'],time.perf_counter())

    def _eligible_paths(self,paths,boost=False):
        if not self._policy_enabled:return paths
        paths=[p for p in paths if p.link_state is not None and p.policy_confirmed and not (p.link_state or {}).get('blocked',False)
               and (p.link_state or {}).get('role')!='never']
        primary=[p for p in paths if (p.link_state or {}).get('role','primary')=='primary']
        secondary=[p for p in paths if (p.link_state or {}).get('role')=='secondary']
        if primary:return primary+secondary if boost else primary
        if secondary:return secondary
        return [p for p in paths if (p.link_state or {}).get('role')=='backup']

    def _adopt_peer(self, prefix, cipher):
        """Called only after a fresh GB03 challenge proof (or legacy pinning)."""
        if self._remote_prefix == prefix:
            return
        if self._remote_prefix is not None:
            self._counts["peer_restarts"] += 1
        self._remote_prefix, self._rx = prefix, cipher
        self._replay = ReplayWindow()
        self._pending.clear()
        self._lost_probes.clear()
        self._flow_paths.clear()
        self._stripe_flows.clear()
        self._repair_cache.clear()
        self._repair_requests.clear()
        self._repair_asked.clear()
        self._repair_next_request = 0.0
        self._copy_ledger = CopyLedger()
        self._bulk_clock = 0.0
        self._reorder = ReorderBuffer(timeout=self._reorder_timeout,allow_late=True)
        self._counts["restart_discarded"] += self._received.clear()
        if self.role == "server":
            self._paths.clear()
            self._policy_enabled=False
            # Parallel path challenges for this same restarting client remain
            # valid; challenges for other sender domains cannot roll it back.
            self._challenges = OrderedDict((key, value) for key, value in self._challenges.items()
                                           if key[2] == prefix)
        else:
            for path in self._paths.values():
                # Preserve pending nonce proofs on the other configured paths.
                fresh = self._new_path(path.socket_index, path.endpoint)
                for attribute in ("last_rx", "rtt_ms", "rtt_jitter_ms", "bulk_finish", "bulk_filtered", "budget", "stripe_rx_bytes", "stripe_rx_highest", "stripe_rx_highest_at",
                                  "feedback_due", "last_feedback", "tx_epoch", "rx_epoch",
                                  "accepted_feedback", "last_sequence", "ready"):
                    setattr(path, attribute, getattr(fresh, attribute))
                path.policy_confirmed=fresh.policy_confirmed;path.last_policy_sent=-1

    def _handshake(self, index, endpoint, prefix, kind, sequence, payload, cipher):
        """Process challenge-bound controls outside the data replay window.

        HELLO/CHALLENGE do not pin a prefix or mark a path healthy. RESET tokens
        are consumed before peer adoption. A duplicate current-peer RESET may
        resend READY, but can never re-adopt a previous prefix.
        """
        now = time.perf_counter()
        identity = (index, endpoint)
        if self.role == "server" and kind == HELLO and len(payload) == 16:
            self._counts["handshake_hellos"] += 1
            self._challenges = OrderedDict((key, value) for key, value in self._challenges.items()
                                           if value[2] > now)
            key = (index, endpoint, prefix)
            challenge = self._challenges.get(key)
            if challenge is None or not hmac.compare_digest(challenge[0], payload):
                if len(self._challenges) >= HANDSHAKE_CAPACITY:
                    self._challenges.popitem(last=False)
                challenge = (payload, secrets.token_bytes(16), now + HANDSHAKE_TIMEOUT)
                self._challenges[key] = challenge
            path = self._paths.get(identity) or self._new_path(index, endpoint)
            self._write(self._encode(CHALLENGE, challenge[1] + challenge[0]), path)
            return
        if self.role == "server" and kind == RESET and len(payload) == 32:
            key = (index, endpoint, prefix)
            challenge = self._challenges.get(key)
            path = self._paths.get(identity)
            valid = (challenge is not None and challenge[2] > now and
                     hmac.compare_digest(payload, challenge[1] + challenge[0]))
            if valid:
                del self._challenges[key]  # consume before adopting/resetting replay state
                changed = self._remote_prefix != prefix
                self._adopt_peer(prefix, cipher)
                if changed:
                    self._replay.accept(sequence)
                    self._receive_floor = sequence + 1
                path = self._paths.get(identity)
                if path is None:
                    if len(self._paths) >= MAX_LINKS:
                        oldest = min(self._paths, key=lambda item: self._paths[item].last_rx)
                        del self._paths[oldest]
                    path = self._paths[identity] = self._new_path(index, endpoint)
                path.confirmation = payload
                path.confirmation_expires = now + HANDSHAKE_TIMEOUT
                self._counts["handshake_resets"] += 1
            elif not (self._remote_prefix == prefix and path is not None and
                      path.confirmation is not None and path.confirmation_expires > now and
                      hmac.compare_digest(payload, path.confirmation)):
                self._counts["handshake_rejected"] += 1
                return
            if self._write(self._encode(READY, payload[16:] + payload[:16]), path):
                if valid or not path.ready:
                    path.last_rx = now
                path.ready = True
                self._counts["handshake_ready"] += 1
            return
        if self.role == "client" and kind in (CHALLENGE, READY) and len(payload) == 32:
            path = self._paths.get(identity)
            if path is None or path.hello_nonce is None or now - path.hello_started >= HANDSHAKE_TIMEOUT:
                self._counts["handshake_rejected"] += 1
                return
            if kind == CHALLENGE:
                if not hmac.compare_digest(payload[16:], path.hello_nonce):
                    self._counts["handshake_rejected"] += 1
                    return
                path.server_nonce, path.challenge_prefix = payload[:16], prefix
                self._counts["handshake_challenges"] += 1
                self._write(self._encode(RESET, payload), path)
                return
            if (path.server_nonce is None or path.challenge_prefix != prefix or
                    not hmac.compare_digest(payload, path.hello_nonce + path.server_nonce)):
                self._counts["handshake_rejected"] += 1
                return
            changed = self._remote_prefix != prefix
            self._adopt_peer(prefix, cipher)
            if changed:
                self._replay.accept(sequence)
                self._receive_floor = sequence + 1
            path.ready = True
            path.last_rx = now
            path.hello_nonce = path.server_nonce = path.challenge_prefix = None
            self._counts["handshake_ready"] += 1
            if path.link_state is not None:self._send_link_policy(path,now)
            return
        self._counts["handshake_rejected"] += 1

    @property
    def addresses(self) -> list[tuple[str, int]]:
        return [sock.getsockname() for sock in self._sockets]

    @property
    def max_payload(self) -> int:
        return self.mtu - OVERHEAD

    def start(self) -> Node:
        with self._lock:
            if self._closed:
                raise RuntimeError("node is closed")
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="gamebond-udp", daemon=True)
                self._thread.start()
        return self

    def _encode(self, kind: int, payload: bytes) -> bytes:
        if len(payload) > self.max_payload:
            raise ValueError(f"payload exceeds {self.max_payload}-byte transport limit")
        if self._sequence >= (1 << 64):
            raise OverflowError("nonce space exhausted; create a fresh session")
        sequence = self._sequence
        self._sequence += 1
        header = HEADER.pack(self._magic, self.session, self._prefix, kind, sequence)
        return header + self._tx.encrypt(b"\0" * 4 + sequence.to_bytes(8, "big"), payload, header)

    def _write(self, packet: bytes, path: _Path, *, direct_udp=False) -> bool:
        if not path.available:return False
        kind=packet[HEADER.size-9]
        now=time.perf_counter()
        if path.link_state is not None:
            if kind in (DATA,DATA_COPY,STRIPED) and (not path.policy_confirmed or path.link_state['blocked'] or path.link_state['role']=='never'):
                return False
            if path.wire_pacer.ready_at(len(packet)+28,now)>now+.000001:return False
        try:
            sock=self._sockets[path.socket_index]
            if direct_udp and hasattr(sock,'send_udp_probe'):sock.send_udp_probe(packet)
            else:sock.sendto(packet, path.endpoint)
            if path.link_state is not None:path.wire_pacer.sent(len(packet)+28,now)
            path.transmitted += 1
            path.tx_bytes += len(packet)
            self._counts["tx_bytes"] += len(packet)
            if packet[HEADER.size - 9] not in (DATA, DATA_COPY, STRIPED):
                # Feedback and probes consume the same physical link too.
                # They stay immediate; only subsequent bulk waits for service.
                path.budget.control_sent(len(packet), time.perf_counter())
            return True
        except OSError:
            path.errors += 1
            self._counts["socket_errors"] += 1
            return False

    def send(self, payload: bytes, replicate: bool = True, flow_id=None, *, urgent: bool = False) -> int:
        """Send data, duplicating gameplay or optionally striping a bulk flow.

        ``flow_id`` must be hashable. In legacy mode affinity lasts until 120s idle, eviction,
        stale path health, or an immediate socket error. Replicated packets
        always use all eligible paths and bypass this 8192-entry cache.
        """
        payload = bytes(payload)
        tcp_control=self.bonding_mode and not replicate and is_tcp_control(payload)
        urgent=urgent or tcp_control
        if self.bonding_mode and not replicate and not urgent:
            return self._send_bonded(payload, flow_id)
        if not replicate and flow_id is not None:
            hash(flow_id)
        with self._lock:
            if self._closed:
                raise RuntimeError("node is closed")
            packet = self._encode(DATA_COPY if (replicate and self._loss_tracking) else DATA, payload)
            now = time.perf_counter()
            paths = list(self._paths.values())
            if self.bonding_mode:
                paths = [path for path in paths if path.ready]
            if self.role == "server":
                paths = [p for p in paths if now - p.last_rx < self.path_timeout]
            paths=self._eligible_paths(paths,boost=replicate or urgent)
            paths=self._fit_paths(paths,len(packet))
            if not replicate and paths:
                paths.sort(key=lambda p: (
                    p.last_rx <= 0 or now - p.last_rx >= self.path_timeout,
                    (p.rtt_ms/2+2*p.rtt_jitter_ms) if p.rtt_ms is not None else float("inf")))
                if flow_id is not None and not urgent:
                    self._expire_flows(now)
                    cached = self._flow_paths.get(flow_id)
                    if cached is not None:
                        preferred = self._paths.get(cached[0])
                        if (preferred is not None and preferred in paths and
                                preferred.last_rx > 0 and now - preferred.last_rx < self.path_timeout):
                            paths.remove(preferred)
                            paths.insert(0, preferred)
            sent = 0
            for path in paths:
                if self._write(packet, path):
                    # Urgent DATA still bypasses bulk gates and never consumes
                    # ACK/window credit. Its physical wire service reduces the
                    # next bulk allowance on every successful duplicate path.
                    path.budget.priority_sent(len(packet), time.perf_counter())
                    wire_bytes = len(packet) + path.budget.wire_overhead
                    path.priority_tx_packets += 1
                    path.priority_tx_wire_bytes += wire_bytes
                    self._counts["priority_tx_packets"] += 1
                    self._counts["priority_tx_wire_bytes"] += wire_bytes
                    sent += 1
                    if not replicate:
                        if flow_id is not None:
                            self._flow_paths[flow_id] = ((path.socket_index, path.endpoint), now)
                            self._flow_paths.move_to_end(flow_id)
                            if len(self._flow_paths) > FLOW_CACHE_CAPACITY:
                                self._flow_paths.popitem(last=False)
                        break  # immediate fallback if an earlier send errored
            if not replicate and not sent and flow_id is not None:
                self._flow_paths.pop(flow_id, None)
            self._counts["tx_packets"] += 1
            if tcp_control:self._counts['tcp_control_tx_packets']=self._counts.get('tcp_control_tx_packets',0)+1
            self._counts["tx_copies"] += sent
            self._counts["tx_payload_bytes"] += len(payload)
            return sent

    def _send_bonded(self, payload: bytes, flow_id) -> int:
        """Stripe successive packets of a flow; never hold the lock while pacing."""
        hash(flow_id)
        if len(payload) + BOND_OVERHEAD > self.max_payload:
            raise ValueError("payload exceeds bonded transport limit")
        size = len(payload) + BOND_OVERHEAD + OVERHEAD
        deadline = time.perf_counter() + .2
        while not self._stop.is_set():
            pacing_waiters=[]
            with self._lock:
                if self._closed:
                    raise RuntimeError("node is closed")
                now = time.perf_counter()
                paths = [p for p in self._paths.values()
                         if p.ready and p.last_rx > 0 and now - p.last_rx < self.path_timeout]
                paths=self._eligible_paths(paths,boost=True)
                if not paths:
                    return 0
                paths=self._fit_paths(paths,size)
                readiness={id(p):p.budget.ready_at(size,now) for p in paths}
                if self._policy_enabled:
                    readiness={id(p):max(readiness[id(p)],p.wire_pacer.ready_at(size+28,now)) for p in paths}
                    primary=[p for p in paths if (p.link_state or {}).get('role','primary')=='primary']
                    if primary and any(readiness[id(p)]<=now+.000001 for p in primary) and not any(
                            p.budget.min_rtt is not None and p.budget.srtt-p.budget.min_rtt>.025 for p in primary):
                        paths=primary
                # Exclude a bulk path only when its transit estimate is beyond
                # the receiver's bounded ordering budget. Probes and gameplay
                # redundancy continue to use it; a sole healthy path stays usable.
                transit={id(p):p.budget.transit_seconds(size,p.rtt_ms) for p in paths}
                best=min(transit.values())
                margin=max(self._reorder_timeout,self._reorder.timeout)
                for p in paths:
                    p.bulk_filtered=(len(paths)>1 and transit[id(p)]>best+margin*(.8 if p.bulk_filtered else 1))
                paths=[p for p in paths if not p.bulk_filtered]
                delay = min(max(0.0, readiness[id(p)] - now) for p in paths)
                if delay>.000001:
                    pacing_waiters=[p.budget for p in paths if p.budget.next_send>now and
                        readiness[id(p)]<=now+delay+.000001]
                if delay <= .000001:
                    ready=[p for p in paths if readiness[id(p)]<=now+.000001]
                    # Weighted virtual service, not permanent lowest-RTT wins.
                    # Even a TCP stream below one path's pacing ceiling must
                    # exercise both links so feedback can discover their capacity.
                    self._bulk_clock=max(self._bulk_clock,min(p.bulk_finish for p in ready))
                    paths=sorted(ready,key=lambda p:(max(p.bulk_finish,self._bulk_clock),readiness[id(p)]+transit[id(p)]))
                    for path in paths:
                        # A fresh random ID on expiration/eviction prevents sequence
                        # reuse while the receiver still retains an older flow.
                        while self._stripe_flows:
                            _, (_, _, touched) = next(iter(self._stripe_flows.items()))
                            if now - touched < FLOW_IDLE_TIMEOUT:
                                break
                            self._stripe_flows.popitem(last=False)
                        cached_flow = self._stripe_flows.get(flow_id)
                        flow, number, _ = cached_flow if cached_flow is not None else (secrets.randbits(64), 0, now)
                        if number >= (1 << 64):
                            flow, number = secrets.randbits(64), 0
                        sequence = self._sequence
                        packet = self._encode(STRIPED, STRIPE_HEADER.pack(flow, number, path.tx_epoch) + payload)
                        if self._write(packet, path):
                            path.budget.sent(sequence, len(packet), now)
                            if len(payload) <= 2048 and _repairable(payload):
                                self._repair_cache[(flow, number)] = (payload, now, 0)
                            while len(self._repair_cache) > 2048:
                                self._repair_cache.popitem(last=False)
                            path.bulk_finish=max(path.bulk_finish,self._bulk_clock)+(len(packet)+28)/path.budget.rate_bytes_per_second
                            self._stripe_flows[flow_id] = (flow, number + 1, now)
                            self._stripe_flows.move_to_end(flow_id)
                            if len(self._stripe_flows) > FLOW_CACHE_CAPACITY:
                                self._stripe_flows.popitem(last=False)
                            self._counts["tx_packets"] += 1
                            self._counts["tx_copies"] += 1
                            self._counts["tx_payload_bytes"] += len(payload)
                            self._counts["bonded_packets"] += 1
                            return 1
                    # Do not busy-spin if every ready socket rejected its write.
                    delay = .001
                remaining = deadline - now
                if remaining <= 0:
                    self._counts["bonding_deadline_drops"] += 1
                    return 0
            waiting_at=time.perf_counter()
            self._stop.wait(min(max(delay, .000001), remaining, .01))
            resumed_at=time.perf_counter()
            with self._lock:
                self._counts['bulk_pacing_wait_us']=self._counts.get('bulk_pacing_wait_us',0)+int((resumed_at-waiting_at)*1e6)
                self._counts['bulk_pacing_wait_calls']=self._counts.get('bulk_pacing_wait_calls',0)+1
                for budget in pacing_waiters:budget.record_pacing_wait(waiting_at,resumed_at)
        return 0

    def _expire_flows(self, now: float) -> None:
        while self._flow_paths:
            _, (_, touched) = next(iter(self._flow_paths.items()))
            if now - touched < FLOW_IDLE_TIMEOUT:
                break
            self._flow_paths.popitem(last=False)

    def recv(self, timeout: float | None = None) -> bytes:
        """Return one authenticated unique payload; raises queue.Empty on timeout."""
        return self._received.get(timeout=timeout)

    def stats(self) -> dict:
        with self._lock:
            now = time.perf_counter()
            return {**self._counts, "affinity_flows": len(self._flow_paths),
                "wire_accounting_complete":self._outer_settings is None or not any(hasattr(s,'stats') and
                    (s.stats()['counters'].get('tx_framed_bytes',0) or s.stats()['counters'].get('rx_framed_bytes',0)) for s in self._sockets),
                "wire_accounting_scope":"UDP-equivalent datagram bytes; stream modes additionally expose framed bytes and exclude TCP/TLS/IP overhead and retransmissions",
                "bonding_mode": self.bonding_mode, "striped_flows": len(self._stripe_flows),
                "pending_handshakes": len(self._challenges),
                "reorder": {**self._reorder.stats(),"effective_timeout_ms":self._reorder.timeout*1000},
                "receive_inbox": self._received.stats(),
                "requested_send_buffer_bytes": self.send_buffer_bytes,
                "requested_receive_buffer_bytes": self.receive_buffer_bytes, "paths": [
                {"slot":p.socket_index,"local": self._sockets[p.socket_index].getsockname(),
                 "remote": p.endpoint,
                 "actual_send_buffer_bytes": self._sockets[p.socket_index].getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                 "actual_receive_buffer_bytes": self._sockets[p.socket_index].getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                 "receive_buffer_force_error": self._receive_buffer_force_errors.get(p.socket_index),
                 "interface_index": self._interface_indices[p.socket_index] if self._interface_indices else None,
                 "outer_transport":self._sockets[p.socket_index].stats() if self._outer_settings is not None and hasattr(self._sockets[p.socket_index],'stats') else dict(mode='udp'),
                 "available":p.available,"ready": p.ready,
                 "healthy": p.available and p.ready and p.policy_confirmed and p.last_rx > 0 and now - p.last_rx < self.path_timeout,
                 "enabled": not p.link_state or (not p.link_state['blocked'] and p.link_state['role']!='never'),
                 "link_policy":p.link_state,"policy_confirmed":p.policy_confirmed,
                 "wire_tx_bytes":p.tx_bytes+28*p.transmitted,
                 "wire_rx_bytes":p.rx_bytes+28*p.rx_wire_packets,
                 "copy_quality":dict(seen=p.copy_seen,missed=p.copy_missed,late=p.copy_late,lag_ms=p.copy_lag_ms,scope='replicated_copies_received_here'),
                 "peer_copy_quality":(dict(seen=p.peer_copy[0],missed=p.peer_copy[1],late=p.peer_copy[2],scope='my_replicated_copies_at_peer') if p.peer_copy else None),
                 "mtu":(dict(p.mtu_prober.stats(),skips=p.mtu_skips,df_enforced=self._df_enforced.get(p.socket_index,False)) if p.mtu_prober else None),
                 "probe_quality":dict(sent=p.probe_sent,acked=p.probe_acked,lost=p.probe_lost,lost_early=p.probe_lost_early,late=p.probe_late,scope='round_trip_probe'),
                 "metered_download_bytes":max(p.rx_bytes+28*p.rx_wire_packets,p.remote_wire_offset+p.remote_wire_tx),
                 "rtt_ms": p.rtt_ms, "rtt_jitter_ms":p.rtt_jitter_ms,"bulk_filtered":p.bulk_filtered,"rx": p.received, "tx": p.transmitted,
                 "rx_bytes": p.rx_bytes, "tx_bytes": p.tx_bytes,
                 "priority_tx_packets": p.priority_tx_packets,
                 "priority_tx_wire_bytes": p.priority_tx_wire_bytes,
                 "priority_rx_first_packets": p.priority_rx_first_packets,
                 "priority_rx_duplicate_packets": p.priority_rx_duplicate_packets,
                 "priority_rx_too_old_packets": p.priority_rx_too_old_packets,
                 "bonding": p.budget.stats(),
                 "errors": p.errors} for p in self._paths.values()]}

    def _receive(self, index: int, packet: bytes, endpoint: tuple[str, int], received_at=None) -> None:
        # Both clocks are local monotonic elapsed clocks. No peer wall-clock
        # timestamp is compared with this value.
        received_at = time.perf_counter() if received_at is None else received_at
        if not OVERHEAD <= len(packet) <= self.mtu:
            self._counts["malformed"] += 1
            return
        header = packet[:HEADER.size]
        magic, session, prefix, kind, sequence = HEADER.unpack(header)
        allowed = (DATA, PROBE, PONG, STRIPED, FEEDBACK, HELLO, CHALLENGE, RESET, READY, REPAIR, LINK_POLICY, LINK_POLICY_ACK,
                   DATA_COPY, MTU_PROBE, MTU_ACK, REPAIR_NA, COPY_REPORT) if self.bonding_mode else (DATA, PROBE, PONG)
        if magic != self._magic or not hmac.compare_digest(session, self.session) or kind not in allowed:
            self._counts["malformed"] += 1
            return
        handshake = self.bonding_mode and kind in (HELLO, CHALLENGE, RESET, READY)
        if not handshake and self._remote_prefix is not None and prefix != self._remote_prefix:
            self._counts["auth_failures"] += 1
            return
        cipher = self._rx if prefix == self._remote_prefix and self._rx is not None else self._cipher(
            prefix, "server" if self.role == "client" else "client")
        try:
            payload = cipher.decrypt(b"\0" * 4 + sequence.to_bytes(8, "big"), packet[HEADER.size:], header)
        except InvalidTag:
            self._counts["auth_failures"] += 1
            return
        identity = (index, endpoint)
        if self.role == "client" and identity not in self._paths:
            self._counts["malformed"] += 1
            return  # configured peer only, before pinning or replay mutation
        # Authenticated wire-copy bytes include data duplicates and probes.
        # Duplicate packets never learn paths or refresh health.
        self._counts["rx_bytes"] += len(packet)
        path = self._paths.get(identity)
        if path is not None:
            path.rx_bytes += len(packet)
            path.rx_wire_packets += 1
        if handshake:
            sock=self._sockets[index]
            recovery=self._udp_recovery.get(index)
            if (self.role=='client' and kind==CHALLENGE and len(payload)==32 and recovery and
                    getattr(sock,'last_received_transport',None)=='udp' and time.perf_counter()-recovery[1]<HANDSHAKE_TIMEOUT and
                    hmac.compare_digest(payload[16:],recovery[0])):
                sock.return_to_udp();path.hello_nonce=recovery[0];path.hello_started=time.perf_counter()
                path.server_nonce=path.challenge_prefix=None;self._udp_recovery.pop(index,None)
            self._handshake(index, endpoint, prefix, kind, sequence, payload, cipher)
            if self.role=='client' and path and path.ready and hasattr(sock,'note_authenticated'):sock.note_authenticated()
            return
        peer_epoch = None
        if self.bonding_mode:
            if kind == PROBE and len(payload) == 24:
                peer_epoch = struct.unpack_from("!Q", payload)[0]
            elif kind == STRIPED and len(payload) >= BOND_OVERHEAD:
                peer_epoch = STRIPE_HEADER.unpack_from(payload)[2]
            movable = (self.role == "server" and peer_epoch is not None and any(
                candidate.ready and candidate.rx_epoch == peer_epoch for candidate in self._paths.values()))
            if (self._remote_prefix is None or (path is None and not movable) or
                    (path is not None and not path.ready)):
                self._counts["handshake_rejected"] += 1
                return
        # A forged high sequence must never advance replay state or learn a path.
        before_handshake = sequence < self._receive_floor
        too_old = self._replay.highest - sequence >= self._replay.width
        if before_handshake or too_old or not self._replay.accept(sequence):
            # Retain the historical aggregate while distinguishing a known
            # duplicate inside the bitmap from an unseen packet aged out by
            # other traffic. Too-old packets cannot be proved duplicates.
            self._counts["duplicates"] += 1
            if before_handshake:
                self._counts["replay_floor_drops"] += 1
            elif too_old:
                self._counts["replay_too_old_drops"] += 1
                if kind in DATA_KINDS:
                    self._counts["priority_rx_too_old_packets"] += 1
                    if path is not None:
                        path.priority_rx_too_old_packets += 1
            else:
                self._counts["duplicate_copies"] += 1
                if kind in DATA_KINDS:
                    self._counts["priority_rx_duplicate_packets"] += 1
                    if path is not None:
                        path.priority_rx_duplicate_packets += 1
                if kind == DATA_COPY and path is not None:
                    self._note_copy(path, identity, sequence, received_at)
            return
        if kind in (PROBE, PONG) and len(payload) != (24 if self.bonding_mode else 16):
            self._counts["malformed"] += 1
            return
        if ((kind == STRIPED and len(payload) < BOND_OVERHEAD) or
                (kind == REPAIR and len(payload) != REPAIR_HEADER.size) or
                (kind == LINK_POLICY and len(payload) != POLICY_HEADER.size) or
                (kind == LINK_POLICY_ACK and len(payload) != POLICY_ACK_HEADER.size) or
                (kind == FEEDBACK and len(payload) != FEEDBACK_HEADER.size) or
                (kind == MTU_PROBE and len(payload) < MTU_PROBE_HEADER.size) or
                (kind == MTU_ACK and len(payload) != MTU_PROBE_HEADER.size) or
                (kind == REPAIR_NA and len(payload) != REPAIR_HEADER.size) or
                (kind == COPY_REPORT and len(payload) != COPY_REPORT_HEADER.size)):
            self._counts["malformed"] += 1
            return
        if kind == FEEDBACK and FEEDBACK_HEADER.unpack(payload)[3] > MAX_ACK_DELAY_US:
            self._counts["feedback_rejected"] += 1
            return
        self._remote_prefix, self._rx = prefix, cipher
        if self.role == "server" and peer_epoch is not None:
            # The authenticated sender's random path epoch survives NAT changes.
            # Move the whole logical path, including cumulative delivery counters
            # and send budget, rather than resetting only the receiver half.
            previous = next(((key, candidate) for key, candidate in self._paths.items()
                             if candidate.rx_epoch == peer_epoch and key != identity), None)
            if previous is not None:
                path = previous[1]
                if sequence > path.last_sequence:
                    del self._paths[previous[0]]
                    path.socket_index, path.endpoint = index, endpoint
                    self._paths[identity] = path
                path.rx_bytes += len(packet)
        if path is None:
            if len(self._paths) >= MAX_LINKS:
                oldest = min(self._paths, key=lambda k: self._paths[k].last_rx)
                del self._paths[oldest]
            path = self._paths[identity] = self._new_path(index, endpoint)
            path.rx_bytes = len(packet)
        if path.rx_epoch is None and peer_epoch is not None:
            path.rx_epoch = peer_epoch
        path.last_rx = time.perf_counter()
        sock=self._sockets[index]
        if self.role=='client' and hasattr(sock,'note_authenticated'):sock.note_authenticated()
        path.last_sequence = max(path.last_sequence, sequence)
        path.received += 1
        if kind in DATA_KINDS:
            path.priority_rx_first_packets += 1
            self._counts["priority_rx_first_packets"] += 1
        if kind == DATA_COPY:
            expected = [(p.socket_index, p.endpoint) for p in self._eligible_paths(
                [p for p in self._paths.values() if p.ready and p.available and
                 received_at - p.last_rx < self.path_timeout], boost=True)]
            self._copy_ledger.first(sequence, identity, expected, received_at)
        if kind == PROBE:
            self._write(self._encode(PONG, payload), path)
        elif kind == PONG:
            pending = self._pending.pop(payload, None)
            if pending is None:
                late = self._lost_probes.pop(payload, None)
                if late is not None and late[1] == identity:
                    # Reclassify: the reply arrived, merely later than a newer
                    # probe's. The delay is real jitter evidence, not loss.
                    path.probe_lost = max(0, path.probe_lost - 1)
                    path.probe_late += 1
                    pending = late
            if pending is not None and pending[1] == identity:
                path.probe_acked+=1
                path.probe_acked_sent_at = max(path.probe_acked_sent_at, pending[0])
                sample = (time.perf_counter() - pending[0]) * 1000
                path.rtt_jitter_ms = (sample/2 if path.rtt_ms is None else
                                      .75*path.rtt_jitter_ms+.25*abs(sample-path.rtt_ms))
                path.rtt_ms = sample if path.rtt_ms is None else .8 * path.rtt_ms + .2 * sample
                # Bulk only; immediate replicated gameplay bypasses reordering.
                self._update_reorder_budget()
        elif kind == FEEDBACK:
            epoch, ack_sequence, delivered_bytes, ack_delay_us = FEEDBACK_HEADER.unpack(payload)
            if epoch == path.tx_epoch and path.accepted_feedback == (ack_sequence, delivered_bytes):
                self._counts["feedback_duplicates"] += 1
            elif epoch == path.tx_epoch and path.budget.acknowledge(
                    ack_sequence, delivered_bytes, time.perf_counter(), ack_delay_us=ack_delay_us):
                path.accepted_feedback = (ack_sequence, delivered_bytes)
                self._counts["feedback_received"] += 1
            else:
                self._counts["feedback_rejected"] += 1
        elif kind == LINK_POLICY:
            if self.role!='server':
                self._counts['malformed']+=1;return
            try:revision,state=decode_state(payload)
            except (ValueError,struct.error):self._counts['malformed']+=1;return
            if revision==path.policy_revision and path.link_state is not None and state!=path.link_state:
                self._counts['malformed']+=1;return
            if revision>=path.policy_revision:
                path.link_state=state;path.policy_revision=revision;self._policy_enabled=True
                path.wire_pacer.set_rate(state['download_mbps'],time.perf_counter())
            acknowledgement=POLICY_ACK_HEADER.pack(path.policy_revision,path.tx_epoch,
                path.tx_bytes+28*path.transmitted+OVERHEAD+POLICY_ACK_HEADER.size+28,
                path.rx_bytes+28*path.rx_wire_packets)
            self._write(self._encode(LINK_POLICY_ACK,acknowledgement),path)
        elif kind == LINK_POLICY_ACK:
            if self.role!='client' or path.link_state is None:
                self._counts['malformed']+=1;return
            revision,epoch,transmitted,received=POLICY_ACK_HEADER.unpack(payload)
            if revision!=path.policy_revision:return
            if path.rx_epoch is not None and path.rx_epoch!=epoch:return
            path.rx_epoch=epoch
            if path.remote_wire_epoch!=epoch:
                path.remote_wire_offset+=path.remote_wire_tx;path.remote_wire_tx=0;path.remote_wire_epoch=epoch
            path.remote_wire_tx=max(path.remote_wire_tx,transmitted)
            path.policy_confirmed=True
        elif kind == REPAIR:
            key = REPAIR_HEADER.unpack(payload)
            cached = self._repair_cache.get(key)
            if cached and time.perf_counter() - cached[1] < 1 and cached[2] < 2:
                self._repair_requests[key] = None
                while len(self._repair_requests) > 64:
                    self._repair_requests.popitem(last=False)
            elif key not in self._repair_requests:
                # Tell the receiver to stop waiting; one answer per request,
                # and the requester itself caps attempts per key.
                if self._write(self._encode(REPAIR_NA, REPAIR_HEADER.pack(*key)), path):
                    self._counts["repair_unavailable_sent"] = self._counts.get("repair_unavailable_sent", 0) + 1
        elif kind == REPAIR_NA:
            key = REPAIR_HEADER.unpack(payload)
            if key in self._repair_asked:
                self._repair_asked[key] = (time.perf_counter(), 99)
                self._counts["repair_unavailable"] = self._counts.get("repair_unavailable", 0) + 1
        elif kind == MTU_PROBE:
            nonce, claimed = MTU_PROBE_HEADER.unpack_from(payload)
            # Answer with the size actually received; the prober only accepts
            # an answer that matches the size it sent.
            self._write(self._encode(MTU_ACK, MTU_PROBE_HEADER.pack(nonce, len(packet))), path)
        elif kind == MTU_ACK:
            nonce, size = MTU_PROBE_HEADER.unpack(payload)
            if path.mtu_prober is not None and path.mtu_prober.acknowledge(nonce, size):
                self._counts["mtu_acks"] = self._counts.get("mtu_acks", 0) + 1
        elif kind == COPY_REPORT:
            report = COPY_REPORT_HEADER.unpack(payload)
            path.peer_copy = report + (time.perf_counter(),)
        elif kind == STRIPED:
            flow, number, epoch = STRIPE_HEADER.unpack_from(payload)
            if path.rx_epoch is None or (path.rx_epoch != epoch and sequence > path.stripe_rx_highest):
                # A new learned endpoint has a fresh sender budget. Its feedback
                # counter must start fresh even if the local socket did not change.
                path.rx_epoch = epoch
                path.stripe_rx_bytes = 0
                path.stripe_rx_highest = -1
                path.stripe_rx_highest_at = None
            if path.rx_epoch == epoch:
                path.stripe_rx_bytes += len(packet)
                if sequence > path.stripe_rx_highest:
                    path.stripe_rx_highest = sequence
                    path.stripe_rx_highest_at = received_at
                path.feedback_due = True
            self._counts["rx_packets"] += 1
            self._counts["rx_payload_bytes"] += len(payload) - BOND_OVERHEAD
            asked = self._repair_asked.get((flow, number))
            if asked is not None:
                name = "gap_filled_late" if self._reorder.is_late(flow, number) else "gap_filled_in_time"
                self._counts[name] = self._counts.get(name, 0) + 1
            for delivered in self._reorder.push(flow, number, payload[BOND_OVERHEAD:]):
                self._deliver(delivered)
        else:
            self._counts["rx_packets"] += 1
            self._counts["rx_payload_bytes"] += len(payload)
            self._deliver(payload, priority=True)

    def _note_copy(self, path, identity, sequence, at):
        result = self._copy_ledger.duplicate(sequence, identity, at)
        if result is None:
            return
        state, lag = result
        lag_ms = lag * 1000
        path.copy_lag_ms = lag_ms if path.copy_lag_ms is None else .8 * path.copy_lag_ms + .2 * lag_ms
        if state == "late":
            path.copy_missed = max(0, path.copy_missed - 1)
            path.copy_late += 1

    def _copy_resolve_delay(self):
        measured = [p for p in self._paths.values() if p.ready and p.rtt_ms is not None]
        if len(measured) < 2:
            return .05
        spread = (max(p.rtt_ms for p in measured) - min(p.rtt_ms for p in measured)) / 2000
        jitter = max(p.rtt_jitter_ms for p in measured) / 1000
        return min(.25, max(.05, spread + 4 * jitter + .02))

    def _deliver(self, payload, *, priority=False):
        try:
            evicted = self._received.put_nowait(payload, priority=priority)
            self._counts["receive_drops"] += int(evicted)
        except queue.Full:
            self._counts["receive_drops"] += 1

    def _maintenance(self):
        now = time.perf_counter()
        # Recover only bounded recent bulk holes; never block gameplay delivery
        # or the receive worker waiting for a pacing slot.
        paths = self._eligible_paths([p for p in self._paths.values() if p.ready and now-p.last_rx < self.path_timeout],boost=True)
        if paths:
            skew = (max(p.rtt_ms or 0 for p in paths)-min(p.rtt_ms or 0 for p in paths))/2000
            path = min(paths, key=lambda p: p.rtt_ms or 1000)
            jitter=max(p.rtt_jitter_ms for p in paths)/1000
            missing = (self._reorder.missing(delay=max(.015,skew+2*jitter), limit=4, now=now,
                                             predicate=_repairable, with_age=True)
                       if now >= self._repair_next_request else [])
            if missing:
                self._repair_next_request = now + .01
            # Earliest useful repair: time already spent behind the hole plus
            # one round trip (request out, retransmission back) on the best path.
            # An unmeasured path cannot prove a repair is too late, so it is not gated.
            round_trip = None if path.rtt_ms is None else path.rtt_ms / 1000
            for flow_id, number, age in missing:
                key = (flow_id, number)
                last, attempts = self._repair_asked.get(key, (-1, 0))
                if attempts == 0 and round_trip is not None and age + round_trip > self._repair_deadline:
                    self._repair_asked[key] = (now, 99)
                    self._counts["repair_skipped_deadline"] = self._counts.get("repair_skipped_deadline", 0) + 1
                    continue
                if attempts < 2 and now-last >= .04:
                    if self._write(self._encode(REPAIR, REPAIR_HEADER.pack(*key)), path):
                        self._repair_asked[key] = (now, attempts+1)
                        self._counts['repair_requests'] = self._counts.get('repair_requests',0)+1
            while self._repair_asked and (len(self._repair_asked)>2048 or now-next(iter(self._repair_asked.values()))[0]>1):
                self._repair_asked.popitem(last=False)
            for key in list(self._repair_requests)[:4]:
                cached = self._repair_cache.get(key)
                if not cached or now-cached[1]>=1 or cached[2]>=2:
                    self._repair_requests.pop(key,None)
                    continue
                inner, sent_at, attempts = cached
                size = len(inner)+BOND_OVERHEAD+OVERHEAD
                ready = [p for p in self._fit_paths(paths,size) if p.budget.ready_at(size,now)<=now+.000001]
                if not ready:
                    break
                target = min(ready,key=lambda p:p.budget.score(size,now,p.rtt_ms))
                sequence = self._sequence
                packet = self._encode(STRIPED, STRIPE_HEADER.pack(*key,target.tx_epoch)+inner)
                if self._write(packet,target):
                    target.budget.sent(sequence,len(packet),now)
                    self._repair_cache[key]=(inner,sent_at,attempts+1)
                    self._repair_requests.pop(key,None)
                    self._counts['repair_packets'] = self._counts.get('repair_packets',0)+1
                    self._counts['tx_copies'] += 1
        while self._repair_cache and now-next(iter(self._repair_cache.values()))[1]>=1:
            self._repair_cache.popitem(last=False)
        for payload in self._reorder.poll(now=now):
            self._deliver(payload)
        for identity, outcome in self._copy_ledger.resolve(now, self._copy_resolve_delay()):
            target = self._paths.get(identity)
            if target is not None:
                if outcome == "seen":
                    target.copy_seen += 1
                else:
                    target.copy_missed += 1
        for path in self._paths.values():
            counters = (path.copy_seen, path.copy_missed, path.copy_late)
            if (counters != path.copy_reported and path.ready and now - path.last_rx < self.path_timeout
                    and now - path.last_copy_report >= COPY_REPORT_INTERVAL):
                if self._write(self._encode(COPY_REPORT, COPY_REPORT_HEADER.pack(*counters)), path):
                    path.copy_reported = counters
                    path.last_copy_report = now
        for path in self._paths.values():
            if path.link_state and (path.link_state['blocked'] or path.link_state['role']=='never'):continue
            # ACKs are cumulative and safe to repeat. A lost final feedback frame
            # must not leave an otherwise healthy sender stuck at its window.
            due = (path.feedback_due and now - path.last_feedback >= .02) or (
                path.stripe_rx_highest >= 0 and now - path.last_feedback >= .1)
            if due and path.ready and now - path.last_rx < self.path_timeout:
                feedback_at = time.perf_counter()
                hold = 0 if path.stripe_rx_highest_at is None else feedback_at - path.stripe_rx_highest_at
                ack_delay_us = min(MAX_ACK_DELAY_US, max(0, int(hold * 1_000_000)))
                payload = FEEDBACK_HEADER.pack(path.rx_epoch, path.stripe_rx_highest, path.stripe_rx_bytes, ack_delay_us)
                if self._write(self._encode(FEEDBACK, payload), path):
                    path.feedback_due = False
                    path.last_feedback = now

    def _update_reorder_budget(self):
        measured=[p for p in self._paths.values() if p.ready and p.rtt_ms is not None]
        if len(measured)<2:
            self._reorder.timeout=self._reorder_timeout
            return
        spread=(max(p.rtt_ms for p in measured)-min(p.rtt_ms for p in measured))/2
        jitter=max(p.rtt_jitter_ms for p in measured)
        slowest=max(p.rtt_ms for p in measured)
        self._reorder.timeout=min(.2,max(self._reorder_timeout,
            (max(spread,slowest/2)+4*jitter)/1000+self._reorder_timeout))

    def _path_mtu(self, path) -> int:
        return path.mtu_prober.path_mtu if path.mtu_prober is not None else self.mtu

    def _fit_paths(self, paths, size):
        """Prefer paths whose discovered MTU carries ``size`` bytes.

        A packet no path is known to carry is still attempted: the discovery is
        evidence, not proof, and a blackholed copy is no worse than no copy.
        """
        if not self._mtu_enabled or not paths:
            return paths
        fit = [p for p in paths if size <= self._path_mtu(p)]
        for p in paths:
            if p not in fit:
                p.mtu_skips += 1
        if fit:
            self._counts["mtu_path_skips"] = self._counts.get("mtu_path_skips", 0) + len(paths) - len(fit)
            return fit
        self._counts["mtu_no_fit"] = self._counts.get("mtu_no_fit", 0) + 1
        return paths

    def _early_loss_delay(self, path) -> float:
        """Minimum age before an overtaken probe counts as lost.

        Two smoothed round trips plus four jitter units, never below 100 ms,
        and bounded by half of path_timeout so the guard stays useful when a
        caller configures long timeouts.
        """
        rtt = path.rtt_ms or 0.0
        return min(self.path_timeout / 2, max(.1, (2 * rtt + 4 * path.rtt_jitter_ms) / 1000))

    def _probe(self) -> None:
        now = time.perf_counter()
        if self.bonding_mode and self.role == "server":
            self._challenges = OrderedDict((key, value) for key, value in self._challenges.items()
                                           if value[2] > now)
        for token,(sent,identity) in list(self._pending.items()):
            path=self._paths.get(identity)
            age=now-sent
            if age>=self.path_timeout:
                if path:path.probe_lost+=1
                self._pending.pop(token,None)
            elif path is not None and sent<path.probe_acked_sent_at and age>=self._early_loss_delay(path):
                # A probe sent after this one has already completed its round
                # trip, so this one is lost or badly late. Waiting the full
                # path_timeout would leave a lossy episode undefended for
                # seconds; the late-reply branch above undoes a false positive.
                path.probe_lost+=1
                path.probe_lost_early+=1
                self._pending.pop(token,None)
                self._lost_probes[token]=(sent,identity)
        while self._lost_probes and (len(self._lost_probes)>256 or
                now-next(iter(self._lost_probes.values()))[0]>=self.path_timeout):
            del self._lost_probes[next(iter(self._lost_probes))]
        # Client always probes configured sockets, including failed links. Server
        # probes learned paths until expiration and relies on new client probes
        # for recovery or NAT rebinding.
        for path in list(self._paths.values()):
            if not path.available:continue
            if self.role=='client' and path.link_state is not None:
                disabled=path.link_state['role']=='never' or path.link_state['blocked']
                if path.ready and (not path.policy_confirmed or (not disabled and now-path.last_policy_sent>=1)):
                    self._send_link_policy(path,now)
                if path.link_state['role']=='never' or path.link_state['blocked']:continue
            if self.role=='server' and path.link_state and (path.link_state['blocked'] or path.link_state['role']=='never'):continue
            sock=self._sockets[path.socket_index]
            if self.role=='client' and hasattr(sock,'tick'):
                sock.tick(now)
                if sock.mode!='udp' and now-sock.last_recovery>=sock.settings.recovery_interval:
                    nonce=secrets.token_bytes(16);self._udp_recovery[path.socket_index]=(nonce,now);sock.last_recovery=now
                    self._write(self._encode(HELLO,nonce),path,direct_udp=True)
            if self.bonding_mode:
                if self.role == "client" and (not path.ready or now - path.last_rx >= self.path_timeout):
                    if path.ready or path.hello_nonce is None or now - path.hello_started >= HANDSHAKE_TIMEOUT:
                        path.ready = False
                        path.hello_nonce, path.hello_started = secrets.token_bytes(16), now
                        path.server_nonce = path.challenge_prefix = None
                    if path.server_nonce is None:
                        self._write(self._encode(HELLO, path.hello_nonce), path)
                    else:
                        self._write(self._encode(RESET, path.server_nonce + path.hello_nonce), path)
                    continue
                if self.role == "server" and not path.ready:
                    continue
            if self.role == "server" and now - path.last_rx >= self.path_timeout:
                continue
            token = secrets.token_bytes(16)
            if self.bonding_mode:
                token = struct.pack("!Q", path.tx_epoch) + token
            if len(self._pending) >= 256:
                # Keep memory bounded even with unusually long expiry settings.
                del self._pending[next(iter(self._pending))]
            self._pending[token] = (now, (path.socket_index, path.endpoint))
            if self._write(self._encode(PROBE, token), path):path.probe_sent+=1
            else:self._pending.pop(token,None)
            if path.mtu_prober is not None and path.ready:
                for nonce, size in path.mtu_prober.due(now, lambda: secrets.randbits(64)):
                    body = MTU_PROBE_HEADER.pack(nonce, size)
                    body += b"\0" * (size - OVERHEAD - len(body))
                    self._write(self._encode(MTU_PROBE, body), path)

    def _send_link_policy(self,path,now):
        if self._write(self._encode(LINK_POLICY,encode_state(path.policy_revision,path.link_state)),path):
            path.last_policy_sent=now

    def _run(self) -> None:
        next_probe = 0.0
        while not self._stop.is_set():
            try:
                readable, _, _ = select.select(self._sockets, [], [], .005 if self.bonding_mode else .05)
            except (OSError, ValueError):
                if self._stop.is_set():break
                continue
            for sock in readable:
                # Bound work per socket, so a noisy link cannot starve probes.
                for _ in range(64):
                    try:
                        packet, endpoint = sock.recvfrom(self.mtu + 1)
                        received_at = time.perf_counter()
                    except BlockingIOError:
                        break
                    except OSError:
                        with self._lock:
                            self._counts["socket_errors"] += 1
                        break
                    with self._lock:
                        if sock in self._sockets:self._receive(self._sockets.index(sock), packet, endpoint, received_at=received_at)
            if self.bonding_mode:
                with self._lock:
                    self._maintenance()
            if time.perf_counter() >= next_probe:
                with self._lock:
                    self._probe()
                next_probe = time.perf_counter() + self.probe_interval

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=1)
        with self._lock:
            self._closed = True
            self._received.close()
            for sock in self._sockets:
                sock.close()

    def __enter__(self) -> Node:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()
