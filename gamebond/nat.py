"""Stateful source NAT for sending local traffic through a transport that has its own address.

GameBond's userspace stack (10.77.0.2) and connected devices (10.77.0.3, ...) use addresses that an
OpenMPTCProuter server does not know. Traffic sent through OMR is rewritten to the OMR tunnel address
(for example 10.255.254.2) and translated back on the way in.

Behavior: port-restricted cone NAT. A mapping (protocol, internal address, internal port) keeps one
external port for all destinations (so peer-to-peer games can hole-punch), but inbound packets are
accepted only from remote address:port pairs the internal host has already sent to. The internal port
is preserved when free. TCP, UDP and ICMP echo are translated; ICMP errors (e.g. fragmentation needed)
are translated when they quote a TCP or UDP packet of a known mapping. IP fragments, other ICMP types
and other protocols are dropped and counted. IPv4 only.
"""
from __future__ import annotations

import ipaddress
import secrets
import struct
import threading
import time
from collections import OrderedDict

TCP, UDP, ICMP = 6, 17, 1
ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST = 0, 8
ICMP_ERRORS = (3, 4, 11, 12)
UDP_TIMEOUT, ICMP_TIMEOUT = 120.0, 30.0
TCP_ESTABLISHED_TIMEOUT, TCP_OTHER_TIMEOUT, TCP_CLOSING_TIMEOUT = 7200.0, 120.0, 30.0
MAX_REMOTES = 128


def _fold(value: int) -> int:
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return value


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    return (~_fold(sum(struct.unpack(f"!{len(data) // 2}H", data)))) & 0xFFFF


def adjust(csum: int, old: bytes, new: bytes) -> int:
    """RFC 1624 incremental update of a ones-complement checksum for replaced 16-bit words."""
    total = (~csum) & 0xFFFF
    for index in range(0, len(old), 2):
        total += ((~((old[index] << 8) | old[index + 1])) & 0xFFFF) + ((new[index] << 8) | new[index + 1])
    return (~_fold(total)) & 0xFFFF


class _Entry:
    __slots__ = ("proto", "int_ip", "int_port", "ext_port", "remotes", "last", "state")

    def __init__(self, proto, int_ip, int_port, ext_port, now):
        self.proto, self.int_ip, self.int_port, self.ext_port = proto, int_ip, int_port, ext_port
        self.remotes: OrderedDict = OrderedDict()
        self.last, self.state = now, "new"

    def timeout(self) -> float:
        if self.proto == UDP:
            return UDP_TIMEOUT
        if self.proto == ICMP:
            return ICMP_TIMEOUT
        return {"est": TCP_ESTABLISHED_TIMEOUT, "closing": TCP_CLOSING_TIMEOUT}.get(self.state, TCP_OTHER_TIMEOUT)


class Nat:
    def __init__(self, external_ip: str, *, max_entries: int = 32768, port_range=(20000, 60999), clock=time.monotonic):
        self.external = ipaddress.IPv4Address(external_ip).packed
        if not 1 <= max_entries <= 1_000_000 or not 1024 <= port_range[0] < port_range[1] <= 65535:
            raise ValueError("invalid NAT limits")
        self.max_entries, self.port_range, self.clock = max_entries, tuple(port_range), clock
        self.lock = threading.Lock()
        self.fwd: OrderedDict = OrderedDict()     # (proto, int_ip, int_port) -> entry, oldest first
        self.rev: dict = {}                       # (proto, ext_port) -> entry
        self.next_sweep = 0.0
        self.counters = dict(out=0, inn=0, created=0, expired=0, evicted=0, fragments=0, unsupported=0, malformed=0,
                             no_mapping=0, filtered=0, port_exhausted=0, not_for_us=0, icmp_errors=0)

    # --- public API -----------------------------------------------------------------------------------------

    def outbound(self, packet: bytes) -> bytes | None:
        """Rewrite the source of a local packet to the external address. None means dropped."""
        parsed = self._parse(packet)
        if parsed is None:
            return None
        data, ihl, proto = parsed
        with self.lock:
            now = self.clock()
            self._sweep(now)
            if proto in (TCP, UDP):
                if len(data) < ihl + (20 if proto == TCP else 8):
                    return self._count("malformed")
                sport, dport = struct.unpack_from("!HH", data, ihl)
                key_port, remote_port = sport, dport
            elif proto == ICMP and len(data) >= ihl + 8 and data[ihl] == ICMP_ECHO_REQUEST:
                key_port, remote_port = struct.unpack_from("!H", data, ihl + 4)[0], 0
            else:
                return self._count("unsupported")
            int_ip = bytes(data[12:16])
            entry = self._entry(proto, int_ip, key_port, now)
            if entry is None:
                return self._count("port_exhausted")
            remote = (bytes(data[16:20]), remote_port)
            entry.remotes[remote] = None
            entry.remotes.move_to_end(remote)
            while len(entry.remotes) > MAX_REMOTES:
                entry.remotes.popitem(last=False)
            entry.last = now
            self.fwd.move_to_end((proto, int_ip, key_port))
            if proto == TCP:
                self._tcp_state(entry, data[ihl + 13])
            self._rewrite(data, ihl, proto, src=(self.external, entry.ext_port), dst=None)
            self.counters["out"] += 1
            return bytes(data)

    def inbound(self, packet: bytes) -> bytes | None:
        """Translate a packet addressed to the external address back to the internal host."""
        parsed = self._parse(packet)
        if parsed is None:
            return None
        data, ihl, proto = parsed
        if bytes(data[16:20]) != self.external:
            self.counters["not_for_us"] += 1
            return None
        with self.lock:
            now = self.clock()
            self._sweep(now)
            if proto in (TCP, UDP):
                if len(data) < ihl + (20 if proto == TCP else 8):
                    return self._count("malformed")
                sport, dport = struct.unpack_from("!HH", data, ihl)
                entry, remote = self.rev.get((proto, dport)), (bytes(data[12:16]), sport)
            elif proto == ICMP and len(data) >= ihl + 8:
                kind = data[ihl]
                if kind == ICMP_ECHO_REPLY:
                    ident = struct.unpack_from("!H", data, ihl + 4)[0]
                    entry, remote = self.rev.get((ICMP, ident)), (bytes(data[12:16]), 0)
                elif kind in ICMP_ERRORS:
                    return self._inbound_error(data, ihl, now)
                else:
                    return self._count("unsupported")
            else:
                return self._count("unsupported")
            if entry is None:
                return self._count("no_mapping")
            if remote not in entry.remotes:
                return self._count("filtered")
            entry.last = now
            self.fwd.move_to_end((entry.proto, entry.int_ip, entry.int_port))
            if proto == TCP:
                self._tcp_state(entry, data[ihl + 13])
            self._rewrite(data, ihl, proto, src=None, dst=(entry.int_ip, entry.int_port))
            self.counters["inn"] += 1
            return bytes(data)

    def stats(self) -> dict:
        with self.lock:
            return dict(self.counters, active=len(self.fwd))

    # --- internals ---------------------------------------------------------------------------------------------

    def _count(self, name: str):
        self.counters[name] += 1
        return None

    def _parse(self, packet: bytes):
        if len(packet) < 20 or packet[0] >> 4 != 4:
            self.counters["malformed"] += 1
            return None
        ihl = (packet[0] & 15) * 4
        total = struct.unpack_from("!H", packet, 2)[0]
        if ihl < 20 or total < ihl or total > len(packet):
            self.counters["malformed"] += 1
            return None
        if struct.unpack_from("!H", packet, 6)[0] & 0x3FFF:
            self.counters["fragments"] += 1
            return None
        return bytearray(packet[:total]), ihl, packet[9]

    def _tcp_state(self, entry: _Entry, flags: int) -> None:
        if flags & 0x05:                      # FIN or RST
            entry.state = "closing"
        elif entry.state == "new" and flags & 0x10 and not flags & 0x02:
            entry.state = "est"

    def _entry(self, proto, int_ip, int_port, now):
        key = (proto, int_ip, int_port)
        entry = self.fwd.get(key)
        if entry is not None:
            return entry
        if len(self.fwd) >= self.max_entries:
            self._remove(next(iter(self.fwd.values())))
            self.counters["evicted"] += 1
        ext_port = self._allocate(proto, int_port)
        if ext_port is None:
            return None
        entry = _Entry(proto, int_ip, int_port, ext_port, now)
        self.fwd[key] = entry
        self.rev[(proto, ext_port)] = entry
        self.counters["created"] += 1
        return entry

    def _allocate(self, proto: int, preferred: int):
        low, high = self.port_range
        lowest = 1 if proto == ICMP else 1024
        if lowest <= preferred <= 65535 and (proto, preferred) not in self.rev:
            return preferred                  # keep the host's own port when free (helps peer-to-peer games)
        for _ in range(64):
            candidate = low + secrets.randbelow(high - low + 1)
            if (proto, candidate) not in self.rev:
                return candidate
        return None

    def _remove(self, entry: _Entry) -> None:
        self.fwd.pop((entry.proto, entry.int_ip, entry.int_port), None)
        self.rev.pop((entry.proto, entry.ext_port), None)

    def _sweep(self, now: float) -> None:
        if now < self.next_sweep:
            return
        self.next_sweep = now + 1.0
        for entry in [e for e in self.fwd.values() if now - e.last > e.timeout()]:
            self._remove(entry)
            self.counters["expired"] += 1

    def _rewrite(self, data: bytearray, ihl: int, proto: int, *, src, dst) -> None:
        """Replace the source and/or destination endpoint and repair every affected checksum incrementally."""
        old_ip, new_ip, offset_ip = (bytes(data[12:16]), src[0], 12) if src else (bytes(data[16:20]), dst[0], 16)
        port = src[1] if src else dst[1]
        data[offset_ip:offset_ip + 4] = new_ip
        header_csum = struct.unpack_from("!H", data, 10)[0]
        struct.pack_into("!H", data, 10, adjust(header_csum, old_ip, new_ip))
        if proto == ICMP:                     # echo identifier; ICMP has no pseudo header
            old_id = bytes(data[ihl + 4:ihl + 6])
            new_id = struct.pack("!H", port)
            data[ihl + 4:ihl + 6] = new_id
            struct.pack_into("!H", data, ihl + 2, adjust(struct.unpack_from("!H", data, ihl + 2)[0], old_id, new_id))
            return
        port_offset = ihl + (0 if src else 2)
        old_port, new_port = bytes(data[port_offset:port_offset + 2]), struct.pack("!H", port)
        data[port_offset:port_offset + 2] = new_port
        csum_offset = ihl + (16 if proto == TCP else 6)
        csum = struct.unpack_from("!H", data, csum_offset)[0]
        if proto == UDP and csum == 0:        # sender used no UDP checksum
            return
        csum = adjust(csum, old_ip + old_port, new_ip + new_port)
        struct.pack_into("!H", data, csum_offset, csum or (0xFFFF if proto == UDP else 0))

    def _inbound_error(self, data: bytearray, ihl: int, now: float):
        """ICMP error quoting one of our outbound TCP/UDP packets: translate outer destination and the quote."""
        self.counters["icmp_errors"] += 1
        inner = ihl + 8
        if len(data) < inner + 28 or data[inner] >> 4 != 4:
            return self._count("malformed")
        inner_ihl = (data[inner] & 15) * 4
        proto = data[inner + 9]
        if proto not in (TCP, UDP) or inner_ihl < 20 or len(data) < inner + inner_ihl + 8:
            return self._count("unsupported")
        if bytes(data[inner + 12:inner + 16]) != self.external:
            return self._count("no_mapping")
        sport = struct.unpack_from("!H", data, inner + inner_ihl)[0]
        entry = self.rev.get((proto, sport))
        if entry is None:
            return self._count("no_mapping")
        quoted_remote = (bytes(data[inner + 16:inner + 20]), struct.unpack_from("!H", data, inner + inner_ihl + 2)[0])
        if quoted_remote not in entry.remotes:
            return self._count("filtered")    # an error about a destination we never contacted
        entry.last = now
        # Outer destination, then the quoted source address/port, then every checksum covering them.
        data[16:20] = entry.int_ip
        struct.pack_into("!H", data, 10, 0)
        struct.pack_into("!H", data, 10, checksum(bytes(data[:ihl])))
        data[inner + 12:inner + 16] = entry.int_ip
        struct.pack_into("!H", data, inner + inner_ihl, entry.int_port)
        struct.pack_into("!H", data, inner + 10, 0)
        struct.pack_into("!H", data, inner + 10, checksum(bytes(data[inner:inner + inner_ihl])))
        struct.pack_into("!H", data, ihl + 2, 0)
        struct.pack_into("!H", data, ihl + 2, checksum(bytes(data[ihl:])))
        self.counters["inn"] += 1
        return bytes(data)
