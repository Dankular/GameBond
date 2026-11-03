"""Original IP/DSCP policy and bounded latency-oriented scheduling.

Classification never guesses the game from packet timing or a port allowlist.
Game ports must be explicitly configured. Effective DSCP affects policy only;
this module does not alter the original packet or expose DSCP on the outer UDP.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass
import math
import struct
import threading
import time
from typing import Callable, Iterable, Mapping


@dataclass(frozen=True)
class QueuePolicy:
    priority: bool = False
    replicate: bool = False
    max_age_ms: float = 100
    capacity: int = 256
    retransmissions: int = 0

    def __post_init__(self):
        if type(self.priority) is not bool or type(self.replicate) is not bool:
            raise ValueError("priority and replicate must be booleans")
        if not math.isfinite(self.max_age_ms) or self.max_age_ms <= 0:
            raise ValueError("max_age_ms must be finite and positive")
        if type(self.capacity) is not int or self.capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        if self.retransmissions != 0:
            raise ValueError("transport retransmission is not implemented; use 0")


@dataclass(frozen=True)
class PacketInfo:
    version: int
    dscp: int
    protocol: int
    source: bytes
    destination: bytes
    source_port: int | None = None
    destination_port: int | None = None
    fragmented: bool = False
    identification: int | None = None
    fragment_offset: int = 0
    more_fragments: bool = False

    @property
    def flow(self) -> tuple | None:
        if self.fragmented or self.source_port is None:
            return None
        endpoints = sorted(((self.source, self.source_port),
                            (self.destination, self.destination_port)))
        return self.version, self.protocol, *endpoints

    @property
    def fragment_key(self) -> tuple | None:
        if self.version == 4 and self.fragmented and self.identification is not None:
            return self.source, self.destination, self.protocol, self.identification
        return None


def parse_packet(packet: bytes) -> PacketInfo:
    """Validate an IP datagram and expose DSCP and safe TCP/UDP flow keys.

    Fragmented packets have no flow key. First IPv4 UDP fragments expose their
    validated UDP ports for classification, without requiring the entire UDP
    datagram to be present. Later fragments never expose ports. IPv6
    jumbograms and ESP are not decoded. Extension headers have bounded traversal.
    Checksums are left to the IP stack; structural lengths are checked here.
    """
    if not packet:
        raise ValueError("empty IP packet")
    version = packet[0] >> 4
    fragmented = False
    identification, fragment_offset, more_fragments = None, 0, False
    if version == 4:
        if len(packet) < 20:
            raise ValueError("short IPv4 header")
        offset = (packet[0] & 15) * 4
        total = int.from_bytes(packet[2:4], "big")
        if offset < 20 or total != len(packet) or offset > total:
            raise ValueError("invalid IPv4 length")
        flags_offset = int.from_bytes(packet[6:8], "big")
        fragmented = bool(flags_offset & 0x3FFF)
        if fragmented:
            identification = int.from_bytes(packet[4:6], "big")
            fragment_offset = (flags_offset & 0x1FFF) * 8
            more_fragments = bool(flags_offset & 0x2000)
            payload_bytes = total - offset
            if (not payload_bytes or (more_fragments and payload_bytes % 8)
                    or fragment_offset + payload_bytes > 65515):
                raise ValueError("invalid IPv4 fragment length")
        proto, dscp = packet[9], packet[1] >> 2
        source, destination = packet[12:16], packet[16:20]
    elif version == 6:
        if len(packet) < 40:
            raise ValueError("short IPv6 header")
        payload_length = int.from_bytes(packet[4:6], "big")
        if payload_length == 0 or payload_length + 40 != len(packet):
            raise ValueError("invalid or unsupported IPv6 payload length")
        dscp = ((packet[0] & 15) << 2) | (packet[1] >> 6)
        source, destination = packet[8:24], packet[24:40]
        proto, offset = packet[6], 40
        for _ in range(16):
            if proto not in (0, 43, 44, 51, 60):
                break
            if offset + 2 > len(packet):
                raise ValueError("short IPv6 extension header")
            next_proto = packet[offset]
            if proto == 44:
                length = 8
                fragmented = True
            elif proto == 51:
                length = (packet[offset + 1] + 2) * 4
            else:
                length = (packet[offset + 1] + 1) * 8
            if offset + length > len(packet):
                raise ValueError("invalid IPv6 extension length")
            offset += length
            proto = next_proto
            if fragmented:
                break  # Later fragments need not contain more extension bytes.
        else:
            raise ValueError("too many IPv6 extension headers")
    else:
        raise ValueError("unsupported IP version")

    sport = dport = None
    first_udp_fragment = version == 4 and fragmented and fragment_offset == 0 and proto == 17
    if (not fragmented and proto in (6, 17)) or first_udp_fragment:
        minimum = 20 if proto == 6 else 8
        if offset + minimum > len(packet):
            raise ValueError("short transport header")
        sport, dport = struct.unpack_from("!HH", packet, offset)
        if proto == 17:
            length = int.from_bytes(packet[offset + 4:offset + 6], "big")
            actual = len(packet) - offset
            if (length < 8 or (first_udp_fragment and not actual < length <= 65535 - offset)
                    or (not first_udp_fragment and length != actual)):
                raise ValueError("invalid UDP length")
        else:
            header_length = (packet[offset + 12] >> 4) * 4
            if header_length < 20 or offset + header_length > len(packet):
                raise ValueError("invalid TCP header length")
    return PacketInfo(version, dscp, proto, source, destination, sport, dport,
                      fragmented, identification, fragment_offset, more_fragments)


@dataclass(frozen=True)
class Classification:
    info: PacketInfo
    dscp: int
    policy: QueuePolicy
    reason: str = "dscp"


def is_tcp_control(packet: bytes) -> bool:
    """Validated IPv4 TCP ACK-only/window updates or SYN/FIN/RST controls.

    Cumulative acknowledgements must not wait for earlier acknowledgements in
    the bulk resequencer. A TCP packet carrying application data stays bulk.
    """
    if len(packet)<40 or packet[0]>>4!=4 or packet[9]!=6:return False
    offset=(packet[0]&15)*4
    if offset<20 or offset+20>len(packet):return False
    flags=packet[offset+13]
    if not flags&7 and (not flags&16 or offset+(packet[offset+12]>>4)*4!=len(packet)):return False
    try:info=parse_packet(packet)
    except ValueError:return False
    if info.fragmented:return False
    if flags&7:return True
    return bool(flags&16 and offset+(packet[offset+12]>>4)*4==len(packet))


class Classifier:
    """Per-DSCP rules with a bounded, expiring bidirectional flow cache."""

    def __init__(self, policies: Mapping[int, QueuePolicy], *,
                 default_policy: QueuePolicy | None = None,
                 game_ports: Iterable[int] = (), cache_size: int = 8192,
                 flow_ttl: float = 120, clock: Callable[[], float] = time.perf_counter,
                 fragment_cache_size: int = 1024, fragment_ttl: float = 2):
        self.policies = dict(policies)
        if any(type(tag) is not int or not 0 <= tag <= 63
               or not isinstance(policy, QueuePolicy)
               for tag, policy in self.policies.items()):
            raise ValueError("policies must map DSCP 0..63 to QueuePolicy")
        self.default_policy = default_policy or QueuePolicy()
        self.game_ports = frozenset(game_ports)
        if any(type(port) is not int or not 1 <= port <= 65535
               for port in self.game_ports):
            raise ValueError("game_ports must be UDP ports 1..65535")
        if type(cache_size) is not int or cache_size <= 0:
            raise ValueError("cache_size must be positive")
        if not math.isfinite(flow_ttl) or flow_ttl <= 0:
            raise ValueError("flow_ttl must be finite and positive")
        if type(fragment_cache_size) is not int or not 1 <= fragment_cache_size <= 8192:
            raise ValueError("fragment_cache_size must be 1..8192")
        if not math.isfinite(fragment_ttl) or not 0 < fragment_ttl <= 30:
            raise ValueError("fragment_ttl must be finite and 0 < TTL <= 30 seconds")
        self.cache_size, self.flow_ttl, self.clock = cache_size, flow_ttl, clock
        self.fragment_cache_size, self.fragment_ttl = fragment_cache_size, fragment_ttl
        self._flows: OrderedDict[tuple, tuple[int, float]] = OrderedDict()
        self._fragments: OrderedDict[tuple, tuple[int, float]] = OrderedDict()
        self._fragment_counts = Counter()
        self._lock = threading.Lock()

    def classify(self, packet: bytes) -> Classification:
        return self.classify_info(parse_packet(packet))

    def classify_info(self, info: PacketInfo) -> Classification:
        """Classify an already validated packet after the caller's address checks."""
        tag, key, now = info.dscp, info.flow, self.clock()
        fragment_key = info.fragment_key
        first_fragment = fragment_key is not None and info.fragment_offset == 0
        reason = "fragment_first" if first_fragment else "dscp"
        # A first fragment may consult the known bidirectional flow policy,
        # while its public flow remains None so transport cannot stripe it as
        # a complete datagram. No payload or reassembly state is retained.
        if first_fragment and info.source_port is not None:
            endpoints = sorted(((info.source, info.source_port),
                                (info.destination, info.destination_port)))
            key = info.version, info.protocol, *endpoints
        if info.protocol == 17 and info.source_port is not None and (
                info.source_port in self.game_ports or
                info.destination_port in self.game_ports):
            tag = 46
            reason = "game_port"
        with self._lock:
            if key is not None:
                # Entries are kept in last-use order; expiry is bounded memory.
                while self._flows and next(iter(self._flows.values()))[1] <= now:
                    self._flows.popitem(last=False)
                cached = self._flows.pop(key, None)
                if cached and cached[1] > now:
                    cached_policy = self.policies.get(cached[0], self.default_policy)
                    # Keep a learned priority flow when its peer uses an
                    # unrelated, unconfigured DSCP. An explicitly configured
                    # nonzero rule still wins, including deliberate demotion.
                    if tag == 0 or (tag not in self.policies and cached_policy.priority):
                        tag = cached[0]
                        if reason != "game_port":
                            reason = "flow_cache"
                self._flows[key] = tag, now + self.flow_ttl
                while len(self._flows) > self.cache_size:
                    self._flows.popitem(last=False)
            if fragment_key is not None:
                while self._fragments and next(iter(self._fragments.values()))[1] <= now:
                    self._fragments.popitem(last=False)
                    self._fragment_counts["expired"] += 1
                if first_fragment:
                    self._fragment_counts["first"] += 1
                    self._fragments.pop(fragment_key, None)
                    self._fragments[fragment_key] = tag, now + self.fragment_ttl
                    while len(self._fragments) > self.fragment_cache_size:
                        self._fragments.popitem(last=False)
                        self._fragment_counts["evicted"] += 1
                else:
                    cached = self._fragments.get(fragment_key)
                    if cached is None:
                        self._fragment_counts["orphans"] += 1
                        if tag == 0:
                            reason = "fragment_orphan"
                    else:
                        self._fragment_counts["hits"] += 1
                        cached_policy = self.policies.get(cached[0], self.default_policy)
                        if tag == 0 or (tag not in self.policies and cached_policy.priority):
                            tag, reason = cached[0], "fragment_cache"
        return Classification(info, tag, self.policies.get(tag, self.default_policy), reason)

    def stats(self):
        """Fragment association counters; orphan fragments are never guessed.

        IPv4 ID reuse within the short TTL can be ambiguous; this is policy
        association, not authenticated IP reassembly. Later arrivals do not
        extend the TTL. Reordered fragments preceding the first remain bulk
        unless their own DSCP explicitly supplies a policy.
        """
        with self._lock:
            return {**{f"fragment_{name}": self._fragment_counts[name]
                       for name in ("first", "hits", "orphans", "expired", "evicted")},
                    "fragment_cache_entries": len(self._fragments),
                    "flow_cache_entries": len(self._flows)}


@dataclass(frozen=True)
class QueuedPacket:
    packet: bytes
    classification: Classification
    enqueued_at: float


class _DeadlineIndex:
    """Indexed min-heap with exactly one entry per queued packet.

    Removing a delivered packet also removes its deadline in O(log n), so long
    bulk deadlines cannot accumulate stale priority entries or trigger a heap
    compaction pause. Tuples are (deadline, sequence, priority).
    """

    def __init__(self):
        self._heap: list[tuple[float, int, bool]] = []
        self._positions: dict[int, int] = {}

    def __len__(self):
        return len(self._heap)

    def peek(self):
        return self._heap[0]

    def add(self, deadline: float, sequence: int, priority: bool):
        self._positions[sequence] = len(self._heap)
        self._heap.append((deadline, sequence, priority))
        self._up(len(self._heap) - 1)

    def remove(self, sequence: int):
        index = self._positions.pop(sequence)
        removed = self._heap[index]
        last = self._heap.pop()
        if index < len(self._heap):
            self._heap[index] = last
            self._positions[last[1]] = index
            if index and last < self._heap[(index - 1) // 2]:
                self._up(index)
            else:
                self._down(index)
        return removed

    def _up(self, index: int):
        heap, positions = self._heap, self._positions
        item = heap[index]
        while index:
            parent = (index - 1) // 2
            if heap[parent] <= item:
                break
            heap[index] = heap[parent]
            positions[heap[index][1]] = index
            index = parent
        heap[index] = item
        positions[item[1]] = index

    def _down(self, index: int):
        heap, positions = self._heap, self._positions
        item, length = heap[index], len(heap)
        child = index * 2 + 1
        while child < length:
            if child + 1 < length and heap[child + 1] < heap[child]:
                child += 1
            if item <= heap[child]:
                break
            heap[index] = heap[child]
            positions[heap[index][1]] = index
            index = child
            child = index * 2 + 1
        heap[index] = item
        positions[item[1]] = index


class PriorityScheduler:
    """Bounded FIFO within each class, with finite priority service bursts.

    A non-priority item is served after priority_burst priority items whenever
    both classes are present. No jitter/reordering delay is introduced.
    Deadline maintenance is O(log n) per insert/remove; a no-expiry check is O(1).
    FIFO order in each service class is independent of deadline order.
    """

    def __init__(self, *, capacity: int = 4096, priority_burst: int = 8,
                 clock: Callable[[], float] = time.perf_counter):
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        if type(priority_burst) is not int or priority_burst <= 0:
            raise ValueError("priority_burst must be a positive integer")
        self.capacity, self.priority_burst, self.clock = capacity, priority_burst, clock
        self._priority: OrderedDict[int, QueuedPacket] = OrderedDict()
        self._normal: OrderedDict[int, QueuedPacket] = OrderedDict()
        self._deadlines = _DeadlineIndex()
        self._next_sequence = 0
        self._counts: Counter[int] = Counter()
        self._stats: Counter[str] = Counter()
        self._tag_stats: dict[int, Counter] = {}
        self._residence_count = 0
        self._residence_total_ms = 0.0
        self._residence_max_ms = 0.0
        self._burst = 0
        self._closed = False
        self._condition = threading.Condition()

    def push(self, packet: bytes, classification: Classification) -> bool:
        tag = classification.dscp
        if type(tag) is not int or not 0 <= tag <= 63:
            raise ValueError("classification DSCP must be 0..63")
        with self._condition:
            if self._closed:
                return False
            now = self.clock()
            self._expire(now)
            tag_stats = self._tag_stats.get(tag)
            if tag_stats is None:
                tag_stats = Counter()
                self._tag_stats[tag] = tag_stats
            if (len(self._deadlines) >= self.capacity or
                    self._counts[tag] >= classification.policy.capacity):
                self._stats["dropped_full"] += 1
                tag_stats["dropped_full"] += 1
                return False
            item = QueuedPacket(bytes(packet), classification, now)
            sequence = self._next_sequence
            self._next_sequence += 1
            priority = classification.policy.priority
            (self._priority if priority else self._normal)[sequence] = item
            self._deadlines.add(now + classification.policy.max_age_ms / 1000,
                                sequence, priority)
            self._counts[tag] += 1
            self._stats["enqueued"] += 1
            tag_stats["enqueued"] += 1
            self._condition.notify()
            return True

    def _expire(self, now: float):
        while self._deadlines and self._deadlines.peek()[0] <= now:
            _, sequence, priority = self._deadlines.peek()
            self._deadlines.remove(sequence)
            item = (self._priority if priority else self._normal).pop(sequence)
            tag = item.classification.dscp
            self._counts[tag] -= 1
            self._stats["dropped_stale"] += 1
            self._tag_stats[tag]["dropped_stale"] += 1

    def pop(self, timeout: float | None = None) -> QueuedPacket | None:
        if timeout is not None and (not math.isfinite(timeout) or timeout < 0):
            raise ValueError("timeout must be finite and nonnegative")
        # Wait deadlines use the real monotonic clock, independent of test clocks.
        deadline = None if timeout is None else time.perf_counter() + timeout
        with self._condition:
            while True:
                now = self.clock()
                self._expire(now)
                if self._priority or self._normal:
                    if self._priority and (not self._normal or self._burst < self.priority_burst):
                        sequence, item = self._priority.popitem(last=False)
                        self._burst = min(self._burst + 1, self.priority_burst)
                    else:
                        sequence, item = self._normal.popitem(last=False)
                        self._burst = 0
                    self._deadlines.remove(sequence)
                    tag = item.classification.dscp
                    self._counts[tag] -= 1
                    self._stats["dequeued"] += 1
                    tag_stats = self._tag_stats[tag]
                    tag_stats["dequeued"] += 1
                    residence_ms = max(0.0, (now - item.enqueued_at) * 1000)
                    tag_stats["residence_total_ms"] += residence_ms
                    tag_stats["residence_max_ms"] = max(tag_stats["residence_max_ms"], residence_ms)
                    self._residence_count += 1
                    self._residence_total_ms += residence_ms
                    self._residence_max_ms = max(self._residence_max_ms, residence_ms)
                    return item
                if self._closed:
                    return None
                remaining = None if deadline is None else deadline - time.perf_counter()
                if remaining is not None and remaining <= 0:
                    return None
                self._condition.wait(remaining)

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    def stats(self) -> dict:
        with self._condition:
            per_tag = {}
            for tag, counts in self._tag_stats.items():
                count = counts["dequeued"]
                per_tag[tag] = {key: counts[key] for key in (
                    "enqueued", "dequeued", "dropped_stale", "dropped_full")}
                per_tag[tag]["queued"] = self._counts[tag]
                per_tag[tag]["residence_ms"] = {
                    "count": count,
                    "mean": counts["residence_total_ms"] / count if count else 0,
                    "max": counts["residence_max_ms"],
                }
            return dict(self._stats, queued=len(self._deadlines),
                        per_dscp=dict(self._counts), per_dscp_stats=per_tag,
                        residence_ms={"count": self._residence_count,
                                      "mean": self._residence_total_ms / self._residence_count
                                      if self._residence_count else 0,
                                      "max": self._residence_max_ms})
