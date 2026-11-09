"""Bounded optional ordering of independent 64-bit data-flow sequences.

These sequences are deliberately separate from transport encryption/replay
sequences, which also cover control packets and unrelated flows. The caller
serializes access, assigns stable flow IDs, and bypasses this buffer for traffic
that must retain immediate first-arrival delivery.
"""
from __future__ import annotations

import heapq
import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field

UINT64_MAX = (1 << 64) - 1
FLOW_IDLE_TTL = 120.0
LATE_WINDOW = 8192
LATE_MASK = (1 << LATE_WINDOW)-1


@dataclass
class _Flow:
    expected: int = 0
    last_seen: float = 0
    pending: dict[int, tuple[bytes, float]] = field(default_factory=dict)
    heap: list[int] = field(default_factory=list)
    deadline: float | None = None
    seen_highest: int = -1
    seen_bits: int = 0


class ReorderBuffer:
    """Per-flow sequence ordering with a bounded wait for each observed gap.

    New flows expect sequence zero. Higher sequences wait at most ``timeout``
    after the first buffered arrival exposing a gap, provided the caller polls.
    Capacity pressure releases the oldest waiting prefix immediately. Flow
    eviction/idle expiry explicitly discards any remaining buffered payloads.
    Idle state expires after 120s; an evicted flow starts again expecting zero.
    An oversized single payload is released without retaining it, after any
    preceding buffered packets in that flow. Missing ranges are counted with
    arithmetic, never by iterating missing sequence numbers.
    """

    def __init__(self, max_flows=1024, max_packets=2048, max_bytes=4 * 1024 * 1024,
                 timeout=.03, clock=time.perf_counter, allow_late=False):
        if any(type(value) is not int or value < 1 for value in (max_flows, max_packets, max_bytes)):
            raise ValueError("flow, packet, and byte capacities must be positive integers")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be finite and nonnegative")
        self.max_flows, self.max_packets, self.max_bytes = max_flows, max_packets, max_bytes
        self.timeout, self.clock = float(timeout), clock
        if type(allow_late) is not bool:raise ValueError('allow_late must be boolean')
        self.allow_late=allow_late
        self._flows: OrderedDict[int, _Flow] = OrderedDict()
        self._packets = self._bytes = 0
        self._next_due = math.inf
        self._counts = dict(delivered=0, duplicate_drops=0, gap_events=0,
                            skipped_sequences=0, deadline_flushes=0, capacity_flushes=0,
                            oversize_releases=0, evicted_flows=0, expired_flows=0,
                            dropped_packets=0, dropped_bytes=0,
                            peak_buffered_packets=0, peak_buffered_bytes=0)
        self._counts['late_releases']=0

    def _first_arrival(self,flow,sequence):
        if sequence>flow.seen_highest:
            shift=sequence-flow.seen_highest
            flow.seen_bits=1 if shift>=LATE_WINDOW else ((flow.seen_bits<<shift)|1)&LATE_MASK
            flow.seen_highest=sequence
            return True
        offset=flow.seen_highest-sequence
        if offset>=LATE_WINDOW or flow.seen_bits&(1<<offset):return False
        flow.seen_bits|=1<<offset
        return True

    def _now(self, now):
        value = self.clock() if now is None else now
        if not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("time must be finite")
        return float(value)

    def _drop_flow(self, flow: _Flow):
        packets, size = len(flow.pending), sum(len(item[0]) for item in flow.pending.values())
        self._packets -= packets
        self._bytes -= size
        self._counts["dropped_packets"] += packets
        self._counts["dropped_bytes"] += size

    def _expire(self, now):
        while self._flows:
            _, flow = next(iter(self._flows.items()))
            if now - flow.last_seen < FLOW_IDLE_TTL:
                break
            self._flows.popitem(last=False)
            self._drop_flow(flow)
            self._counts["expired_flows"] += 1

    def _gap(self, flow, sequence):
        if sequence > flow.expected:
            self._counts["gap_events"] += 1
            self._counts["skipped_sequences"] = min(
                UINT64_MAX, self._counts["skipped_sequences"] + sequence - flow.expected)

    def _deadline(self, flow, added_time=None):
        if added_time is not None:
            # New later arrivals cannot extend the first gap's deadline.
            deadline = added_time + self.timeout
            flow.deadline = deadline if flow.deadline is None else min(flow.deadline, deadline)
        else:
            # Only delivery/pressure flushing can remove the oldest arrival.
            # Bound this occasional rescan by the configured packet capacity.
            flow.deadline = min(item[1] for item in flow.pending.values()) + self.timeout if flow.pending else None
        if flow.deadline is not None:
            self._next_due = min(self._next_due, flow.deadline)

    def _drain(self, flow):
        output = []
        while flow.heap and flow.heap[0] == flow.expected:
            sequence = heapq.heappop(flow.heap)
            payload, _ = flow.pending.pop(sequence)
            self._packets -= 1
            self._bytes -= len(payload)
            output.append(payload)
            flow.expected += 1
        self._deadline(flow)
        self._counts["delivered"] += len(output)
        return output

    def _flush_prefix(self, flow, reason):
        self._gap(flow, flow.heap[0])
        flow.expected = flow.heap[0]
        self._counts[reason] += 1
        return self._drain(flow)

    def _due(self, now):
        if now < self._next_due:
            return []  # no per-packet scan of all tracked idle/ordered flows
        output = []
        next_due = math.inf
        for flow in self._flows.values():
            while flow.deadline is not None and flow.deadline <= now:
                output.extend(self._flush_prefix(flow, "deadline_flushes"))
            if flow.deadline is not None:
                next_due = min(next_due, flow.deadline)
        self._next_due = next_due
        return output

    def push(self, flow_id: int, sequence: int, payload: bytes, now=None) -> list[bytes]:
        if any(type(value) is not int or not 0 <= value <= UINT64_MAX for value in (flow_id, sequence)):
            raise ValueError("flow_id and sequence must be unsigned 64-bit integers")
        now = self._now(now)
        payload = bytes(payload)
        self._expire(now)
        flow = self._flows.get(flow_id)
        if flow is None:
            if len(self._flows) >= self.max_flows:
                _, evicted = self._flows.popitem(last=False)
                self._drop_flow(evicted)
                self._counts["evicted_flows"] += 1
            flow = self._flows[flow_id] = _Flow(last_seen=now)
        flow.last_seen = now
        self._flows.move_to_end(flow_id)
        output = []
        if not self._first_arrival(flow,sequence):
            self._counts["duplicate_drops"] += 1
        elif sequence < flow.expected:
            if self.allow_late:
                # A gap timeout is not proof of loss. Forward a first-arrival
                # late IP datagram to inner TCP instead of manufacturing loss.
                output.append(payload)
                self._counts['late_releases']+=1
                self._counts['delivered']+=1
            else:self._counts['duplicate_drops']+=1
        elif sequence == flow.expected:
            output.append(payload)
            flow.expected += 1
            self._counts["delivered"] += 1
            output.extend(self._drain(flow))
        elif self.timeout == 0:
            self._gap(flow, sequence)
            flow.expected = sequence + 1
            output.append(payload)
            self._counts["delivered"] += 1
        elif len(payload) > self.max_bytes:
            # This packet cannot be retained. Advance only its own flow, first
            # releasing already buffered lower sequences in order.
            while flow.heap and flow.heap[0] < sequence:
                output.extend(self._flush_prefix(flow, "capacity_flushes"))
            self._gap(flow, sequence)
            flow.expected = sequence + 1
            output.append(payload)
            self._counts["delivered"] += 1
            self._counts["oversize_releases"] += 1
            output.extend(self._drain(flow))
        else:
            released_incoming = False
            while self._packets >= self.max_packets or self._bytes + len(payload) > self.max_bytes:
                oldest = min((item for item in self._flows.values() if item.pending),
                             key=lambda item: item.deadline)
                if oldest is flow and sequence < flow.heap[0]:
                    # Prefer the arriving predecessor over skipping past it to
                    # release a buffered successor under the same pressure.
                    self._gap(flow, sequence)
                    flow.expected = sequence + 1
                    output.append(payload)
                    self._counts["delivered"] += 1
                    self._counts["capacity_flushes"] += 1
                    output.extend(self._drain(flow))
                    released_incoming = True
                    break
                output.extend(self._flush_prefix(oldest, "capacity_flushes"))
            # A pressure flush may have made this incoming packet expected.
            if released_incoming:
                pass
            elif sequence < flow.expected:
                self._counts["duplicate_drops"] += 1
            elif sequence == flow.expected:
                output.append(payload)
                flow.expected += 1
                self._counts["delivered"] += 1
                output.extend(self._drain(flow))
            else:
                flow.pending[sequence] = (payload, now)
                heapq.heappush(flow.heap, sequence)
                self._packets += 1
                self._bytes += len(payload)
                self._counts["peak_buffered_packets"] = max(self._counts["peak_buffered_packets"], self._packets)
                self._counts["peak_buffered_bytes"] = max(self._counts["peak_buffered_bytes"], self._bytes)
                self._deadline(flow, now)
        output.extend(self._due(now))
        return output

    def poll(self, now=None) -> list[bytes]:
        now = self._now(now)
        self._expire(now)
        return self._due(now)

    def is_late(self, flow_id, sequence):
        """True when this flow already released past ``sequence``."""
        flow = self._flows.get(flow_id)
        return flow is not None and sequence < flow.expected

    def missing(self, delay=.01, limit=16, now=None, predicate=None, with_age=False):
        """Bounded requests for holes that have persisted beyond path skew.

        With ``with_age`` each item is ``(flow, number, age_seconds)``, the age
        being how long the flow's oldest buffered packet has waited behind the
        hole.
        """
        now = self._now(now)
        result = []
        for key, flow in self._flows.items():
            if not flow.pending:
                continue
            age = now - min(v[1] for v in flow.pending.values())
            if age < delay:
                continue
            if predicate is not None and not predicate(flow.pending[flow.heap[0]][0]):
                continue
            for number in range(flow.expected, min(flow.heap[0], flow.expected + limit - len(result))):
                result.append((key, number, age) if with_age else (key, number))
            if len(result) >= limit:
                break
        return result

    def stats(self):
        return {**self._counts, "flows": len(self._flows),
                "buffered_packets": self._packets, "buffered_bytes": self._bytes}
