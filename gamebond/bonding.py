"""Original per-path pacing/window budget with ACK-gated startup, not BBR.

Caller supplies a monotonic ``now`` in seconds and serializes access. Byte sizes
and authenticated cumulative delivery counters must use the same DATA byte unit.
Pacing additionally charges outer IPv4/UDP headers (28 bytes by default); ACK
and congestion-window counters retain their original encrypted-payload units.
A fresh path-feedback epoch needs a fresh budget; counters cannot be rebased by
an arbitrary ACK. No method sleeps or performs I/O.
"""
from collections import OrderedDict
from dataclasses import dataclass
import math


MAX_PENDING = 4096
MAX_PACKET_BYTES = 65535
MAX_WINDOW_BYTES = 1024 * 1024
MAX_PACING_CATCHUP_SECONDS = .002
MAX_PRIORITY_DEBT_SECONDS = .1


@dataclass(frozen=True)
class _Pending:
    size: int
    sent_at: float


def _time(now):
    if not math.isfinite(now) or now < 0:
        raise ValueError("now must be finite, nonnegative monotonic seconds")


def _size(size):
    if type(size) is not int or not 1 <= size <= MAX_PACKET_BYTES:
        raise ValueError("packet size must be 1..65535 bytes")


BASE_RTT_WINDOW = 10.0   # seconds per bucket; the baseline spans one to two buckets


class PathBudget:
    """Pace bulk on one path; urgent traffic can be tracked without waiting.

    Window credit follows the protocol's highest-sequence ACK, while actual
    delivered-byte deltas drive rate measurements. This does not retransmit or
    prove that every lower sequence arrived. Expiry is a conservative loss
    signal, not proof that a packet was permanently lost.
    """

    def __init__(self, initial_rate_mbps=1, max_rate_mbps=100, *, wire_overhead=28):
        if (isinstance(initial_rate_mbps, bool) or isinstance(max_rate_mbps, bool)
                or not math.isfinite(initial_rate_mbps)
                or not math.isfinite(max_rate_mbps)
                or not 0 < initial_rate_mbps <= max_rate_mbps):
            raise ValueError("rates must be finite and 0 < initial <= maximum")
        if type(wire_overhead) is not int or not 0 <= wire_overhead <= 128:
            raise ValueError("wire_overhead must be 0..128 bytes")
        self.wire_overhead = wire_overhead
        self._priority_wire_bytes = self._priority_wire_packets = 0
        self._control_wire_bytes = self._control_wire_packets = 0
        self._priority_debt_saturations = 0
        self._pacing_observed_at = 0.0
        self.initial_rate_mbps = float(initial_rate_mbps)
        self.max_rate_mbps = float(max_rate_mbps)
        self._rate = initial_rate_mbps * 125000.0
        self._minimum_rate = min(initial_rate_mbps, .05) * 125000.0
        self._maximum_rate = max_rate_mbps * 125000.0
        self.next_send = 0.0
        self.inflight_bytes = 0
        self.srtt = .25
        self.raw_srtt = .25
        self.min_rtt = None
        # Jitter-aware delay baseline: a lifetime minimum is a rare best case on
        # a variable link, so smoothed RTT sits far above it even with no queue.
        self._rtt_var = 0.0
        self._base_cur = self._base_prev = None
        self._base_started = None
        self._rto_backoff = 1.0
        self._pending = OrderedDict()
        self._last_sent_sequence = -1
        self._last_sent_at = None
        self._last_ack_sequence = -1
        self._delivery_counter = 0
        self._sent_bytes = self._sent_packets = 0
        self._acked_packets = self._expired_packets = self._expired_bytes = 0
        self._invalid_acks = self._untracked_packets = self._rtt_samples = 0
        self._backoffs = self._rate_increases = 0
        self._last_backoff = -math.inf
        self._epoch_started = None
        self._epoch_sent = self._epoch_delivered = 0
        self._epoch_bulk_wire = self._epoch_unpaced_wire = 0
        self._growth_app_limited = True
        self._growth_utilization = 0.0
        self._growth_bulk_allowance = 0.0
        self._epoch_retired = 0
        self._epoch_pressure_seconds = 0.0
        self._pressure_at = None
        self._pressure_active = False
        self._congestion_epochs = 0
        self._last_pressure_ratio = 0.0
        self._last_loss_ratio = 0.0
        self._timeout_backoffs = 0
        self._delivery_rate = 0.0
        self._app_limited = True
        self._delay_samples = 0
        self._delay_backoffs = 0
        self._startup = True
        self._startup_increases = 0
        self._startup_exit_reason = None
        self._epoch_pacing_wait = 0.0
        self._pacing_wait_until = 0.0
        self._pacing_wait_ratio = 0.0

    @property
    def rate_bytes_per_second(self):
        return self._rate

    @property
    def rate_mbps(self):
        return self._rate / 125000.0

    @property
    def timeout(self):
        return min(2.0, max(.25, 4 * self.raw_srtt) * self._rto_backoff)

    @property
    def window_bytes(self):
        # About two bandwidth-delay products, bounded independently of rate.
        return int(max(6000, min(MAX_WINDOW_BYTES, self._rate * max(.02, self.raw_srtt) * 2)))

    def _observe_pressure(self, now, active=None):
        if self._pressure_at is not None and self._epoch_started is not None:
            if self._pressure_active:
                self._epoch_pressure_seconds += max(0.0, now - self._pressure_at)
        self._pressure_at = now if self._pressure_at is None else max(now, self._pressure_at)
        if active is not None:
            self._pressure_active = active

    def ready_at(self, size, now):
        _size(size)
        _time(now)
        self._pacing_observed_at = max(self._pacing_observed_at, now)
        self.expire(now)
        if (len(self._pending) < MAX_PENDING and
                self.inflight_bytes + size <= max(size, self.window_bytes)):
            self._observe_pressure(now, False)
            return max(now, self.next_send)
        # All entries use the current bounded RTO and insertion-ordered times.
        # No full queue scan or stale heap entries are needed.
        oldest = next(iter(self._pending.values()))
        self._observe_pressure(now, True)
        return max(now, oldest.sent_at + self.timeout)

    def score(self, size, now, rtt_ms):
        ready = self.ready_at(size, now)
        return ready + self.transit_seconds(size, rtt_ms)

    def transit_seconds(self, size, rtt_ms):
        """Arrival cost without re-running expiry/measurement side effects."""
        rtt = self.srtt
        if rtt_ms is not None and math.isfinite(rtt_ms) and rtt_ms > 0:
            # Small probes can understate the delay experienced by bulk data.
            # Once DATA feedback exists, do not let a lower probe RTT keep
            # steering a stream into a path whose real delivery is queueing.
            probe = rtt_ms / 1000.0
            rtt = max(rtt,probe) if self._rtt_samples else probe
        return (size + self.wire_overhead) / self._rate + rtt / 2

    def record_pacing_wait(self, started, ended):
        """Record real caller backlog, including a late OS timer wakeup.

        Merely inspecting a candidate never records demand. The sender calls
        this only after waiting with an actual bulk packet pending. Intervals
        are clipped to the current epoch and never counted twice.
        """
        _time(started);_time(ended)
        if ended<started:raise ValueError('pacing wait timestamps are reversed')
        if self._epoch_started is not None:
            self._epoch_pacing_wait+=max(0.0,ended-max(started,self._epoch_started,self._pacing_wait_until))
        self._pacing_wait_until=max(self._pacing_wait_until,ended)

    def priority_sent(self, size, now):
        """Charge a successful urgent UDP write; return bulk pacing delay.

        ``size`` excludes outer IP/UDP headers, as in sent(). This never waits,
        consumes ACK/window credit, or changes the capacity estimate. Only bulk
        waits for this physical service debt. Debt added by urgent traffic is
        capped at 100ms: sustained priority overload cannot accumulate an
        unlimited future bulk stall, but can still overload the real network.
        No delivery estimate is inferred from these unacknowledged writes.
        Authenticated bulk progress is assessed against the remaining service
        for additive discovery, rather than treating priority use as idle time.
        """
        return self._unpaced_sent(size, now, control=False)

    def control_sent(self, size, now):
        """Reserve physical service for successful probes/feedback, without ACK credit."""
        return self._unpaced_sent(size, now, control=True)

    def _unpaced_sent(self, size, now, *, control):
        _size(size)
        _time(now)
        if now < self._pacing_observed_at:
            raise ValueError("priority timestamps must be monotonic")
        self._pacing_observed_at = now
        wire_bytes = size + self.wire_overhead
        if self._epoch_started is None:
            self._epoch_started = now
        self._epoch_unpaced_wire += wire_bytes
        if control:
            self._control_wire_bytes += wire_bytes
            self._control_wire_packets += 1
        else:
            self._priority_wire_bytes += wire_bytes
            self._priority_wire_packets += 1
        proposed = max(now, self.next_send) + wire_bytes / self._rate
        bounded = min(proposed, now + MAX_PRIORITY_DEBT_SECONDS)
        if bounded < proposed:
            self._priority_debt_saturations += 1
        self.next_send = max(self.next_send, bounded)
        return max(0.0, self.next_send - now)

    def sent(self, sequence, size, now):
        """Record a successful write; return False if tracking was not accepted.

        Call ready_at before a paced bulk write. Priority traffic may bypass its
        gate, but tracking still cannot exceed MAX_PENDING. Successful physical
        writes always contribute to the counter bound, even if tracking is full.
        """
        _size(size)
        _time(now)
        if type(sequence) is not int or not 0 <= sequence < 2**64:
            raise ValueError("sequence must be an unsigned 64-bit integer")
        if self._last_sent_at is not None and now < self._last_sent_at:
            raise ValueError("sent timestamps must be monotonic")
        if sequence <= self._last_sent_sequence:
            return False
        self.expire(now)
        self._last_sent_at = now
        self._last_sent_sequence = sequence
        self._sent_bytes += size
        self._sent_packets += 1
        if self._epoch_started is None:
            self._epoch_started = now
        self._epoch_sent += size
        self._epoch_bulk_wire += size + self.wire_overhead
        # Preserve at most 2ms of late-wakeup/idle credit. Resetting to `now`
        # every packet would permanently discard timer oversleep and cap the
        # achievable rate. The credit is bounded, so a long idle cannot dump an
        # arbitrarily large burst into a modem/kernel queue.
        self._pacing_observed_at = max(self._pacing_observed_at, now)
        self.next_send = (max(now - MAX_PACING_CATCHUP_SECONDS, self.next_send)
                          + (size + self.wire_overhead) / self._rate)
        if len(self._pending) >= MAX_PENDING:
            self._untracked_packets += 1
            return False
        self._pending[sequence] = _Pending(size, now)
        self.inflight_bytes += size
        return True

    def acknowledge(self, sequence, delivered_bytes, now, ack_delay_us=0):
        _time(now)
        if (type(sequence) is not int or type(delivered_bytes) is not int
                or type(ack_delay_us) is not int or not 0 <= ack_delay_us <= 1_000_000):
            self._invalid_acks += 1
            return False
        pending = self._pending.get(sequence)
        if (pending is None or sequence <= self._last_ack_sequence
                or delivered_bytes <= self._delivery_counter
                or delivered_bytes > self._sent_bytes
                or delivered_bytes - self._delivery_counter < pending.size
                or now < pending.sent_at):
            self._invalid_acks += 1
            return False
        self.expire(now, _measure=False)
        if sequence not in self._pending:
            self._invalid_acks += 1
            self._measure(now)
            return False
        raw_sample = max(.000001, now - pending.sent_at)
        sample = max(.000001, raw_sample - min(raw_sample, ack_delay_us / 1_000_000))
        self._rtt_var = 0.0 if not self._rtt_samples else self._rtt_var * .75 + abs(sample - self.srtt) * .25
        self.raw_srtt = raw_sample if not self._rtt_samples else self.raw_srtt * .875 + raw_sample * .125
        self.srtt = sample if not self._rtt_samples else self.srtt * .875 + sample * .125
        self.min_rtt = sample if self.min_rtt is None else min(self.min_rtt, sample)
        if self._base_started is None or now - self._base_started >= BASE_RTT_WINDOW:
            self._base_prev, self._base_cur, self._base_started = self._base_cur, None, now
        self._base_cur = sample if self._base_cur is None else min(self._base_cur, sample)
        self._rtt_samples += 1
        self._rto_backoff = max(1.0, self._rto_backoff / 2)
        while self._pending:
            first = next(iter(self._pending))
            if first > sequence:
                break
            entry = self._pending.popitem(last=False)[1]
            self.inflight_bytes -= entry.size
            self._acked_packets += 1
            self._epoch_retired += entry.size
        self._observe_pressure(now, False)
        delta = delivered_bytes - self._delivery_counter
        self._delivery_counter = delivered_bytes
        self._last_ack_sequence = sequence
        self._epoch_delivered += delta
        base_rtt = min(r for r in (self._base_cur, self._base_prev) if r is not None)
        queue_delay = max(0.0, self.srtt - base_rtt)
        elapsed = 0 if self._epoch_started is None else now - self._epoch_started
        utilization = self._epoch_sent / (self._rate * elapsed) if elapsed > 0 else 0
        self._app_limited = utilization < .8
        # Feedback is deliberately batched for up to 20ms. Ordinary ACK holding
        # and radio jitter under light application load are not congestion.
        if not self._app_limited and queue_delay > max(.025, base_rtt * .5, 4 * self._rtt_var):
            self._delay_samples = min(3, self._delay_samples + 1)
        else:
            self._delay_samples = 0
        self._measure(now)
        return True

    def _measure(self, now):
        if self._epoch_started is None:
            return
        elapsed = now - self._epoch_started
        if elapsed < max(.25, 2 * self.raw_srtt):
            return
        delivered_rate = self._epoch_delivered / elapsed
        self._delivery_rate = (delivered_rate if not self._delivery_rate else
                               .75 * self._delivery_rate + .25 * delivered_rate)
        utilization = self._epoch_sent / (self._rate * elapsed)
        pressure_ratio = min(1.0, self._epoch_pressure_seconds / elapsed)
        self._last_pressure_ratio = pressure_ratio
        self._last_loss_ratio = (max(0.0, (self._epoch_retired - self._epoch_delivered) / self._epoch_retired)
                                 if self._epoch_retired else 0.0)
        self._app_limited = utilization < .8 and pressure_ratio < .5
        # Growth compares acknowledged bulk with the service actually left for
        # bulk. Both urgent categories have already consumed physical bytes;
        # subtract those once, then convert wire allowance to the unchanged ACK
        # payload unit using this epoch's observed packet mix. Never count an
        # unacknowledged priority/control write as delivered capacity.
        remaining_wire = max(0.0, self._rate * elapsed - self._epoch_unpaced_wire)
        payload_fraction = self._epoch_sent / self._epoch_bulk_wire if self._epoch_bulk_wire else 0.0
        bulk_allowance = remaining_wire * payload_fraction
        self._growth_bulk_allowance = bulk_allowance
        self._growth_utilization = self._epoch_sent / bulk_allowance if bulk_allowance > 0 else 0.0
        self._pacing_wait_ratio=min(1.0,self._epoch_pacing_wait/elapsed)
        self._growth_app_limited = (self._growth_utilization < .8 and pressure_ratio < .5
                                    and self._pacing_wait_ratio < .1)
        # A low sampled rate or larger RTT alone is not lost capacity. Require
        # sustained actual window waits AND a receiver-confirmed settled-byte
        # deficit for two complete observation epochs. Expiry alone is not proof
        # of loss: delayed/held feedback must only back off its retry timer.
        corroborated = (not self._app_limited and pressure_ratio >= .25
                        and self._epoch_retired >= 6000 and self._last_loss_ratio >= .10
                        and delivered_rate < self._rate * .85)
        self._congestion_epochs = self._congestion_epochs + 1 if corroborated else 0
        # Slow additive-only discovery strands a short download near the 1Mbps
        # initial budget even on a much faster link. Probe faster only while
        # authenticated, complete observation epochs confirm useful backlog.
        # Corroborated loss ends startup; delay pauses its growth gate below.
        # A transient radio delay must not strand a healthy link at an early
        # discovery budget for the remainder of the transfer. Neither writes nor ACK
        # compression can independently create an increase.
        # Highest-sequence feedback can retire a reordered packet before its
        # byte counter catches up. A one-epoch deficit alone is not packet loss
        # and must not permanently disable discovery on the slower link.
        if self._startup and corroborated:
            self._startup = False
            self._startup_exit_reason = 'loss'
        if self._congestion_epochs >= 2:
            self._reduce(now)
            self._congestion_epochs = 0
        # Startup increases at most 50% per full epoch and 10Mbps per step.
        # After congestion evidence, retain conservative additive probing.
        if (not self._growth_app_limited and not self._delay_samples and not corroborated
                and self._last_loss_ratio < .01 and pressure_ratio < .25
                and bulk_allowance > 0 and self._epoch_delivered >= 6000
                and self._epoch_retired >= 6000 and self._epoch_delivered >= bulk_allowance * .65
                and now - self._last_backoff >= max(.25, self.raw_srtt)):
            increment = max(12500.0,min(self._rate*.5,1250000.0)) if self._startup else 12500.0
            updated = min(self._maximum_rate, self._rate + increment)
            if updated > self._rate:
                self._rate = updated
                self._rate_increases += 1
                if self._startup:self._startup_increases += 1
        self._epoch_started = now
        self._epoch_sent = self._epoch_delivered = 0
        self._epoch_bulk_wire = self._epoch_unpaced_wire = 0
        self._epoch_retired = 0
        self._epoch_pressure_seconds = 0.0
        self._epoch_pacing_wait = 0.0

    def _reduce(self, now):
        if now - self._last_backoff < max(.1, self.srtt):
            return False
        self._rate = max(self._minimum_rate, self._rate * .8)
        self._last_backoff = now
        self._backoffs += 1
        self._epoch_started = now
        self._epoch_sent = self._epoch_delivered = 0
        self._epoch_bulk_wire = self._epoch_unpaced_wire = 0
        self._epoch_retired = 0
        self._epoch_pressure_seconds = 0.0
        self._epoch_pacing_wait = 0.0
        self._delay_samples = 0
        return True

    def expire(self, now, _measure=True):
        _time(now)
        self._pacing_observed_at = max(self._pacing_observed_at, now)
        self._observe_pressure(now)
        expired = 0
        timeout = self.timeout
        while self._pending:
            pending = next(iter(self._pending.values()))
            if now < pending.sent_at + timeout:
                break
            self._pending.popitem(last=False)
            self.inflight_bytes -= pending.size
            self._expired_bytes += pending.size
            self._expired_packets += 1
            expired += 1
        if expired:
            # Without timeout backoff a genuine RTT increase could make every
            # subsequent ACK arrive after expiry, preventing SRTT from learning
            # the new path delay forever. Progress gradually removes this guard.
            self._rto_backoff = min(16.0, self._rto_backoff * 2)
            self._timeout_backoffs += 1
            self._observe_pressure(now, False)
        if _measure:
            self._measure(now)
        return expired

    def stats(self):
        return {
            "rate_mbps": self.rate_mbps, "delivery_rate_mbps": self._delivery_rate / 125000,
            "initial_rate_mbps": self.initial_rate_mbps, "max_rate_mbps": self.max_rate_mbps,
            "next_send": self.next_send, "inflight_bytes": self.inflight_bytes,
            "wire_overhead": self.wire_overhead,
            "priority_wire_bytes": self._priority_wire_bytes,
            "priority_wire_packets": self._priority_wire_packets,
            "control_wire_bytes": self._control_wire_bytes,
            "control_wire_packets": self._control_wire_packets,
            "priority_debt_saturations": self._priority_debt_saturations,
            "pacing_debt_ms": max(0.0, self.next_send - self._pacing_observed_at) * 1000,
            "pacing_observed_at": self._pacing_observed_at,
            "window_bytes": self.window_bytes, "pending_packets": len(self._pending),
            "srtt_ms": self.srtt * 1000, "min_rtt_ms": None if self.min_rtt is None else self.min_rtt * 1000,
            "raw_srtt_ms": self.raw_srtt * 1000,
            "rtt_var_ms": self._rtt_var * 1000,
            "queue_delay_ms": 0 if self.min_rtt is None else max(0, self.srtt - self.min_rtt) * 1000,
            "timeout_seconds": self.timeout, "sent_packets": self._sent_packets,
            "rto_backoff": self._rto_backoff,
            "sent_bytes": self._sent_bytes, "acked_packets": self._acked_packets,
            "delivered_bytes": self._delivery_counter, "expired_packets": self._expired_packets,
            "expired_bytes": self._expired_bytes, "invalid_acks": self._invalid_acks,
            "untracked_packets": self._untracked_packets, "backoffs": self._backoffs,
            "rate_increases": self._rate_increases, "app_limited": self._app_limited,
            "startup": self._startup, "startup_increases": self._startup_increases,
            "startup_exit_reason": self._startup_exit_reason,
            "growth_app_limited": self._growth_app_limited,
            "growth_bulk_utilization": self._growth_utilization,
            "growth_bulk_allowance_bytes": self._growth_bulk_allowance,
            "pacing_wait_ratio":self._pacing_wait_ratio,
            "delay_samples": self._delay_samples, "delay_backoffs": self._delay_backoffs,
            "timeout_backoffs": self._timeout_backoffs,
            "window_pressure_ratio": self._last_pressure_ratio,
            "settled_loss_ratio": self._last_loss_ratio,
            "congestion_epochs": self._congestion_epochs,
        }
