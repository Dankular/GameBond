"""Bounded, clock-free state machines for data-plane path evidence.

``CopyLedger`` compares replicated copies of one packet across paths.
``MtuProber`` runs one path's outbound MTU search. Both are pure: the caller
supplies every timestamp and serializes access.

Limits: a packet lost on every path leaves no ledger entry, so it is invisible
here, and a copy that arrives later than the resolve delay is counted missed
until it shows up (see ``CopyLedger.duplicate``).
"""
from __future__ import annotations

from collections import OrderedDict

# Outer UDP payload sizes (the complete datagram body, as ``Node.mtu`` counts).
MTU_LADDER = (1472, 1400, 1344, 1280, 1232, 1200, 1100, 1000, 800, 600, 548)
MTU_ROUND_SECONDS = 1.0     # spacing between search rounds
MTU_STRIKES = 3             # unanswered rounds before a size counts as failed
MTU_RECHECK_SECONDS = 60.0  # settled/blocked paths re-run the search this often


class CopyLedger:
    """First-arrival ledger for replicated packets, keyed by transport sequence.

    ``first`` records which paths were expected to carry a copy. ``duplicate``
    notes further copies. ``resolve`` decides, once a packet is older than the
    resolve delay, which expected paths delivered it and which did not.
    """

    def __init__(self, capacity=4096):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        self.capacity = capacity
        self._pending = OrderedDict()   # sequence -> [first_at, expected, {identity: at}]
        self._resolved = OrderedDict()  # sequence -> (first_at, {identities counted missed})

    @property
    def has_pending(self):
        return bool(self._pending)

    def first(self, sequence, identity, expected, now):
        self._pending[sequence] = [now, tuple(expected), {identity: now}]
        while len(self._pending) > self.capacity:
            self._pending.popitem(last=False)

    def duplicate(self, sequence, identity, now):
        """Return ``('pending'|'late', lag_seconds)`` or ``None`` if unknown.

        'late' means the path had already been counted missed for this packet;
        the caller reverses that count and treats the lag as jitter evidence.
        """
        entry = self._pending.get(sequence)
        if entry is not None:
            if identity in entry[2]:
                return None
            entry[2][identity] = now
            return "pending", max(0.0, now - entry[0])
        resolved = self._resolved.get(sequence)
        if resolved is not None and identity in resolved[1]:
            resolved[1].discard(identity)
            return "late", max(0.0, now - resolved[0])
        return None

    def resolve(self, now, delay):
        """Return ``[(identity, 'seen'|'missed')]`` for packets older than delay.

        Packets with fewer than two expected paths carry no comparison and
        produce no outcome.
        """
        outcomes = []
        while self._pending:
            sequence, (first_at, expected, arrived) = next(iter(self._pending.items()))
            if now - first_at < delay:
                break
            self._pending.popitem(last=False)
            if len(expected) < 2:
                continue
            missed = set()
            for identity in expected:
                if identity in arrived:
                    outcomes.append((identity, "seen"))
                else:
                    outcomes.append((identity, "missed"))
                    missed.add(identity)
            if missed:
                self._resolved[sequence] = (first_at, missed)
                while len(self._resolved) > self.capacity:
                    self._resolved.popitem(last=False)
        return outcomes

    def stats(self):
        return dict(pending=len(self._pending), resolved=len(self._resolved))


class MtuProber:
    """Outbound MTU search for one path.

    Until the peer answers *any* probe, ``path_mtu`` stays at ``ceiling``: a
    peer that predates the probe message would otherwise look like a path that
    drops every large packet. After the first answer, ``path_mtu`` is the
    largest answered size. Every ladder size above it is probed once per round;
    a size unanswered for ``MTU_STRIKES`` rounds is failed until the next
    recheck.
    """

    def __init__(self, ceiling, floor):
        if type(ceiling) is not int or type(floor) is not int or not 0 < floor <= ceiling:
            raise ValueError("invalid MTU bounds")
        sizes = {ceiling} | {s for s in MTU_LADDER if floor <= s <= ceiling}
        self.sizes = tuple(sorted(sizes, reverse=True))
        self.ceiling = ceiling
        self.confirmed = None
        self._strikes = {}
        self._outstanding = {}   # (nonce, size) -> sent_at
        self._round_at = None
        self._recheck_at = None
        self.rounds = self.acks = 0

    @property
    def capable(self):
        return self.confirmed is not None

    @property
    def path_mtu(self):
        return self.confirmed if self.confirmed is not None else self.ceiling

    def _failed(self, size):
        return self._strikes.get(size, 0) >= MTU_STRIKES

    def _open_sizes(self):
        above = self.confirmed if self.confirmed is not None else 0
        return [s for s in self.sizes if s > above and not self._failed(s)]

    def due(self, now, new_nonce):
        """Return ``[(nonce, size)]`` to transmit now (possibly empty)."""
        # A round that went unanswered strikes every size it covered.
        stale = [k for k, sent in self._outstanding.items() if now - sent >= MTU_ROUND_SECONDS * 1.5]
        for key in stale:
            del self._outstanding[key]
            self._strikes[key[1]] = self._strikes.get(key[1], 0) + 1
        open_sizes = self._open_sizes()
        if not open_sizes:
            if self._recheck_at is None:
                self._recheck_at = now + MTU_RECHECK_SECONDS
            elif now >= self._recheck_at:
                self._strikes.clear()
                self._recheck_at = None
                open_sizes = self._open_sizes()
            if not open_sizes:
                return []
        if self._round_at is not None and now - self._round_at < MTU_ROUND_SECONDS:
            return []
        self._round_at = now
        self.rounds += 1
        sends = []
        for size in open_sizes:
            nonce = new_nonce()
            self._outstanding[(nonce, size)] = now
            sends.append((nonce, size))
        return sends

    def acknowledge(self, nonce, size):
        """Record an answer; return True when it matched an outstanding probe."""
        if self._outstanding.pop((nonce, size), None) is None:
            return False
        self.acks += 1
        if self.confirmed is None or size > self.confirmed:
            self.confirmed = size
        for other in list(self._strikes):
            if other <= size:
                del self._strikes[other]
        # Probes for smaller sizes in this round no longer add information.
        for key in [k for k in self._outstanding if k[1] <= size]:
            del self._outstanding[key]
        return True

    def stats(self):
        return dict(path_mtu=self.path_mtu, ceiling=self.ceiling, confirmed=self.confirmed,
                    capable=self.capable, rounds=self.rounds, acks=self.acks,
                    failed_sizes=sorted(s for s in self.sizes if self._failed(s)))
