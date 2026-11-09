"""Run the GameBond tunnel and an OpenMPTCProuter tunnel side by side behind one Node-like object.

Traffic classes listed in `gamebond_dscp` (default gameplay 46 and calls 26) use the GameBond transport,
with its replication, dedupe, deadline queues and adaptive QoS intact. Everything else uses OMR, with its
source rewritten by a stateful NAT to the OMR tunnel address. A flow stays on one transport; if its
transport stops being ready the flow is re-decided onto the other one (a TCP flow breaks once, which beats
stalling forever). Inbound packets from both transports are merged, OMR's through the NAT.

The runtime keeps using this object exactly like a Node: send / recv / stats / close, plus delegation of
everything else (link updates, link states) to the GameBond transport.
"""
from __future__ import annotations

import queue
import threading
import time
from collections import OrderedDict

GAMEBOND, OMR = "gamebond", "omr"
DEFAULT_GAMEBOND_DSCP = (46, 26)
FLOW_CACHE = 16384


class TransportRouter:
    def __init__(self, gamebond, omr, nat, *, gamebond_dscp=DEFAULT_GAMEBOND_DSCP, flow_ttl: float = 120.0,
                 ready_ttl: float = 0.25, clock=time.monotonic):
        self.gamebond, self.omr, self.nat = gamebond, omr, nat
        self.gamebond_dscp = frozenset(gamebond_dscp)
        self.flow_ttl, self.ready_ttl, self.clock = flow_ttl, ready_ttl, clock
        self.flows: OrderedDict = OrderedDict()          # flow_id -> (transport, last seen)
        self.lock = threading.Lock()
        self.inbox: "queue.Queue[bytes]" = queue.Queue(maxsize=8192)
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        self._ready_cache = {GAMEBOND: (-1e9, False), OMR: (-1e9, False)}
        self.counts = dict(sent_gamebond=0, sent_omr=0, fallbacks=0, nat_dropped=0, send_failed=0,
                           recv_gamebond=0, recv_omr=0, recv_nat_dropped=0, inbox_full=0)

    # --- lifecycle --------------------------------------------------------------------------------------------

    def start(self) -> "TransportRouter":
        for name, source in ((GAMEBOND, self.gamebond), (OMR, self.omr)):
            thread = threading.Thread(target=self._pump, args=(name, source), daemon=True, name="gamebond-router-" + name)
            thread.start()
            self.threads.append(thread)
        return self

    def close(self) -> None:
        self.stop.set()
        for thread in self.threads:
            thread.join(2)
        for transport in (self.omr, self.gamebond):
            try:
                transport.close()
            except Exception:                      # one transport failing to close must not leak the other
                pass

    def __getattr__(self, name):
        # Link updates, link states and the rest of the Node surface belong to the GameBond transport.
        if name in ("gamebond", "omr", "nat"):
            raise AttributeError(name)
        return getattr(self.gamebond, name)

    # --- readiness and routing --------------------------------------------------------------------------------

    def _ready(self, name: str) -> bool:
        now = self.clock()
        stamp, value = self._ready_cache[name]
        if now - stamp < self.ready_ttl:
            return value
        try:
            if name == OMR:
                value = bool(self.omr.ready)
            else:
                paths = self.gamebond.stats().get("paths", [])
                value = any(p.get("healthy") and p.get("enabled", True) for p in paths)
        except Exception:
            value = False
        self._ready_cache[name] = (now, value)
        return value

    def choose(self, flow_id, dscp) -> str:
        want = GAMEBOND if dscp in self.gamebond_dscp else OMR
        now = self.clock()
        with self.lock:
            if flow_id is not None:
                cached = self.flows.get(flow_id)
                if cached is not None and now - cached[1] < self.flow_ttl and self._ready(cached[0]):
                    self.flows[flow_id] = (cached[0], now)
                    self.flows.move_to_end(flow_id)
                    return cached[0]
            if not self._ready(want):
                other = OMR if want == GAMEBOND else GAMEBOND
                if self._ready(other):
                    want = other
                    self.counts["fallbacks"] += 1
            if flow_id is not None:
                self.flows[flow_id] = (want, now)
                self.flows.move_to_end(flow_id)
                while len(self.flows) > FLOW_CACHE:
                    self.flows.popitem(last=False)
            return want

    # --- link changes: the GameBond transport owns them, the OMR leg follows --------------------------------

    def update_client_paths(self, bind, interface_indices=None, available=None):
        errors = list(self.gamebond.update_client_paths(bind, interface_indices, available) or [])
        try:
            errors += [dict(leg="omr", **e) for e in self.omr.update_paths([b[0] for b in bind], interface_indices, available)]
        except (ValueError, OSError) as exc:
            errors.append(dict(leg="omr", error=str(exc)))
        return errors

    def set_link_states(self, states):
        """Roles, caps and speed limits apply to both legs; a blocked (over-cap) link counts as role "never"."""
        self.gamebond.set_link_states(states)
        try:
            self.omr.set_roles(["never" if s.get("blocked") else s.get("role", "primary") for s in states])
            self.omr.set_rates([s.get("upload_mbps", 0) or 0 for s in states], [s.get("download_mbps", 0) or 0 for s in states])
        except (ValueError, AttributeError):
            self.counts["link_state_errors"] = self.counts.get("link_state_errors", 0) + 1

    # --- data plane -------------------------------------------------------------------------------------------

    def send(self, payload: bytes, replicate: bool = True, flow_id=None, *, urgent: bool = False, dscp: int = 0) -> int:
        """Send one IPv4 packet; returns the number of copies handed to a transport (0 if dropped)."""
        target = self.choose(flow_id, dscp)
        if target == OMR:
            translated = self.nat.outbound(bytes(payload))
            if translated is None:
                self.counts["nat_dropped"] += 1
                return 0
            sent = 1 if self.omr.send(translated, urgent=urgent or dscp in self.gamebond_dscp) else 0
            self.counts["sent_omr" if sent else "send_failed"] += 1
            return sent
        sent = self.gamebond.send(payload, replicate=replicate, flow_id=flow_id, urgent=urgent)
        self.counts["sent_gamebond" if sent else "send_failed"] += 1
        return sent

    def recv(self, timeout: float | None = None) -> bytes:
        return self.inbox.get(timeout=timeout)

    def _pump(self, name: str, source) -> None:
        while not self.stop.is_set():
            try:
                packet = source.recv(0.2)
            except queue.Empty:
                continue
            except Exception:
                if self.stop.is_set():
                    return
                time.sleep(0.05)
                continue
            if name == OMR:
                packet = self.nat.inbound(packet)
                if packet is None:
                    self.counts["recv_nat_dropped"] += 1
                    continue
            self.counts["recv_" + name] += 1
            try:
                self.inbox.put_nowait(packet)
            except queue.Full:
                self.counts["inbox_full"] += 1

    # --- observability ----------------------------------------------------------------------------------------

    def stats(self) -> dict:
        omr = {}
        try:
            omr = dict(self.omr.stats())
        except Exception:
            pass
        return {**self.gamebond.stats(), "router": dict(self.counts, flows=len(self.flows), nat=self.nat.stats(),
                                                        gamebond_ready=self._ready(GAMEBOND), omr_ready=self._ready(OMR)),
                "omr": omr}
