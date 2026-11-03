"""Bounded metadata-only observations of priority flows; gaps are not loss rates."""
from collections import OrderedDict
import ipaddress
import threading
import time


class PriorityFlowTelemetry:
    def __init__(self, game_ports=(), *, capacity=128, clock=time.perf_counter):
        self.game_ports = frozenset(game_ports)
        self.capacity, self.clock = capacity, clock
        self.flows = OrderedDict()
        self.lock = threading.Lock()

    def observe(self, classification, size, *, incoming):
        if not classification.policy.priority:
            return
        info, now = classification.info, self.clock()
        source = [str(ipaddress.ip_address(info.source)), info.source_port]
        destination = [str(ipaddress.ip_address(info.destination)), info.destination_port]
        direction = 'incoming' if incoming else 'outgoing'
        key = (direction, info.protocol, tuple(source), tuple(destination))
        reason = ('configured_game_port' if info.protocol == 17 and
                  (info.source_port in self.game_ports or info.destination_port in self.game_ports)
                  else 'learned_flow' if info.dscp != classification.dscp else 'dscp_rule')
        if info.fragmented:
            reason = classification.reason
        with self.lock:
            record = self.flows.pop(key, None)
            if record is None:
                record = dict(direction=direction, protocol=info.protocol, source=source,
                    destination=destination, packets=0, bytes=0, observed_gap_samples=0,
                    observed_gap_max_ms=0.0, observed_gaps_over_50ms=0, observed_gaps_over_100ms=0)
            else:
                gap = max(0.0, now - record['last_seen']) * 1000
                record['observed_gap_samples'] += 1
                record['observed_gap_max_ms'] = max(record['observed_gap_max_ms'], gap)
                record['observed_gaps_over_50ms'] += gap > 50
                record['observed_gaps_over_100ms'] += gap > 100
            record.update(original_dscp=info.dscp, effective_dscp=classification.dscp,
                          reason=reason, replicate=classification.policy.replicate,
                          fragmented=info.fragmented, last_seen=now)
            record['packets'] += 1
            record['bytes'] += size
            self.flows[key] = record
            while len(self.flows) > self.capacity:
                self.flows.popitem(last=False)

    def stats(self):
        with self.lock:
            now = self.clock()
            return [{**{k: v for k, v in value.items() if k != 'last_seen'},
                     'age_ms': max(0.0, now-value['last_seen'])*1000}
                    for value in self.flows.values()]
