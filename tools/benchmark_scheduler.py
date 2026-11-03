"""Bounded scheduler microbenchmark; does not open tunnels or send traffic.

Keep a bulk FIFO backlog, then repeatedly enqueue eight priority datagrams and
serve nine packets. Bulk is replenished only when served. This checks both the
priority residence time and the promised minimum bulk service under bursts.
Compare the same command before/after a scheduler change; figures are local
Python scheduling measurements, not game RTT or a throughput guarantee.
"""
import argparse
import json
from pathlib import Path
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gamebond.policy import Classification, PacketInfo, PriorityScheduler, QueuePolicy


def percentile(values, percent):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * percent))] if values else 0


def run(rounds=200, backlog=1024, priority_age_ms=20):
    scheduler = PriorityScheduler(capacity=backlog + 32, priority_burst=8)
    info = PacketInfo(4, 0, 17, b"\x0a\0\0\1", b"\x0a\0\0\2", 3075, 4000)
    bulk = Classification(info, 0, QueuePolicy(capacity=backlog + 16, max_age_ms=60000))
    game = Classification(info, 46, QueuePolicy(priority=True, replicate=True,
                                               capacity=32, max_age_ms=priority_age_ms))
    payload = b"benchmark-datagram" * 4
    for _ in range(backlog):
        assert scheduler.push(payload, bulk)
    residence, priority_served, bulk_served, push_rejections = [], 0, 0, 0
    started = time.perf_counter()
    for _ in range(rounds):
        for _ in range(8):
            if not scheduler.push(payload, game):
                push_rejections += 1
        for _ in range(9):
            item = scheduler.pop(0)
            if item is None:
                continue
            if item.classification.policy.priority:
                priority_served += 1
                residence.append(max(0, (time.perf_counter() - item.enqueued_at) * 1000))
            else:
                bulk_served += 1
                if not scheduler.push(payload, bulk):
                    push_rejections += 1
    elapsed = time.perf_counter() - started
    stats = scheduler.stats()
    result = {
        "rounds": rounds, "bulk_backlog": backlog, "elapsed_seconds": elapsed,
        "scheduler_calls_per_second": (rounds * 17 + bulk_served) / elapsed,
        "priority_served": priority_served, "bulk_served": bulk_served,
        "priority_residence_ms": {"mean": statistics.fmean(residence) if residence else 0,
                                   "p50": percentile(residence, .50),
                                   "p95": percentile(residence, .95),
                                   "max": max(residence, default=0)},
        "push_rejections": push_rejections,
        "dropped_stale": stats.get("dropped_stale", 0),
        "dropped_full": stats.get("dropped_full", 0),
        "priority_all_delivered": priority_served == rounds * 8,
        "bulk_not_starved": bulk_served >= rounds,
        "remaining_queued": stats["queued"],
    }
    scheduler.close()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="current")
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--backlog", type=int, default=1024)
    parser.add_argument("--priority-age-ms", type=float, default=20)
    arguments = parser.parse_args()
    if not 1 <= arguments.rounds <= 10000 or not 1 <= arguments.backlog <= 4096:
        parser.error("rounds must be 1..10000 and backlog 1..4096")
    print(json.dumps({"label": arguments.label, **run(arguments.rounds, arguments.backlog,
                                                    arguments.priority_age_ms)}))
