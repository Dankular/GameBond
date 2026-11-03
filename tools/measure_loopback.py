"""Measure real UDP loopback delivery under synthetic per-path send blackholes.

This is a transport integration measurement, not a packet capture or a test of
physical 5G/Starlink links, routing, NAT, VPS latency, or CoD disconnection limits.
Run from any directory: python tools/measure_loopback.py
"""
from __future__ import annotations

import argparse
import json
import platform
import queue
import secrets
import struct
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gamebond.transport import Node

PAYLOAD = struct.Struct("!IQ")
PHASES = [
    ("baseline", 1.5, None),
    ("path_1_blackhole", 1.5, 0),
    ("both_paths_recovered", .5, None),
    ("path_2_blackhole", 1.5, 1),
    ("final_recovery", 1.0, None),
]


def percentiles(values):
    if not values:
        return {"p50": None, "p95": None, "max": None}
    ordered = sorted(values)
    def percentile(fraction):
        position = (len(ordered) - 1) * fraction
        low, high = int(position), min(int(position) + 1, len(ordered) - 1)
        return round(ordered[low] + (ordered[high] - ordered[low]) * (position - low), 4)
    return {"p50": percentile(.5), "p95": percentile(.95), "max": round(max(ordered), 4)}


def summarize(sent, arrivals):
    sent_sequences = set(sent)
    selected = [(seq, arrived, elapsed) for seq, arrived, elapsed in arrivals if seq in sent_sequences]
    seen = set()
    unique = []
    duplicate_count = reordered = gap_events = max_sequence_gap = 0
    previous = None
    for seq, arrived, elapsed in selected:
        if seq in seen:
            duplicate_count += 1
            continue
        seen.add(seq)
        unique.append((seq, arrived, elapsed))
        if previous is not None:
            if seq < previous:
                reordered += 1
            elif seq > previous + 1:
                gap_events += 1
                max_sequence_gap = max(max_sequence_gap, seq - previous - 1)
        previous = seq
    intervals = [(unique[i][1] - unique[i - 1][1]) / 1e6 for i in range(1, len(unique))]
    return {
        "sent": len(sent_sequences), "received": len(seen),
        "lost": len(sent_sequences - seen), "duplicates": duplicate_count,
        "reordered": reordered, "sequence_gap_events": gap_events,
        "max_sequence_gap": max_sequence_gap,
        "rtt_ms": percentiles([row[2] for row in unique]),
        "interarrival_ms": percentiles(intervals),
    }


def measure(rate_hz=60):
    if not 1 <= rate_hz <= 1000:
        raise ValueError("rate must be between 1 and 1000 Hz")
    key, session = secrets.token_bytes(32), secrets.token_bytes(16)
    server = Node(key, "server", session, [("127.0.0.1", 0)],
                  probe_interval=.05, path_timeout=.3)
    client = Node(key, "client", session, [("127.0.0.1", 0), ("127.0.0.1", 0)],
                  peer=server.addresses[0], probe_interval=.05, path_timeout=.3)
    stop = threading.Event()
    current = {"disabled": None}
    injected = Counter()
    arrivals = []
    sent = {}
    errors = []
    client_write, server_write = client._write, server._write
    client_addresses = client.addresses

    def write_client(packet, path):
        if path.socket_index == current["disabled"]:
            injected["client_dropped_copies"] += 1
            return False
        return client_write(packet, path)

    def write_server(packet, path):
        disabled = current["disabled"]
        if disabled is not None and path.endpoint == client_addresses[disabled]:
            injected["server_dropped_copies"] += 1
            return False
        return server_write(packet, path)

    # Only this process's send calls are selectively suppressed. No host route,
    # network adapter, firewall, VPN, or physical interface setting is changed.
    client._write, server._write = write_client, write_server

    def echo():
        while not stop.is_set():
            try:
                payload = server.recv(.05)
            except queue.Empty:
                continue
            if not server.send(payload, replicate=True):
                errors.append("server had no writable learned path")

    def collect():
        while not stop.is_set():
            try:
                payload = client.recv(.05)
            except queue.Empty:
                continue
            arrived = time.perf_counter_ns()
            if len(payload) != PAYLOAD.size:
                errors.append("unexpected echo size")
                continue
            sequence, started = PAYLOAD.unpack(payload)
            arrivals.append((sequence, arrived, (arrived - started) / 1e6))

    workers = []
    try:
        server.start()
        client.start()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            paths = server.stats()["paths"]
            if len(paths) == 2 and all(path["healthy"] for path in paths):
                break
            time.sleep(.01)
        else:
            raise RuntimeError("two loopback paths failed to register")
        for operation in (echo, collect):
            worker = threading.Thread(target=operation, daemon=True)
            worker.start()
            workers.append(worker)
        sequence = 0
        phase_reports = []
        started_ns = time.perf_counter_ns()
        for name, duration, disabled in PHASES:
            current["disabled"] = disabled
            phase_start = sequence
            count = round(duration * rate_hz)
            for _ in range(count):
                target_ns = started_ns + round(sequence * 1e9 / rate_hz)
                delay = (target_ns - time.perf_counter_ns()) / 1e9
                if delay > 0:
                    time.sleep(delay)
                sent_ns = time.perf_counter_ns()
                sent[sequence] = name
                if not client.send(PAYLOAD.pack(sequence, sent_ns), replicate=True):
                    errors.append("client had no writable configured path")
                sequence += 1
            phase_reports.append({"phase": name, "duration_seconds": duration,
                                  "disabled_path": None if disabled is None else disabled + 1,
                                  "first_sequence": phase_start, "last_sequence": sequence - 1})
        current["disabled"] = None
        # Allow delayed responses to arrive; elapsed transmission phases remain 6s.
        grace_deadline = time.monotonic() + 1
        while time.monotonic() < grace_deadline:
            if len({row[0] for row in arrivals}) >= len(sent):
                time.sleep(.1)  # observe late duplicate deliveries, if any
                break
            time.sleep(.01)
        stop.set()
        for worker in workers:
            worker.join(timeout=1)
        for report in phase_reports:
            phase_sequences = {seq for seq, name in sent.items() if name == report["phase"]}
            report.update(summarize(phase_sequences, arrivals))
        result = {
            "measurement": "UDP loopback with synthetic per-path send blackholes",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(), "python": platform.python_version(),
            "measurement_clock": "time.perf_counter_ns",
            "clock_resolution_seconds": time.get_clock_info("perf_counter").resolution,
            "limitations": [
                "Real UDP sockets on loopback; blackholes injected by suppressing Node._write per path in this harness.",
                "Not a packet capture. Does not measure physical Starlink/5G links, actual routing, NAT, VPS, or CoD behavior.",
                "RTT includes Python scheduling and echo processing; no physical failover or no-disconnect guarantee.",
                "Interarrival metrics group arrivals by the request's send phase; phase transitions are additionally covered by aggregate metrics.",
            ],
            "rate_hz": rate_hz, "transmission_seconds": sum(row[1] for row in PHASES),
            "traffic": f"12-byte sequence/timestamp payloads, {rate_hz}Hz client requests with server echoes, duplicated both ways",
            "aggregate": summarize(set(sent), arrivals), "phases": phase_reports,
            "injected_send_blackholes": dict(injected), "errors": errors,
            "client_transport": client.stats(), "server_transport": server.stats(),
        }
        return result
    finally:
        stop.set()
        for worker in workers:
            worker.join(timeout=1)
        client.close()
        server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "evidence" / "loopback-measurement.json")
    parser.add_argument("--rate-hz", type=int, default=60)
    args = parser.parse_args()
    result = measure(args.rate_hz)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "aggregate": result["aggregate"],
                      "phases": result["phases"], "errors": result["errors"]}, indent=2))
    return int(result["aggregate"]["lost"] > 0 or bool(result["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
