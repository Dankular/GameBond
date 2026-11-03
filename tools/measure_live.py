"""Measure an IPv4 UDP echo path through the existing active tunnel.

No adapter, route, firewall, VPN, or privileged setting is changed. An echo
listener must already exist at the destination. This measures ordinary probe
traffic, not Call of Duty packets, and does not establish a game kick threshold.
Ctrl+C/SIGTERM stops transmission and writes a partial JSON result.
"""
from __future__ import annotations

import argparse
import json
import math
import select
import signal
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = struct.Struct("!4sIQ")
MAGIC = b"GBL1"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def percentiles(values):
    if not values:
        return {"p50": None, "p95": None, "max": None}
    values = sorted(values)
    def at(fraction):
        position = (len(values) - 1) * fraction
        low, high = int(position), min(int(position) + 1, len(values) - 1)
        return round(values[low] + (values[high] - values[low]) * (position - low), 4)
    return {"p50": at(.5), "p95": at(.95), "max": round(values[-1], 4)}


def summarize(transmissions, arrivals):
    sent = {row["sequence"] for row in transmissions}
    selected = [row for row in arrivals if row["sequence"] in sent]
    seen, unique = set(), []
    duplicates = reordered = gap_events = max_sequence_gap = 0
    highest = -1
    for row in selected:
        seq = row["sequence"]
        if seq in seen:
            duplicates += 1
            continue
        seen.add(seq)
        unique.append(row)
        if highest >= 0:
            if seq < highest:
                reordered += 1
            elif seq > highest + 1:
                gap_events += 1
                max_sequence_gap = max(max_sequence_gap, seq - highest - 1)
        highest = max(highest, seq)
    intervals = [(unique[i]["received_perf_ns"] - unique[i - 1]["received_perf_ns"]) / 1e6
                 for i in range(1, len(unique))]
    return {
        "sent": len(sent), "received": len(seen), "lost": len(sent - seen),
        "loss_percent": round(100 * len(sent - seen) / len(sent), 4) if sent else None,
        "duplicates": duplicates, "reordered": reordered,
        "sequence_gap_events": gap_events, "max_sequence_gap": max_sequence_gap,
        "rtt_ms": percentiles([row["rtt_ms"] for row in unique]),
        "interarrival_ms": percentiles(intervals),
        "lost_sequences": sorted(sent - seen),
    }


def measure(args):
    stop = {"signal": None}
    previous_handlers = {}
    def request_stop(number, frame):
        stop["signal"] = signal.Signals(number).name
    for number in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[number] = signal.signal(number, request_stop)
    transmissions, arrivals, errors = [], [], []
    sent_by_sequence = {}
    invalid = cadence_slips = attempted = 0
    started_utc = utc_now()
    started_ns = time.perf_counter_ns()
    next_send = started_ns
    next_progress = started_ns + round(args.window_seconds * 1e9)
    end_ns = started_ns + round(args.duration * 1e9)
    grace_end_ns = end_ns + round(args.grace_seconds * 1e9)
    destination = (args.destination, args.port)
    period_ns = round(1e9 / args.rate_hz)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bound = None
    fatal_error = None
    try:
        sock.bind((args.bind, 0))
        bound = sock.getsockname()
        sock.setblocking(False)
        print(f"Probe {bound[0]}:{bound[1]} -> {destination[0]}:{destination[1]}, "
              f"{args.rate_hz}Hz for {args.duration:g}s; Ctrl+C saves partial results.", flush=True)
        while True:
            now = time.perf_counter_ns()
            if stop["signal"] is not None:
                end_ns = min(end_ns, now)
                grace_end_ns = min(grace_end_ns, now + round(args.grace_seconds * 1e9))
            if now >= grace_end_ns:
                break
            if now < end_ns and now >= next_send:
                sequence = attempted
                attempted += 1
                sent_ns = time.perf_counter_ns()
                payload = PAYLOAD.pack(MAGIC, sequence, sent_ns)
                try:
                    sock.sendto(payload, destination)
                    row = {"sequence": sequence, "sent_perf_ns": sent_ns,
                           "sent_utc": utc_now(), "elapsed_seconds": (sent_ns - started_ns) / 1e9}
                    transmissions.append(row)
                    sent_by_sequence[sequence] = row
                except OSError as exc:
                    errors.append({"sequence": sequence, "utc": utc_now(), "operation": "sendto", "error": str(exc)})
                next_send += period_ns
                if next_send < now - 2 * period_ns:
                    cadence_slips += 1
                    next_send = now + period_ns
            if now >= next_progress:
                elapsed = (now - started_ns) / 1e9
                summary = summarize(transmissions, arrivals)
                print(f"{elapsed:6.1f}s sent={summary['sent']} received={summary['received']} "
                      f"pending/lost={summary['lost']} RTTp95={summary['rtt_ms']['p95']}ms "
                      f"maxgap={summary['interarrival_ms']['max']}ms", flush=True)
                next_progress += round(args.window_seconds * 1e9)
            now = time.perf_counter_ns()
            next_event = min(next_progress, grace_end_ns, next_send if now < end_ns else grace_end_ns)
            readable, _, _ = select.select([sock], [], [], max(0, min(.1, (next_event - now) / 1e9)))
            if readable:
                for _ in range(256):
                    try:
                        payload, source = sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    except OSError as exc:
                        errors.append({"utc": utc_now(), "operation": "recvfrom", "error": str(exc)})
                        break
                    received_ns = time.perf_counter_ns()
                    if source != destination or len(payload) != PAYLOAD.size:
                        invalid += 1
                        continue
                    magic, sequence, sent_ns = PAYLOAD.unpack(payload)
                    original = sent_by_sequence.get(sequence)
                    if magic != MAGIC or original is None or original["sent_perf_ns"] != sent_ns:
                        invalid += 1
                        continue
                    arrivals.append({"sequence": sequence, "received_perf_ns": received_ns,
                                     "received_utc": utc_now(), "rtt_ms": (received_ns - sent_ns) / 1e6})
    except OSError as exc:
        fatal_error = str(exc)
    finally:
        sock.close()
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    finished_ns = time.perf_counter_ns()
    active_seconds = max(0, min(args.duration, (min(end_ns, finished_ns) - started_ns) / 1e9))
    windows = []
    for index in range(max(1, math.ceil(active_seconds / args.window_seconds))):
        low, high = index * args.window_seconds, min((index + 1) * args.window_seconds, active_seconds)
        selected = [row for row in transmissions if low <= row["elapsed_seconds"] < high]
        windows.append({"window": index, "start_seconds": low, "end_seconds": high,
                        **summarize(selected, arrivals)})
    result = {
        "measurement": "Normal IPv4 UDP echo probe through an existing tunnel",
        "started_utc": started_utc, "finished_utc": utc_now(),
        "clock": "time.perf_counter_ns", "clock_resolution_seconds": time.get_clock_info("perf_counter").resolution,
        "started_perf_ns": started_ns, "finished_perf_ns": finished_ns,
        "requested_duration_seconds": args.duration, "transmission_seconds": active_seconds,
        "rate_hz": args.rate_hz, "window_seconds": args.window_seconds,
        "local": bound, "destination": destination, "payload_bytes": PAYLOAD.size,
        "attempted": attempted, "cadence_slips": cadence_slips, "invalid_datagrams": invalid,
        "interrupted_by": stop["signal"], "partial": bool(stop["signal"] or fatal_error),
        "fatal_error": fatal_error, "errors": errors,
        "aggregate": summarize(transmissions, arrivals), "windows": windows,
        "transmissions": transmissions, "arrivals": arrivals,
        "limitations": [
            "Application UDP echo measurement; no packet capture or physical-link state observation.",
            "Loss is unanswered successful sends after the receive grace period; progress pending/lost includes in-flight requests.",
            "Windows are disjoint send-time intervals; aggregate interarrival metrics also include gaps across interval boundaries.",
            "RTT includes host scheduling and echo handling. No Call of Duty traffic or disconnection threshold is measured.",
            "A physical interruption is meaningful only if independently recorded; this tool never changes network settings.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "partial": result["partial"],
                      "aggregate": result["aggregate"], "fatal_error": fatal_error}, indent=2), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="10.77.0.2")
    parser.add_argument("--destination", default="10.77.0.1")
    parser.add_argument("--port", type=int, default=9009)
    parser.add_argument("--duration", type=float, default=90)
    parser.add_argument("--rate-hz", type=int, default=60)
    parser.add_argument("--window-seconds", type=float, default=10)
    parser.add_argument("--grace-seconds", type=float, default=1)
    parser.add_argument("--output", type=Path, default=ROOT / "evidence" / "live-measurement.json")
    args = parser.parse_args()
    if not 0 < args.duration <= 86400 or not 1 <= args.rate_hz <= 1000 or not 0 < args.window_seconds <= 3600 or not 0 <= args.grace_seconds <= 60:
        parser.error("invalid duration, rate, window, or grace")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between1 and65535")
    socket.inet_aton(args.bind)
    socket.inet_aton(args.destination)
    result = measure(args)
    return int(bool(result["fatal_error"]))


if __name__ == "__main__":
    raise SystemExit(main())
