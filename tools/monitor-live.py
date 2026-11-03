"""Passively retain relay telemetry and print compact live health samples."""
import json
from pathlib import Path
import socket
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.tty_server import connect, read_metadata

duration = float(sys.argv[1]) if len(sys.argv) > 1 else 300
target = ROOT / "evidence" / ("monitor-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".jsonl")
print(str(target), flush=True)
with target.open("a", encoding="utf-8") as output, connect(read_metadata(), "attach", tail=2) as sock:
    sock.settimeout(1)
    deadline = time.monotonic() + duration
    pending = b""
    while time.monotonic() < deadline:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue
        if not data:
            print("Relay disconnected", flush=True)
            break
        pending += data
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if "transport" not in row:
                continue
            stamp = datetime.now(timezone.utc).isoformat()
            output.write(json.dumps({"observed_at": stamp, **row}) + "\n")
            output.flush()
            t, q = row["transport"], row["queues"]
            print(json.dumps({"time": stamp, "paths": [{"healthy": p["healthy"], "rtt": round(p["rtt_ms"] or 0, 1), "budget": p["bonding"]["rate_mbps"], "cuts": p["bonding"]["backoffs"], "expired": p["bonding"]["expired_packets"]} for p in t["paths"]], "queued": q.get("queued", 0), "stale": q.get("dropped_stale", 0), "full": q.get("dropped_full", 0), "receive_drops": t["receive_drops"], "socket_errors": t["socket_errors"], "game_packets": row["packets"]["direct_priority_packets"], "reorder_gaps": t["reorder"]["gap_events"]}), flush=True)
