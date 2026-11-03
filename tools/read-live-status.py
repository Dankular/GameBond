"""Read current client telemetry through the authenticated local relay."""
import json
import io
from datetime import datetime, timezone
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.tty_server import connect, read_metadata, control


def unavailable(state, owner_pid, reason):
    marker = dict(live=False, observed_at=datetime.now(timezone.utc).isoformat(),
                  state=state, owner_pid=owner_pid, reason=reason)
    (ROOT / 'evidence/live-current.json').write_text(json.dumps(marker, indent=2)+'\n')
    print(json.dumps(marker))


def main():
    metadata = read_metadata()
    status = control("status", output=io.StringIO())
    if not status.get("owner_pid") or status.get("state") != "running":
        unavailable(status.get('state'), status.get('owner_pid'),
                    'No running supervised client; retained relay telemetry is historical')
        return
    received = bytearray()
    # tail=0 deliberately excludes replayed records from an earlier run.
    with connect(metadata, "attach", tail=0) as sock:
        sock.settimeout(.2)
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            try:
                data = sock.recv(16384)
            except TimeoutError:
                continue
            if not data:
                break
            received.extend(data)
            if any(b'"transport"' in line for line in received.split(b'\n')[:-1]):
                break
    rows = []
    for line in received.decode("utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    current = next((row for row in reversed(rows) if "transport" in row), None)
    after = control("status", output=io.StringIO())
    if (current is None or after.get("owner_pid") != status["owner_pid"] or after.get("state") != "running"
            or current.get('pid', status['owner_pid']) != status['owner_pid']):
        unavailable(after.get('state'), after.get('owner_pid'),
                    'No fresh telemetry from the same running supervisor')
        return
    current["live"] = True
    current["received_at"] = datetime.now(timezone.utc).isoformat()
    current.setdefault("observed_at", current["received_at"])
    current["owner_pid"] = status["owner_pid"]
    (ROOT / "evidence/live-current.json").write_text(json.dumps(current, indent=2) + "\n")
    transport = current["transport"]
    print(json.dumps(dict(live=True, observed_at=current["observed_at"], owner_pid=status["owner_pid"],
        paths=[dict(local=p["local"], remote=p["remote"], healthy=p["healthy"],
        rtt_ms=round(p["rtt_ms"], 2) if p["rtt_ms"] else None, rate_mbps=p["bonding"]["rate_mbps"],
        delay_backoffs=p["bonding"].get("delay_backoffs"), expired_packets=p["bonding"]["expired_packets"])
        for p in transport["paths"]], auth_failures=transport["auth_failures"],
        socket_errors=transport["socket_errors"], receive_drops=transport["receive_drops"],
        bonded_packets=transport["bonded_packets"], deadline_drops=transport["bonding_deadline_drops"],
        queues=current["queues"].get("queued"))))


if __name__ == "__main__":
    main()
