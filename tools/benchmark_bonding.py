"""Single-flow software-paced loopback aggregation check. No physical-link claim."""
import argparse
import json
from pathlib import Path
import queue
import secrets
import struct
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gamebond.bonding import PathBudget
from gamebond.transport import Node, OVERHEAD, BOND_OVERHEAD


def measure(direction, rates, seconds):
    key, session = secrets.token_bytes(32), secrets.token_bytes(16)
    options = dict(bonding_mode=True, mtu=1280 + OVERHEAD + BOND_OVERHEAD,
                   probe_interval=.05, path_timeout=.5, receive_capacity=4096)
    server = Node(key, "server", session, [("127.0.0.1", 0)], **options).start()
    client = Node(key, "client", session, [("127.0.0.1", 0)] * len(rates),
                  peer=server.addresses[0], **options).start()
    sender, receiver = (client, server) if direction == "upload" else (server, client)
    stop = threading.Event()
    received = []
    def consume():
        while not stop.is_set():
            try:
                received.append((time.perf_counter(), receiver.recv(.05)))
            except queue.Empty:
                pass
    consumer = threading.Thread(target=consume, daemon=True)
    try:
        deadline = time.perf_counter() + 3
        while time.perf_counter() < deadline:
            if len(server._paths) == len(rates) and all(p.last_rx for p in client._paths.values()):
                break
            time.sleep(.005)
        else:
            raise RuntimeError("loopback authentication timed out")
        with sender._lock:
            for path, rate in zip(sender._paths.values(), rates):
                path.budget = PathBudget(initial_rate_mbps=rate, max_rate_mbps=rate)
        consumer.start()
        start = time.perf_counter()
        sent = 0
        while time.perf_counter() - start < seconds:
            payload = struct.pack("!Q", sent) + b"x" * 992
            if sender.send(payload, replicate=False, flow_id="single-session-single-flow"):
                sent += 1
        end = time.perf_counter()
        deadline = end + 1
        while len(received) < sent and time.perf_counter() < deadline:
            time.sleep(.005)
        stats = sender.stats()
        numbers = [struct.unpack_from("!Q", payload)[0] for _, payload in received]
        delivered_in_window = sum(len(payload) for stamp, payload in received if stamp <= end)
        return dict(direction=direction, configured_path_caps_mbps=rates,
                    seconds=end - start, sent=sent, received=len(numbers),
                    ordered=numbers == list(range(sent)),
                    payload_mbps=delivered_in_window * 8 / (end - start) / 1e6,
                    per_path_packets=[p["bonding"]["sent_packets"] for p in stats["paths"]],
                    deadline_drops=stats["bonding_deadline_drops"],
                    feedback_received=stats["feedback_received"],
                    receive_drops=receiver.stats()["receive_drops"])
    finally:
        stop.set()
        if consumer.is_alive():
            consumer.join(1)
        client.close()
        server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=3)
    parser.add_argument("--output", type=Path, default=Path("evidence/bonding-loopback.json"))
    args = parser.parse_args()
    if not 1 <= args.seconds <= 30:
        parser.error("seconds must be 1..30")
    rows = [measure(direction, rates, args.seconds)
            for direction in ("upload", "download") for rates in ([1], [2], [1, 2])]
    result = dict(scope="Real UDP loopback sockets with software path caps; not Starlink/5G or ISP capacity measurement",
                  cases=rows)
    args.output.parent.mkdir(exist_ok=True, parents=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not all(r["ordered"] and r["receive_drops"] == 0 and r["deadline_drops"] == 0 for r in rows):
        raise SystemExit("delivery/order check failed")
    for offset in (0, 3):
        if rows[offset + 2]["payload_mbps"] < max(r["payload_mbps"] for r in rows[offset:offset + 2]) * 1.15:
            raise SystemExit("single-flow aggregation did not exceed the faster single path by 15%")


if __name__ == "__main__":
    main()
