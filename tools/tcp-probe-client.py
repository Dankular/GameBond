"""Measure a small single TCP flow through the active tunnel, not link maxima."""
import json
from pathlib import Path
import socket
import time

SIZE = 1024 * 1024
results = []
for mode in (b"U", b"D"):
    with socket.create_connection(("10.77.0.1", 9010), timeout=10) as connection:
        connection.settimeout(20)
        connection.sendall(mode)
        start = time.perf_counter()
        if mode == b"U":
            for _ in range(SIZE // 16384):
                connection.sendall(b"x" * 16384)
            assert connection.recv(2) == b"OK"
            total = SIZE
        else:
            total = 0
            while total < SIZE:
                chunk = connection.recv(min(65536, SIZE - total))
                if not chunk:
                    break
                total += len(chunk)
        elapsed = time.perf_counter() - start
        assert total == SIZE
        results.append(dict(direction="upload" if mode == b"U" else "download",
                            bytes=total, seconds=elapsed, payload_mbps=total * 8 / elapsed / 1e6))
print(json.dumps(results))
Path("evidence/tunnel-tcp-0.3.1.json").write_text(json.dumps(results, indent=2) + "\n")
