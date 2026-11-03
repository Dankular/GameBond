"""Two bounded 1 MiB tests, reachable only through the private TUN address."""
import socket
import time

SIZE = 1024 * 1024
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("10.77.0.1", 9010))
    listener.listen(2)
    listener.settimeout(45)
    for _ in range(2):
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(20)
            mode = connection.recv(1)
            if mode == b"U":
                remaining = SIZE
                while remaining:
                    chunk = connection.recv(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                connection.sendall(b"OK" if not remaining else b"NO")
            elif mode == b"D":
                for _ in range(SIZE // 16384):
                    connection.sendall(b"x" * 16384)
