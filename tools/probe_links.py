"""Read-only HTTPS reachability check using explicitly pinned Windows paths."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import ssl
import struct
import time


def probe(path):
    ip, index = path
    start = time.perf_counter()
    stage = "create socket"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(8)
            stage = "pin interface"
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_UNICAST_IF", 31),
                            struct.pack("=I", socket.htonl(index)))
            stage = "bind source"
            sock.bind((ip, 0))
            stage = "connect HTTPS"
            sock.connect(("1.1.1.1", 443))
            with ssl.create_default_context().wrap_socket(sock, server_hostname="one.one.one.one") as tls:
                tls.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
                response = b""
                while len(response) < 65536:
                    part = tls.recv(4096)
                    if not part:
                        break
                    response += part
        lines = response.decode("utf-8", errors="replace").splitlines()
        egress = next((line[3:] for line in lines if line.startswith("ip=")), None)
        return {"source": ip, "interface_index": index, "http": lines[0] if lines else "empty",
                "egress_ipv4": egress, "elapsed_ms": round((time.perf_counter() - start) * 1000, 2)}
    except OSError as exc:
        return {"source": ip, "interface_index": index, "stage": stage, "error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", action="append", required=True, help="localIPv4:interfaceIndex")
    args = parser.parse_args()
    paths = [(ip, int(index)) for ip, index in (p.rsplit(":", 1) for p in args.path)]
    with ThreadPoolExecutor(max_workers=8) as executor:
        result = list(executor.map(probe, paths))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
