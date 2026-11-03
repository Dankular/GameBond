"""Bounded, exact-host DNS overrides on the GameBond client address.

Restricted RFC1035 UDP/TCP responder, not a general authoritative DNS server.
Configured names never fall through to upstream, including absent AAAA records.
No OS resolver, hosts-file, NRPT or certificate settings are changed here.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import ipaddress
import math
import errno
import selectors
import secrets
import socket
import struct
import threading
import time

HEADER = struct.Struct("!HHHHHH")
MAX_QUERY = 4096
MAX_RESPONSE = 65535


class DNSFormatError(ValueError):
    pass


def normalize_name(name):
    if not isinstance(name, str):
        raise ValueError("DNS names must be strings")
    name = name[:-1] if name.endswith(".") else name
    try:
        labels = [label.encode("idna").decode("ascii").lower() for label in name.split(".")]
    except UnicodeError as exc:
        raise ValueError("invalid DNS name") from exc
    if (not labels or any(not label or len(label) > 63 or
            any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for char in label)
            for label in labels) or sum(len(label) + 1 for label in labels) + 1 > 255):
        raise ValueError("an exact DNS hostname is required; wildcards are unsupported")
    return ".".join(labels)


def valid_bind(address, port):
    ip = ipaddress.IPv4Address(address)
    if str(ip) != "10.77.0.2" and not ip.is_loopback:
        raise ValueError("DNS must bind only 10.77.0.2 or test loopback")
    if type(port) is not int or not 0 <= port <= 65535 or (not ip.is_loopback and port != 53):
        raise ValueError("production DNS must bind client port53; loopback tests may use ephemeral ports")
    return str(ip), port


def source_is_local(source, bind_host):
    try:
        ip = ipaddress.IPv4Address(source)
        return ip.is_loopback or str(ip) == str(ipaddress.IPv4Address(bind_host))
    except ipaddress.AddressValueError:
        return False


@dataclass(frozen=True)
class DNSConfig:
    records: dict
    enabled: bool = True
    bind: tuple = ("10.77.0.2", 53)
    ttl: int = 15
    upstream: tuple | None = None
    workers: int = 4
    pending: int = 16
    timeout: float = 1.0

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise ValueError("DNS enabled must be a boolean")
        if not isinstance(self.bind, (tuple, list)) or len(self.bind) != 2:
            raise ValueError("DNS bind must contain IPv4 and port")
        object.__setattr__(self, "bind", valid_bind(*self.bind))
        if type(self.ttl) is not int or not 0 <= self.ttl <= 300:
            raise ValueError("DNS TTL must be 0..300 seconds")
        if type(self.workers) is not int or not 1 <= self.workers <= 8:
            raise ValueError("DNS workers must be 1..8")
        if type(self.pending) is not int or not 0 <= self.pending <= 32:
            raise ValueError("DNS pending requests must be 0..32")
        if type(self.timeout) not in (int, float) or not math.isfinite(self.timeout) or not .05 <= self.timeout <= 3:
            raise ValueError("DNS timeout must be finite and 0.05..3 seconds")
        if not isinstance(self.records, dict) or not (1 if self.enabled else 0) <= len(self.records) <= 64:
            raise ValueError("DNS requires 1..64 exact-host overrides")
        normalized = {}
        for name, record_types in self.records.items():
            name = normalize_name(name)
            if name in normalized or not isinstance(record_types, dict) or not record_types:
                raise ValueError("duplicate normalized hostname or empty DNS override")
            normalized[name] = {}
            for record_type, values in record_types.items():
                if record_type not in ("A", "AAAA") or not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 16:
                    raise ValueError("DNS records support only 1..16 A/AAAA addresses per family")
                if any(not isinstance(value, str) for value in values):
                    raise ValueError("DNS record addresses must be strings")
                addresses = tuple(ipaddress.ip_address(value) for value in values)
                version = 4 if record_type == "A" else 6
                if any(ip.version != version for ip in addresses):
                    raise ValueError("DNS record address family mismatch")
                normalized[name][record_type] = tuple(str(ip) for ip in addresses)
        object.__setattr__(self, "records", normalized)
        if self.upstream is not None:
            if not isinstance(self.upstream, (tuple, list)) or len(self.upstream) != 2:
                raise ValueError("DNS upstream must contain public IPv4 and port")
            host, port = self.upstream
            ip = ipaddress.IPv4Address(host)
            if not ip.is_global or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("DNS upstream must be an explicit public IPv4 resolver")
            object.__setattr__(self, "upstream", (str(ip), port))


def load_dns_config(raw):
    """Parse optional app DNS; disabled profiles remain validated/editable."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("DNS configuration must be an object")
    if type(raw.get("enabled", True)) is not bool:
        raise ValueError("DNS enabled must be a boolean")
    if set(raw) - {"enabled", "records", "bind", "ttl", "upstream", "workers", "pending", "timeout"}:
        raise ValueError("unknown DNS configuration option")
    values = dict(raw)
    values.setdefault("records", {})
    return DNSConfig(**values)


def _name(packet, offset):
    labels, visited, consumed, wire_size = [], set(), None, 1
    for _ in range(128):
        if offset >= len(packet) or offset in visited:
            raise DNSFormatError("DNS compression loop or truncated name")
        visited.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise DNSFormatError("truncated DNS compression pointer")
            if consumed is None:
                consumed = offset + 2
            offset = ((size & 63) << 8) | packet[offset + 1]
            continue
        if size & 0xC0 or size > 63:
            raise DNSFormatError("invalid DNS label")
        offset += 1
        if size == 0:
            return tuple(labels), consumed if consumed is not None else offset
        if offset + size > len(packet):
            raise DNSFormatError("truncated DNS label")
        label = packet[offset:offset + size]
        try:
            label.decode("ascii")
        except UnicodeError as exc:
            raise DNSFormatError("unsupported DNS label encoding") from exc
        if any(char not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in label):
            raise DNSFormatError("unsupported DNS hostname label")
        labels.append(label)
        wire_size += size + 1
        if wire_size > 255:
            raise DNSFormatError("DNS name exceeds 255 bytes")
        offset += size
    raise DNSFormatError("DNS name traversal limit")


@dataclass(frozen=True)
class Question:
    labels: tuple
    kind: int
    cls: int
    udp_size: int = 512

    @property
    def name(self):
        return b".".join(self.labels).decode("ascii").lower()

    @property
    def wire(self):
        return b"".join(bytes([len(label)]) + label for label in self.labels) + b"\0" + struct.pack("!HH", self.kind, self.cls)


def parse_question(packet, *, response=False):
    if not 12 <= len(packet) <= (MAX_RESPONSE if response else MAX_QUERY):
        raise DNSFormatError("invalid DNS message length")
    _, flags, qd, an, ns, ar = HEADER.unpack_from(packet)
    if qd != 1 or bool(flags & 0x8000) != response or flags & 0x7800:
        raise DNSFormatError("only one standard DNS question is supported")
    labels, end = _name(packet, 12)
    if end + 4 > len(packet):
        raise DNSFormatError("truncated DNS question")
    kind, cls = struct.unpack_from("!HH", packet, end)
    end += 4
    udp_size = 512
    if not response:
        if an or ns or ar > 1:
            raise DNSFormatError("unexpected records in DNS query")
        if ar:
            opt_name, opt_end = _name(packet, end)
            if opt_end + 10 > len(packet):
                raise DNSFormatError("truncated EDNS record")
            opt_type, size, ttl, length = struct.unpack_from("!HHIH", packet, opt_end)
            if opt_name or opt_type != 41 or (ttl >> 16) & 255 or opt_end + 10 + length != len(packet):
                raise DNSFormatError("unsupported or invalid EDNS record")
            udp_size = max(512, min(MAX_QUERY, size))
            end = opt_end + 10 + length
        if end != len(packet):
            raise DNSFormatError("unexpected trailing DNS query bytes")
    return Question(labels, kind, cls, udp_size)


def _response(query, question=None, *, rcode=0, authoritative=False, answers=(), ttl=15, tcp=False):
    transaction = int.from_bytes(query[:2], "big") if len(query) >= 2 else 0
    request_flags = int.from_bytes(query[2:4], "big") if len(query) >= 4 else 0
    flags = 0x8000 | (request_flags & 0x0100) | (0x0400 if authoritative else 0) | rcode
    body = question.wire if question is not None else b""
    records = []
    for kind, address in answers:
        raw = ipaddress.ip_address(address).packed
        records.append(b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, ttl, len(raw)) + raw)
    result = HEADER.pack(transaction, flags, int(question is not None), len(records), 0, 0) + body + b"".join(records)
    if not tcp and question is not None and len(result) > question.udp_size:
        result = HEADER.pack(transaction, flags | 0x0200, 1, 0, 0, 0) + body
    return result


class DNSResponder:
    def __init__(self, config):
        if not isinstance(config, DNSConfig):
            raise TypeError("DNSResponder requires a validated DNSConfig")
        self.config = config
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sockets = set()
        self.admission = threading.BoundedSemaphore(config.workers + config.pending)
        self.executor = ThreadPoolExecutor(config.workers, thread_name_prefix="gamebond-dns")
        self.selector = selectors.DefaultSelector()
        self.counts = dict(queries=0, overrides=0, forwarded=0, malformed=0, refused_sources=0, busy=0, upstream_errors=0)
        self.thread = None

    def _count(self, key):
        with self.lock:
            self.counts[key] += 1

    def stats(self):
        with self.lock:
            return dict(self.counts)

    def start(self):
        if not self.config.enabled:
            raise ValueError("DNS profile is disabled")
        try:
            # An ephemeral UDP port may be reserved/unusable for TCP on
            # Windows. TCP's allocator can repeatedly pick consecutive ports
            # inside a whole UDP exclusion range. After the first OS-selected
            # port, try independent random high ports, still reserving both
            # protocols and never changing an explicitly configured port.
            attempts=32 if self.config.bind[1]==0 else 1
            for attempt in range(attempts):
                self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    candidate=self.config.bind
                    if attempt:candidate=(candidate[0],49152+secrets.randbelow(16384))
                    self.tcp.bind(candidate)
                    self.address=self.tcp.getsockname()
                    self.udp.bind(self.address)
                    break
                except OSError as exc:
                    self.tcp.close();self.udp.close()
                    if self.config.bind[1] or attempt==attempts-1 or (exc.errno not in (errno.EACCES,errno.EADDRINUSE,10013,10048)
                            and getattr(exc,'winerror',None) not in (10013,10048)):
                        raise
            self.udp.setblocking(False)
            self.tcp.listen(self.config.workers + self.config.pending)
            self.tcp.setblocking(False)
            self.selector.register(self.udp, selectors.EVENT_READ)
            self.selector.register(self.tcp, selectors.EVENT_READ)
            self.thread = threading.Thread(target=self._run, name="gamebond-dns-listener", daemon=True)
            self.thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def _submit(self, function, *args):
        if not self.admission.acquire(blocking=False):
            self._count("busy")
            return False
        try:
            future = self.executor.submit(function, *args)
            future.add_done_callback(lambda _: self.admission.release())
            return True
        except RuntimeError:
            self.admission.release()
            return False

    def _run(self):
        while not self.stop.is_set():
            try:
                events = self.selector.select(.1)
            except (OSError, ValueError):
                break
            for key, _ in events:
                try:
                    if key.fileobj is self.udp:
                        packet, source = self.udp.recvfrom(MAX_QUERY + 1)
                        if not source_is_local(source[0], self.config.bind[0]):
                            self._count("refused_sources")
                            continue
                        if not self._submit(self._udp_query, packet, source):
                            self.udp.sendto(_response(packet, rcode=2), source)
                    else:
                        client, source = self.tcp.accept()
                        if not source_is_local(source[0], self.config.bind[0]):
                            self._count("refused_sources")
                            client.close()
                            continue
                        client.settimeout(self.config.timeout)
                        with self.lock:
                            self.sockets.add(client)
                        if not self._submit(self._tcp_queries, client):
                            self._close_socket(client)
                except OSError:
                    continue

    def answer(self, packet, *, tcp=False):
        self._count("queries")
        try:
            question = parse_question(packet)
        except DNSFormatError:
            self._count("malformed")
            return _response(packet, rcode=1)
        if question.cls != 1:
            return _response(packet, question, rcode=5)
        records = self.config.records.get(question.name)
        if records is not None:
            self._count("overrides")
            family = "A" if question.kind == 1 else "AAAA" if question.kind == 28 else None
            answers = [(question.kind, value) for value in records.get(family, ())]
            return _response(packet, question, authoritative=True, answers=answers, ttl=self.config.ttl, tcp=tcp)
        if self.config.upstream is None:
            return _response(packet, question, rcode=5)
        try:
            transaction = secrets.token_bytes(2)
            forwarded = transaction + packet[2:]
            result = self._exchange(forwarded, tcp=tcp)
            returned = parse_question(result, response=True)
            if result[:2] != transaction or (returned.name, returned.kind, returned.cls) != (question.name, question.kind, question.cls):
                raise DNSFormatError("upstream DNS response does not match the query")
            self._count("forwarded")
            return packet[:2] + result[2:]
        except (OSError, DNSFormatError):
            self._count("upstream_errors")
            return _response(packet, question, rcode=2)

    def _exchange(self, packet, *, tcp):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        with self.lock:
            self.sockets.add(sock)
        try:
            sock.settimeout(self.config.timeout)
            sock.bind((self.config.bind[0], 0))  # Keep forwarded DNS inside TUN.
            sock.connect(self.config.upstream)  # UDP connect also filters reply source.
            if tcp:
                deadline = time.monotonic() + self.config.timeout
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                length = struct.unpack("!H", self._exact(sock, 2, deadline=deadline))[0]
                if not 12 <= length <= MAX_RESPONSE:
                    raise DNSFormatError("invalid upstream TCP DNS length")
                return self._exact(sock, length, deadline=deadline)
            sock.send(packet)
            return sock.recv(MAX_RESPONSE)
        finally:
            self._close_socket(sock)

    @staticmethod
    def _exact(sock, length, *, deadline=None):
        result = bytearray()
        while len(result) < length:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TCP DNS request deadline exceeded")
                sock.settimeout(remaining)
            chunk = sock.recv(length - len(result))
            if not chunk:
                raise ConnectionError("short TCP DNS frame")
            result.extend(chunk)
        return bytes(result)

    def _udp_query(self, packet, source):
        try:
            self.udp.sendto(self.answer(packet), source)
        except OSError:
            pass

    def _tcp_queries(self, client):
        try:
            # Bound persistent connection lifetime and queries as well as workers.
            deadline = time.monotonic() + self.config.timeout * 2
            for _ in range(16):
                if self.stop.is_set() or time.monotonic() >= deadline:
                    break
                length = struct.unpack("!H", self._exact(client, 2, deadline=deadline))[0]
                if not 12 <= length <= MAX_QUERY:
                    break
                packet = self._exact(client, length, deadline=deadline)
                response = self.answer(packet, tcp=True)
                client.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, DNSFormatError):
            pass
        finally:
            self._close_socket(client)

    def _close_socket(self, sock):
        with self.lock:
            self.sockets.discard(sock)
        sock.close()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(1)
        for name in ("udp", "tcp"):
            sock = getattr(self, name, None)
            if sock is not None:
                sock.close()
        with self.lock:
            active = list(self.sockets)
        for sock in active:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._close_socket(sock)
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.selector.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()
