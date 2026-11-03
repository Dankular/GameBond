"""Loopback logs plus authenticated stop/restart/status; no shell or arbitrary input."""
from __future__ import annotations
import argparse
from collections import deque
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time


def metadata_path():
    return Path(__file__).resolve().parent.parent / ".runtime" / "tty-session.json"


class Ring:
    def __init__(self, limit=256 * 1024):
        self.limit, self.size, self.chunks = limit, 0, deque()

    def append(self, data):
        data = bytes(data[-self.limit:])
        if data:
            self.chunks.append(data)
            self.size += len(data)
        while self.size > self.limit:
            first = self.chunks.popleft()
            excess = self.size - self.limit
            if len(first) > excess:
                self.chunks.appendleft(first[excess:])
                self.size -= excess
            else:
                self.size -= len(first)

    def tail(self, lines):
        return b"".join(b"".join(self.chunks).splitlines(keepends=True)[-lines:]) if lines else b""


class LogRelay:
    def __init__(self, metadata=None, *, ring_limit=256 * 1024,
                 reader_limit=256 * 1024, max_attachments=8):
        self.metadata = Path(metadata) if metadata is not None else metadata_path()
        self.token = secrets.token_hex(32)
        self.ring = Ring(ring_limit)
        self.reader_limit, self.max_attachments = reader_limit, max_attachments
        self.stop = threading.Event()
        self.selector = selectors.DefaultSelector()
        self.clients = {}
        self.counts = dict(auth_rejected=0, slow_readers=0, input_rejected=0, published_bytes=0)
        self.thread = None
        self.owner = None
        self.owner_state = "unavailable"
        self.pending_controls = {}

    def start(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.setblocking(False)
        self.port = self.listener.getsockname()[1]
        self.selector.register(self.listener, selectors.EVENT_READ)
        self.metadata.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.metadata.with_suffix(".tmp-" + secrets.token_hex(8))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump({"version": 1, "pid": os.getpid(), "port": self.port, "token": self.token}, file)
            os.replace(temporary, self.metadata)
        finally:
            temporary.unlink(missing_ok=True)
        self.thread = threading.Thread(target=self._run, name="gamebond-log-relay", daemon=True)
        self.thread.start()
        return self

    def _drop(self, client):
        sock = client["socket"]
        if client is self.owner:
            self.owner = None
            self.owner_state = "unavailable"
            for request_id, reader in list(self.pending_controls.items()):
                self._control_reply(reader, {"ok": False, "complete": True,
                    "request_id": request_id, "state": "unavailable", "error": "Control owner disconnected"})
            self.pending_controls.clear()
        for request_id, reader in list(self.pending_controls.items()):
            if reader is client:
                del self.pending_controls[request_id]
        self.clients.pop(sock, None)
        try:
            self.selector.unregister(sock)
        except (KeyError, ValueError):
            pass
        sock.close()

    def _events(self, client):
        self.selector.modify(client["socket"], selectors.EVENT_READ |
                             (selectors.EVENT_WRITE if client["out"] else 0), client)

    def _json(self, client, value):
        data = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        if len(client["out"]) + len(data) > self.reader_limit:
            self._drop(client)
            return
        client["out"].extend(data)
        self._events(client)

    def _control_reply(self, client, value):
        self._json(client, value)
        if value.get("complete"):
            client["close_after"] = True

    def _request_control(self, client, command):
        if command == "status":
            self._control_reply(client, {"ok": True, "complete": True,
                "state": self.owner_state, "owner_pid": self.owner.get("pid") if self.owner else None})
        elif self.owner is None:
            self._control_reply(client, {"ok": False, "complete": True,
                "state": "unavailable", "error": "No elevated client supervisor is registered"})
        elif self.pending_controls:
            self._control_reply(client, {"ok": False, "complete": True,
                "state": self.owner_state, "error": "A previous control operation is still in progress"})
        else:
            request_id = secrets.token_hex(12)
            self.pending_controls[request_id] = client
            self._control_reply(client, {"ok": True, "complete": False,
                "request_id": request_id, "state": "requested", "command": command})
            self._json(self.owner, {"request_id": request_id, "command": command})

    def _owner_data(self, client, data):
        client["input"].extend(data)
        if len(client["input"]) > 8192:
            raise ValueError("oversized owner response")
        while b"\n" in client["input"]:
            line, _, remainder = client["input"].partition(b"\n")
            client["input"] = bytearray(remainder)
            message = json.loads(line)
            if not isinstance(message, dict) or message.get("state") not in (
                    "starting", "running", "stopping", "stopped", "restarting", "failed"):
                raise ValueError("invalid owner state")
            self.owner_state = message["state"]
            if message.get("event") == "status":
                continue
            request_id = message.get("request_id")
            if request_id not in self.pending_controls:
                continue  # Requester may have disconnected while cleanup continued.
            if type(message.get("complete")) is not bool or type(message.get("ok")) is not bool:
                raise ValueError("invalid owner result")
            response = {"request_id": request_id, "ok": message["ok"],
                        "complete": message["complete"], "state": message["state"]}
            if "error" in message:
                response["error"] = str(message["error"])[:1024]
            self._control_reply(self.pending_controls[request_id], response)
            if message["complete"]:
                self.pending_controls.pop(request_id, None)

    def _publish(self, data):
        self.ring.append(data)
        self.counts["published_bytes"] += len(data)
        for client in list(self.clients.values()):
            if client["role"] != "attach":
                continue
            if len(client["out"]) + len(data) > self.reader_limit:
                self.counts["slow_readers"] += 1
                self._drop(client)
            else:
                client["out"].extend(data)
                self._events(client)

    def _authenticate(self, client):
        line, remainder = bytes(client["input"]).split(b"\n", 1)
        try:
            auth = json.loads(line)
            if not isinstance(auth, dict) or not isinstance(auth.get("token"), str):
                raise ValueError()
            if not hmac.compare_digest(auth["token"], self.token):
                raise ValueError()
            role, tail = auth.get("role"), auth.get("tail", 100)
            if role not in ("publish", "attach", "owner", "control") or type(tail) is not int or not 0 <= tail <= 5000:
                raise ValueError()
            count = sum(item["role"] == role for item in self.clients.values())
            limit = self.max_attachments if role == "attach" else (1 if role == "owner" else 2 if role == "publish" else 8)
            if count >= limit:
                raise ValueError()
            if role in ("attach", "control") and remainder:
                raise ValueError()
            if role == "control" and auth.get("command") not in ("stop", "restart", "status"):
                raise ValueError()
            if role == "owner" and (type(auth.get("pid")) is not int or auth["pid"] <= 0):
                raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            self.counts["auth_rejected"] += 1
            self._drop(client)
            return
        client["input"].clear()
        client["role"] = role
        client["close_after"] = False
        client["out"].extend(b'{"ok":true}\n')
        if role == "attach":
            replay = self.ring.tail(tail)
            remaining = max(0, self.reader_limit - len(client["out"]))
            if remaining:
                client["out"].extend(replay[-remaining:])
        self._events(client)
        if role == "owner":
            self.owner, self.owner_state = client, "starting"
            client["pid"] = auth["pid"]
        elif role == "control":
            self._request_control(client, auth["command"])
        if role == "publish" and remainder:
            self._publish(remainder)
        elif role == "owner" and remainder:
            self._owner_data(client, remainder)

    def _service(self, client, events):
        sock = client["socket"]
        if events & selectors.EVENT_READ:
            try:
                data = sock.recv(16384)
            except BlockingIOError:
                data = None
            if data == b"":
                self._drop(client)
                return
            if data:
                if client["role"] is None:
                    client["input"].extend(data)
                    if len(client["input"]) > 4096:
                        self._drop(client)
                        return
                    if b"\n" in client["input"]:
                        self._authenticate(client)
                        if sock not in self.clients:
                            return
                elif client["role"] == "publish":
                    self._publish(data)
                elif client["role"] == "owner":
                    self._owner_data(client, data)
                else:
                    self.counts["input_rejected"] += 1
                    self._drop(client)
                    return
        if events & selectors.EVENT_WRITE and client["out"]:
            try:
                sent = sock.send(client["out"])
            except BlockingIOError:
                return
            del client["out"][:sent]
            if not client["out"] and client.get("close_after"):
                self._drop(client)
                return
            self._events(client)

    def _run(self):
        try:
            while not self.stop.is_set():
                for key, events in self.selector.select(.1):
                    if key.fileobj is self.listener:
                        sock, _ = self.listener.accept()
                        sock.setblocking(False)
                        if len(self.clients) >= 16:
                            sock.close()
                            continue
                        client = {"socket": sock, "role": None, "input": bytearray(),
                                  "out": bytearray(), "created": time.monotonic()}
                        self.clients[sock] = client
                        self.selector.register(sock, selectors.EVENT_READ, client)
                    else:
                        try:
                            self._service(key.data, events)
                        except (OSError, ValueError, KeyError):
                            self._drop(key.data)
                for client in list(self.clients.values()):
                    if client["role"] is None and time.monotonic() - client["created"] > 5:
                        self._drop(client)
        finally:
            for client in list(self.clients.values()):
                self._drop(client)
            self.selector.close()
            self.listener.close()
            try:
                if json.loads(self.metadata.read_text())["token"] == self.token:
                    self.metadata.unlink()
            except (OSError, ValueError, KeyError):
                pass

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(2)


def read_metadata(path=None):
    path = Path(path) if path is not None else metadata_path()
    if path.stat().st_size > 4096:
        raise ValueError("invalid log relay metadata")
    record = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(record, dict) or record.get("version") != 1 or type(record.get("port")) is not int or
            not 1 <= record["port"] <= 65535 or not isinstance(record.get("token"), str)
            or len(record["token"]) != 64):
        raise ValueError("invalid log relay metadata")
    return record


def connect(record, role, *, tail=100, **fields):
    sock = socket.create_connection(("127.0.0.1", record["port"]), timeout=1)
    try:
        sock.sendall(json.dumps({"token": record["token"], "role": role, "tail": tail, **fields}).encode() + b"\n")
        acknowledgement = bytearray()
        while len(acknowledgement) <= 4096:
            byte = sock.recv(1)
            if not byte:
                raise ConnectionError("log relay rejected the connection")
            acknowledgement.extend(byte)
            if byte == b"\n":
                break
        if json.loads(acknowledgement) != {"ok": True}:
            raise ConnectionError("log relay authentication failed")
        return sock
    except BaseException:
        sock.close()
        raise


def ensure_server(path=None):
    path = Path(path) if path is not None else metadata_path()
    try:
        record = read_metadata(path)
        with connect(record, "attach", tail=0):
            return record
    except (OSError, ValueError, ConnectionError):
        pass
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    subprocess.Popen([sys.executable, "-m", "gamebond.tty_server", "serve", "--metadata", str(path.resolve())],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=flags, close_fds=True)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            record = read_metadata(path)
            with connect(record, "attach", tail=0):
                return record
        except (OSError, ValueError, ConnectionError):
            time.sleep(.05)
    raise RuntimeError("read-only log relay did not become ready")


def attach(path=None, *, tail=100, duration=30, output=None):
    if type(tail) is not int or not 0 <= tail <= 5000:
        raise ValueError("tail must be 0..5000")
    if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 < duration <= 3600:
        raise ValueError("duration must be positive and at most 3600 seconds")
    output = output if output is not None else sys.stdout.buffer
    with connect(read_metadata(path), "attach", tail=tail) as sock:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            sock.settimeout(min(.25, max(.001, deadline - time.monotonic())))
            try:
                data = sock.recv(16384)
            except socket.timeout:
                continue
            if not data:
                break
            output.write(data)
            output.flush()


def control(command, path=None, *, timeout=60, output=None):
    if command not in ("stop", "restart", "status"):
        raise ValueError("only stop/restart/status are supported")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 180:
        raise ValueError("timeout must be positive and at most 180 seconds")
    output = output if output is not None else sys.stdout
    with connect(read_metadata(path), "control", command=command) as sock:
        deadline, buffer = time.monotonic() + timeout, bytearray()
        while time.monotonic() < deadline:
            sock.settimeout(min(.25, max(.001, deadline - time.monotonic())))
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                raise ConnectionError("Control connection ended before a completed result")
            buffer.extend(data)
            if len(buffer) > 8192:
                raise ValueError("invalid control response size")
            while b"\n" in buffer:
                line, _, rest = buffer.partition(b"\n")
                buffer = bytearray(rest)
                message = json.loads(line)
                output.write(json.dumps(message) + "\n")
                output.flush()
                if message.get("complete") is True:
                    return message
    raise TimeoutError("Control operation did not complete before timeout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("serve", "ensure", "attach", "stop", "restart", "status"):
        child = sub.add_parser(command)
        child.add_argument("--metadata", type=Path, default=metadata_path())
        if command == "attach":
            child.add_argument("--tail", type=int, default=100)
            child.add_argument("--duration", type=float, default=30)
        elif command in ("stop", "restart", "status"):
            child.add_argument("--timeout", type=float, default=60)
    arguments = list(sys.argv[1:])
    if arguments and arguments[0] in ("-stop", "-restart", "-status"):
        arguments[0] = arguments[0][1:]
    args = parser.parse_args(arguments)
    if args.command == "ensure":
        record = ensure_server(args.metadata)
        print(json.dumps({"pid": record["pid"], "port": record["port"], "metadata": str(args.metadata)}))
    elif args.command == "attach":
        attach(args.metadata, tail=args.tail, duration=args.duration)
    elif args.command in ("stop", "restart", "status"):
        result = control(args.command, args.metadata, timeout=args.timeout)
        if not result.get("ok"):
            raise SystemExit(1)
    else:
        relay = LogRelay(args.metadata).start()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: relay.stop.set())
        try:
            while not relay.stop.wait(.25):
                pass
        finally:
            relay.close()


if __name__ == "__main__":
    main()
