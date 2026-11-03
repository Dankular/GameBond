"""Interactive client console with a nonblocking copy of logs to a local relay."""
from __future__ import annotations
import argparse
import contextlib
import importlib
import json
import queue
import os
import socket
import sys
import threading
import traceback
from . import __version__, app
from .tty_server import connect, ensure_server, read_metadata
from .windows_network import cleanup_legacy


class AsyncPublisher:
    def __init__(self, record, capacity=128):
        self.record, self.pending = record, queue.Queue(capacity)
        self.stop = threading.Event()
        self.dropped = 0
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._run, name="gamebond-log-publisher", daemon=True)
        self.thread.start()
        return self

    def write(self, text):
        data = text.encode("utf-8", errors="replace")
        if len(data) > 16384:
            data = data[:16384] + b"\n[relay log chunk truncated]\n"
        if data:
            try:
                self.pending.put_nowait(data)
            except queue.Full:
                self.dropped += 1

    def _run(self):
        sock = None
        try:
            while not self.stop.is_set() or not self.pending.empty():
                if sock is None:
                    try:
                        sock = connect(self.record, "publish", tail=0)
                        sock.settimeout(.5)
                    except (OSError, ValueError, ConnectionError):
                        if self.stop.wait(.25):
                            break
                        continue
                try:
                    data = self.pending.get(timeout=.1)
                except queue.Empty:
                    continue
                try:
                    sock.sendall(data)
                except OSError:
                    sock.close()
                    sock = None
                    self.dropped += 1
        finally:
            if sock is not None:
                sock.close()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(2)


class Tee:
    def __init__(self, original, publisher):
        self.original, self.publisher = original, publisher

    def write(self, text):
        self.publisher.write(text)
        return self.original.write(text)

    def flush(self):
        return self.original.flush()

    def __getattr__(self, name):
        return getattr(self.original, name)


class ControlOwner:
    """Supervisor control channel: only cooperative stop/restart, never a shell."""

    def __init__(self, record):
        self.record = record
        self.shutdown = threading.Event()
        self.requests = queue.Queue(1)
        self.outgoing = queue.Queue(64)
        self.lock = threading.RLock()
        self.active_stop = None
        self.pending_request = None
        self.state = "starting"
        self.thread = None
        self.registered = threading.Event()

    def start(self, timeout=3):
        self.thread = threading.Thread(target=self._run, name="gamebond-control-owner", daemon=True)
        self.thread.start()
        if not self.registered.wait(timeout):
            self.close()
            raise RuntimeError("Client supervisor could not acquire the exclusive control owner slot; another launcher may be active")
        return self

    def _send(self, message):
        try:
            self.outgoing.put_nowait(message)
        except queue.Full:
            # Fail closed rather than allowing unbounded command/response state.
            self.shutdown.set()
            if self.active_stop is not None:
                self.active_stop.set()

    def set_state(self, state):
        with self.lock:
            self.state = state
        self._send({"event": "status", "state": state})

    def bind_stop(self, stop, *, restarting_request=None):
        with self.lock:
            self.active_stop = stop
            if (stop is not None and self.pending_request is not None
                    and self.pending_request[0] != restarting_request):
                # A stop arriving during startup must not be lost.
                stop.set()

    def complete(self, request_id, *, ok=True, state="stopped", error=None):
        with self.lock:
            self.state = state
            if self.pending_request and self.pending_request[0] == request_id:
                self.pending_request = None
        message = {"request_id": request_id, "complete": True, "ok": ok, "state": state}
        if error is not None:
            message["error"] = str(error)[:1024]
        self._send(message)

    def _request(self, message):
        if (not isinstance(message, dict) or message.get("command") not in ("stop", "restart")
                or not isinstance(message.get("request_id"), str) or len(message["request_id"]) > 64):
            raise ValueError("invalid supervisor command")
        request_id, command = message["request_id"], message["command"]
        with self.lock:
            if self.pending_request is not None:
                self._send({"request_id": request_id, "complete": True, "ok": False,
                            "state": self.state, "error": "Supervisor operation already in progress"})
                return
            self.pending_request = (request_id, command)
            self.requests.put_nowait((request_id, command))
            if self.active_stop is not None:
                self.active_stop.set()
            state = "stopping" if self.active_stop is not None else "restarting" if command == "restart" else "stopped"
        self._send({"request_id": request_id, "complete": False, "ok": True, "state": state})

    def _run(self):
        sock, incoming = None, bytearray()
        try:
            while not self.shutdown.is_set():
                if sock is None:
                    try:
                        sock = connect(self.record, "owner", tail=0, pid=os.getpid())
                        self.registered.set()
                        sock.settimeout(.05)
                        incoming.clear()
                        self._send({"event": "status", "state": self.state})
                    except (OSError, ValueError, ConnectionError):
                        try:
                            self.record = read_metadata()
                        except (OSError, ValueError):
                            pass
                        if self.shutdown.wait(.25):
                            break
                        continue
                try:
                    while True:
                        try:
                            message = self.outgoing.get_nowait()
                        except queue.Empty:
                            break
                        sock.sendall(json.dumps(message).encode() + b"\n")
                    try:
                        data = sock.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        raise ConnectionError("relay disconnected")
                    incoming.extend(data)
                    if len(incoming) > 8192:
                        raise ValueError("oversized supervisor command")
                    while b"\n" in incoming:
                        line, _, remainder = incoming.partition(b"\n")
                        incoming = bytearray(remainder)
                        self._request(json.loads(line))
                except (OSError, ValueError, ConnectionError):
                    self.registered.clear()
                    sock.close()
                    sock = None
        finally:
            self.registered.clear()
            if sock is not None:
                sock.close()

    def close(self):
        self.shutdown.set()
        if self.active_stop is not None:
            self.active_stop.set()
        if self.thread is not None:
            self.thread.join(2)


def reload_runtime():
    """Refresh owned runtime code only after the previous app finished cleanup."""
    global cleanup_legacy
    for name in ("gamebond", "gamebond.bonding", "gamebond.reorder", "gamebond.policy",
                 "gamebond.pacing", "gamebond.tun", "gamebond.transport", "gamebond.dns", "gamebond.telemetry",
                 "gamebond.windows_network", "gamebond.windows_dns", "gamebond.app"):
        importlib.reload(importlib.import_module(name))
    cleanup_legacy = importlib.import_module("gamebond.windows_network").cleanup_legacy


def supervise(config, key, configure, owner, *, once=False, initially_stopped=False,
              reload_on_restart=False, config_path=None):
    """Run app on the main thread; retain elevated owner after cooperative stop."""
    should_run, restart_request, status, last_failure = not initially_stopped, None, 0, None
    runs = 0
    if initially_stopped:
        owner.set_state("stopped")
    while not owner.shutdown.is_set():
        if should_run:
            stop = threading.Event()
            owner.bind_stop(stop, restarting_request=restart_request)
            owner.set_state("restarting" if restart_request else "starting")

            def ready():
                nonlocal restart_request
                owner.set_state("running")
                if restart_request is not None:
                    owner.complete(restart_request, state="running")
                    restart_request = None

            failed = None
            last_failure = None
            try:
                if reload_on_restart and runs:
                    reload_runtime()
                if config_path is not None:
                    config = app.load_config(config_path)
                runs += 1
                if configure:
                    print(json.dumps({"status": "cleanup_previous_session"}), flush=True)
                    removed = cleanup_legacy()
                    print(json.dumps({"status": "cleanup_previous_session_complete",
                                      "removed_legacy_qos": removed}), flush=True)
                app.run(config, key, configure=configure, stop_event=stop, on_ready=ready)
            except KeyboardInterrupt:
                print("GameBond stopped.")
            except Exception as exc:
                traceback.print_exc()
                failed, last_failure, status = exc, exc, 1
            finally:
                owner.bind_stop(None)
            owner.set_state("failed" if failed else "stopped")
            if restart_request is not None:
                owner.complete(restart_request, ok=False, state="failed",
                               error=failed or "Client stopped before becoming ready")
                restart_request = None
            if once:
                return status
            should_run = False
        try:
            request_id, command = owner.requests.get(timeout=.2)
        except queue.Empty:
            continue
        if command == "stop":
            owner.complete(request_id, ok=last_failure is None,
                           state="failed" if last_failure else "stopped", error=last_failure)
        elif command == "restart":
            restart_request, should_run = request_id, True
    return status


def launch():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--configure", action="store_true")
    parser.add_argument("--once", action="store_true", help="exit after one run instead of retaining restart supervisor")
    parser.add_argument("--stopped", action="store_true", help="register supervisor without starting the tunnel; wait for authenticated restart")
    args = parser.parse_args()
    publisher, owner, status = None, None, 0
    try:
        config = app.load_config(args.config)
        record = ensure_server()
        publisher = AsyncPublisher(record).start()
        with (contextlib.redirect_stdout(Tee(sys.stdout, publisher)),
              contextlib.redirect_stderr(Tee(sys.stderr, publisher))):
            print(json.dumps({"status": "launcher", "version": __version__, "config": args.config,
                              "bonding_mode": config.get("bonding_mode", False),
                              "redundant_mode": config.get("redundant_mode", True),
                              "bulk_rate_mbps": config.get("bulk_rate_mbps", 0),
                              "log_relay": "127.0.0.1 read-only"}), flush=True)
            try:
                owner = ControlOwner(record).start()
                status = supervise(config, args.key, args.configure, owner, once=args.once,
                                   initially_stopped=args.stopped, reload_on_restart=True,
                                   config_path=args.config)
            except KeyboardInterrupt:
                print("GameBond stopped.")
            except Exception:
                traceback.print_exc()
                status = 1
    except KeyboardInterrupt:
        print("GameBond stopped.")
    except Exception:
        traceback.print_exc()
        status = 1
    finally:
        if owner is not None:
            owner.close()
        if publisher is not None:
            publisher.close()
        # CMD has exited after opening this console, so it cannot intercept the
        # client's Ctrl+C with a competing Terminate batch job prompt.
        if sys.stdin.isatty():
            try:
                input("GameBond has exited. Press Enter to close this window. ")
            except (EOFError, KeyboardInterrupt):
                pass
    return status


if __name__ == "__main__":
    raise SystemExit(launch())
