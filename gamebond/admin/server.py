"""HTTPS admin portal: login, live status, config edit/validate/apply, restart."""
from __future__ import annotations
import ipaddress
import json
import os
import ssl
import tempfile
import threading
import time
from collections import deque
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import system
from .auth import Sessions, Throttle, hash_password, verify_password

STATIC = Path(__file__).with_name("static")
RESTART_EXIT_CODE = 75
MAX_BODY = 256 * 1024
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store", "Strict-Transport-Security": "max-age=31536000",
}


class AdminSettings:
    def __init__(self, raw):
        if not isinstance(raw, dict):
            raise ValueError("admin must be an object")
        unknown = set(raw) - {"enabled", "bind", "password_hash", "tls_cert", "tls_key", "log_lines"}
        if unknown:
            raise ValueError(f"unknown admin keys: {sorted(unknown)}")
        self.enabled = raw.get("enabled", True)
        host, port = raw.get("bind", ["127.0.0.1", 8443])
        ipaddress.IPv4Address(host)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid admin port")
        self.bind = (host, port)
        self.password_hash = raw.get("password_hash", "")
        self.tls_cert, self.tls_key = raw.get("tls_cert"), raw.get("tls_key")
        self.log_lines = raw.get("log_lines", 200)
        if not isinstance(self.enabled, bool) or type(self.log_lines) is not int or not 10 <= self.log_lines <= 2000:
            raise ValueError("invalid admin settings")
        if self.enabled:
            if not str(self.password_hash).startswith("scrypt$"):
                raise ValueError("admin.password_hash is required (python -m gamebond admin-passwd)")
            if not (self.tls_cert and self.tls_key) and not ipaddress.IPv4Address(host).is_loopback:
                raise ValueError("admin.tls_cert and admin.tls_key are required unless the portal binds loopback")


class AdminPortal:
    def __init__(self, settings, *, snapshot, config_path, key_path=None, validate=None, request_restart=None, clock=time.monotonic):
        self.settings, self.snapshot, self.config_path = settings, snapshot, Path(config_path)
        self.validate = validate or (lambda path: None)
        self.request_restart = request_restart or (lambda: None)
        self.sessions, self.throttle = Sessions(clock), Throttle(clock)
        self.log = deque(maxlen=settings.log_lines)
        self.lock = threading.Lock()
        self.password_hash = settings.password_hash
        self.httpd = self.thread = None

    # ---- lifecycle
    def start(self):
        portal = self

        class Handler(_Handler):
            owner = portal
        self.httpd = ThreadingHTTPServer(self.settings.bind, Handler)
        self.httpd.daemon_threads = True
        if self.settings.tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(self.settings.tls_cert, self.settings.tls_key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="gamebond-admin", daemon=True)
        self.thread.start()
        return self

    def close(self):
        if self.httpd:
            self.httpd.shutdown(); self.httpd.server_close()

    def note(self, line):
        self.log.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}")

    # ---- config
    def read_config(self):
        return self.config_path.read_text(encoding="utf-8")

    def check_config(self, text):
        """Return (error, parsed). The admin block can only be changed by admin-passwd, never here."""
        try:
            new = json.loads(text)
            if not isinstance(new, dict):
                return "config must be a JSON object", None
            old = json.loads(self.read_config())
            if new.get("admin") != old.get("admin"):
                return "the admin block cannot be edited here; use the Administration page", None
            with tempfile.TemporaryDirectory() as d:
                probe = Path(d) / "server.json"
                probe.write_text(text, encoding="utf-8")
                self.validate(probe)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            return f"{type(exc).__name__}: {exc}", None
        return None, new

    def apply_config(self, text):
        error, _ = self.check_config(text)
        if error:
            return error
        with self.lock:
            previous = self.read_config()
            Path(tempfile.gettempdir(), "gamebond-config.previous.json").write_text(previous, encoding="utf-8")
            # Written in place: the compose file bind-mounts the single file, so rename-over would fail.
            with open(self.config_path, "w", encoding="utf-8") as f:
                f.write(text); f.flush(); os.fsync(f.fileno())
        self.note("configuration written; restart required to apply")
        return None

    def set_password(self, current, new):
        if not verify_password(current, self.password_hash):
            return "current password is wrong"
        try:
            hashed = hash_password(new)
        except ValueError as exc:
            return str(exc)
        with self.lock:
            cfg = json.loads(self.read_config())
            cfg.setdefault("admin", {})["password_hash"] = hashed
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2); f.flush(); os.fsync(f.fileno())
            self.password_hash = hashed
        self.sessions.drop_all()
        self.note("admin password changed; all sessions ended")
        return None


class _Handler(BaseHTTPRequestHandler):
    owner: AdminPortal
    server_version = "GameBondAdmin"
    sys_version = ""

    def log_message(self, *_):
        pass

    def _send(self, code, body=b"", ctype="application/json", extra=()):
        self.send_response(code)
        for k, v in {**HEADERS, "Content-Type": ctype, "Content-Length": str(len(body))}.items():
            self.send_header(k, v)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, value, extra=()):
        self._send(code, json.dumps(value).encode(), extra=extra)

    def _session(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        token = jar["gb_session"].value if "gb_session" in jar else None
        return token, self.owner.sessions.get(token)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            return None
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            return self._api_get(path)
        name = "index.html" if path == "/" else path.removeprefix("/static/") if path.startswith("/static/") else None
        file = (STATIC / name) if name and "/" not in name and not name.startswith(".") else None
        if file and file.is_file() and file.suffix in TYPES:
            return self._send(200, file.read_bytes(), TYPES[file.suffix])
        self._json(404, {"error": "not found"})

    def _api_get(self, path):
        _, s = self._session()
        if path == "/api/session":
            return self._json(200, {"authenticated": bool(s), "csrf": s["csrf"] if s else None})
        if not s:
            return self._json(401, {"error": "login required"})
        o = self.owner
        routes = {"/api/status": lambda: o.snapshot(), "/api/interfaces": system.interfaces, "/api/routes": system.routes,
                  "/api/nat": system.nat_rules, "/api/log": lambda: {"lines": list(o.log)},
                  "/api/config": lambda: {"text": o.read_config()}}
        fn = routes.get(path)
        self._json(200, fn()) if fn else self._json(404, {"error": "not found"})

    def do_POST(self):
        path, o = self.path.split("?", 1)[0], self.owner
        body = self._body()
        if body is None:
            return self._json(400, {"error": "invalid request body"})
        if path == "/api/login":
            return self._login(body)
        token, s = self._session()
        if not s:
            return self._json(401, {"error": "login required"})
        if not isinstance(self.headers.get("X-CSRF-Token"), str) or self.headers["X-CSRF-Token"] != s["csrf"]:
            return self._json(403, {"error": "bad CSRF token"})
        if path == "/api/logout":
            o.sessions.drop(token)
            return self._json(200, {"ok": True}, extra=[("Set-Cookie", "gb_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")])
        if path == "/api/config/validate":
            error, _ = o.check_config(str(body.get("text", "")))
            return self._json(200, {"ok": error is None, "error": error})
        if path == "/api/config":
            error = o.apply_config(str(body.get("text", "")))
            return self._json(200 if not error else 422, {"ok": error is None, "error": error})
        if path == "/api/password":
            error = o.set_password(str(body.get("current", "")), str(body.get("new", "")))
            return self._json(200 if not error else 422, {"ok": error is None, "error": error})
        if path == "/api/restart":
            if body.get("confirm") is not True:
                return self._json(400, {"error": "confirmation required"})
            o.note("restart requested from the portal")
            self._json(202, {"ok": True})
            threading.Timer(0.5, o.request_restart).start()
            return
        self._json(404, {"error": "not found"})

    def _login(self, body):
        o, addr = self.owner, self.client_address[0]
        wait = o.throttle.retry_after(addr)
        if wait > 0:
            return self._json(429, {"error": f"too many attempts; retry in {int(wait) + 1}s"}, extra=[("Retry-After", str(int(wait) + 1))])
        password = body.get("password")
        if not isinstance(password, str) or not verify_password(password, o.password_hash):
            o.throttle.fail(addr)
            o.note(f"failed login from {addr}")
            return self._json(401, {"error": "invalid password"})
        o.throttle.success(addr)
        token, csrf = o.sessions.create()
        o.note(f"login from {addr}")
        self._json(200, {"ok": True, "csrf": csrf},
                   extra=[("Set-Cookie", f"gb_session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800")])
