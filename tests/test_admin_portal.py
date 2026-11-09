"""Admin portal: auth, CSRF, throttling, config edit rules, restart, TLS."""
import http.client
import json
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from gamebond import app
from gamebond.admin.auth import Sessions, Throttle, hash_password, verify_password
from gamebond.admin.cert import write_self_signed
from gamebond.admin.server import AdminPortal, AdminSettings

PASSWORD = "correct horse battery"
HASH = hash_password(PASSWORD, n=2 ** 10)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def server_config(**admin):
    return {"role": "server", "bind": [["0.0.0.0", 4433]], "session": "00" * 16, "client_tunnel_ip": "10.77.0.2",
            "admin": {"bind": ["127.0.0.1", free_port()], "password_hash": HASH, **admin}}


class Client:
    def __init__(self, port, tls_ctx=None):
        self.port, self.ctx, self.cookie, self.csrf = port, tls_ctx, None, None

    def call(self, method, path, body=None, csrf=True):
        conn = (http.client.HTTPSConnection("127.0.0.1", self.port, context=self.ctx) if self.ctx
                else http.client.HTTPConnection("127.0.0.1", self.port))
        headers = {"Content-Type": "application/json"}
        if self.cookie: headers["Cookie"] = self.cookie
        if csrf and self.csrf: headers["X-CSRF-Token"] = self.csrf
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        r = conn.getresponse(); raw = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie" and v.startswith("gb_session=") and "Max-Age=0" not in v:
                self.cookie = v.split(";")[0]
        conn.close()
        try: data = json.loads(raw)
        except ValueError: data = raw
        return r.status, data, dict(r.getheaders())

    def login(self, password=PASSWORD):
        s, d, _ = self.call("POST", "/api/login", {"password": password})
        if s == 200: self.csrf = d["csrf"]
        return s


class AuthUnits(unittest.TestCase):
    def test_hash_roundtrip_and_rejects_short(self):
        self.assertTrue(verify_password(PASSWORD, HASH))
        self.assertFalse(verify_password("wrong password!", HASH))
        self.assertFalse(verify_password(PASSWORD, "garbage"))
        with self.assertRaises(ValueError): hash_password("short")

    def test_throttle_locks_then_expires(self):
        now = [0.0]; t = Throttle(clock=lambda: now[0], free=2, base=2)
        for _ in range(3): t.fail("a")
        self.assertGreater(t.retry_after("a"), 0)
        self.assertEqual(t.retry_after("b"), 0)
        now[0] += 3
        self.assertEqual(t.retry_after("a"), 0)

    def test_session_idle_and_cap(self):
        now = [0.0]; s = Sessions(clock=lambda: now[0])
        token, _ = s.create(); self.assertIsNotNone(s.get(token))
        now[0] += 31 * 60; self.assertIsNone(s.get(token))
        for _ in range(40): s.create()
        self.assertLessEqual(len(s.items), 16)

    def test_settings_rules(self):
        with self.assertRaises(ValueError): AdminSettings({"bind": ["0.0.0.0", 8443], "password_hash": HASH})  # public, no TLS
        with self.assertRaises(ValueError): AdminSettings({"bind": ["127.0.0.1", 8443]})  # no password
        with self.assertRaises(ValueError): AdminSettings({"password_hash": HASH, "bogus": 1})
        AdminSettings({"bind": ["127.0.0.1", 8443], "password_hash": HASH})

    def test_load_config_checks_admin_block(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps(server_config())); self.assertEqual(app.load_config(p)["role"], "server")
            bad = server_config(); bad["admin"]["bind"] = ["0.0.0.0", 8443]
            p.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): app.load_config(p)


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(); self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "server.json"
        self.path.write_text(json.dumps(server_config(), indent=2))
        self.restarted = threading.Event()
        self.portal = AdminPortal(AdminSettings(server_config()["admin"]), snapshot=lambda: {"version": "t", "transport": {"paths": []}},
                                  config_path=self.path, validate=app.load_config, request_restart=self.restarted.set).start()
        self.addCleanup(self.portal.close)
        self.c = Client(self.portal.port)

    def test_requires_login_and_security_headers(self):
        s, _, h = self.c.call("GET", "/api/status")
        self.assertEqual(s, 401)
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
        s, body, h = self.c.call("GET", "/")
        self.assertEqual(s, 200); self.assertIn(b"GameBond", body)
        self.assertEqual(self.c.login("nope nope nope"), 401)
        self.assertEqual(self.c.login(), 200)
        self.assertEqual(self.c.call("GET", "/api/status")[0], 200)

    def test_cookie_flags(self):
        _, _, h = self.c.call("POST", "/api/login", {"password": PASSWORD})
        for flag in ("HttpOnly", "Secure", "SameSite=Strict"): self.assertIn(flag, h["Set-Cookie"])

    def test_post_needs_csrf(self):
        self.c.login()
        self.assertEqual(self.c.call("POST", "/api/restart", {"confirm": True}, csrf=False)[0], 403)
        self.assertFalse(self.restarted.is_set())

    def test_login_lockout(self):
        for _ in range(5): self.c.login("wrong wrong wrong")
        self.assertEqual(self.c.login(PASSWORD), 429)

    def test_static_path_traversal_rejected(self):
        for p in ("/static/../server.py", "/static/..%2fserver.py", "/static/.hidden"):
            self.assertEqual(self.c.call("GET", p)[0], 404)

    def test_config_validate_and_apply(self):
        self.c.login()
        cfg = json.loads(self.path.read_text()); cfg["lan_tunnel_ips"] = ["10.77.0.3"]
        ok = self.c.call("POST", "/api/config/validate", {"text": json.dumps(cfg)})[1]
        self.assertTrue(ok["ok"], ok)
        bad = dict(cfg, mtu=99999)
        self.assertFalse(self.c.call("POST", "/api/config/validate", {"text": json.dumps(bad)})[1]["ok"])
        s, _, _ = self.c.call("POST", "/api/config", {"text": json.dumps(bad)}); self.assertEqual(s, 422)
        self.assertNotIn("lan_tunnel_ips", self.path.read_text())  # invalid save did not write
        self.assertEqual(self.c.call("POST", "/api/config", {"text": json.dumps(cfg)})[0], 200)
        self.assertEqual(json.loads(self.path.read_text())["lan_tunnel_ips"], ["10.77.0.3"])

    def test_admin_block_not_editable_via_config(self):
        self.c.login()
        cfg = json.loads(self.path.read_text()); cfg["admin"]["bind"] = ["127.0.0.1", 9999]
        s, d, _ = self.c.call("POST", "/api/config", {"text": json.dumps(cfg)})
        self.assertEqual(s, 422); self.assertIn("admin block", d["error"])

    def test_password_change_ends_sessions(self):
        self.c.login()
        self.assertEqual(self.c.call("POST", "/api/password", {"current": "bad", "new": "another long pass"})[0], 422)
        self.assertEqual(self.c.call("POST", "/api/password", {"current": PASSWORD, "new": "another long pass"})[0], 200)
        self.assertEqual(self.c.call("GET", "/api/status")[0], 401)
        self.assertEqual(Client(self.portal.port).login("another long pass"), 200)
        self.assertTrue(verify_password("another long pass", json.loads(self.path.read_text())["admin"]["password_hash"]))
        app.load_config(self.path)

    def test_restart_requires_confirm_then_fires(self):
        self.c.login()
        self.assertEqual(self.c.call("POST", "/api/restart", {})[0], 400)
        self.assertEqual(self.c.call("POST", "/api/restart", {"confirm": True})[0], 202)
        self.assertTrue(self.restarted.wait(3))

    def test_oversized_body_rejected(self):
        self.assertEqual(self.c.call("POST", "/api/login", {"password": "x" * 300000})[0], 400)


class TlsTest(unittest.TestCase):
    def test_serves_https_with_generated_cert(self):
        with tempfile.TemporaryDirectory() as d:
            files = write_self_signed(d, ["127.0.0.1"])
            path = Path(d) / "s.json"; path.write_text(json.dumps(server_config()))
            settings = AdminSettings(server_config(tls_cert=files["cert"], tls_key=files["key"])["admin"])
            portal = AdminPortal(settings, snapshot=lambda: {}, config_path=path, validate=app.load_config).start()
            try:
                ctx = ssl.create_default_context(cafile=files["cert"])
                c = Client(portal.port, ctx)
                self.assertEqual(c.login(), 200)
                self.assertEqual(c.call("GET", "/api/session")[0], 200)
                with self.assertRaises(ssl.SSLError):  # untrusted by default
                    Client(portal.port, ssl.create_default_context()).call("GET", "/api/session")
            finally:
                portal.close()


if __name__ == "__main__":
    unittest.main()
