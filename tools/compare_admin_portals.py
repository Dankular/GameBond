"""Drive the Python and Go admin portals with identical requests and diff the answers.

Usage: python tools/compare_admin_portals.py build/adminportal-probe.exe
Both portals get a copy of the same config file and the same password hash.
"""
import http.client
import socket
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.admin.auth import hash_password  # noqa: E402
from gamebond.admin.server import AdminPortal, AdminSettings  # noqa: E402

PASSWORD = "correct horse battery"
HASH = hash_password(PASSWORD, n=1 << 12)
CONFIG = json.dumps({"role": "server", "x": 1}, indent=1)


class Client:
    def __init__(self, port):
        self.port, self.cookie, self.csrf = port, None, None

    def call(self, method, path, body=None, raw=None, csrf=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.cookie:
            headers["Cookie"] = self.cookie
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        c.request(method, path, data, headers)
        r = c.getresponse()
        payload = r.read()
        cookie = r.getheader("Set-Cookie")
        if cookie and "Max-Age=0" not in cookie:
            self.cookie = cookie.split(";")[0]
        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = payload.decode("utf-8", "replace")
        if isinstance(parsed, dict) and parsed.get("csrf") and path == "/api/login":
            self.csrf = parsed["csrf"]
        keep = {k.lower(): re.sub(r"gb_session=[^;]+", "gb_session=T", v) for k, v in r.getheaders()
                if k.lower() in ("content-type", "set-cookie", "retry-after", "cache-control", "x-content-type-options", "content-security-policy")}
        return r.status, keep, parsed


def scenario(c, cfgpath):
    out = []
    def step(*a, **k):
        s, h, b = c.call(*a, **k)
        if isinstance(b, dict) and "csrf" in b and b["csrf"]:
            b = dict(b, csrf="C")
        b = mask(b)
        if isinstance(b, dict) and isinstance(b.get("error"), str) and "retry in" in b["error"]:
            b = dict(b, error=re.sub(r"\d+", "N", b["error"]))
            h = {k2: ("N" if k2 == "retry-after" else v2) for k2, v2 in h.items()}
        out.append((a[0], a[1], s, h, b if not (a[1].startswith("/api/") and a[1] in ("/api/interfaces", "/api/routes", "/api/nat")) else "system"))
    def mask(b):
        if isinstance(b, dict) and isinstance(b.get("lines"), list):
            return {"lines": [re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ", "T ", x) for x in b["lines"]]}
        if isinstance(b, dict) and b.get("error") and "ok" in b and "Error" in str(b["error"]):
            return dict(b, error="<parser message>")  # JSON parser wording is language specific; ok/accept must match
        return b
    for p in ("/", "/static/app.js", "/static/style.css", "/static/nope.js", "/static/../x", "/nothing", "/api/session", "/api/status", "/api/config"):
        step("GET", p)
    step("POST", "/api/login", raw=b"not json")
    step("POST", "/api/login", {"password": 5})
    step("POST", "/api/login", {"password": "wrong"})
    step("POST", "/api/config", {"text": "{}"})
    step("POST", "/api/login", {"password": PASSWORD})
    for p in ("/api/session", "/api/status", "/api/log", "/api/config", "/api/nope", "/api/interfaces"):
        step("GET", p)
    step("POST", "/api/config/validate", {"text": "{bad"})
    step("POST", "/api/config/validate", {"text": '{"role":"server"}'})
    step("POST", "/api/config", {"text": '{"role":"server","y":2}'})
    step("GET", "/api/config")
    step("POST", "/api/config", {"text": 5})
    step("POST", "/api/password", {"current": "no", "new": "long enough password"})
    step("POST", "/api/password", {"current": PASSWORD, "new": "short"})
    step("POST", "/api/restart", {"confirm": False})
    step("POST", "/api/restart", {})
    step("POST", "/api/nope", {})
    old = c.csrf; c.csrf = "bad"
    step("POST", "/api/config", {"text": "{}"})
    c.csrf = old
    step("POST", "/api/password", {"current": PASSWORD, "new": "a brand new password"})
    step("GET", "/api/log")
    step("POST", "/api/logout", {})
    step("GET", "/api/session")
    for _ in range(6):
        step("POST", "/api/login", {"password": "wrong"})
    step("POST", "/api/login", {"password": PASSWORD})
    text = Path(cfgpath).read_bytes().decode().replace("\r\n", "\n")
    out.append(("FILE", re.sub(r"scrypt\$[^\"]+", "H", text)))
    return out


def free_port():
    with socket.socket() as k:
        k.bind(("127.0.0.1", 0))
        return k.getsockname()[1]


def run(probe):
    tmp = Path(tempfile.mkdtemp())
    pcfg, gcfg = tmp / "py.json", tmp / "go.json"
    pcfg.write_bytes(CONFIG.encode()); gcfg.write_bytes(CONFIG.encode())
    portal = AdminPortal(AdminSettings({"enabled": True, "bind": ["127.0.0.1", free_port()], "password_hash": HASH}),
                         snapshot=lambda: {"version": "x", "pid": 1}, config_path=pcfg)
    portal.start()
    proc = subprocess.Popen([probe, str(gcfg), HASH], stdout=subprocess.PIPE, text=True)
    try:
        gport = int(proc.stdout.readline())
        time.sleep(.2)
        py, go = scenario(Client(portal.port), pcfg), scenario(Client(gport), gcfg)
    finally:
        portal.close(); proc.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    bad = 0
    for a, b in zip(py, go):
        if a != b:
            bad += 1
            print("DIFF\n python", json.dumps(a, default=str)[:400], "\n go    ", json.dumps(b, default=str)[:400])
    print(f"{len(py)} steps, {bad} differences")
    return bad


if __name__ == "__main__":
    sys.exit(1 if run(sys.argv[1]) else 0)
