"""Password hashing, sessions, CSRF tokens and login throttling."""
from __future__ import annotations
import base64
import hashlib
import hmac
import secrets
import threading
import time

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
IDLE_SECONDS, ABSOLUTE_SECONDS = 30 * 60, 8 * 3600
MAX_SESSIONS = 16


def hash_password(password: str, *, n=SCRYPT_N) -> str:
    if len(password) < 10:
        raise ValueError("password must be at least 10 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024 * 1024, dklen=32)
    return "scrypt$%d$%s$%s" % (n, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=SCRYPT_R, p=SCRYPT_P,
                                maxmem=128 * 1024 * 1024, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


class Throttle:
    """Per-address and global failed-login lockout with exponential delay."""

    def __init__(self, clock=time.monotonic, free=4, base=2.0, cap=900.0, global_limit=40, window=300.0):
        self.clock, self.free, self.base, self.cap = clock, free, base, cap
        self.global_limit, self.window = global_limit, window
        self.failures, self.blocked_until, self.recent = {}, {}, []
        self.lock = threading.Lock()

    def retry_after(self, address) -> float:
        with self.lock:
            now = self.clock()
            self.recent = [t for t in self.recent if now - t < self.window]
            wait = max(0.0, self.blocked_until.get(address, 0) - now)
            if len(self.recent) >= self.global_limit:
                wait = max(wait, self.window - (now - self.recent[0]))
            return wait

    def fail(self, address):
        with self.lock:
            now = self.clock()
            count = self.failures[address] = self.failures.get(address, 0) + 1
            self.recent.append(now)
            if count > self.free:
                self.blocked_until[address] = now + min(self.cap, self.base * 2 ** (count - self.free - 1))
            if len(self.failures) > 4096:
                self.failures.clear(); self.blocked_until.clear()

    def success(self, address):
        with self.lock:
            self.failures.pop(address, None)
            self.blocked_until.pop(address, None)


class Sessions:
    def __init__(self, clock=time.monotonic):
        self.clock, self.items, self.lock = clock, {}, threading.Lock()

    def create(self):
        now = self.clock()
        with self.lock:
            self._expire(now)
            while len(self.items) >= MAX_SESSIONS:
                del self.items[min(self.items, key=lambda k: self.items[k]["seen"])]
            token = secrets.token_urlsafe(32)
            self.items[token] = {"csrf": secrets.token_urlsafe(24), "born": now, "seen": now}
            return token, self.items[token]["csrf"]

    def _expire(self, now):
        for token, s in list(self.items.items()):
            if now - s["seen"] > IDLE_SECONDS or now - s["born"] > ABSOLUTE_SECONDS:
                del self.items[token]

    def get(self, token):
        if not token:
            return None
        now = self.clock()
        with self.lock:
            self._expire(now)
            s = self.items.get(token)
            if s:
                s["seen"] = now
            return dict(s) if s else None

    def drop(self, token):
        with self.lock:
            self.items.pop(token, None)

    def drop_all(self):
        with self.lock:
            self.items.clear()
