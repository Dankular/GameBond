"""Client for the OpenMPTCProuter server's admin API (omr-admin, HTTPS, default port 65500).

Request and response shapes were read from `openmptcprouter-vps-admin/omradmin.py`:
  POST /token  form fields username, password -> {"access_token", "token_type": "bearer"}; 400 on bad credentials
  GET  /config  with `Authorization: Bearer ...` -> {"glorytun": {"key", "udp": {"host_ip", "client_ip"}, "port", "chacha"}, ...}

The server certificate is self-signed, so chain verification cannot be used. As OMR's own router does, the
server is identified by a public-key pin: the base64 SHA-256 of its SubjectPublicKeyInfo (curl's
`--pinnedpubkey sha256//...` format; the VPS installer prints it). Differences from the router, on purpose:
credentials are never sent before a pin is configured, and a pin is never learned silently: `learn_pin`
returns it for the user to confirm. A wrong login is never retried (the server bans an address after six
failures).

Not verified against a real server: nothing here has talked to a live omr-admin.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import socket
import ssl
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

MAX_RESPONSE = 2 * 1024 * 1024
_PIN = re.compile(r"^(?:sha256//)?([A-Za-z0-9+/]{43}=)$")
_HEX_KEY = re.compile(r"^[0-9a-fA-F]{64}$")


class OmrAdminError(Exception):
    pass


class OmrAuthError(OmrAdminError):
    """Credentials were refused. Do not retry automatically."""


class OmrPinError(OmrAdminError):
    """The server's key does not match the pin; nothing was sent."""


def normalize_pin(text: str) -> str:
    match = _PIN.match((text or "").strip())
    if not match:
        raise ValueError("pin must be the base64 SHA-256 of the server public key, optionally prefixed sha256//")
    return match.group(1)


def spki_pin(der_certificate: bytes) -> str:
    key = x509.load_der_x509_certificate(der_certificate).public_key()
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def _context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE        # replaced by the pin comparison before any data is sent
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def learn_pin(host: str, port: int = 65500, timeout: float = 10.0) -> str:
    """Connect (TLS handshake only, no HTTP data sent) and return the server's public-key pin for the user to confirm."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, _context().wrap_socket(raw, server_hostname=host) as tls:
            return spki_pin(tls.getpeercert(binary_form=True))
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise OmrAdminError(f"cannot read the server certificate from {host}:{port}: {exc}") from exc


class OmrAdmin:
    def __init__(self, host: str, port: int = 65500, *, pin: str, timeout: float = 10.0):
        if not pin:
            raise OmrPinError("no certificate pin configured: learn it, confirm it, and save it before logging in")
        self.host, self.port, self.timeout = host, int(port), timeout
        self.pin = normalize_pin(pin)
        self.token = ""

    def _request(self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=_context())
        try:
            connection.connect()
            actual = spki_pin(connection.sock.getpeercert(binary_form=True))
            if not hmac.compare_digest(actual, self.pin):
                raise OmrPinError(f"server key {actual} does not match the pin; nothing was sent")
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise OmrAdminError("admin API response is too large")
            return response.status, data
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise OmrAdminError(f"admin API {method} {path} failed: {exc}") from exc
        finally:
            connection.close()

    @staticmethod
    def _json(data: bytes):
        try:
            return json.loads(data)
        except ValueError as exc:
            raise OmrAdminError("admin API returned invalid JSON") from exc

    def login(self, username: str, password: str) -> None:
        """One attempt. A refused login raises OmrAuthError and must not be repeated automatically."""
        form = urllib.parse.urlencode(dict(username=username, password=password)).encode()
        status, data = self._request("POST", "/token", body=form,
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        if status in (400, 401, 403):
            raise OmrAuthError("the server refused the username or password")
        if status != 200:
            raise OmrAdminError(f"login failed with HTTP {status}")
        token = self._json(data).get("access_token")
        if not isinstance(token, str) or not token:
            raise OmrAdminError("login response had no access token")
        self.token = token

    def get(self, path: str):
        if not self.token:
            raise OmrAdminError("not logged in")
        status, data = self._request("GET", path, headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"})
        if status in (401, 403):
            self.token = ""
            raise OmrAuthError("the session token was refused; log in again")
        if status != 200:
            raise OmrAdminError(f"GET {path} failed with HTTP {status}")
        return self._json(data)

    def get_config(self) -> dict:
        config = self.get("/config")
        if not isinstance(config, dict):
            raise OmrAdminError("unexpected /config response")
        return config


def tunnel_settings(config: dict) -> dict:
    """What the Glorytun UDP client needs from /config: the key and, if the server uses a static one, our tunnel address.

    The `port` field is deliberately ignored: omr-admin fills it from the TCP tunnel's file, and the UDP tunnel
    listens on 65001 unless the user says otherwise.
    """
    glorytun = config.get("glorytun")
    if not isinstance(glorytun, dict):
        raise OmrAdminError("the server reports no Glorytun configuration")
    key = glorytun.get("key")
    if not isinstance(key, str) or not _HEX_KEY.match(key):
        raise OmrAdminError("the server has no usable Glorytun key (is glorytun installed there?)")
    client_ip = (glorytun.get("udp") or {}).get("client_ip")
    try:
        address = ipaddress.IPv4Address(client_ip)
        tunnel_ip = None if address.is_unspecified or address.is_multicast or address.is_loopback else str(address)
    except (ValueError, TypeError):
        tunnel_ip = None                     # "dhcp" or missing: keep the configured address
    return dict(key=bytes.fromhex(key), tunnel_ip=tunnel_ip, chacha=bool(glorytun.get("chacha")))
