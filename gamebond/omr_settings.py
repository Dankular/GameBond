"""Validated `server_type` and `omr` configuration. Imports nothing heavy (no PyNaCl) so config loading stays cheap."""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass

SERVER_TYPES = ("gamebond", "both")
OMR_KEYS = {"server", "key_file", "admin", "tunnel_ip", "rate_mbps", "beat_ms", "gamebond_dscp"}
ADMIN_KEYS = {"host", "port", "username", "password_file", "pin"}


@dataclass(frozen=True)
class OmrSettings:
    server: tuple
    key_file: str = ""                 # either a key file ...
    admin: dict | None = None          # ... or an admin-API login that supplies the key (host, port, username, password_file, pin)
    tunnel_ip: str = "10.255.254.2"
    tunnel_ip_set: bool = False        # True when the user fixed it; otherwise the server's /config value is used when static
    rate_mbps: float = 100.0
    beat_ms: int = 100
    gamebond_dscp: tuple = (46, 26)


def _load_admin(raw, server_host: str) -> dict:
    """The admin login: host defaults to the tunnel server; the password is only ever a file reference."""
    if not isinstance(raw, dict) or set(raw) - ADMIN_KEYS or not {"username", "password_file", "pin"} <= set(raw):
        raise ValueError("omr.admin needs username, password_file and pin (optional: host, port)")
    host = ipaddress.IPv4Address(raw.get("host", server_host))
    if host.is_unspecified or host.is_multicast or host.is_loopback or host.is_link_local:
        raise ValueError("omr.admin.host must be a usable unicast IPv4 address")
    port = raw.get("port", 65500)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("omr.admin.port must be 1..65535")
    for name in ("username", "password_file", "pin"):
        if not isinstance(raw[name], str) or not raw[name].strip() or len(raw[name]) > 512:
            raise ValueError(f"omr.admin.{name} must be a non-empty string")
    import base64, re
    pin = re.sub(r"^sha256//", "", raw["pin"].strip())
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", pin):
        raise ValueError("omr.admin.pin must be the base64 SHA-256 of the server's public key (the installer prints it)")
    base64.b64decode(pin, validate=True)
    return dict(host=str(host), port=port, username=raw["username"], password_file=raw["password_file"], pin=pin)


def load_server_mode(config: dict):
    """Return (server_type, OmrSettings | None). 'omr' alone is not available yet and is refused explicitly."""
    mode = config.get("server_type", "gamebond")
    if mode == "omr":
        raise ValueError("server_type 'omr' alone is not available yet; use 'both' (GameBond tunnel plus OMR) or 'gamebond'")
    if mode not in SERVER_TYPES:
        raise ValueError("server_type must be 'gamebond' or 'both'")
    raw = config.get("omr")
    if mode == "gamebond":
        if raw is not None:
            raise ValueError("an omr block needs server_type 'both'")
        return mode, None
    if config.get("role") != "client":
        raise ValueError("server_type 'both' belongs to the client configuration")
    if not isinstance(raw, dict) or set(raw) - OMR_KEYS or "server" not in raw or ("key_file" in raw) == ("admin" in raw):
        raise ValueError("omr needs server and exactly one of key_file or admin (optional: tunnel_ip, rate_mbps, beat_ms, gamebond_dscp)")
    server = raw["server"]
    if not isinstance(server, (list, tuple)) or len(server) != 2 or type(server[1]) is not int or not 1 <= server[1] <= 65535:
        raise ValueError("omr.server must be [IPv4, port]")
    host = ipaddress.IPv4Address(server[0])
    if host.is_unspecified or host.is_multicast or host.is_loopback or host.is_link_local:
        raise ValueError("omr.server must be a usable unicast IPv4 address")
    key_file, admin = raw.get("key_file", ""), None
    if "key_file" in raw and (not isinstance(key_file, str) or not key_file):
        raise ValueError("omr.key_file must name a file holding the 64-hex-character Glorytun key")
    if "admin" in raw:
        admin = _load_admin(raw["admin"], str(host))
    tunnel = ipaddress.IPv4Address(raw.get("tunnel_ip", "10.255.254.2"))
    if tunnel.is_unspecified or tunnel.is_multicast or tunnel.is_loopback or tunnel.is_link_local:
        raise ValueError("omr.tunnel_ip must be a unicast IPv4 address")
    rate = raw.get("rate_mbps", 100.0)
    if type(rate) not in (int, float) or not math.isfinite(rate) or not 0.1 <= rate <= 10_000:
        raise ValueError("omr.rate_mbps must be between 0.1 and 10000")
    beat = raw.get("beat_ms", 100)
    if type(beat) is not int or not 10 <= beat <= 1000:
        raise ValueError("omr.beat_ms must be 10..1000")
    dscp = raw.get("gamebond_dscp", [46, 26])
    if not isinstance(dscp, (list, tuple)) or any(type(v) is not int or not 0 <= v <= 63 for v in dscp):
        raise ValueError("omr.gamebond_dscp must list DSCP values 0..63")
    return mode, OmrSettings((str(host), server[1]), key_file, admin, str(tunnel), "tunnel_ip" in raw, float(rate), beat, tuple(dscp))
