"""Validated `server_type` and `omr` configuration. Imports nothing heavy (no PyNaCl) so config loading stays cheap."""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass

SERVER_TYPES = ("gamebond", "both")
OMR_KEYS = {"server", "key_file", "tunnel_ip", "rate_mbps", "beat_ms", "gamebond_dscp"}


@dataclass(frozen=True)
class OmrSettings:
    server: tuple
    key_file: str
    tunnel_ip: str = "10.255.254.2"
    rate_mbps: float = 100.0
    beat_ms: int = 100
    gamebond_dscp: tuple = (46, 26)


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
    if not isinstance(raw, dict) or set(raw) - OMR_KEYS or not {"server", "key_file"} <= set(raw):
        raise ValueError("omr needs server and key_file (optional: " + ", ".join(sorted(OMR_KEYS - {"server", "key_file"})) + ")")
    server = raw["server"]
    if not isinstance(server, (list, tuple)) or len(server) != 2 or type(server[1]) is not int or not 1 <= server[1] <= 65535:
        raise ValueError("omr.server must be [IPv4, port]")
    host = ipaddress.IPv4Address(server[0])
    if host.is_unspecified or host.is_multicast or host.is_loopback or host.is_link_local:
        raise ValueError("omr.server must be a usable unicast IPv4 address")
    if not isinstance(raw["key_file"], str) or not raw["key_file"]:
        raise ValueError("omr.key_file must name a file holding the 64-hex-character Glorytun key")
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
    return mode, OmrSettings((str(host), server[1]), raw["key_file"], str(tunnel), float(rate), beat, tuple(dscp))
