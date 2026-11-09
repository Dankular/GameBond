"""Read-only views of the container's network state. Fixed argv, no shell."""
from __future__ import annotations
import json
import shutil
import subprocess


def _run(argv, timeout=3):
    if shutil.which(argv[0]) is None:
        return None, f"{argv[0]} is not installed"
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if done.returncode:
        return None, (done.stderr or done.stdout).strip()[:500] or f"exit {done.returncode}"
    return done.stdout, None


def _json(argv):
    out, error = _run(argv)
    if error:
        return {"error": error}
    try:
        return {"data": json.loads(out or "[]")}
    except ValueError:
        return {"error": "unparseable output"}


def interfaces():
    result = _json(["ip", "-j", "-s", "addr", "show"])
    if "data" in result:
        result["data"] = [{"name": i.get("ifname"), "state": i.get("operstate"), "mtu": i.get("mtu"), "mac": i.get("address"),
                           "addresses": [f"{a.get('local')}/{a.get('prefixlen')}" for a in i.get("addr_info", [])],
                           "rx_bytes": (i.get("stats64") or {}).get("rx", {}).get("bytes"),
                           "tx_bytes": (i.get("stats64") or {}).get("tx", {}).get("bytes")} for i in result["data"]]
    return result


def routes():
    result = _json(["ip", "-j", "-4", "route", "show"])
    if "data" in result:
        result["data"] = [{"destination": r.get("dst"), "gateway": r.get("gateway"), "device": r.get("dev"),
                           "protocol": r.get("protocol"), "source": r.get("prefsrc")} for r in result["data"]]
    return result


def nat_rules():
    out, error = _run(["nft", "list", "table", "ip", "gamebond"])
    return {"error": error} if error else {"text": out}
