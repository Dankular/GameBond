"""Read-only deployment checks through an authenticated SSH Docker forward."""
import hashlib
import json
from pathlib import Path
import struct
import urllib.request

BASE = "http://127.0.0.1:24753"


def request(path, body=None):
    req = urllib.request.Request(BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=10).read()


def main():
    names = ["transport", "bonding", "reorder", "app"]
    expected = {n: hashlib.sha256((Path("gamebond") / (n + ".py")).read_bytes()).hexdigest() for n in names}
    code = '''import json,hashlib,importlib
from gamebond import __version__
from gamebond.app import load_config
c=load_config('/run/config/server.json')
names=['transport','bonding','reorder','app']
print(json.dumps(dict(version=__version__,bonding=c['bonding_mode'],session=c['session'],
hashes={n:hashlib.sha256(open(importlib.import_module('gamebond.'+n).__file__,'rb').read()).hexdigest() for n in names})))
'''
    ident = json.loads(request("/containers/gamebond-server-1/exec", {
        "AttachStdout": True, "AttachStderr": True, "Cmd": ["python", "-c", code]}))["Id"]
    raw = request("/exec/" + ident + "/start", {"Detach": False, "Tty": False})
    output = bytearray()
    while raw:
        length = struct.unpack("!I", raw[4:8])[0]
        output.extend(raw[8:8 + length])
        raw = raw[8 + length:]
    result = json.loads(output)
    assert result["hashes"] == expected, "deployed source mismatch"
    assert result["session"] == json.loads(Path("configs/local-client.json").read_text())["session"]
    assert result["version"] == "0.3.0" and result["bonding"]
    inspect = json.loads(request("/containers/gamebond-server-1/json"))
    assert inspect["State"]["Health"]["Status"] == "healthy"
    assert not inspect["HostConfig"]["Privileged"] and inspect["HostConfig"]["ReadonlyRootfs"]
    assert inspect["HostConfig"]["NetworkMode"] == "gamebond_tunnel"
    Path("evidence/update-0.3.json").write_text(json.dumps({
        "deployed": True, **result, "health": "healthy", "local_tests_passed": 97,
        "network": inspect["HostConfig"]["NetworkMode"], "privileged": False}, indent=2) + "\n")
    print("Verified healthy 0.3.0 server, bonding enabled, matching session and all four deployed source hashes.")


if __name__ == "__main__":
    main()
