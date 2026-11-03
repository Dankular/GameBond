"""Update only GameBond through a short-lived, authenticated SSH Docker forward.

build prepares an image without interrupting the current server. rollout stages
the release into its own host directory and replaces only gamebond-server-1.
"""
import argparse
import copy
import io
import json
from pathlib import Path
import secrets
import struct
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:24753"
VERSION = "0.3.1"
IMAGE = "gamebond:" + VERSION


def api(path, data=None, method=None, timeout=30):
    headers = {}
    if isinstance(data, dict):
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    elif data is not None:
        headers["Content-Type"] = "application/x-tar"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return raw


def context():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name in ["Dockerfile", "pyproject.toml", "tools/container-entrypoint.sh"] + [
                str(p.relative_to(ROOT)) for p in sorted((ROOT / "gamebond").glob("*.py"))]:
            tar.add(ROOT / name, arcname=name.replace("\\", "/"))
    return output.getvalue()


def build():
    result = api("/build?t=" + IMAGE + "&rm=true", context(), timeout=240)
    lines = result.decode().splitlines() if isinstance(result, bytes) else []
    for line in lines:
        row = json.loads(line)
        if row.get("error"):
            raise RuntimeError(row["error"])
        if "stream" in row:
            print(row["stream"], end="", flush=True)
    api("/images/" + IMAGE + "/json")
    print("IMAGE_READY=" + IMAGE, flush=True)


def exec_container(name, command):
    ident = api("/containers/" + name + "/exec", {"AttachStdout": True, "AttachStderr": True, "Cmd": command})["Id"]
    raw = api("/exec/" + ident + "/start", {"Detach": False, "Tty": False})
    if raw:
        while raw:
            size = struct.unpack("!I", raw[4:8])[0]
            print(raw[8:8 + size].decode(), end="")
            raw = raw[8 + size:]
    assert api("/exec/" + ident + "/json")["ExitCode"] == 0


def rollout():
    old = api("/containers/gamebond-server-1/json")
    assert old["Config"]["Labels"]["com.docker.compose.project"] == "gamebond"
    old_release = old["Config"]["Labels"]["com.docker.compose.project.working_dir"]
    assert old_release.startswith("/opt/gamebond/releases/")
    session = secrets.token_hex(16)
    release = "/opt/gamebond/releases/" + session
    staged = {}
    for role in ("client", "server"):
        config = json.loads((ROOT / "configs" / ("local-" + role + ".json")).read_text())
        config["session"] = session
        staged[role] = json.dumps(config, indent=2) + "\n"
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as tar:
        for name in ["Dockerfile", "pyproject.toml", "compose.yaml", "tools/container-entrypoint.sh"] + [
                str(p.relative_to(ROOT)) for p in (ROOT / "gamebond").glob("*.py")]:
            tar.add(ROOT / name, arcname=name.replace("\\", "/"))
        for name, content in [("configs/local-server.json", staged["server"].encode()),
                              ("secrets/gamebond.key", (ROOT / "secrets/gamebond.key").read_bytes()),
                              ("deploy.env", b"GAMEBOND_SERVER_CONFIG=./configs/local-server.json\nGAMEBOND_KEY_FILE=./secrets/gamebond.key\n")]:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(content), 0o600
            tar.addfile(info, io.BytesIO(content))
    helper = "gamebond-release-stage-" + session[:8]
    api("/containers/create?name=" + helper, {"Image": IMAGE,
        "Entrypoint": ["python", "-c"], "Cmd": ["import time;time.sleep(180)"],
        "HostConfig": {"Binds": [release + ":/stage:rw"], "NetworkMode": "none", "CapDrop": ["ALL"],
                       "ReadonlyRootfs": True, "SecurityOpt": ["no-new-privileges:true"], "Memory": 67108864}})
    try:
        api("/containers/" + helper + "/start", method="POST")
        api("/containers/" + helper + "/archive?path=/stage", payload.getvalue(), method="PUT")
        exec_container(helper, ["python", "-c", "import os;os.chmod('/stage',0o700);os.chmod('/stage/secrets',0o700)"])
    finally:
        api("/containers/" + helper + "?force=true", method="DELETE")
    config = copy.deepcopy(old["Config"])
    config["Image"] = IMAGE
    config["Labels"]["com.docker.compose.project.working_dir"] = release
    config["Labels"]["com.docker.compose.project.config_files"] = release + "/compose.yaml"
    host = copy.deepcopy(old["HostConfig"])
    for mount in host.get("Mounts", []):
        assert mount["Source"].startswith(old_release + "/")
        mount["Source"] = release + mount["Source"][len(old_release):]
    config["HostConfig"] = host
    config["NetworkingConfig"] = {"EndpointsConfig": {"gamebond_tunnel": {"Aliases": ["server", "gamebond-server-1"]}}}
    backup = "gamebond-rollback-" + session[:8]
    api("/containers/gamebond-server-1/stop?t=10", method="POST")
    api("/containers/gamebond-server-1/rename?name=" + backup, method="POST")
    try:
        api("/containers/create?name=gamebond-server-1", config)
        api("/containers/gamebond-server-1/start", method="POST")
        for _ in range(60):
            new = api("/containers/gamebond-server-1/json")
            if new["State"].get("Health", {}).get("Status") == "healthy":
                break
            time.sleep(.5)
        else:
            raise RuntimeError("new container did not become healthy")
        exec_container("gamebond-server-1", ["python", "-c", "from gamebond import __version__;assert __version__=='0.3.1';print('version='+__version__)"])
    except Exception:
        try:
            api("/containers/gamebond-server-1?force=true", method="DELETE")
        except Exception:
            pass
        api("/containers/" + backup + "/rename?name=gamebond-server-1", method="POST")
        api("/containers/gamebond-server-1/start", method="POST")
        raise
    api("/containers/" + backup, method="DELETE")
    for role, content in staged.items():
        (ROOT / "configs" / ("local-" + role + ".json")).write_text(content)
    (ROOT / "evidence/update-0.3.1.json").write_text(json.dumps({
        "deployed": True, "version": VERSION, "health": "healthy", "release": release,
        "session": session, "privileged": False, "network": "gamebond_tunnel"}, indent=2))
    print("DEPLOYED=" + IMAGE + " HEALTH=healthy", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["build", "rollout"])
    args = parser.parse_args()
    build() if args.phase == "build" else rollout()
