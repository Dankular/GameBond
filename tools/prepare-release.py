"""Stage a new target/session without changing the active client configuration."""
import argparse
import io
import ipaddress
import json
from pathlib import Path
import secrets
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond import __version__
from gamebond.app import load_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer")
    parser.add_argument("--keep-session", action="store_true", help="wire-compatible update using the current shared session")
    args = parser.parse_args()
    peer = ipaddress.IPv4Address(args.peer)
    if peer.is_unspecified or peer.is_multicast:
        raise ValueError("invalid endpoint")
    session = secrets.token_hex(16)
    image = "gamebond:" + __version__ + "-" + session
    stage = ROOT / ".runtime/releases" / session
    stage.mkdir(parents=True)
    configs = {}
    for role in ("client", "server"):
        config = load_config(ROOT / "configs" / ("local-" + role + ".json"))
        config.update(session=config["session"] if args.keep_session else session,
                      bonding_mode=True, redundant_mode=False, bulk_rate_mbps=0)
        if role == "client":
            config["peer"] = [str(peer), 4433]
        configs[role] = json.dumps(config, indent=2) + "\n"
        (stage / (role + ".json")).write_text(configs[role])
        load_config(stage / (role + ".json"))
    archive = ROOT / "secrets" / ("gamebond-" + __version__ + "-" + session + ".tar.gz")
    with tarfile.open(archive, "x:gz") as tar:
        files = ["Dockerfile", "compose.yaml", ".dockerignore", "pyproject.toml", "tools/container-entrypoint.sh"]
        files += [str(p.relative_to(ROOT)) for p in (ROOT / "gamebond").glob("*.py")]
        for name in files:
            tar.add(ROOT / name, arcname=name.replace("\\", "/"))
        for name, data in (("configs/local-server.json", configs["server"].encode()),
                           ("secrets/gamebond.key", (ROOT / "secrets/gamebond.key").read_bytes()),
                           ("deploy.env", ("GAMEBOND_SERVER_CONFIG=./configs/local-server.json\nGAMEBOND_KEY_FILE=./secrets/gamebond.key\nGAMEBOND_IMAGE=" + image + "\n").encode())):
            info = tarfile.TarInfo(name)
            info.mode, info.size = 0o600, len(data)
            tar.addfile(info, io.BytesIO(data))
    plan = dict(version=__version__, peer=str(peer), release_id=session, image=image,
                session=json.loads(configs["client"])["session"], archive=str(archive),
                stage=str(stage), release="/opt/gamebond/releases/" + session)
    (ROOT / ".runtime/deployment-plan.json").write_text(json.dumps(plan, indent=2))
    print(json.dumps(plan))


if __name__ == "__main__":
    main()
