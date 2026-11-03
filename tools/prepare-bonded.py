"""Stage a matching bonded pair without replacing active configs or deploying."""
import io
import argparse
import json
from pathlib import Path
import secrets
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gamebond.app import load_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-archive", action="store_true", help="repackage code using the already staged session")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    destinations = [root / "configs" / f"bonded-{role}.json" for role in ("client", "server")]
    if not args.refresh_archive and any(path.exists() for path in destinations):
        raise SystemExit("Bonded configs already staged; refusing to replace their session.")
    key = root / "secrets" / "gamebond.key"
    if len(key.read_bytes()) != 32:
        raise ValueError("existing key must contain 32 bytes")
    session = secrets.token_hex(16)
    configs = []
    if args.refresh_archive:
        staged = [load_config(path) for path in destinations]
        if (staged[0]["session"] != staged[1]["session"] or
                not all(c.get("bonding_mode") and not c.get("redundant_mode") for c in staged)):
            raise ValueError("staged pair does not match")
        session = staged[0]["session"]
        configs = [path.read_text(encoding="utf-8") for path in destinations]
    else:
        for role in ("client", "server"):
            config = load_config(root / "configs" / f"local-{role}.json")
            config.update(session=session, bonding_mode=True, redundant_mode=False,
                          bonding_initial_rate_mbps=1, bonding_max_rate_mbps=100,
                          reorder_timeout_ms=30, bulk_rate_mbps=0)
            configs.append(json.dumps(config, indent=2) + "\n")
    created = []
    try:
        for path, content in ([] if args.refresh_archive else zip(destinations, configs)):
            with path.open("x", encoding="utf-8") as file:
                file.write(content)
            created.append(path)
            load_config(path)
        archive = root / "secrets" / f"bonded-server-{session}.tar.gz"
        with tarfile.open(archive, "w:gz" if args.refresh_archive else "x:gz") as tar:
            paths = [root / name for name in ("Dockerfile", "compose.yaml", ".dockerignore", "pyproject.toml",
                     "tools/container-entrypoint.sh", "secrets/gamebond.key")]
            paths.extend(sorted((root / "gamebond").glob("*.py")))
            for path in paths:
                info = tar.gettarinfo(str(path), arcname=path.relative_to(root).as_posix())
                info.mode = 0o600
                with path.open("rb") as source:
                    tar.addfile(info, source)
            for name, content in (("configs/local-server.json", configs[1]),
                                  ("deploy.env", "GAMEBOND_SERVER_CONFIG=./configs/local-server.json\nGAMEBOND_KEY_FILE=./secrets/gamebond.key\n")):
                payload = content.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o600, len(payload)
                tar.addfile(info, io.BytesIO(payload))
    except Exception:
        for path in created:
            path.unlink()
        raise
    print(json.dumps(dict(staged=True, deployed=False, active_configs_changed=False,
                          client_config=str(destinations[0]), server_config=str(destinations[1]),
                          archive=str(archive), remote_release="/opt/gamebond/releases/" + session)))


if __name__ == "__main__":
    main()
