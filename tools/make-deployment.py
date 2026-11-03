"""Create a private server deployment archive and matching local client config."""
import json
from pathlib import Path
import secrets
import tarfile


def main():
    root = Path(__file__).resolve().parents[1]
    private = root / "secrets"
    private.mkdir(exist_ok=True)
    key = private / "gamebond.key"
    if not key.exists():
        with key.open("xb") as file:
            file.write(secrets.token_bytes(32))
    if len(key.read_bytes()) != 32:
        raise ValueError("existing GameBond key is invalid")
    # Both ends must be updated together; this command intentionally makes a new session.
    session = secrets.token_hex(16)
    for role in ("client", "server"):
        config = json.loads((root / "configs" / f"{role}.example.json").read_text())
        config["session"] = session
        if role == "client":
            config["peer"] = ["178.104.238.86", 4433]
        (root / "configs" / f"local-{role}.json").write_text(json.dumps(config, indent=2) + "\n")
    env = private / "deploy.env"
    env.write_text("GAMEBOND_SERVER_CONFIG=./configs/local-server.json\nGAMEBOND_KEY_FILE=./secrets/gamebond.key\n")
    archive = private / "server-deployment.tar.gz"
    files = ["Dockerfile", "compose.yaml", ".dockerignore", "pyproject.toml",
             "tools/container-entrypoint.sh", "configs/local-server.json", "secrets/gamebond.key"]
    files += [str(p.relative_to(root)) for p in (root / "gamebond").glob("*.py")]
    with tarfile.open(archive, "w:gz") as tar:
        for relative in files:
            info = tar.gettarinfo(str(root / relative), arcname=relative.replace("\\", "/"))
            info.mode = 0o600
            with (root / relative).open("rb") as file:
                tar.addfile(info, file)
        info = tar.gettarinfo(str(env), arcname="deploy.env")
        info.mode = 0o600
        with env.open("rb") as file:
            tar.addfile(info, file)
    print(json.dumps({"archive": str(archive), "session": session,
                      "remote_release": "/opt/gamebond/releases/" + session}))


if __name__ == "__main__":
    main()
