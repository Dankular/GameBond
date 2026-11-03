"""Elevated, cooperative replacement of the one registered GameBond supervisor."""
import ctypes
import io
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.tty_server import control
from gamebond import __version__


def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError("Supervisor source update requires the existing Administrator privilege")
    status = control("status", output=io.StringIO())
    pid = status.get("owner_pid")
    if not pid:
        raise RuntimeError("No registered supervisor to update")
    stopped = control("stop", output=sys.stdout)
    if stopped.get("state") not in ("stopped", "failed"):
        raise RuntimeError("Client cleanup did not complete; refusing supervisor replacement")
    subprocess.run([sys.executable, str(ROOT / "tools/replace-supervisor.py"), "--old-pid", str(pid)],
                   cwd=ROOT, check=True)
    result = json.loads((ROOT / ".runtime/supervisor-replacement.json").read_text())
    if not result.get("ok"):
        raise RuntimeError(result.get("error", "Supervisor replacement failed"))
    restarted = control("restart", output=sys.stdout)
    if not restarted.get("ok") or restarted.get("state") != "running":
        raise RuntimeError("Updated client did not reach running state")
    print(json.dumps({"status": "updated_client_running", "owner_pid": result["owner_pid"]}), flush=True)


if __name__ == "__main__":
    status_file = ROOT / ".runtime/client-update-status.json"
    status_file.write_text(json.dumps({"state": "starting"}))
    try:
        main()
    except Exception as exc:
        status_file.write_text(json.dumps({"state": "failed", "error": str(exc)}))
        raise
    else:
        status_file.write_text(json.dumps({"state": "running", "version": __version__}))
