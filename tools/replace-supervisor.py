"""Replace only an already-stopped GameBond supervisor; start its successor stopped.

Invoked through normal Windows RunAs elevation. No security settings are changed.
"""
import argparse
import ctypes
import io
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.tty_server import control


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-pid", type=int, required=True)
    args = parser.parse_args()
    status = control("status", output=io.StringIO())
    if status.get("owner_pid") != args.old_pid or status.get("state") not in ("stopped", "failed"):
        raise RuntimeError("Expected stopped GameBond owner; refusing process replacement")
    if status.get("state") == "failed":
        # A failed run is replaceable only after its adapter was actually closed.
        remaining = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Name -ceq 'GameBond' }).Count"], text=True)
        if remaining.strip() != "0":
            raise RuntimeError("Failed client still owns a tunnel adapter; refusing process replacement")
        for path in (ROOT / ".runtime/network").glob("*.json"):
            record = json.loads(path.read_text())
            if (record.get("owner") or {}).get("pid") == args.old_pid:
                raise RuntimeError("Failed client still has an ownership journal; cleanup must complete first")
    command = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-CimInstance Win32_Process -Filter 'ProcessId = " + str(args.old_pid) + "').CommandLine"], text=True)
    if "-m gamebond.windows_launcher" not in command:
        raise RuntimeError("Owner is not the expected GameBond launcher")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    handle = kernel.OpenProcess(0x100001, False, args.old_pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    try:
        if not kernel.TerminateProcess(handle, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel.WaitForSingleObject(handle, 5000)
    finally:
        kernel.CloseHandle(handle)
    time.sleep(.25)
    child = subprocess.Popen([sys.executable, "-m", "gamebond.windows_launcher", "--config",
        str(ROOT / "configs/local-client.json"), "--key", str(ROOT / "secrets/gamebond.key"),
        "--configure", "--stopped"], cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    for _ in range(60):
        state = control("status", output=io.StringIO())
        if state.get("owner_pid") == child.pid and state.get("state") == "stopped":
            return dict(ok=True, old_pid=args.old_pid, owner_pid=child.pid, state="stopped")
        time.sleep(.1)
    raise RuntimeError("New stopped supervisor did not register")


if __name__ == "__main__":
    try:
        result = main()
    except Exception as exc:
        result = dict(ok=False, error=str(exc))
    (ROOT / ".runtime/supervisor-replacement.json").write_text(json.dumps(result))
