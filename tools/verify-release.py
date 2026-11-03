"""Verify the staged VPS container and exact deployed source bytes over SSH."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", type=int, required=True)
    args = parser.parse_args()
    plan = json.loads((ROOT / ".runtime/deployment-plan.json").read_text())
    host = plan["peer"]
    info = json.loads((ROOT / ".runtime/vps138-inspect.json").read_text(encoding="utf-8-sig"))[0]
    modules = ["transport", "bonding", "reorder", "app", "windows_launcher", "tty_server", "policy", "tun", "windows_network", "dns", "windows_dns", "dns_management", "telemetry"]
    result = (ROOT / ".runtime/vps138-hashes.txt").read_text(encoding="utf-8-sig")
    hashes = {Path(line.split()[1]).stem: line.split()[0] for line in result.splitlines()}
    expected = {name: hashlib.sha256((ROOT / "gamebond" / (name + ".py")).read_bytes()).hexdigest() for name in modules}
    assert hashes == expected, "deployed source hashes differ"
    assert info["State"]["Health"]["Status"] == "healthy"
    assert info["Config"]["Image"] == plan.get("image", "gamebond:" + plan["version"])
    assert not info["HostConfig"]["Privileged"] and info["HostConfig"]["ReadonlyRootfs"]
    assert info["HostConfig"]["NetworkMode"] == "gamebond_tunnel"
    evidence = dict(deployed=True, version=plan["version"], peer=host, session=plan["session"],
        health="healthy", source_hashes=hashes, local_tests_passed=args.tests,
        privileged=False, readonly=True, network="gamebond_tunnel", release=plan["release"])
    (ROOT / ("evidence/update-" + plan["version"] + ".json")).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(dict(verified=True, peer=host, version=plan["version"], health="healthy", matching_modules=len(hashes))))


if __name__ == "__main__":
    main()
