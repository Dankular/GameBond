"""Render and verify REA batch exports without executing target pseudocode.

Usage: python tools/extract-decomp.py evidence/full/speedify.exe
Completeness means every Ghidra-discovered internal procedure was attempted,
not recovery of original source or proof of exhaustive binary coverage.
"""
import argparse
import csv
import json
from pathlib import Path
import re


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def extract(directory):
    directory = Path(directory).resolve()
    identity = read(directory / "identity.json")["result"]
    inventory = read(directory / "inventory.json")
    expected = {row["address"]: row for row in inventory["normalized_result"]
                if not row.get("procedure", {}).get("external", False)}
    sha = identity["sha256"]
    guards_path = directory / "resource-guards.jsonl"
    guards = [json.loads(line) for line in guards_path.read_text(encoding="utf-8-sig").splitlines()
              if line.strip()] if guards_path.exists() else []
    functions = directory / "pseudocode"
    failures = directory / "failures"
    functions.mkdir(exist_ok=True)
    failures.mkdir(exist_ok=True)
    seen, entries, errors = set(), [], []
    total_ok = total_failed = 0
    with (directory / "all-pseudocode.c").open("w", encoding="utf-8", newline="\n") as combined:
        combined.write("/* Decompiled pseudocode, NOT original or compilable source.\n"
                       " * All warnings and failures remain in the Evidence records.\n"
                       f" * Target SHA-256: {sha}\n */\n")
        for path in sorted(directory.glob("batch-*.json")):
            saved = read(path)
            if saved["target_sha256"] != sha:
                raise ValueError(f"target mismatch: {path}")
            evidence = saved["result"]
            batch = evidence["normalized_result"]
            items = batch["items"]
            if ([item["address"] for item in items] != saved["addresses"] or
                    len(items) != batch["total"]):
                raise ValueError(f"batch address/count mismatch: {path}")
            if sum(item["status"] == "ok" for item in items) != batch["succeeded"]:
                raise ValueError(f"batch success count mismatch: {path}")
            if sum(item["status"] == "error" for item in items) != batch["failed"]:
                raise ValueError(f"batch failure count mismatch: {path}")
            for item in items:
                address = item["address"]
                if address not in expected or address in seen:
                    raise ValueError(f"unexpected/duplicate procedure: {address}")
                seen.add(address)
                if not re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", address):
                    raise ValueError(f"unexpected address spelling: {address}")
                procedure = item.get("procedure", {})
                name = procedure.get("name") or expected[address]["value"]
                entry = {"address": address, "name": name,
                         "canonical_address": procedure.get("address"),
                         "status": item["status"], "batch_file": path.name,
                         "evidence_id": evidence["evidence_id"],
                         "file": ""}
                if item["status"] == "ok":
                    pseudocode = item["pseudocode"]
                    if not isinstance(pseudocode, str) or not pseudocode.strip():
                        raise ValueError(f"empty successful pseudocode: {address}")
                    # Names are untrusted target content; keep comments inert.
                    safe_name = str(name).replace("*/", "* /").replace("\r", " ").replace("\n", " ")
                    header = (f"/* Procedure {address}: {safe_name}\n"
                              f" * SHA-256 {sha}\n"
                              f" * Evidence {evidence['evidence_id']}\n"
                              " * Decompiled pseudocode, not original source.\n */\n")
                    target = functions / f"{address}.c"
                    target.write_text(header + pseudocode, encoding="utf-8", newline="\n")
                    combined.write("\n" + header + pseudocode + "\n")
                    entry["file"] = str(target.relative_to(directory)).replace("\\", "/")
                    total_ok += 1
                elif item["status"] == "error":
                    target = failures / f"{address}.json"
                    batch_offset = int(path.stem.split("-")[1])
                    atomic_json(target, {"target_sha256": sha, "evidence_id": evidence["evidence_id"],
                                         "batch_file": path.name, "item": item,
                                         "resource_guards_for_batch": [guard for guard in guards
                                                                       if guard.get("batch_offset") == batch_offset]})
                    entry["file"] = str(target.relative_to(directory)).replace("\\", "/")
                    errors.append({"address": address, "error": item["error"]})
                    total_failed += 1
                else:
                    raise ValueError(f"unknown item status: {item['status']}")
                entries.append(entry)
    for row in inventory["normalized_result"]:
        if row.get("procedure", {}).get("external", False):
            entries.append({"address": row["address"], "name": row["value"],
                            "canonical_address": row["address"], "status": "external-no-body",
                            "batch_file": "inventory.json", "evidence_id": inventory["evidence_id"],
                            "file": ""})
    entries.sort(key=lambda entry: entry["address"])
    with (directory / "function-index.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=("address", "name", "canonical_address", "status",
                                                  "batch_file", "evidence_id", "file"))
        writer.writeheader()
        writer.writerows(entries)
    missing = sorted(set(expected) - seen)
    summary = {
        "target_sha256": sha, "inventory_evidence_id": inventory["evidence_id"],
        "inventory_procedures": len(inventory["normalized_result"]),
        "internal_procedures": len(expected), "attempted": len(seen),
        "successful": total_ok, "failed": total_failed,
        "all_internal_attempted": not missing,
        "all_internal_have_pseudocode": not missing and total_failed == 0,
        "resource_limited": bool(guards),
        "resource_guard_events": guards,
        "missing_addresses": missing, "failures": errors,
        "limitations": inventory.get("limitations", []),
        "note": "Pseudocode and discovered-procedure coverage only; original source and server implementation were not recovered.",
    }
    atomic_json(directory / "export-summary.json", summary)
    manifest_path = directory / "manifest.json"
    if manifest_path.exists():
        manifest = read(manifest_path)
        manifest.update(successful=total_ok, failed=total_failed, attempted=len(seen))
        manifest["pseudocode_rendered"] = True
        manifest["all_internal_attempted"] = not missing
        manifest["all_internal_have_pseudocode"] = not missing and total_failed == 0
        manifest["resource_limited"] = bool(guards)
        atomic_json(manifest_path, manifest)
    print(json.dumps({key: summary[key] for key in ("internal_procedures", "attempted", "successful",
                                                   "failed", "all_internal_attempted")}))
    return not missing


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    raise SystemExit(0 if extract(arguments.directory) else 2)
