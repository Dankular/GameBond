"""Repeatable through-the-tunnel throughput benchmark; one labelled record per run.

Run the same command before and after a change (for example Python server ->
Go server) and compare the records in evidence/benchmark-*.json. It measures
what an application sees: single-stream and parallel HTTPS downloads from a
fixed public file, while sampling the VPS container's CPU and snapshotting the
client's own status. It does not generate traffic outside the tunnel, so the
client must be running with capture covering curl.

    python tools/benchmark_tunnel.py --label python-baseline --impl python
    python tools/benchmark_tunnel.py --compare python-baseline go-edge

Scope: one remote file host and one client at one moment. Remote-host speed,
time of day and the physical link all move these numbers; use the recorded
spread (repeated runs) and compare only runs taken under similar conditions.
"""
import argparse
import json
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
URL = "https://proof.ovh.net/files/1Gb.dat"
HOST = "195.154.119.136"
PLINK = "C:/Program Files (x86)/PuTTY/plink.exe"
KEY = str(Path.home() / "Desktop/privkey.ppk")
STATUS = ROOT / ".runtime/userspace-status.json"


def ssh(command, timeout=30):
    result = subprocess.run([PLINK, "-batch", "-T", "-i", KEY, "root@" + HOST, command],
                            capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()


def download(seconds, url):
    """Return (bytes, elapsed seconds) for one curl, stopped at `seconds`."""
    start = time.perf_counter()
    out = subprocess.run(["curl", "-s", "-A", "Mozilla/5.0", "-o", "NUL" if sys.platform == "win32" else "/dev/null",
                          "-m", str(seconds), "-w", "%{size_download}", url],
                         capture_output=True, text=True).stdout.strip()
    return int(out or 0), time.perf_counter() - start


def single(seconds, url):
    size, elapsed = download(seconds, url)
    return size * 8 / elapsed / 1e6


def parallel(streams, seconds, url):
    results = []
    threads = [threading.Thread(target=lambda: results.append(download(seconds, url))) for _ in range(streams)]
    start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - start
    return sum(size for size, _ in results) * 8 / wall / 1e6


def client_snapshot():
    try:
        status = json.loads(STATUS.read_text())
        paths = status["transport"]["paths"]
        return dict(state=status.get("state"), healthy_paths=sum(bool(p["healthy"]) for p in paths),
                    paths=[dict(rtt_ms=p["rtt_ms"], rtt_jitter_ms=p["rtt_jitter_ms"],
                                budget_mbps=p["bonding"]["rate_mbps"], delivery_mbps=p["bonding"]["delivery_rate_mbps"])
                           for p in paths], reorder_gap_events=status["transport"]["reorder"]["gap_events"])
    except (OSError, KeyError, ValueError) as error:
        return dict(unavailable=str(error))


def server_info():
    image = ssh("docker inspect --format '{{.Config.Image}} {{index .Config.Labels \"gamebond.git_revision\"}}' gamebond-server-1")
    return dict(container_image=image.split()[0] if image else None,
                git_revision=image.split()[1] if len(image.split()) > 1 else None,
                cores=ssh("nproc"))


def sample_cpu(stop, samples):
    # One persistent SSH session sampling docker stats; far cheaper than one login per sample.
    proc = subprocess.Popen([PLINK, "-batch", "-T", "-i", KEY, "root@" + HOST,
                             "while true; do docker stats --no-stream --format '{{.CPUPerc}}' gamebond-server-1; done"],
                            stdout=subprocess.PIPE, text=True)
    def reader():
        for line in proc.stdout:
            try:
                samples.append(float(line.strip().rstrip("%")))
            except ValueError:
                pass
    t = threading.Thread(target=reader, daemon=True)
    t.start()
    stop.wait()
    proc.kill()


def summarize(values):
    return dict(runs=[round(v, 2) for v in values], median=round(statistics.median(values), 2),
                best=round(max(values), 2), worst=round(min(values), 2)) if values else None


def run(args):
    record = dict(label=args.label, implementation=args.impl, notes=args.notes,
                  recorded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), url=args.url,
                  seconds_per_run=args.seconds, server=server_info(), client_before=client_snapshot())
    stop, cpu = threading.Event(), []
    sampler = threading.Thread(target=sample_cpu, args=(stop, cpu), daemon=True)
    sampler.start()
    time.sleep(1)
    single_runs, parallel_runs = [], []
    for index in range(args.repeats):
        single_runs.append(single(args.seconds, args.url))
        print(f"single {index + 1}/{args.repeats}: {single_runs[-1]:.2f} Mbps", flush=True)
    for index in range(args.repeats):
        parallel_runs.append(parallel(args.streams, args.seconds, args.url))
        print(f"{args.streams} streams {index + 1}/{args.repeats}: {parallel_runs[-1]:.2f} Mbps aggregate", flush=True)
    stop.set()
    time.sleep(.5)
    record.update(single_stream_mbps=summarize(single_runs),
                  parallel_streams=args.streams, parallel_aggregate_mbps=summarize(parallel_runs),
                  server_cpu_percent=dict(samples=len(cpu), mean=round(statistics.mean(cpu), 1) if cpu else None,
                                          max=max(cpu) if cpu else None),
                  client_after=client_snapshot())
    path = ROOT / "evidence" / f"benchmark-{args.label}.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: record[k] for k in ("single_stream_mbps", "parallel_aggregate_mbps", "server_cpu_percent")}, indent=2))
    print("wrote", path)


def compare(a, b):
    rows = []
    for label in (a, b):
        rows.append(json.loads((ROOT / "evidence" / f"benchmark-{label}.json").read_text()))
    def med(r, key):
        return (r.get(key) or {}).get("median")
    print(f"{'':28}{rows[0]['label']:>22}{rows[1]['label']:>22}{'ratio':>9}")
    for key, name in (("single_stream_mbps", "single stream (Mbps, median)"),
                      ("parallel_aggregate_mbps", "parallel aggregate (Mbps, median)")):
        x, y = med(rows[0], key), med(rows[1], key)
        print(f"{name:28}{x:>22}{y:>22}{(y / x if x else float('nan')):>9.2f}x")
    x, y = rows[0]["server_cpu_percent"]["mean"], rows[1]["server_cpu_percent"]["mean"]
    print(f"{'server CPU % (mean)':28}{x:>22}{y:>22}")
    print("implementations:", rows[0]["implementation"], "->", rows[1]["implementation"])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--label")
    parser.add_argument("--impl", choices=("python", "go"), help="server data-path implementation under test")
    parser.add_argument("--notes", default="")
    parser.add_argument("--url", default=URL)
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--streams", type=int, default=4)
    parser.add_argument("--compare", nargs=2, metavar=("A", "B"))
    args = parser.parse_args()
    if args.compare:
        compare(*args.compare)
    elif args.label and args.impl:
        run(args)
    else:
        parser.error("--label and --impl are required (or use --compare A B)")


if __name__ == "__main__":
    main()
