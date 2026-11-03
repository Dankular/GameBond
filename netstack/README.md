# Driver-free netstack smoke test

This Go module uses WireGuard's `tun/netstack` adapter around gVisor. Two
in-memory IP devices exchange TCP and UDP without opening a host network
adapter, changing routes, running GameBond, or installing ProxiFyre.

From this directory, in an ordinary PowerShell terminal:

```powershell
$env:GOCACHE = Join-Path (Resolve-Path ..).Path '.runtime/go-build'
go build -buildvcs=false -o ../build/netstack-smoke.exe .
../build/netstack-smoke.exe
```

Dependencies are pinned in `go.mod` and `go.sum`. Build-time dependency
downloads may use the network; the executable itself uses only in-memory
devices. The harness has a 45-second process timeout and verifies a 45,056-byte
TCP echo plus 100 UDP echoes with 1,252-byte payloads (1,280-byte IPv4 packets).
The default smoke mode is short-lived; its in-memory device pumps live until
process exit. `--proxy-stdio` is the separate persistent runtime mode.

The first successful Windows run is recorded in
`../evidence/netstack-smoke.json`. HTTPS checks passed before and after execution;
IPv4 route and adapter snapshots were unchanged. This does not establish
continuous connectivity, physical-link performance, GameBond protocol
integration, or CoD/ProxiFyre compatibility.

## End-to-end transport and capture tests

From the project root, after building:

```powershell
python tools/test_netstack_e2e.py
python tools/test_netstack_e2e.py --capture
```

The first test exchanges netstack packets through fresh encrypted GameBond
client/server sessions with two real loopback UDP paths. TCP must stripe across
both paths; UDP port 8081 is classified as replicated gameplay. At UDP packet
51, one path is synthetically blackholed in both directions. All 100 echoed
datagrams must retain their payloads, and deduplication must be exercised.

The capture test additionally stages the already-installed ProxiFyre runtime
from `C:/Program Files/ProxiFyre` into `.runtime/proxifyre-e2e`. It requires an
already installed and accessible Windows Packet Filter driver; it does not
install or start the Windows service. Its only application rule selects the
generated `gamebond-capture-probe.exe`. That probe uses ordinary Windows sockets
without proxy configuration. ProxiFyre runs with `--allow-not-admin`; a loopback
SOCKS5 listener forwards only to the two private in-memory echo ports. This
listener is test code, not a general-purpose or production proxy.

Capture runs need working HTTPS connectivity, a stopped ProxiFyre service and
no other ProxiFyre process. Check these before invoking the harness. A concurrent
HTTPS watchdog stops the test-owned ProxiFyre process if connectivity fails.
The harness bounds the child lifetime and terminates its own processes at exit.
Route and adapter snapshots plus HTTPS checks should also be taken before and
after capture; the recorded run's checks are in
`../evidence/netstack-capture-network-check.json`.

Evidence: `../evidence/netstack-e2e.json` and
`../evidence/netstack-capture-e2e.json`. These tests cover the local capture,
stack and encrypted transport chain. They do not test the physical 5G/Starlink
links, production VPS routing/NAT, or actual CoD capture/anti-cheat compatibility.

Upstream references:
- https://github.com/WireGuard/wireguard-go/tree/master/tun/netstack
- https://gvisor.dev/docs/architecture_guide/networking/
