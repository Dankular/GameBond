# Native GB03 edge

An experimental Go server packet path. Linux TUN integration and isolated VPS
HTTPS/UDP egress have passed. Production readiness and useful physical
aggregation gains remain unproven.

Implemented: authenticated GB03 transport, path learning, replay protection,
reordering, pacing, TCP repair, priority queues, and link policies.
Bidirectional socket tests verify interoperability with the Python transport.

## Build and test

From the repository root with Go 1.25 or newer:

```sh
go -C native-edge test ./...
go -C native-edge vet ./...
go -C native-edge build -o ../build/gamebond-native-receiver-probe ./cmd/receiver-probe
```

The Linux daemon is in `cmd/edge`. Build it on Linux, or cross-compile with
`GOOS=linux` and `GOARCH=amd64`. It requires `/dev/net/tun` and matching
configuration; the container entrypoint manages address assignment and NAT.

`cmd/receiver-probe` is a short-lived loopback harness. Windows interoperability
tools expect the binary at `build/gamebond-native-receiver-probe.exe`:

```powershell
python tools/check_native_receiver.py
python tools/check_native_receiver.py --bonded
python tools/check_native_receiver.py --bonded --repair --policies
```

Remaining work includes production application-profile/adaptive-redundancy and
fallback integration, lifecycle/metrics validation, and physical performance
comparisons. See [current status](../docs/local-status.md).
