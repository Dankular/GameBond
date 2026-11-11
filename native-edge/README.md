# GameBond native edge

The Go implementation of GameBond: Windows client and daemon (`cmd/client`),
Linux server edge (`cmd/edge`), desktop widget (`cmd/tray`), supervisor control
(`cmd/desktopctl`), admin tools and probes.

Includes the authenticated GB03 transport, path learning, replay protection,
reordering, pacing, TCP repair, priority queues, link policies, per-app capture
policy, LAN device gateways (several devices can share one adapter) and the
admin portal.

## Build and test

From the repository root with Go 1.25 or newer:

```sh
export GOFLAGS=-buildvcs=false
go -C native-edge test ./...
go -C native-edge vet ./...
GOOS=linux GOARCH=amd64 go -C native-edge build -o ../build/gamebond-native-edge-linux ./cmd/edge
go -C native-edge build -o ../build/gamebond-native-client.exe ./cmd/client
```

The edge needs `/dev/net/tun`; the container entrypoint (`tools/container-entrypoint.sh`)
handles addressing and NAT. Build the image with `docker compose build` at the root.

`testdata/*.json.gz` vectors were generated from the retired Python implementation
by the scripts in `testdata-gen/` (reference only; they need the old package from git history).
