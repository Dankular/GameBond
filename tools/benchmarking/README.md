# GameBond network benchmarking utilities

This standalone Go CLI records capability evidence from an isolated switch/router lab, compares device reports, and converts GameBond's existing tunnel speed-test result into a portable report. It uses only the Go standard library.

Build and invoke from this directory:

```sh
go build -o benchmark .
./benchmark --help
```

`go run . --help` is also available without creating a binary.

## Device lab guides

```sh
./benchmark device list
./benchmark device guide switching_capacity
./benchmark device guide total_non_blocking_throughput
./benchmark device guide forwarding_rate
./benchmark device guide supported_vlans
./benchmark device guide mac_address_table_size
./benchmark device guide ipv4_static_routes
./benchmark device guide packet_buffer_size
./benchmark device guide multi_wan_load_balancing
./benchmark device guide dpi_traffic_identification
```

Assess the lab setup against all nine benchmark prerequisites:

```sh
./benchmark device assess --input lab-setup.json --output lab-assessment.json
```

The input lists the exact prerequisite strings printed by `device guide`:

```json
{
  "target": "lab-router-01",
  "available_prerequisites": [
    "traffic generator at every tested port",
    "isolated test topology"
  ]
}
```

The output marks each capability `ready` or `skipped` and lists missing prerequisites and required measurement conditions. `ready` means the declared setup prerequisites are present; it does not mean a measurement was run. External traffic generators and device configuration remain operator-controlled.

Guides specify the needed traffic generator, preconfigured topology, measurement conditions, and interpretation limits. Device mode does not configure a device or generate traffic. VLAN, MAC, route, buffer, multi-WAN, and DPI measurements require an isolated lab and suitable fixtures. If the fixture is unavailable, record a vendor-reported value and cite the source in the result note instead of claiming a direct measurement.

To validate and save an observed run, create a JSON file such as:

```json
{
  "schema_version": 1,
  "timestamp": "2026-11-13T12:00:00Z",
  "target": "lab-router-01",
  "mode": "device",
  "results": [
    {
      "key": "forwarding_rate",
      "name": "Forwarding rate",
      "method": "measured",
      "value": 148.8,
      "unit": "Mpps",
      "conditions": [
        {"name": "packet_size", "value": "64-byte Ethernet frames"},
        {"name": "port_count", "value": "8"},
        {"name": "traffic_direction", "value": "full duplex"},
        {"name": "offered_rate", "value": "line rate"},
        {"name": "loss_threshold", "value": "0.01%"}
      ],
      "note": "Attach traffic-generator run ID and port map here."
    }
  ],
  "warnings": [],
  "prerequisites": [
    "traffic generator at every tested port",
    "packet-capable traffic generator",
    "isolated test topology"
  ]
}
```

Save/validate it with `./benchmark device record --input lab-run.json --output lab-run-report.json`. Existing files are preserved; use `--force` only when intentionally replacing a report.

## Compare specifications or measurements

```sh
./benchmark specs compare --input router-a.json --input router-b.json
./benchmark specs compare --input router-a.json --input router-b.json --format json
```

Comparisons retain each result's `measured` or `vendor_reported` method. Each benchmark group is assessed separately and marked not directly comparable when devices are missing a result or units, conditions, or methods differ. No combined score is calculated. Matching conditions do not guarantee that vendors used the same methodology; review the cited notes and source documents.

## Import a GameBond speed-test result

The client stores the last successful speed test as `speedtest-last.json` next to its status files. Convert that file with:

```sh
./benchmark gamebond import --input speedtest-last.json --output gamebond-run.json --target "two-uplink tunnel"
```

The report includes upload/download payload rates and byte counts, streams, server, latency, and jitter. It explicitly leaves wire-byte counts unavailable because the current speed-test result does not contain per-link or tunnel wire counters. Results describe the tested server and network path and are not estimates of general ISP capacity.

## Report format

Every report is JSON with schema version, timestamp, target, mode, result values and units, evidence method, conditions, warnings, and prerequisites. Measured device results must use the unit and condition keys shown in their guide and list every required lab prerequisite. Vendor-reported results must identify their source in `note`. Device keys are `switching_capacity`, `total_non_blocking_throughput`, `forwarding_rate`, `supported_vlans`, `mac_address_table_size`, `ipv4_static_routes`, `packet_buffer_size`, `multi_wan_load_balancing`, and `dpi_traffic_identification`.

On Windows, `--force` removes the existing destination before replacing it, so forced replacement is not atomic. Without `--force`, existing output files are never overwritten.
