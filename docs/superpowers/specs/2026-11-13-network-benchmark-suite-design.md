# Network Benchmark Suite Design

## Goal

Provide repeatable utilities for measuring physical switch/router capabilities, comparing advertised device specifications, and measuring GameBond tunnel performance. Results must identify whether each value is measured or vendor-reported and preserve enough test context to interpret comparisons.

## Scope

The suite will live under `GameBond.Client/tools/benchmarking/` and expose three independent modes:

- **Device mode:** lab-oriented measurements for switching capacity, total non-blocking throughput, forwarding rate, supported VLAN scale, MAC address table size, IPv4 static route scale, packet-buffer behavior, multi-WAN load balancing, and DPI/traffic-identification performance.
- **Specs mode:** import and compare vendor-reported values using a documented JSON format. It will not present advertised specifications as measured results.
- **GameBond mode:** run or collect repeatable tunnel performance measurements, distinguishing unique delivered payload from wire traffic and recording direction, stream count, duration, endpoints, and relevant network conditions.

## Device test contract

Device mode will describe required topology, endpoints, traffic profile, prerequisites, and measurement limits for each benchmark. It will not configure or mutate the device. Tests that require traffic generation, extra hosts, multiple WANs, or preconfigured VLANs/routes must report missing prerequisites and avoid claiming a result. Packet-buffer behavior, load balancing, and DPI results must include the offered load and observed loss/latency or identification outcomes; a single throughput number is insufficient for those tests.

Capabilities such as VLAN support, MAC table capacity, and route scale may be established by controlled scale tests or recorded as vendor specifications. Reports must identify which method produced each value. Switching capacity, forwarding rate, and non-blocking throughput must include packet size, directionality, port/link rates, and offered load so results are comparable.

## Reports

Each run will produce machine-readable JSON and a concise human-readable summary. The report schema will include suite/version, timestamp, target identity, mode, benchmark name, method (`measured` or `vendor_reported`), units, setup, conditions, result, warnings, and skipped/missing prerequisites. Comparing devices must keep incompatible test conditions visible rather than imply a normalized ranking.

## Safety and limits

Physical device tests are intended for an isolated lab. No test may automatically change device configuration, generate traffic without an explicit invocation, or claim hardware capability from a software-only simulation. GameBond results describe the tested endpoints and path; they are not guarantees of ISP capacity or gameplay quality.

## Acceptance criteria

1. Users can invoke each of the three modes independently and receive clear usage and prerequisite guidance.
2. The nine requested device capability categories are represented with defined measurement inputs and output units or an explicit reason a value cannot be measured by the selected setup.
3. Vendor-reported and directly measured values remain distinguishable in reports and comparisons.
4. Reports are reproducible enough to compare runs, including topology/test conditions and warnings.
5. GameBond throughput reports distinguish useful delivered payload from wire bytes and include direction and stream count.
6. The tools never configure the target device or run a benchmark implicitly.
