# Network Benchmark Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standard-library Go CLI for recording and comparing device capability benchmarks and capturing repeatable GameBond tunnel benchmark results.

**Architecture:** Add an isolated Go module under `GameBond.Client/tools/benchmarking`. A reusable package will validate benchmark records and serialize reports; the CLI will provide `device`, `specs`, and `gamebond` commands. Device mode will guide and record externally measured lab results without configuring hardware; specs mode will compare submitted vendor figures; GameBond mode will import results emitted by the existing tunnel speed test and preserve measurement scope.

**Tech Stack:** Go 1.26 standard library only; JSON and Markdown output.

**Spec:** [../specs/2026-11-13-network-benchmark-suite-design.md](../specs/2026-11-13-network-benchmark-suite-design.md)

## Global Constraints

- The suite will live under `GameBond.Client/tools/benchmarking/` and expose three independent modes.
- Reports will distinguish `measured` from `vendor_reported` values.
- Device mode will not configure or mutate the device.
- Physical device tests are intended for an isolated lab.
- No benchmark runs implicitly.
- GameBond throughput reports distinguish useful delivered payload from wire traffic.
- The suite will use no external Go dependencies.

## Review Focus

- Missing, malformed, or negative benchmark values must fail validation with a field-specific error.
- Different units or test conditions must not be silently compared as equivalent.
- Device benchmark names must be restricted to the nine supported capability categories.
- Report file creation must not overwrite an existing result unless the user explicitly requests it.
- GameBond results without useful-payload and wire-byte values must be labeled incomplete, not presented as a complete throughput comparison.

---

### Task 1: Shared report model and validation

**Files:**
- Create: `GameBond.Client/tools/benchmarking/go.mod`
- Create: `GameBond.Client/tools/benchmarking/report/report.go`
- Create: `GameBond.Client/tools/benchmarking/report/replace_unix.go`
- Create: `GameBond.Client/tools/benchmarking/report/replace_windows.go`

**Interfaces:**
- Produces package `gamebond.local/benchmarking/report` with `Run`, `Result`, and `Condition` structs and `Validate(Run) error`.
- `Result` contains benchmark key, display name, method, numeric value, unit, conditions, and optional note.
- `Run` contains schema version, timestamp, target, mode, results, warnings, and prerequisites.

- [ ] Define JSON-stable structs using `time.Time` timestamps and explicit JSON tags.
- [ ] Define the exact benchmark keys for the nine device capabilities and reject unknown keys.
- [ ] Validate required identifiers, supported modes/methods, finite numeric values, units, and conditions.
- [ ] Add `WriteJSON(path string, run Run, force bool) error` using a temporary file and atomic rename; refuse an existing path when `force` is false.
- [ ] Implement JSON read/write error messages with the path and field context.

### Task 2: Device mode and lab procedure output

**Files:**
- Create: `GameBond.Client/tools/benchmarking/device/catalog.go`
- Create: `GameBond.Client/tools/benchmarking/cmd/device.go`

**Interfaces:**
- Consumes `report` from Task 1.
- Produces `ListBenchmarks() []Benchmark`, `Guide(key string) (string, error)`, `Assess(Setup) (Assessment, error)`, and `ValidateRun(report.Run) error`.
- Each `Benchmark` provides key, name, measurement unit, required conditions, lab prerequisites, and interpretation notes.

- [ ] Encode the nine categories: switching capacity, total non-blocking throughput, forwarding rate, supported VLANs, MAC address table size, IPv4 static routes, packet buffer size, multi-WAN load balancing, and DPI/traffic identification.
- [ ] For each category, document valid measurement inputs and the evidence needed to mark the value as measured; preserve vendor-reported values as a separate method.
- [ ] Implement `device list`, `device guide <key>`, `device assess --input <setup.json> --output <assessment.json>`, and `device record --input <json> --output <json>`; assessment reports per-capability ready/skipped prerequisites, and record validates without applying config or launching traffic.
- [ ] Include offered load, packet size, direction, test endpoints, loss/latency, and identification outcome fields where relevant.
- [ ] Ensure missing test prerequisites are surfaced as warnings and prevent claiming a measured result.

### Task 3: Specification comparison mode

**Files:**
- Create: `GameBond.Client/tools/benchmarking/specs/compare.go`
- Create: `GameBond.Client/tools/benchmarking/cmd/specs.go`

**Interfaces:**
- Consumes `report.Run` records from Task 1.
- Produces `Compare([]report.Run) (Comparison, error)` where each `Comparison` row retains device, benchmark, value, unit, method, and comparability status.

- [ ] Read multiple JSON records supplied by the user and validate every record before comparison.
- [ ] Compare only results with matching benchmark key, unit, method, and compatible conditions; report comparability and reasons independently for each benchmark.
- [ ] Emit readable Markdown and optional JSON comparison output.
- [ ] Keep vendor-reported and measured values visibly distinct and avoid generating an overall score.

### Task 4: GameBond mode and existing speed-test result adapter

**Files:**
- Create: `GameBond.Client/tools/benchmarking/gamebond/adapter.go`
- Create: `GameBond.Client/tools/benchmarking/cmd/gamebond.go`
- Modify: `GameBond.Client/native-edge/cmd/client/netprobes.go` only if the existing result schema lacks fields required for useful payload versus wire bytes.

**Interfaces:**
- Consumes the existing `speedtest_result` JSON event emitted by the netstack helper and maps it to a `report.Run`.
- Produces `FromSpeedTest(raw []byte, target string) (report.Run, error)`.
- GameBond result conditions include direction, stream count, duration, server, and tested endpoint/path note.

- [ ] Inspect the emitted result fields and retain the timestamp, server, stream count, latency, jitter, upload/download rates, and bytes.
- [ ] Represent useful payload bytes and wire bytes independently; if the existing probe does not provide both, label the relevant measurement incomplete and do not fabricate a wire-byte value.
- [ ] Implement `gamebond import --input <json> --output <json>` and a Markdown summary for repeated runs.
- [ ] State in output that the result applies to the measured endpoint and path.

### Task 5: CLI integration and operator documentation

**Files:**
- Create: `GameBond.Client/tools/benchmarking/main.go`
- Create: `GameBond.Client/tools/benchmarking/README.md`

- [ ] Add top-level help and subcommands `device`, `specs`, and `gamebond`; invalid invocations return nonzero status and usage text.
- [ ] Ensure every command is read-only with respect to benchmark targets and requires explicit input/output paths.
- [ ] Document module invocation, JSON schema examples, all nine device benchmark guides, report interpretation, and isolated-lab prerequisites.
- [ ] Document that device mode records supplied evidence and does not generate traffic or change switch/router configuration.
- [ ] Build the CLI with `go build ./...` from the module directory and manually inspect help and sample report output.
- [ ] Preserve no-overwrite behavior by default; document that forced replacement uses a non-atomic remove-and-rename on Windows.

## Coverage map

- Report schema and separation of evidence methods: Tasks 1 and 3.
- Nine device capability categories, inputs, units, and prerequisites: Task 2.
- Useful payload versus wire bytes and path-scoped claims: Task 4.
- Independent commands, read-only operation, output formats, and operator instructions: Task 5.
