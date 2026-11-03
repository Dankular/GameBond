# Channel bonding investigation

Read-only review, 2026-11-02. Target: installed Speedify daemon 17.2.1.13911, SHA-256 `0098d5e1a34025c5b623f719934d457d324215f4c90a5491d2c1af98c30cc4f8`. This maps emitted pseudocode to documented features, not recovered original source or measured runtime behavior. See [reconstruction limitations](reconstruction.md), especially Ghidra's incorrect nonreturning stack-cookie-helper assumption and unresolved virtual calls.

The user's intended result is packet-level aggregation within one session: for example, packets 1/3 travel over Starlink and 2/4 over 5G, with adaptive proportions and one VPS exit. It must support a single transfer using both links. This is also the behavior described in Speedify's official [channel bonding documentation](https://speedify.com/features/channel-bonding/) and [Speed mode description](https://support.speedify.com/article/1001-speed-bonding-mode). Documentation establishes the vendor's contract; the incomplete static trace below does not independently prove every end-to-end detail. Aggregate useful throughput aims toward the sum of usable link capacities after overhead and other bottlenecks, rather than a guaranteed sum of advertised ISP rates.

REA MCP imported and validated the prior bundle (25 records) and full export (623 records). The full records remain available locally. MCP `inspect_analysis_view` does not support the legacy `procedure_pseudo_code` and `batch_decompile` record operations; those bodies were inspected from the retained export. No live native session, network changes, server restart, or client changes were needed.

## SDK documentation mapping

Source: [Speedify SDK release notes](https://speedify.github.io/speedify-sdk-docs/desktop/whatsnew.html#whatsnew_1721), retrieved 2026-11-02.

| Documentation | Matching binary evidence | Boundary |
| --- | --- | --- |
| 17.2.1 extends the TCP CCA enum; non-auto/system choices require a registered kernel algorithm. | `0x1402eb7b2` registers `set_tcp_cca` with handler `0x1402f4e00`. The handler reads `tcp_cca`, identifies `set_tcp_cca_cb`, and dispatches selector `0x193`. `0x1403521b8` parses the setting with `0x14038b0a8`; the parser recognizes multiple algorithm values, including literal cubic, hybla, illinois, vegas and westwood. `0x14038b21a` maps enum to a name table. `0x14038b40b` reads persisted configuration and calls `0x14038b26f`, which has platform-specific unavailable-algorithm branches. | This Windows build's pseudocode does not establish that every documented Linux kernel algorithm can be selected on Windows. It also does not prove which choice is active. No comparison binary was supplied to prove these functions were introduced in 17.2.1. |
| 16.5 exposes bondingFiltered / poorConnection; 16.9 adds slowConnection. | `0x14035f5d4` explicitly marks/unmarks bonding-filtered connections. `0x14043b350` starts a filtering timer and `0x14043b460` accumulates time spent filtered. | This establishes filtering and timing state, not a complete field-to-JSON trace for all three SDK fields. |

TCP CCA parser/name-table/setter batch Evidence: `ev_e507f36766f0c571f5d6f6201a6013a0ccc43b244415a9691939ae9105abb60f`; persisted-setting reader: `ev_525245bbc7faa8311eca60c8f89461ccfb455c8f36307ef584a325debe066a76`. Exact additional batch IDs are in each function file header and [function-index.csv](../evidence/full/speedify.exe/function-index.csv).

Registration Evidence: `ev_4a3f22b92e7aa955790d007e06ea53ebc24dcc700714b9461cf8f7ce8f236f91`; API handler: `ev_34053408a8b07f5349c2ec24125e9f6451a7724b463a1243c865d9bb6f13a46b`; dispatcher and settings reporting: `ev_7d296d2365ed7997f9a67b1fd79c3a111a92208e3ca2d4e59ed685873b0d3f82`. The reporting switch `0x14034f7b2`, case `0x193`, names the public field `tcpCca`.

## Concrete bonding decisions

`0x14035e286` checks candidate eligibility, sums weights obtained from `0x14035e0f6`, generates a normalized random value, and subtracts each eligible candidate's share of the total until a candidate is selected. `0x14035e0f6` uses bandwidth-like virtual getters and reduces a candidate's weight under an excess-latency condition. Both have Evidence `ev_ded286fcec910e5260f47131554419caff53a14043c3f5b6c3ed5c4a8f244cf8`. This supports capacity/latency-weighted selection, rather than assuming equal round robin. Its complete return tail and the selected runtime policy require further resolution; this function alone does not prove how every packet of one flow is striped.

`0x14035f5d4`, in the recovered `connectionchooser.cc` region, iterates candidate connections and calls `0x14035feb0` for a transfer-time-like score. It compares scores against a threshold derived from the lowest score, applies a 0.9 threshold factor for already-filtered candidates, compares bandwidth-like quantities (including an 8.5 ratio), and removes filtered candidates from the working list. It clears filtering when only one candidate remains and has an all-filtered fallback that resets candidates to unfiltered. These are observed branches; exact virtual getter types and operational units remain partly inferred.

`0x14035feb0` combines a latency-like term divided by 1000 with `packet_bytes / (bandwidth_like_value * 1,000,000 * 0.125)`. This is consistent with estimated transfer completion time (delay plus serialization), rather than selecting solely on RTT. Some branches penalize degraded conditions. Both functions have batch Evidence `ev_d571ae777e00b63ea5778ed1a54ad79939517d5ea07a73cf8fb2b8c04a165e0a`.

Filtering timers: `0x14043b350`, Evidence `ev_55675574adfb03e22a734959f6d6be5ebaea46f09772c9b715d0905aa795254d`; `0x14043b460`, Evidence `ev_654b82d999dcbe967882e9f8811976caf5817f908e3a040cbf0599c09e3711cb`.

The internal `bbrcongestioncontrol.cc` region contains state transitions in `0x140514e7a` with STARTUP, DRAIN, bandwidth-probe and RTT-probe paths. Related routines `0x140514c50` and `0x140514d8a` update window/rate-like fields from measured values and gains. Their batch Evidence is `ev_02f895e1abb2fa1c38ea0513f5066d727cd118e6797ce5ee985aec1859feae67`. This is evidence of an internal adaptive controller, separate from the SDK's kernel TCP CCA selection. It does not establish BBR1/2/3 equivalence or which runtime transport uses it in every configuration.

## What GameBond needs

The current `Node.send` keeps nonreplicated flows on one healthy path, initially selected by smoothed RTT. It has no measured delivery-rate/in-flight model and no packet striping within one bulk flow. Its global bulk pacer is configured to 2 Mbps in the current client configuration. Consequently, the current build cannot demonstrate single-flow aggregated throughput.

Proposed work, separate from observed Speedify behavior:

1. Add authenticated per-path delivery feedback: bytes delivered, elapsed time, RTT samples, loss, in-flight bytes, and delivery gaps. Maintain separate upstream/downstream estimates.
2. Introduce per-path pacing and in-flight budgets. Start conservatively, probe capacity, and reduce bulk load when queue delay rises. Replace the fixed bulk ceiling only after these controls are validated.
3. Schedule bulk packets across eligible links using estimated arrival time and available budget. Retain immediate selective duplication for gameplay. Add flow fairness so a download cannot monopolize the sender.
4. Add per-flow sequence numbers and a bounded receiver reorder policy for striped bulk traffic. Do not make gameplay wait behind a bulk-flow gap. Assess selective recovery against deadlines and sender-cache limits.
5. Filter degraded paths with hysteresis and continue probing them for recovery. A responding probe alone should not make a path eligible for a large share of bulk traffic.

Validation must compare each physical link alone against both together, separately for single-stream and parallel-stream throughput, in both directions. Record useful payload throughput, per-path wire bytes, reorder depth, loss, RTT percentiles, queue residence, and gameplay delivery gaps under concurrent downloads. No sum-of-link-speeds claim is justified until measured; the VPS, game/download server, transport overhead and path asymmetry can constrain results.

See [loss recovery, reordering and MTU evidence](analysis-recovery.md) for concrete sequence-range recovery and reordering branches. That review also corrects the earlier mistaken attribution of `0x14045e15c` to direct retransmission: it is a queue failover-credit wrapper. FEC remains unresolved.
