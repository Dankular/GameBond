# QoS review against current 0.3.4 source

Reviewed 2026-11-02. The earlier scheduling proposals describe an older
GameBond implementation. Current source already includes authenticated bulk
feedback, adaptive per-path budgets, packet striping, bounded bulk reordering,
immediate replicated gameplay and accounting for priority/control wire bytes.
These are implementation observations, not new physical performance results.

Remaining priorities:

1. **Bulk flow isolation and byte fairness.** `PriorityScheduler` still uses
   one FIFO per service class. A large download can queue ahead of sparse
   nonpriority traffic. Add bounded per-flow bulk queues and byte-deficit
   scheduling. Preserve FIFO within each flow and direct gameplay sends.
   The retained multiflow routine `0x14045c566`, Evidence
   `ev_5b5af77d3d24bb0fdfaf67238f0472b2a6a1a7e146d97ad08e4e92a1f76a340a`,
   supports deficit-style service; original types and whole-system fairness
   remain unresolved. Validate small-flow latency against a saturated download,
   unequal packet sizes, flow churn, expiry and memory bounds.
2. **Persistent queue-delay control.** `PathBudget` collects delay samples and
   suppresses growth, but only corroborated loss/window pressure reduces rate;
   `delay_backoffs` is never incremented. This deliberately protects sparse
   radio traffic from rate collapse, but leaves delay-only congestion untreated.
   Develop an opt-in controller with sustained-backlog evidence, baseline aging
   and recovery hysteresis. Test both a lossless bottleneck FIFO and propagation
   delay changes; retain sparse/jitter/held-feedback regression coverage.
   Retained routine `0x1405230dc`, Evidence
   `ev_ce6883ba52a4cf05587680e5a7180d3efe91473a1ba8a0e706024e307cb6b47c`,
   contains persistent dropping state and interval/sqrt(count) mechanics.
   It supports a CoDel-style inference, not recovered parameter defaults.
3. **End-to-end packet age.** Scheduler expiry applies before dequeue. Later
   optional global pacing and transport budget waits do not consume one shared
   packet deadline. Carry an absolute deadline through these waits and expose
   separate post-dequeue expiry counters. Test pacing plus queue residence
   together and ensure expired packets never reach the socket.

Implement flow isolation and common deadlines before adding active queue
management. Compare game delivery gaps, queue residence tails, useful bulk
throughput and per-path wire load under concurrent downloads in both directions.
Do not infer physical improvement from the retained daemon or loopback tests.

Startup repair during this review: current Windows enumeration maps
`192.168.1.93` to index 25 and `172.20.10.2` to index 16. Updated the private
client profile from stale indices 21/57. Both IP_UNICAST_IF plus local bind
checks passed without sending traffic or configuring routes. Transport now
reports the source/index and recovery command on pinning failures; 19 transport
tests passed. Speedify also had an active adapter/default route at inspection;
the full GameBond tunnel was not restarted.
