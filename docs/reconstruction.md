# Reconstruction ledger

The user selected `C:\Program Files (x86)\Speedify`. The primary networking target is `speedify.exe`, version 17.2.1.13911, x86-64 PE, SHA-256 `0098d5e1a34025c5b623f719934d457d324215f4c90a5491d2c1af98c30cc4f8`.

The installed-file inventory is [installed-files.json](../evidence/installed-files.json). REA MCP `open_binary` independently confirmed this daemon identity. The earlier matching evidence bundle was imported through REA MCP (25 records) and retained as [prior-evidence.json](../evidence/prior-evidence.json). Static observations do not establish observed execution, original names/types, measured failover, or working server compatibility.

## Full daemon export result

All **19,886 Ghidra-discovered internal procedures were attempted**. **19,882 produced pseudocode; four failed explicitly.** The inventory contains 20,283 procedures, including 397 external imports without local bodies. The export finished at 2026-11-02 02:44:39 UTC. The native session closed cleanly and its resource watchdog exited.

| Artifact | Result |
| --- | --- |
| [export-summary.json](../evidence/full/speedify.exe/export-summary.json) | Verified internal-address coverage, successes, failures and resource guard records. No missing internal addresses. |
| [function-index.csv](../evidence/full/speedify.exe/function-index.csv) | 20,283 rows, including external imports; function names, addresses, status, batch Evidence IDs and file paths. |
| [inventory.json](../evidence/full/speedify.exe/inventory.json) | Complete discovered procedure inventory; Evidence `ev_f505ac13876c09ac191413c7e350f79a5b1fb2a28894f85ee4f02d2700dbbcc1`. |
| [all-pseudocode.c](../evidence/full/speedify.exe/all-pseudocode.c) | 43,090,312 bytes of combined C-like pseudocode. Not original or compilable source. |
| [pseudocode](../evidence/full/speedify.exe/pseudocode) | 19,882 individual pseudocode files. |
| [evidence-bundle.json](../evidence/full/speedify.exe/evidence-bundle.json) | Canonical REA bundle: 55,937,134 bytes, 623 retained records. |
| [manifest.json](../evidence/full/speedify.exe/manifest.json) | Completed attempt/export manifest with reconciled counters. `completed` means attempts finished, not every function succeeded. |
| [tool-identity.json](../evidence/full/speedify.exe/tool-identity.json) | REA 6.5.0 / Ghidra 12.1.4; selected installed-versus-workspace tool copies verified byte-identical. |

Failures are retained under [failures](../evidence/full/speedify.exe/failures) and in their original batch Evidence:

| Procedure | Failure and Evidence |
| --- | --- |
| `0x1401b3bfe` | Owned native decompiler terminated by the resource guard; Ghidra reported `Decompiler process died`. Batch Evidence `ev_525831c312bcb4580d270f749d42b89bdb3ad19279f19c220e866bbb1ac189df`. |
| `0x1401cd8c0` | Owned native decompiler terminated by the resource guard; Ghidra reported `Decompiler process died`. Batch Evidence `ev_18527739e06310c62550cabc1bb6c0a3f51861ecfb743bc74d1b6a7f716366c4`. |
| `0x140562440` | Ghidra low-level error: `Symbol offset is incompatible with VariableGroup`. Batch Evidence `ev_f65ec5c6ab2a4837ef4aa6c8cb88ca0a10a971200460cb782ec1added6e06339`. |
| `0x140564840` | Same Ghidra low-level error and batch Evidence `ev_f65ec5c6ab2a4837ef4aa6c8cb88ca0a10a971200460cb782ec1added6e06339`. |

The [resource-guards.jsonl](../evidence/full/speedify.exe/resource-guards.jsonl) audit identifies exact process ownership, executable, timestamps, memory and CPU at each intervention. Only native `decompile.exe` children of this export's Java process, at the exact workspace tool path, were terminated. Java retained its analysis database; Ghidra restarted the helper and continued. The watchdog applied an 8 GiB private-memory guard and a 120-second unchanged-batch-progress guard with native CPU growth. These are batch/helper resource controls, not a claim of precise per-function time limits. This export is **resource-limited**, and the four failed functions remain unresolved.

## Recovered networking observations

The following are decompiled-code observations for the exact daemon digest, except the explicitly labelled documentation row. Function names, structure layouts and some control flow are inferred by Ghidra.

| Question | Evidence and remaining boundary |
| --- | --- |
| Duplicate sender | Prior function `0x140296502`, Evidence `ev_0fb303e69e105663776160ae6179afdb6b95f0e6d98ebeb8f8cbb09189fad67e`: eligible connection iteration, packet copies and send-count enforcement. Current full-export copy has batch Evidence `ev_37ae39ae8092cfa972d92cbadb5a16c634ec64b62a752f55ec1205444b85defb`. Exact full wire semantics remain unresolved. |
| Adaptive redundancy | Prior function `0x140466908`, Evidence `ev_d52122a23007675b7d27e1dc1f85be0c356e772c5f627bd4f1942fc3a5ad08a9`: condition/log text includes a 15-second return condition. All thresholds/configurations are not established. |
| Priority classification | Prior function `0x140347c50`, Evidence `ev_36b004d201dcbc24586a0b52659abe994a3200cbe22f2250e1ba4d88eb930394`: allowlist/measurement-driven promotion. GameBond uses explicit DSCP/process rules. |
| Earlier recovery attribution — corrected | The prior summary incorrectly attributed buffered packet retrieval/retransmission to `0x14045e15c`, Evidence `ev_df18b05920b9f0f5203ba040787197bf63bb77a701c91f6cbce9efcb56b67623`. Re-reading both that retained record and full-export Evidence `ev_5fd579af1683e322e9c67cab23361a40638ffaf4977d508cb3cb1803e6d09310` shows a `CreditFailoverBlock` callback wrapper in `multiflowcodelqueue.cc`, not the direct recovery routine. The earlier claim is retained here as an identified error. |
| Buffered retransmission recovery | `0x14028f0e0` retrieves buffered packets and enforces a DSCP-dependent retry counter; `0x14028f9d4` separately retrieves a connection's buffered packets for failover recovery. Both have full-export Evidence `ev_9f6b92458cd8dcfe5eeef66388b04936cb53ed57c2704de95fbe305310d7ea58`. The branch evidence, related procedures, and remaining ARQ/reordering/MTU limits are recorded in [analysis-recovery.md](analysis-recovery.md). |
| Failure detection | Prior function `0x140458924`, Evidence `ev_f14ea7c39721c7814c9098b574b903538b4e6bad4eb5cc61028f0e58c4d263ec`: ping state, elapsed time and RTT-related terms. No universal failover delay established. |
| Documented DSCP contract | Installed `SpeedifyCLI.html`, lines 667-695: independent priority, replication, retransmission limits and matching return-flow handling. This remains documentation evidence for those end-to-end promises. |
| Server implementation | Unresolved: no Speedify server binary was supplied. GameBond uses an independent protocol. |
| Real CoD continuity | Unresolved: actual process/tag/family verification and physical link interruption measurements are required. |

## New DSCP findings from the full export

A bounded search of the successfully exported pseudocode followed concrete DSCP field names and their direct calls. It establishes additional static implementation evidence:

* [0x1401bf7c2](../evidence/full/speedify.exe/pseudocode/0x1401bf7c2.c) invokes a common parser separately with `priority`, `replication` and `retransmission_attempts`. The replication and retransmission results are passed to separate setters `0x14029b76a` and `0x14029b7aa`. Evidence `ev_525831c312bcb4580d270f749d42b89bdb3ad19279f19c220e866bbb1ac189df`.
* [0x1403814dc](../evidence/full/speedify.exe/pseudocode/0x1403814dc.c) iterates rule entries, looks for `value` and the selected policy key, handles `monitoring_tags`, and has an `invalid DSCP rule` log path. Priority/replication use string comparisons; retransmission attempts are read as a byte-sized value. The complete accepted enum/range/default behavior is not established by this reading. Evidence `ev_6d812e27b86f0abc3eddbbe1d555e08453bec1458a35f3f1eb1472b794d27e8b`.
* [0x140291e9e](../evidence/full/speedify.exe/pseudocode/0x140291e9e.c) serializes three separate maps via `0x14038183d`, using type values 1, 3 and 4, then calls the sender with message type `0x2e`. The serializer writes a type byte, a count byte and pairs of entry bytes, with a maximum count of 255 and available-buffer bounds. Evidence `ev_9f6b92458cd8dcfe5eeef66388b04936cb53ed57c2704de95fbe305310d7ea58` for the sender; serializer Evidence `ev_6d812e27b86f0abc3eddbbe1d555e08453bec1458a35f3f1eb1472b794d27e8b`.
* [0x1402846c0](../evidence/full/speedify.exe/pseudocode/0x1402846c0.c), case `0x2e`, parses a `DSCP rules message`, handles the same three type values and updates separate maps at offsets `0xed8`, `0xf18` and `0xf58`. Evidence `ev_bdb67a758fc4143728f0a3a06b1ec4e8b9710934601d904b6c166eac64bdf416`.
* [0x140296c2e](../evidence/full/speedify.exe/pseudocode/0x140296c2e.c) gets a packet's DSCP through `0x140318e28` and uses it to look up the map at `0xed8`, the same map used by the replication setter. This supports a DSCP-dependent replication decision path, but its return/control flow is incomplete. Evidence `ev_5cf2ce191e9cfedeb768598c2f998effcb0b1aad7fa30c9329c8aedd450e1d31`.
* [0x14028f0e0](../evidence/full/speedify.exe/pseudocode/0x14028f0e0.c) retrieves buffered packets, reads their DSCP, looks up the separate `0xf18` map and compares a packet field (getter `0x14031ab6c`, offset `0x108`) with the selected byte limit before calling `0x140298fac`. This is evidence of a DSCP-dependent recovery limit, not a recovered universal retry count or complete ARQ specification. Evidence `ev_9f6b92458cd8dcfe5eeef66388b04936cb53ed57c2704de95fbe305310d7ea58`.

The API wrapper [0x1402fd7b0](../evidence/full/speedify.exe/pseudocode/0x1402fd7b0.c) also visibly accepts `queues` and dispatches `set_dscp_queues_cb` with selector `0x239`; Evidence `ev_9a7014d7b6f177b93476bc8ae44f9fc49fc22e1fc2bfb814f35b0171efc960c9`. These observations do not establish original source, server implementation, full scheduler semantics, exact packet extraction, runtime behavior or protocol compatibility.

## Analysis limitations and reproducibility

The exporter [export-decomp.cjs](../tools/export-decomp.cjs) drove a separate REA **MCP stdio** session using existing REA 6.5.0 and Ghidra 12.1.4. It did not run the target. Startup needed a process-local extended deadline and a writable workspace Temp directory. Java initially failed canonicalizing a jar under the installed user's tool directory. Existing Ghidra, REA and already-installed dependencies were copied into `.tools`; no download/install, global registration, engine code or sandbox policy change was made. Selected original/copy hashes are retained in `tool-identity.json`. The first failed attempt is preserved separately.

Ghidra references `speedify.exe.pdb`, GUID `8059cee6-aa7a-7be7-4c4c-44205044422e`, age 1, but reports load state unknown. Names and types can be missing or wrong. The inventory covers Ghidra-discovered functions, not proof that every executable byte or function boundary was correctly understood. The launcher, UI, support tools, external imports and remote server are not implicitly decompiled by the daemon export.

There is also a concrete **no-return/control-flow limitation**: many caller pseudocode files mark `FUN_140593df0` as terminal/nonreturning, while that helper's own [pseudocode](../evidence/full/speedify.exe/pseudocode/0x140593df0.c) contains a returning branch. Helper Evidence `ev_548915b2e68483a96be4da718cbe4a38c81aa0c79bd30bac2f49fd64106f3f10`; a caller/terminal-flow warning is retained in first-batch Evidence `ev_1615c731ae176de13ba41cad24f61a09bd86325476171778b612f3cd35aa8364`. This inconsistency means some caller returns/tails may be truncated. The shipped REA no-return repair script explicitly does not mutate Windows P0 databases; it was not changed or bypassed. Therefore a successfully emitted body is not a guarantee of semantically complete decompilation.

To reproduce with the workspace tool copies:

```powershell
$env:GHIDRA_INSTALL_DIR = 'D:\Dev Proj\Speedify\.tools\ghidra'
node tools/export-decomp.cjs 'D:\Dev Proj\Speedify\.tools\rea-agents'
python tools/extract-decomp.py evidence/full/speedify.exe
```

The exporter retains 32-function batches and resumes only matching target/address batches. The resource watchdog is retained as `evidence/full/speedify.exe/guard-export.ps1`; its Java PID parameter and exact target paths must identify the new owned export if used again. All failures and limitations must remain attached to later reconstruction claims.

## Independent design decisions

GameBond's protocol, nonce/key derivation, 8,192-packet replay window, probes, health expiry, queue capacities and packet-age limits are our initial design choices, not recovered Speedify constants. The current prototype supports explicit DSCP priority/replication, authenticated bidirectional duplication and zero transport retransmissions; nonzero retransmission configuration is rejected. Speedify-equivalent production reliability, adaptive behavior, complete scheduler reconstruction and proprietary wire compatibility have not been established.
