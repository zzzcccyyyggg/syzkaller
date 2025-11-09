# UAF-Barrier Fuzzing Framework Design

## 1. Goals and Scope
- **Primary objective**: extend syzkaller with a use-after-free (UAF) focused fuzzing mode that leverages DDRD barrier execution and preserves interesting `may_uaf_pair` results as dedicated seeds.
- **Secondary objectives**: integrate seamlessly with the existing manager/fuzzer/executor architecture, reuse the stock mutation engine, and provide hooks for future validation and triage pipelines.
- **Non-goals**: redesigning the global scheduler, altering non-UAF modes, or introducing brand-new mutation operators in the initial milestone.

## 2. High-Level Architecture
```
syz-manager (UAF-aware mode)
    │
    ├── corpus service (programs, coverage, UAF summaries)
    ├── scheduler (barrier-aware dispatch policy)
    └── RPC surface (extended ExecFlags & RPC objects)
         │
syz-fuzzer (UAF mode)
    │
    ├── dual work queues
    │     ├─ program queue (existing queue)
    │     └─ uaf-pair queue (new: seeds referencing `may_uaf_pair` metadata)
    │
    ├── UAF corpus manager
    │     ├─ persistent store (local, synced with manager)
    │     ├─ selection heuristics (probability per new pair quality)
    │     └─ flush hooks for validation mode
    │
    ├── mutation stage (reuse syzkaller mutators)
    │     └─ optional pair-guided hints (future)
    │
    └── execution controller
          ├─ barrier master election & orchestration
          ├─ synchronous `trace_manager_clear` + LOG/MONITOR toggling
          └─ result harvesting (UAF records → corpus update)
```

## 3. Data Model
### 3.1 UAF Corpus Entry
```
type UAFCorpusEntry struct {
    Prog          *prog.Prog          // canonical serialized program
    CallIdx       int                 // call index linked with pair
    PairBasicInfo ddrd.MayUAFPair     // basic UAF metadata from executor
    Extended      *ddrd.ExtendedPair  // optional extended trace if requested
    BarrierMeta   BarrierSnapshot     // group id, size, scheduling info
    Signals       ddrd.UAFSignal      // hashed signal for deduplication
    Timestamp     time.Time
}
```
- Corpus uniqueness determined by a composite key: `(PairBasicInfo.Signal, CallIdx, BarrierMeta.GroupID)`.
- The `BarrierSnapshot` stores executor-side context necessary for deterministic replay (group size, master index, etc.).

### 3.2 Sync Messages
Extend existing manager⇄fuzzer sync payloads:
- `FuzzerConnect` response: advertise `ExecFlagCollectDdrdUaf`, `ExecFlagBarrier`, and new `FuzzerModeUAF`.
- Periodic `Sync` RPC: attach `[]UAFCorpusEntryMeta` describing freshly discovered pairs (metadata only; use lazy fetch for large traces).

## 4. Control Flow
### 4.1 Execution Path
1. **Selection**
   - Scheduler picks either a regular corpus program or a UAF corpus seed.
   - UAF seeds are prioritized by freshness, uniqueness of signals, and optional heuristics (e.g., time since last validation).
2. **Barrier Preparation**
   - Selected seed ensures `ExecOpts` enable DDRD flags (`CollectDdrdUaf`, `CollectDdrdExtended` when needed) and `BarrierGroupSize > 1`.
   - Master proc clears ftrace via `trace_manager_clear` leveraging `clear_trace` fast path.
3. **Execution**
   - RUN barrier program: master enters LOG mode, others stay in MONITOR.
   - Executor collects `may_uaf_pair` array + extended context and emits in RPC response (`DdrdRaw`).
4. **Post-processing**
   - Fuzzer parses `DdrdRaw`, normalizes UAF records, and hashes signals.
   - New unique pairs inserted into `uafCorpus`. Each entry references the parent program (for reproduction), call index, and barrier snapshot.
   - For each new pair: push to `uafPairWorkQueue` for follow-up mutations/validation.

### 4.2 Manager Synchronization
- Manager stores authoritative UAF corpus per target triple.
- On sync, manager merges new entries, dedups by signal, and persists to disk (e.g., under `workdir/uaf-corpus/`).
- Manager shares refreshed stats (counts per subsystem, failure rates) back to fuzzer for scheduling hints.

## 5. Mutation Strategy
- Start with existing syzkaller mutation pipeline (`Generate`, `Mutate`, `Triaged`, `Smash`) on the owning program.
- Constraint: maintain call ordering that participated in the recorded pair (avoid deleting required calls).
- Store `CallIdx` + dependencies: embed keep masks to ensure target call(s) survive mutation.
- Future work: pair-guided mutation (e.g., nudge pointer lifetimes, reorder free/use pairs).

## 6. Validation Workflow (Future)
- Maintain `pendingValidation` queue referencing UAF corpus entries not yet confirmed.
- Validation mode toggled via manager configuration; runs dedicated `syz-fuzzer` in `uaf-validate` mode.
- Validation executor requests pass the original program with deterministic barrier configuration to confirm reproducibility.

## 7. Integration Plan for Upstream Syzkaller
### 7.1 IPC & Protocol
- Extend `rpc::ExecFlag` enum (`CollectDdrdUaf`, `CollectDdrdExtended`, `BarrierGroupId`, `BarrierIndex`, etc.) already available in modified executor—ensure upstream proto/go bindings updated.
- Update `pkg/ipc/ipc.go` to deserialize `DdrdRaw` payloads and expose via `ExecResult`.

### 7.2 Manager Changes
1. **Configuration**: add `uaf_mode` block enabling barrier parameters (group size, master policy) and DDRD flags.
2. **Corpus Storage**: create new DB bucket `uaf-corpus` (can reuse existing `db` package). Each entry stores serialized `UAFCorpusEntry`.
3. **Scheduler**: add `uafScheduler` branch selecting between regular and UAF seeds. Reuse fairness logic from `fuzz_scheduler.go`.
4. **RPC Routes**: extend `NewInput`, `Poll`, `Sync` RPCs to include UAF metadata.

### 7.3 Fuzzer Changes
1. **Modes**: reuse `currentMode` string in `fuzzer.go`; add branch for `"uaf"` (or reuse `concurrency` flag) to activate UAF logic.
2. **Work Queues**: instantiate `uafPairWorkQueue` (already present in legacy tree) and integrate into scheduler loop (`proc.loop`).
3. **Corpus Manager**: port `uafCorpus` bookkeeping (maps, coverage, signal tracking) ensuring thread-safe access (`sync.RWMutex`).
4. **Execution Options**: set new exec flags before calling `proc.execute`, including barrier positions and DDRD toggles.
5. **Result Handling**: extend `proc.execute` return path to inspect `ExecResult.DdrdRaw`, convert to `UAFCorpusEntry`, update coverage & signals, and enqueue follow-up tasks.

### 7.4 Executor
- Ensure `trace_manager_clear` uses `clear_trace` fast path (fall back to `O_TRUNC` if unavailable).
- Maintain master-only LOG transitions; continue to reset controller state in parent (`ukc_enter_monitor_mode`).
- Serialize DDRD output via `rpc::DdrdRaw`; update `finish_output` to include new offset only when data present (already implemented in modified tree).

### 7.5 Build & Config
- Introduce new make tags or config toggles so users can opt-in without affecting stable setups.
- Provide sample `manager.config` snippet with `uaf_mode` block (barrier size, validation toggle, DDRD extended collection).

## 8. Migration Checklist
1. **Protocol Alignment**
   - Regenerate FlatBuffers / Go bindings after adding `DdrdRaw` fields.
   - Synchronize `pkg/rpctype` structs with executor changes (new ExecFlags, `UAFCorpusEntry` RPC payload).
2. **Feature Flags**
   - Advertise `host.FeatureDdrd` in `host` package to guard hardware dependencies (UKC device, ftrace access).
3. **Testing**
   - Unit-test corpus manager logic (dedup by signal, eviction policies).
   - Add integration test: run syz-fuzzer in mock mode, inject synthetic `DdrdRaw`, ensure UAF seeds recorded.
   - Create end-to-end script: spawn barrier executors under QEMU, confirm repeated pairs stored and reused.
4. **Documentation**
   - Update `docs/ddrd_executor_flow.md` and new `docs/uaf_barrier_fuzzing.md` with usage instructions.
   - Provide operator guide for enabling UAF mode, explaining additional host permissions (debugfs, UKC device).

## 9. Open Questions & Future Enhancements
- **Pair-Guided Mutation**: integrate heuristics that nudge use/free call arguments based on trace metadata.
- **Automatic Validation Scheduling**: build scoring system to decide when a stored pair should be re-run in dedicated validation mode.
- **Crash Bucketing**: reuse pair signals to group related crashes and reduce triage noise.
- **Cross-Instance Sharing**: extend syz-hub protocol to exchange UAF corpus entries across clusters.
- **Performance Telemetry**: record barrier overhead, ftrace clear latency, and DDRD parsing time for continuous tuning.

## 10. Current Implementation Snapshot
- Manager side persists the authoritative corpus in `pkg/manager/uaf_store.go` using `uaf-corpus.db`, hydrates new fuzzer instances via `mgr.enqueueUAFCorpusSeeds`, and logs store growth during the main loop.
- Fuzzer side exposes `PendingUAFCorpusEntries`/`EnqueueUAFCorpus` in `pkg/fuzzer/fuzzer.go`, restores persisted seeds through `uaf.restore`, and pushes them onto the dedicated queue with barrier metadata preserved.
- Configuration gating lives under `experimental.uaf_mode`; enabling it wires the store initialization, DDRD exec flags, and barrier helpers without affecting non-UAF runs.
- Persistence currently captures program bodies, barrier snapshots, hashed signals, and timestamps; extended traces remain TODO and are called out in the open questions section.

## 11. Summary
The proposed framework augments syzkaller with a UAF-focused fuzzing loop that:
- Executes programs under DDRD barrier control, guaranteeing clean tracing per cycle.
- Captures every `may_uaf_pair` as a first-class corpus entry with associated metadata.
- Reuses existing mutation and scheduling infrastructure while introducing a parallel queue for UAF seeds.
- Lays groundwork for a validation pipeline and future pair-guided optimizations.

Implementing the described components and synchronization hooks will enable systematic exploration of UAF vulnerabilities while maintaining compatibility with upstream syzkaller architectures.