# UAF Validate Mode Overview

## Purpose
The UAF validate mode replays persisted Use-After-Free candidates under controlled conditions to confirm true positives and capture reproducible diagnostics. It orchestrates barrier-aware executions across the VM pool, gathers DDRD telemetry, and records validation outcomes to disk for later triage.

## High-Level Flow

### One-Shot Mode (Default)
1. **Corpus Load**: `syz-manager` opens the persisted UAF corpus (`uaf-corpus.db`) and queues every entry for validation.
2. **Stage Manager**: `pkg/racevalidate` spins up a `StageManager` with worker goroutines sized to the VM pool. Each worker:
   - Allocates barrier delays via the delay manager.
   - Sets up a fresh executor instance via `validatorExecutorFactory`.
   - Runs the entry, capturing execution output, crash metadata, and DDRD reports.
3. **Repeat Loop**: Every candidate runs `RepeatCount` times (default 1). Each repeat is attempted until it either succeeds, crashes, or hits the per-repeat retry budget; the final run's outcome determines the confirmation status.
4. **Intersection Tracking**: On each successful repeat, DDRD pairs are intersected to identify those that appear at least `repeat/2 + 1` times. The last iteration publishes the stable set in the result payload and optionally kicks off pair verification.
5. **Result Handling & Verification**: `syz-manager/uaf_validate.go` consumes `ValidationResult` objects, logs status per run, updates counters, triggers verification for stable pairs, and persists the consolidated outcome into `validated_uaf.db`.
6. **Shutdown**: Once all tasks finish and channels drain, the manager exits cleanly using the guarded shutdown helper to avoid double-close panics.

### Continuous Mode (Incremental Reload)
When `continuous_mode` is enabled, the validator runs indefinitely and periodically reloads new corpus entries:

1. **Initial Load**: Load all existing entries from `uaf-corpus.db` using `EntriesSince(0)`.
2. **Periodic Reload**: Every `incremental_reload_minutes` (default 10), check for new entries added since the last reload.
3. **Idle Reload**: When no tasks are pending, check for new entries every `idle_reload_seconds` (default 30).
4. **Deduplication**: The `StageManager` tracks all seen keys (`seenKeys`) to avoid re-processing entries that have already been enqueued.
5. **Graceful Shutdown**: On context cancellation (SIGINT), the manager calls `Shutdown()` and waits for workers to drain.

This mode is ideal for long-running fuzzing sessions where new UAF candidates are continuously discovered and need validation without restarting the manager.

## Key Components
- **`pkg/racevalidate/StageManager`** (Go package name is `uafvalidate`)
  - Handles task queuing, worker lifecycle, repeat scheduling, and intersection collection.
  - Guards against context cancellation (SIGINT, timeout) and aborts in-flight tasks gracefully.
  - Tracks `seenKeys` to prevent re-processing entries in continuous mode.
  - Provides `HasPending()`, `PendingCount()`, and `SeenCount()` methods for monitoring.
  - Launches verification runs for stable DDRD pairs, skipping any already marked as invalid in `invalid_uaf.db`.
- **`pkg/manager/UAFCorpusStore`**
  - `Entries()`: Returns all corpus entries (used in one-shot mode).
  - `EntriesSince(seq)`: Returns entries with sequence number greater than `seq` (used in continuous mode for incremental reads).
- **`validatorExecutorFactory` (`syz-manager/uaf_validate.go`)**
  - Reuses the VM pool in round-robin fashion, setting up `instance.ExecProg` adapters for validation runs according to `uaf_validate.max_concurrent` (clamped to the VM count).
- **Delay Management** (`pkg/racevalidate/delay.go`)
  - Builds per-run barrier delays and retries within a configurable budget to tame flakiness.
  - When a corpus entry carries DDRD pairs, the first pair's `time_diff` seeds a leading delay so the free/use windows compress towards the observed overlap.

## Configuration Knobs (`manager.Config.Experimental.UAFValidate`)

> **Note**: For detailed configuration documentation with examples, see [uaf_validate_config.md](uaf_validate_config.md).

### Core Settings
- `MaxConcurrent`: Caps worker count (auto-clamped to VM pool size).
- `DelayRetryBudget`: Maximum retries per repeat when crashes or transient errors occur.
- `TimeoutSeconds`: Execution timeout for each repeat.
- `RepeatCount`: Total number of repeats attempted per entry (default 1). Stable pair intersection requires `repeat/2 + 1` successful observations.
- `VerifyRepeatTimes`: Number of times to repeat verification phase for stable pairs (default 10). Higher values increase confidence but take longer.

### Runtime Mode
- `ContinuousMode`: Enable incremental corpus reloading instead of one-shot validation. When enabled, the validator runs indefinitely and periodically checks for new entries.
- `IncrementalReloadMinutes`: How often to reload new corpus entries in continuous mode (default: 10 minutes).
- `IdleReloadSeconds`: How long to wait before reloading when no tasks are pending (default: 30 seconds).

### Scheduling
- `EnableVarNameScheduling`: Enable VarName-based round-robin scheduling. Ensures fair resource distribution across different VarName pairs by prioritizing those with fewer entries.

### Stable Pairs
- `RequireOriginMatch`: When false (default), any runtime-discovered pair meeting the stability threshold is accepted. When true, pairs must also exist in the original corpus entry.

### Performance
- `EnableVMSnapshot`: Enable QEMU VM snapshot support for faster validation cycles (experimental). See "VM Snapshot Optimization" section below.
- `ExecutorProgramTimeoutSeconds`: Optional override for the executor's per-program watchdog (defaults to the target timeout if unset).
- `ExecutorSyscallTimeoutMillis`: Optional override for the executor's per-syscall watchdog; useful when DDRD delays exceed the default 50 ms budget.

### Debugging
- `TargetVarNamePair`: Specify a VarName pair to debug (format: `"hex-hex"`). Only entries containing this pair are validated, and all skip logic is bypassed.

### Example Configuration (Continuous Mode with VarName Scheduling)
```json
{
  "experimental": {
    "uaf_validate": {
      "max_concurrent": 4,
      "delay_retry_budget": 3,
      "timeout_seconds": 120,
      "repeat_count": 3,
      "continuous_mode": true,
      "incremental_reload_minutes": 10,
      "idle_reload_seconds": 30,
      "enable_varname_scheduling": true,
      "require_origin_match": false
    }
  }
}
```

Additional runtime files:
- `invalid_uaf.db`: Tracks DDRD pairs that failed dedicated verification so future runs can skip them early.

## Logging & Diagnostics
- **Per-Run Status**: Success, crash, or executor error is logged with repeat indices and pair counts.
- **Stable Intersection**: Final repeat logs the number of stable DDRD pairs (meeting the majority threshold) and enumerates each with access names, call stack hashes (`free_stack` / `use_stack`), signal, timing, sequence numbers, lock classification, and access type.
- **Verification Phase**: Stable pairs are rerun (default 3 repeats) with targeted DDRD collection; pairs that fail to trigger are persisted into `invalid_uaf.db` to avoid future verification attempts.
- **Executor Debug**: Runner-side debug (via `executor/executor_runner.h`) prints DDRD pairs with stack hashes, aiding correlation with kernel traces.
- **Continuous Mode Logging**: Logs reload events with entry counts, sequence numbers, pending count, and seen count.

## Persistence Artifacts
- `uaf-corpus.db`: Source corpus entries (programs, barriers, replay plans, original DDRD metadata).
- `validated_uaf.db`: Validation outcomes with attempts, notes, timestamps, last seen pairs, and stable intersections.
- `invalid_uaf.db`: Cache of DDRD pairs that consistently fail verification, preventing repeat work.
- `varname_backoff_stats.db`: VarName-pair validation backoff statistics and Verified markers used for probabilistic skipping (legacy file name `varname_hb_stats.db` is still loaded).

## Error Handling
- Executor errors and crashes trigger retries (bounded by the delay budget). Persistent failures mark the entry as `failed` with diagnostic notes.
- Context cancellation (manager shutdown) aborts active tasks to ensure clean exit.

## Operational Notes
- Rebuild the executor binaries (`make executor`) after logging-related changes.
- Ensure target kernels expose DDRD instrumentation (KCCWF stack logging) to populate pair data.
- Monitor `syz-manager` logs for `uaf validation:` and `ddrd:` prefixes during triage sessions.
- In continuous mode, new entries from the fuzzer are automatically picked up without restarting.

## Future Enhancements
- Symbolize stack hashes when resolver data becomes available.
- Add regression tests around intersection logic and store persistence.
- Extend dashboards to display confirmation results and stable pair digests.

## VM Snapshot Optimization (Experimental)

### Overview
By default, each validation attempt creates a fresh VM, which incurs 30-60 seconds of startup overhead. The VM snapshot feature uses QEMU's `-loadvm` option to load a pre-saved snapshot during VM boot, reducing reset time to approximately **3-4 seconds**.

### How It Works
1. **First Run**: Create VM with a standalone qcow2 image copy, wait for SSH to be ready, save snapshot using `savevm` via QMP.
2. **Subsequent Runs**: Close the current VM and start a new QEMU process with `-loadvm` flag to restore the saved snapshot. This is faster than using `loadvm` via QMP because QEMU optimizes the startup path.
3. **State Reset**: The snapshot captures the entire VM state (memory, CPU, disk), so each restoration returns to a clean post-boot state.

### Performance Optimizations
The implementation includes several optimizations:

1. **Fast SSH Polling**: After snapshot restore, SSH is expected to be available immediately. Instead of the default 5-second initial wait + 5-second polling intervals, we use 0 initial wait + 500ms polling intervals.

2. **Binary Path Caching**: The paths to `syz-execprog` and `syz-executor` inside the VM are cached after the first setup. On snapshot restore, these paths are reused without re-copying via SCP.

3. **Standalone qcow2 Copy**: Instead of using overlay images, the system creates a standalone qcow2 copy of the base image. This ensures `savevm`/`loadvm` work correctly (overlay mode has issues with snapshot persistence).

### Prerequisites
1. **QEMU VM Type**: Snapshot support is only available for QEMU VMs.
2. **qcow2 Image Format**: The disk image must be in qcow2 format (raw images do not support snapshots). The system automatically converts images to qcow2.
3. **Migratable CPU**: The QEMU CPU configuration must allow migration/snapshots. **Do NOT use `-cpu host,migratable=off`** as this prevents savevm from working.

### Configuration

#### Manager Configuration

```json
{
  "image": "/path/to/base-image.img",
  "vm": {
    "qemu": "qemu-system-x86_64",
    "count": 8,
    "cpu": 2,
    "mem": 4096,
    "qemu_args": "-enable-kvm"
  },
  "experimental": {
    "uaf_validate": {
      "max_concurrent": 8,
      "enable_vm_snapshot": true,
      "continuous_mode": true
    }
  }
}
```

**Important QEMU configuration:**
- **DO**: Use `-enable-kvm` for performance
- **DO**: Use `-cpu host` (without `migratable=off`) or omit the `-cpu` option
- **DON'T**: Use `-cpu host,migratable=off` - this blocks snapshot save with error: `State blocked by non-migratable CPU device (invtsc flag)`

### Fallback Behavior
If snapshot save fails (e.g., due to incompatible CPU settings), the system automatically falls back to standard VM restart mode:

```
uafvalidate: vm 0 failed to save snapshot: savevm failed: ... (continuing without snapshot)
```

In fallback mode, each task still gets a fresh VM, but without the snapshot optimization.

### Performance Impact
| Mode | Reset Time | Notes |
|------|-----------|-------|
| Standard (VM restart) | 30-60s | Creates fresh VM each time |
| VM Snapshot (old) | ~10s | Using loadvm via QMP |
| VM Snapshot (optimized) | **3-4s** | Using -loadvm flag + fast SSH + cached binaries |

For validation workloads with many entries, this can reduce total validation time by **80-90%**.

### Troubleshooting

#### Snapshot Save Fails with "non-migratable CPU"
```
Error: State blocked by non-migratable CPU device (invtsc flag)
```
**Solution**: Remove `migratable=off` from your qemu_args. Use `-cpu host` instead of `-cpu host,migratable=off`.

#### Image Lock Conflicts
```
Failed to get "write" lock. Is another process using the image?
```
**Solution**: This indicates a previous QEMU process didn't fully terminate. The system will retry with a fresh image copy. If persistent, check for orphaned QEMU processes.

#### Slow Restore Times
If restore takes longer than 5 seconds, check the logs for timing breakdown:
```
qemu: vm 0 boot: SSH wait completed in Xs
uafvalidate: vm 0 executor setup took Xs
```

### Limitations
1. **Single Snapshot per VM**: Each VM maintains one snapshot. State changes after snapshot save are discarded on restore.
2. **Disk Space**: Each VM gets its own qcow2 image copy (~2-5GB depending on base image).
3. **SSH Reconnection**: After restore, the SSH connection needs to be re-established (handled automatically).
4. **QEMU Only**: Not supported for other VM backends (GCE, AWS, etc.).
