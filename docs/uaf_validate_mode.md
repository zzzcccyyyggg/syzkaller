# UAF Validate Mode Overview

## Purpose
The UAF validate mode replays persisted Use-After-Free candidates under controlled conditions to confirm true positives and capture reproducible diagnostics. It orchestrates barrier-aware executions across the VM pool, gathers DDRD telemetry, and records validation outcomes to disk for later triage.

## High-Level Flow

### One-Shot Mode (Default)
1. **Corpus Load**: `syz-manager` opens the persisted UAF corpus (`uaf-corpus.db`) and queues every entry for validation.
2. **Stage Manager**: `pkg/uafvalidate` spins up a `StageManager` with worker goroutines sized to the VM pool. Each worker:
   - Allocates barrier delays via the delay manager.
   - Sets up a fresh executor instance via `validatorExecutorFactory`.
   - Runs the entry, capturing execution output, crash metadata, and DDRD reports.
3. **Repeat Loop**: Every candidate runs `RepeatCount` times (default 1). Each repeat is attempted until it either succeeds, crashes, or hits the per-repeat retry budget; the final run's outcome determines the confirmation status.
4. **Intersection Tracking**: On each successful repeat, DDRD pairs are intersected to identify those that appear at least `repeat/2 + 1` times. The last iteration publishes the stable set in the result payload and optionally kicks off pair verification.
5. **Result Handling & Verification**: `syz-manager/uaf_validate.go` consumes `ValidationResult` objects, logs status per run, updates counters, triggers verification for stable pairs, and persists the consolidated outcome into `uaf-validated.db`.
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
- **`pkg/uafvalidate/StageManager`**
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
- **Delay Management** (`pkg/uafvalidate/delay.go`)
  - Builds per-run barrier delays and retries within a configurable budget to tame flakiness.
  - When a corpus entry carries DDRD pairs, the first pair's `time_diff` seeds a leading delay so the free/use windows compress towards the observed overlap.

## Configuration Knobs (`manager.Config.Experimental.UAFValidate`)
- `MaxConcurrent`: Caps worker count (auto-clamped to VM pool size).
- `DelayRetryBudget`: Maximum retries per repeat when crashes or transient errors occur.
- `TimeoutSeconds`: Execution timeout for each repeat.
- `RepeatCount`: Total number of repeats attempted per entry (default 1). Stable pair intersection requires `repeat/2 + 1` successful observations.
- `ExecutorProgramTimeoutSeconds`: Optional override for the executor's per-program watchdog (defaults to the target timeout if unset).
- `ExecutorSyscallTimeoutMillis`: Optional override for the executor's per-syscall watchdog; useful when DDRD delays exceed the default 50 ms budget.
- `ContinuousMode`: Enable incremental corpus reloading instead of one-shot validation. When enabled, the validator runs indefinitely and periodically checks for new entries.
- `IncrementalReloadMinutes`: How often to reload new corpus entries in continuous mode (default: 10 minutes).
- `IdleReloadSeconds`: How long to wait before reloading when no tasks are pending (default: 30 seconds).
- `ThresholdUpdateMinutes`: How often to update the adaptive race detection threshold (default: 5 minutes).
- `Debug`: Surfaces additional logging when enabled.

### Example Configuration (Continuous Mode)
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
      "threshold_update_minutes": 5
    }
  }
}
```

Additional runtime files:
- `invalid_uaf.db`: Tracks DDRD pairs that failed dedicated verification so future runs can skip them early.
- `threshold_config.json`: Stores adaptive race detection threshold state for cross-process communication.

## Logging & Diagnostics
- **Per-Run Status**: Success, crash, or executor error is logged with repeat indices and pair counts.
- **Stable Intersection**: Final repeat logs the number of stable DDRD pairs (meeting the majority threshold) and enumerates each with access names, call stack hashes (`free_stack` / `use_stack`), signal, timing, sequence numbers, lock classification, and access type.
- **Verification Phase**: Stable pairs are rerun (default 3 repeats) with targeted DDRD collection; pairs that fail to trigger are persisted into `invalid_uaf.db` to avoid future verification attempts.
- **Executor Debug**: Runner-side debug (via `executor/executor_runner.h`) prints DDRD pairs with stack hashes, aiding correlation with kernel traces.
- **Continuous Mode Logging**: Logs reload events with entry counts, sequence numbers, pending count, and seen count.

## Persistence Artifacts
- `uaf-corpus.db`: Source corpus entries (programs, barriers, replay plans, original DDRD metadata).
- `uaf-validated.db`: Validation outcomes with attempts, notes, timestamps, last seen pairs, and stable intersections.
- `invalid_uaf.db`: Cache of DDRD pairs that consistently fail verification, preventing repeat work.
- `varname_hb_stats.db`: VarName-based HB (happens-before) statistics for probabilistic pair skipping.
- `threshold_config.json`: Adaptive race detection threshold configuration shared between fuzz and validate phases.

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

## Adaptive Race Detection Threshold

The system implements an adaptive threshold mechanism to balance the rate of pair collection (fuzz phase) with verification throughput (validate phase).

### Algorithm
The threshold controller adjusts the race detection time window based on:
- **Recent collection rate**: How many pairs were collected in the last period
- **Recent verification rate**: How many pairs were verified in the last period  
- **Backlog ratio**: Total unverified pairs as a percentage of total collected

```
speedRatio = max(1.0, recentCollected / max(1, recentVerified))
backlogRatio = (totalCollected - totalVerified) / max(1, totalCollected)
adjustFactor = clamp(1 / (speedRatio * (1 + backlogRatio)), 0.5, 1.2)
newThreshold = clamp(currentThreshold * adjustFactor, MinThresholdNs, MaxThresholdNs)
```

### Threshold Range
| Value | Time | Description |
|-------|------|-------------|
| `MinThresholdNs` | 427,000 ns (0.427 ms) | Tightest - fewer pairs collected |
| `DefaultThresholdNs` | 427,000 ns (0.427 ms) | Starts conservative, grows as needed |
| `MaxThresholdNs` | 427,000,000 ns (427 ms) | Loosest - more pairs collected |

### Cross-Process Communication
When running fuzz and validate phases as separate processes, they communicate via `threshold_config.json`:

```
┌─────────────────┐     threshold_config.json      ┌─────────────────┐
│ VALIDATE Phase  │ ─────────────────────────────→ │ FUZZ Phase      │
│ (Updates stats  │                                │ (Reads threshold│
│  & threshold)   │                                │  every 30 sec)  │
└─────────────────┘                                └─────────────────┘
```

### Usage Example
```bash
# Terminal 1: Fuzz phase (collects pairs)
sudo ./bin/syz-manager --config=./config.cfg

# Terminal 2: Validate phase (verifies pairs & adjusts threshold)
sudo ./bin/syz-manager --config=./config-validate.cfg --mode uaf-validate
```

The validate phase periodically updates the threshold based on verification statistics. The fuzz phase reloads the threshold from file every 30 seconds, automatically adapting to the new value.
