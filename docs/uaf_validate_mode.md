# UAF Validate Mode Overview

## Purpose
The UAF validate mode replays persisted Use-After-Free candidates under controlled conditions to confirm true positives and capture reproducible diagnostics. It orchestrates barrier-aware executions across the VM pool, gathers DDRD telemetry, and records validation outcomes to disk for later triage.

## High-Level Flow
1. **Corpus Load**: `syz-manager` opens the persisted UAF corpus (`uaf-corpus.db`) and queues every entry for validation.
2. **Stage Manager**: `pkg/uafvalidate` spins up a `StageManager` with worker goroutines sized to the VM pool. Each worker:
   - Allocates barrier delays via the delay manager.
   - Sets up a fresh executor instance via `validatorExecutorFactory`.
   - Runs the entry, capturing execution output, crash metadata, and DDRD reports.
3. **Repeat Loop**: Every candidate runs `RepeatCount` times (default 3). Success is only acknowledged after the final repeat completes without crashes or executor errors.
4. **Intersection Tracking**: On each successful repeat, DDRD pairs are intersected to identify pairs stable across runs. The last iteration publishes the stable set in the result payload.
5. **Result Handling**: `syz-manager/uaf_validate.go` consumes `ValidationResult` objects, logs status per run, updates counters, and persists the consolidated outcome into `uaf-validated.db`.
6. **Shutdown**: Once all tasks finish and channels drain, the manager exits cleanly using the guarded shutdown helper to avoid double-close panics.

## Key Components
- **`pkg/uafvalidate/StageManager`**
  - Handles task queuing, worker lifecycle, repeat scheduling, and intersection collection.
  - Guards against context cancellation (SIGINT, timeout) and aborts in-flight tasks gracefully.
- **`validatorExecutorFactory` (`syz-manager/uaf_validate.go`)**
  - Reuses the VM pool in round-robin fashion, setting up `instance.ExecProg` adapters for validation runs.
- **Delay Management** (`pkg/uafvalidate/delay.go`)
  - Builds per-run barrier delays and retries within a configurable budget to tame flakiness.

## Configuration Knobs (`manager.Config.Experimental.UAFValidate`)
- `MaxConcurrent`: Caps worker count (auto-clamped to VM pool size).
- `DelayRetryBudget`: Maximum retries per repeat when crashes or transient errors occur.
- `TimeoutSeconds`: Execution timeout for each repeat.
- `RepeatCount`: Number of successful repeats required for confirmation.
- `Debug`: Surfaces additional logging when enabled.

## Logging & Diagnostics
- **Per-Run Status**: Success, crash, or executor error is logged with repeat indices and pair counts.
- **Stable Intersection**: Final repeat logs the number of stable DDRD pairs and enumerates each with access names, call stack hashes (`free_stack` / `use_stack`), signal, timing, sequence numbers, lock classification, and access type.
- **Executor Debug**: Runner-side debug (via `executor/executor_runner.h`) prints DDRD pairs with stack hashes, aiding correlation with kernel traces.

## Persistence Artifacts
- `uaf-corpus.db`: Source corpus entries (programs, barriers, replay plans, original DDRD metadata).
- `uaf-validated.db`: Validation outcomes with attempts, notes, timestamps, last seen pairs, and stable intersections.

## Error Handling
- Executor errors and crashes trigger retries (bounded by the delay budget). Persistent failures mark the entry as `failed` with diagnostic notes.
- Context cancellation (manager shutdown) aborts active tasks to ensure clean exit.

## Operational Notes
- Rebuild the executor binaries (`make executor`) after logging-related changes.
- Ensure target kernels expose DDRD instrumentation (KCCWF stack logging) to populate pair data.
- Monitor `syz-manager` logs for `uaf validation:` and `ddrd:` prefixes during triage sessions.

## Future Enhancements
- Symbolize stack hashes when resolver data becomes available.
- Add regression tests around intersection logic and store persistence.
- Extend dashboards to display confirmation results and stable pair digests.
