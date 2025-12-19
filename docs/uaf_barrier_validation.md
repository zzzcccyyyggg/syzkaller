# UAF Barrier Validation Progress

## Completed work
- Propagated the `--debug` flag through the UAF validator so executor-side traces and DDRD logs reach `debug.log` (`pkg/uafvalidate/executor.go`).
- Added detailed barrier trace logging and staged-result handling to the RPC runner, ensuring each member reports `handshake`, `staged`, and `flush` events with group/index tags (`pkg/rpcserver/runner.go`).
- Reworked the executor-side runner handshake so all barrier participants wait until every member finishes setup before issuing the first syscall (`executor/executor_runner.h`).
- Updated the validator’s barrier execution path to stop the VM runner as soon as the aggregated queue result is staged, preventing spurious `ExecFailure` timeouts after successful DDRD collection (`pkg/uafvalidate/executor.go`).
- Added a configurable repeat mode so each UAF corpus entry can be revalidated `RepeatCount` times (default 1) via `uaf_validate.repeat_count`, enabling multi-run analysis for UAF pair intersection (`pkg/uafvalidate/manager.go`, `pkg/mgrconfig/config.go`).
- Captured DDRD reports for every repeat, computed the stable pair intersection, and persisted it alongside the validation record (`pkg/uafvalidate/manager.go`, `pkg/manager/uaf_validated_store.go`, `syz-manager/uaf_validate.go`).
- **Fixed multi-VM concurrency issue**: Replaced round-robin VM index allocation with channel-based VM pool management to prevent index conflicts when multiple workers run concurrently (`syz-manager/uaf_validate.go`).
- **Fixed port forwarding cache bug**: Removed stale port forwarding cache in `ExecutorAdapter` that caused RPC connection failures when reusing adapters (`pkg/uafvalidate/executor.go`).
- **Fixed runner ID mismatch**: Changed runner command to always use ID 0 since each validation task has its own RPC server. Previously, using the VM index as runner ID caused "unknown VM tries to connect" errors when VM index > 0 (`pkg/uafvalidate/executor.go`).

## Current behaviour
- Barrier runs now emit synchronized `handshake → staged → flush` traces for all members; the collected DDRD report shows the expected 23 UAF pairs in the provided `debug.log`.
- Before the latest fix the VM command kept running even after the barrier result was returned, so the validator timed out after two minutes (`context closed while waiting the result`). Cancelling the VM run once the queue result arrives resolves this hang.
- Bluetooth `command tx timeout` kernel messages continue to appear during teardown; they do not block barrier completion but warrant monitoring during longer runs.
- Multi-VM validation now correctly manages VM pool resources via a channel-based approach, ensuring each VM index is used by only one executor at a time.

## Pending items
- Consider trimming the validator timeout once repeated runs confirm stability, and continue monitoring for residual Bluetooth timeouts.

## Adaptive Threshold Feature (Latest)
- Implemented `ThresholdController` in `pkg/ddrd/threshold.go` that dynamically adjusts the DDRD race time threshold based on collection/verification statistics.
- Threshold calculation uses speed ratio (`recentVerified / recentCollected`) and backlog ratio to adjust within range 427,000 ns to 427,000,000 ns.
- Threshold propagation path: `ThresholdController` → `StageManager` → `ExecutionRequest` → `queue.Request` → FlatBuffers → Executor.
- Fuzz and validate phases share threshold via JSON config file (`threshold_config.json`) with periodic reload (every 30 seconds in fuzz phase).
- Key files modified: `pkg/ddrd/threshold.go`, `pkg/uafvalidate/manager.go`, `pkg/uafvalidate/executor.go`, `syz-manager/manager.go`, `syz-manager/uaf_validate.go`.
