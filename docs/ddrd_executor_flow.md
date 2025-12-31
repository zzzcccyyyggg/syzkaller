# DDRD Flow Inside the Executor and Runner

This note explains how the modern executor and runner wire the DDRD (race/UAF detector) into the
request lifecycle and where cleanup happens. For barrier requests, DDRD management is handled
at the runner level to ensure proper synchronization and result collection across all barrier members.

## Overview

DDRD support is driven entirely by `ExecFlagCollectDdrdUaf`, `ExecFlagCollectDdrdRace`,
and `ExecFlagCollectDdrdExtended`. The execution flow differs between regular (non-barrier) requests
and barrier requests:

### Barrier Requests (Current Implementation)

For barrier requests, DDRD management is handled entirely at the **runner** level:
- `RunnerDdrdController::PrepareForGroup()` initializes the detector and switches to LOG mode before dispatch
- `RunnerDdrdController::CollectResults()` gathers results after all members complete
- `ddrd_build_output()` serializes runner-injected results into the master's ExecResult

This ensures:
1. All barrier members execute under the same LOG phase
2. Results are collected only after all members complete
3. Only the master member (barrier_index == 0) includes DDRD results in its ExecResult

### Regular (Non-Barrier) Requests

Regular requests currently do not use DDRD collection in the executor; DDRD is primarily designed
for barrier-coordinated executions where multiple procs need synchronized tracing.

## Barrier Request Flow

```
Runner::TryDispatchBarrier()
  └─ Check if any member requests DDRD flags
       ├─ ddrd_controller_.PrepareForGroup(collect_uaf, collect_extended, req)
       │    ├─ Lazy init RaceDetector if needed
       │    ├─ Set target pair for validation (if applicable)
       │    ├─ Switch UKC device to LOG mode
       │    ├─ Clear trace buffer (trace_manager_clear)
       │    ├─ Enable/disable history based on extended flag
       │    └─ Reset detector state (race_detector_reset)
       ├─ Mark group as ddrd_active
       └─ Dispatch all members to their respective Proc instances

Barrier members execute normally
  └─ UKC device remains in LOG mode, collecting trace data

All barrier members complete

Runner::CheckBarrierCompletions() (called from main loop)
  └─ Detect when all members of a barrier group have finished
       ├─ ddrd_controller_.CollectResults()
       │    ├─ Switch UKC device to DISABLE mode
       │    ├─ race_detector_analyze_and_generate_race_infos()
       │    ├─ Optional extended history gathering per UAF pair
       │    └─ Store results in controller's internal DdrdOutputState
       ├─ For master member (barrier_index == 0):
       │    ├─ ddrd_set_runner_output(&controller.GetOutput())
       │    ├─ finish_output() reads runner-injected output
       │    └─ Send ExecResult with DDRD payload to manager
       ├─ For other members:
       │    ├─ ddrd_clear_runner_output()
       │    ├─ finish_output() returns empty DDRD payload
       │    └─ Send ExecResult without DDRD data
       └─ ddrd_controller_.ResetAfterGroup()
            ├─ Clear internal output state
            └─ Ensure UKC is in DISABLE mode

executor shutdown (main path)
  └─ RunnerDdrdController destructor
        ├─ race_detector_cleanup()
        └─ Release all resources
```

## Entry Points

### `RunnerDdrdController::PrepareForGroup`

* Triggered from `TryDispatchBarrier` before dispatching any barrier members.
* Checks if any member of the barrier group requests DDRD flags.
* Optionally sets a target UAF pair for validation via `ukc_set_may_uaf_pair()`.
* Lazily initializes the process-wide `RaceDetector` if not already done.
* Opens `/dev/kccwf_ctl_dev` and switches to LOG mode via `ukc_enter_log_mode()`.
* Clears ftrace buffer using `trace_manager_clear(nullptr)`.
* Enables or disables history collection based on `ExecFlagCollectDdrdExtended`.
* Resets detector state to prepare for the new barrier group.

### `RunnerDdrdController::CollectResults`

* Called from `CheckBarrierCompletions` after all barrier members have finished.
* Switches UKC device to DISABLE mode via `ukc_enter_disable_mode()` to stop logging.
* Calls `race_detector_analyze_and_generate_race_infos()` to generate UAF/race pair array.
* If extended info was requested, materializes per-thread histories by walking `ThreadAccessHistory` objects.
* Stores results in internal `DdrdOutputState` for injection into master's result.

### `RunnerDdrdController::ResetAfterGroup`

* Called after all barrier members' results have been sent.
* Clears internal output state.
* Ensures UKC device is in DISABLE mode.
* Prepares controller for the next barrier group.

### `ddrd_build_output`

* Called from `finish_output` just before the FlatBuffer reply is finished.
* Reads from `g_ddrd_runner_output` (set by runner for master member).
* Clears the runner output pointer after serialization.
* Converts UAF pairs and extended records into FlatBuffer vectors matching `pkg/flatrpc/flatrpc.fbs`.

## Cleanup

### Runner-Level

* `RunnerDdrdController` destructor runs when the runner process exits.
* Calls `race_detector_cleanup()` to free detector resources.
* Note: The destructor does not explicitly switch UKC modes; cleanup happens via `ResetAfterGroup()`.

### Executor-Level

* For barrier requests, executor-side DDRD state remains unused; all management happens in runner.
* The `g_ddrd_runner_output` global pointer is cleared after each serialization.

## Failure Modes

* If the UKC device cannot be opened or an IOCTL fails, the controller logs the error and proceeds without collecting DDRD data.
* Detector availability is cached; once `race_detector_is_available` reports false, no further DDRD work is attempted.
* For barrier requests, if DDRD preparation fails, the group's `ddrd_active` flag remains false, and no results are collected.

## Key Design Points

1. **Barrier Synchronization**: All barrier members execute under a single LOG phase started by the runner before dispatch.

2. **Single Point of Collection**: Only the runner collects DDRD results, avoiding redundant analysis in child processes.

3. **Master-Only Results**: Only the master member (barrier_index == 0) receives DDRD results, reducing data duplication.

4. **DISABLE Mode**: After collection, the UKC device is switched to DISABLE mode (not MONITOR mode) to minimize kernel overhead.

5. **Runner Injection**: The runner injects DDRD output into the executor's global state via `g_ddrd_runner_output` pointer, allowing `finish_output` to serialize it transparently.

These hooks keep DDRD processing transparent to the rest of the executor pipeline while ensuring the kernel module is toggled at the right moments and results are collected efficiently for barrier executions.
