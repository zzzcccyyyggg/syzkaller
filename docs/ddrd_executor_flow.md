# DDRD Flow Inside the Executor and Runner# DDRD Flow Inside the Executor



This note explains how the modern executor and runner wire the DDRD (race/UAF detector) into theThis note explains how the modern executor wires the DDRD (race/UAF detector) into the

request lifecycle and where cleanup happens. For barrier requests, DDRD management has been movedrequest lifecycle and where cleanup happens. It complements the higher level design

to the runner level to ensure proper synchronization and result collection across all barrier members.docs by focusing on the exact execution points in `executor/executor.cc`.



## Overview## Overview



DDRD support is driven entirely by `ExecFlagCollectDdrdUaf`, `ExecFlagCollectDdrdRace`,DDRD support is driven entirely by `ExecFlagCollectDdrdUaf`, `ExecFlagCollectDdrdRace`,

and `ExecFlagCollectDdrdExtended`. The execution flow differs between regular (non-barrier) requestsand `ExecFlagCollectDdrdExtended`. When a request arrives with any of these bits set,

and barrier requests:the executor prepares the detector, switches the kernel module into LOG mode, records

state while syscalls run, and finally gathers and serializes results before returning to

### Regular (Non-Barrier) Requeststhe runner.



For regular requests, DDRD operates at the executor level as before:The full sequence is shown below.

- `ddrd_prepare_for_request()` initializes the detector and switches to LOG mode

- `ddrd_collect_results()` gathers results after execution```

- `ddrd_build_output()` serializes results into the ExecResultreceive_execute()

  └─ parse_execute(req)

### Barrier Requests        ├─ cache exec flags (CollectDdrd*)

        └─ ddrd_prepare_for_request()

For barrier requests, DDRD management has been moved to the **runner** level to ensure:             ├─ ensure UKC device opened & LOG mode

1. All barrier members execute under the same LOG phase             ├─ lazily init RaceDetector once per executor

2. Results are collected only after all members complete             ├─ enable/disable history depending on extended flag

3. Only the master member (barrier_index == 0) includes DDRD results in its ExecResult             ├─ reset detector state (race_detector_reset)

             └─ clear previous outputs

The full sequence for barrier requests is shown below.execute_one()

  ├─ execute syscalls as usual

```  └─ ddrd_collect_results()

Runner::TryDispatchBarrier()        ├─ bail out early if detector unavailable or request inactive

  └─ Check if any member requests DDRD flags        ├─ race_detector_analyze_and_generate_uaf_infos()

       ├─ ddrd_controller_.PrepareForGroup(collect_uaf, collect_extended)        ├─ optional extended history gathering per UAF pair

       │    ├─ Lazy init RaceDetector if needed        ├─ record results in g_ddrd_output

       │    ├─ Switch UKC device to LOG mode        └─ switch UKC device back to MONITOR mode

       │    ├─ Clear trace buffer (trace_manager_clear)finish_output()

       │    ├─ Enable/disable history based on extended flag  └─ ddrd_build_output()

       │    └─ Reset detector state (race_detector_reset)        ├─ serialize basic pairs into DdrdUafPairRaw vector

       ├─ Mark group as ddrd_active        ├─ serialize extended records when requested

       └─ Dispatch all members to their respective Proc instances        └─ provide rpc::DdrdRaw offset to ProgInfoRaw

executor shutdown (main path)

Barrier members execute normally  └─ ukc_cleanup()

  └─ executor-side ddrd_prepare_for_request() returns early for barriers        ├─ if still in LOG mode, request MONITOR

       (DDRD already managed by runner)        ├─ close the device fd

        └─ reset controller bookkeeping for next request

All barrier members complete```



Runner::CheckBarrierCompletions() (called from main loop)## Entry Points

  └─ Detect when all members of a barrier group have finished

       ├─ ddrd_controller_.CollectResults()### `ddrd_prepare_for_request`

       │    ├─ Switch UKC device back to MONITOR mode

       │    ├─ race_detector_analyze_and_generate_uaf_infos()* Triggered from `parse_execute` once per incoming request.

       │    ├─ Optional extended history gathering per UAF pair* No-op when the request is not a `Program` or none of the DDRD flags is set.

       │    └─ Store results in controller's internal DdrdOutputState* First ensures the UKC control path is active:

       ├─ For master member (barrier_index == 0):  * Opens `/dev/kccwf_ctl_dev` if needed, issuing `TURN_OFF` on first success.

       │    ├─ ddrd_set_runner_output(&controller.GetOutput())  * Switches to LOG mode via `START_LOG_PHASE`.

       │    ├─ finish_output() reads runner-injected output* Lazily initializes the process-wide `RaceDetector` (`race_detector_init`) and records

       │    └─ Send ExecResult with DDRD payload to manager  whether the kernel provides DDRD support (`race_detector_is_available`). If the

       ├─ For other members:  detector is unavailable a single warning is printed and nothing else happens for this

       │    ├─ ddrd_clear_runner_output()  request.

       │    ├─ finish_output() returns empty DDRD payload* Resets detector state for the new program (`race_detector_reset`), toggles history

       │    └─ Send ExecResult without DDRD data  collection based on the `ExecFlagCollectDdrdExtended` bit, and clears any previously

       └─ ddrd_controller_.ResetAfterGroup()  buffered output.

            ├─ Clear internal output state

            └─ Ensure UKC is in MONITOR mode### `ddrd_collect_results`



executor shutdown (main path)* Invoked near the end of `execute_one`, before file descriptors are closed.

  └─ RunnerDdrdController destructor* If the detector was not active (for example because LOG mode could not be entered or

        ├─ race_detector_cleanup()  the feature is missing) it simply asks the UKC device to return to MONITOR mode and

        ├─ ukc_enter_monitor_mode()  exits.

        └─ Release all resources* Before the detector is queried the barrier master switches the kernel back to MONITOR

```  mode so logging stops once every member of the group has finished executing its

  program.

## Entry Points* In barrier execution mode only the participant with `barrier_index == 0` toggles the

  UKC device, performs the expensive analysis, and serializes results. The other

### Runner-Level (Barrier Requests Only)  executors leave the device untouched and return immediately so the coordinator

  receives a single consolidated DDRD payload per barrier group.

#### `RunnerDdrdController::PrepareForGroup`* Afterwards the master calls `race_detector_analyze_and_generate_uaf_infos` to fill a temporary

  array of UAF pairs and copies the valid range into `g_ddrd_output.basic_pairs`.

* Triggered from `TryDispatchBarrier` before dispatching any barrier members.* When the extended flag was set, per-thread histories are materialized by walking the

* Checks if any member of the barrier group requests DDRD flags.  detector’s `ThreadAccessHistory` objects. The entries are serialized into the

* Lazily initializes the process-wide `RaceDetector` if not already done.  temporary `history` vector inside each `DdrdExtendedUafRecord`.

* Opens `/dev/kccwf_ctl_dev` and switches to LOG mode via `ukc_enter_log_mode()`.* Results are marked as ready and UKC is switched back to MONITOR mode so the kernel

* Clears ftrace buffer using `trace_manager_clear(nullptr)`.  stops logging aggressively.

* Enables or disables history collection based on `ExecFlagCollectDdrdExtended`.

* Resets detector state to prepare for the new barrier group.### `ddrd_build_output`



#### `RunnerDdrdController::CollectResults`* Called from `finish_output` just before the FlatBuffer reply is finished.

* Converts the in-memory basic pairs and extended records into FlatBuffer vectors that

* Called from `CheckBarrierCompletions` after all barrier members have finished.  match the structures in `pkg/flatrpc/flatrpc.fbs`.

* Switches UKC device back to MONITOR mode to stop aggressive logging.* Clears `g_ddrd_output` afterwards so the next request starts from a clean slate.

* Calls `race_detector_analyze_and_generate_uaf_infos` to generate UAF pair array.

* If extended info was requested, materializes per-thread histories by walking `ThreadAccessHistory` objects.## Cleanup

* Stores results in internal `DdrdOutputState` for injection into master's result.

* `ukc_cleanup` runs when the executor is about to exit. It best-effort switches the UKC

#### `RunnerDdrdController::ResetAfterGroup`  device back to MONITOR mode, closes the file descriptor, and resets the controller

  bookkeeping (`initialized`, `log_mode`). On the next request the executor will reopen

* Called after all barrier members' results have been sent.  the device and re-enter LOG mode as needed.

* Clears internal output state.* `ddrd_clear_output` is called both when preparing a request and after serializing the

* Ensures UKC device is in MONITOR mode.  results to avoid leaking state across requests.

* Prepares controller for the next barrier group.

## Failure Modes

### Executor-Level (Regular Requests Only)

* If the UKC device cannot be opened or an IOCTL fails, the executor logs the error and

#### `ddrd_prepare_for_request`  proceeds without collecting DDRD data.

* Detector availability is cached; once `race_detector_is_available` reports false the

* Triggered from `parse_execute` once per incoming request.  executor will skip future DDRD work until it is restarted.

* **For barrier requests**: Returns early without any action (DDRD managed by runner).

* **For regular requests**:These hooks keep DDRD processing transparent to the rest of the executor pipeline while

  * Opens UKC device and switches to LOG mode.ensuring the kernel module is toggled at the right moments.

  * Lazily initializes `RaceDetector` and checks availability.
  * Resets detector state and configures history collection.

#### `ddrd_collect_results`

* Invoked near the end of `execute_one`, before file descriptors are closed.
* **For barrier requests**: Skipped (returns early).
* **For regular requests**:
  * Switches UKC device to MONITOR mode.
  * Calls `race_detector_analyze_and_generate_uaf_infos`.
  * Collects extended info if requested.
  * Stores results in `g_ddrd_output` for serialization.

#### `ddrd_build_output`

* Called from `finish_output` just before the FlatBuffer reply is finished.
* **For barrier requests with runner-injected output**:
  * Reads from `g_ddrd_runner_output` (set by runner for master member).
  * Clears the runner output pointer after serialization.
* **For regular requests or non-master barrier members**:
  * Reads from `g_ddrd_output` (local executor state).
  * Clears local output after serialization.
* Converts UAF pairs and extended records into FlatBuffer vectors.

## Cleanup

### Runner-Level

* `RunnerDdrdController` destructor runs when the runner process exits.
* Calls `race_detector_cleanup()` to free detector resources.
* Switches UKC device to MONITOR mode via `ukc_enter_monitor_mode()`.
* Closes the UKC device file descriptor.

### Executor-Level

* For regular requests, `g_ddrd_output` is cleared after each request in `ddrd_build_output()`.
* For barrier requests, executor-side DDRD state remains unused; all management happens in runner.

## Failure Modes

* If the UKC device cannot be opened or an IOCTL fails, the controller logs the error and proceeds without collecting DDRD data.
* Detector availability is cached; once `race_detector_is_available` reports false, no further DDRD work is attempted.
* For barrier requests, if DDRD preparation fails, the group's `ddrd_active` flag remains false, and no results are collected.

## Key Design Points

1. **Barrier Synchronization**: All barrier members execute under a single LOG phase started by the runner before dispatch.

2. **Single Point of Collection**: Only the runner collects DDRD results, avoiding redundant analysis in child processes.

3. **Master-Only Results**: Only the master member (barrier_index == 0) receives DDRD results, reducing data duplication.

4. **Clean Separation**: Executor-side DDRD code remains unchanged for regular requests; barrier logic is isolated to runner.

5. **Runner Injection**: The runner injects DDRD output into the executor's global state via `g_ddrd_runner_output` pointer, allowing `finish_output` to serialize it transparently.

These hooks keep DDRD processing transparent to the rest of the executor pipeline while ensuring the kernel module is toggled at the right moments and results are collected efficiently for barrier executions.
