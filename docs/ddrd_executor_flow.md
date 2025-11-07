# DDRD Flow Inside the Executor

This note explains how the modern executor wires the DDRD (race/UAF detector) into the
request lifecycle and where cleanup happens. It complements the higher level design
docs by focusing on the exact execution points in `executor/executor.cc`.

## Overview

DDRD support is driven entirely by `ExecFlagCollectDdrdUaf`, `ExecFlagCollectDdrdRace`,
and `ExecFlagCollectDdrdExtended`. When a request arrives with any of these bits set,
the executor prepares the detector, switches the kernel module into LOG mode, records
state while syscalls run, and finally gathers and serializes results before returning to
the runner.

The full sequence is shown below.

```
receive_execute()
  └─ parse_execute(req)
        ├─ cache exec flags (CollectDdrd*)
        └─ ddrd_prepare_for_request()
             ├─ ensure UKC device opened & LOG mode
             ├─ lazily init RaceDetector once per executor
             ├─ enable/disable history depending on extended flag
             ├─ reset detector state (race_detector_reset)
             └─ clear previous outputs
execute_one()
  ├─ execute syscalls as usual
  └─ ddrd_collect_results()
        ├─ bail out early if detector unavailable or request inactive
        ├─ race_detector_analyze_and_generate_uaf_infos()
        ├─ optional extended history gathering per UAF pair
        ├─ record results in g_ddrd_output
        └─ switch UKC device back to MONITOR mode
finish_output()
  └─ ddrd_build_output()
        ├─ serialize basic pairs into DdrdUafPairRaw vector
        ├─ serialize extended records when requested
        └─ provide rpc::DdrdRaw offset to ProgInfoRaw
executor shutdown (main path)
  └─ ukc_cleanup()
        ├─ if still in LOG mode, request MONITOR
        ├─ close the device fd
        └─ reset controller bookkeeping for next request
```

## Entry Points

### `ddrd_prepare_for_request`

* Triggered from `parse_execute` once per incoming request.
* No-op when the request is not a `Program` or none of the DDRD flags is set.
* First ensures the UKC control path is active:
  * Opens `/dev/kccwf_ctl_dev` if needed, issuing `TURN_OFF` on first success.
  * Switches to LOG mode via `START_LOG_PHASE`.
* Lazily initializes the process-wide `RaceDetector` (`race_detector_init`) and records
  whether the kernel provides DDRD support (`race_detector_is_available`). If the
  detector is unavailable a single warning is printed and nothing else happens for this
  request.
* Resets detector state for the new program (`race_detector_reset`), toggles history
  collection based on the `ExecFlagCollectDdrdExtended` bit, and clears any previously
  buffered output.

### `ddrd_collect_results`

* Invoked near the end of `execute_one`, before file descriptors are closed.
* If the detector was not active (for example because LOG mode could not be entered or
  the feature is missing) it simply asks the UKC device to return to MONITOR mode and
  exits.
* Before the detector is queried the barrier master switches the kernel back to MONITOR
  mode so logging stops once every member of the group has finished executing its
  program.
* In barrier execution mode only the participant with `barrier_index == 0` toggles the
  UKC device, performs the expensive analysis, and serializes results. The other
  executors leave the device untouched and return immediately so the coordinator
  receives a single consolidated DDRD payload per barrier group.
* Afterwards the master calls `race_detector_analyze_and_generate_uaf_infos` to fill a temporary
  array of UAF pairs and copies the valid range into `g_ddrd_output.basic_pairs`.
* When the extended flag was set, per-thread histories are materialized by walking the
  detector’s `ThreadAccessHistory` objects. The entries are serialized into the
  temporary `history` vector inside each `DdrdExtendedUafRecord`.
* Results are marked as ready and UKC is switched back to MONITOR mode so the kernel
  stops logging aggressively.

### `ddrd_build_output`

* Called from `finish_output` just before the FlatBuffer reply is finished.
* Converts the in-memory basic pairs and extended records into FlatBuffer vectors that
  match the structures in `pkg/flatrpc/flatrpc.fbs`.
* Clears `g_ddrd_output` afterwards so the next request starts from a clean slate.

## Cleanup

* `ukc_cleanup` runs when the executor is about to exit. It best-effort switches the UKC
  device back to MONITOR mode, closes the file descriptor, and resets the controller
  bookkeeping (`initialized`, `log_mode`). On the next request the executor will reopen
  the device and re-enter LOG mode as needed.
* `ddrd_clear_output` is called both when preparing a request and after serializing the
  results to avoid leaking state across requests.

## Failure Modes

* If the UKC device cannot be opened or an IOCTL fails, the executor logs the error and
  proceeds without collecting DDRD data.
* Detector availability is cached; once `race_detector_is_available` reports false the
  executor will skip future DDRD work until it is restarted.

These hooks keep DDRD processing transparent to the rest of the executor pipeline while
ensuring the kernel module is toggled at the right moments.
