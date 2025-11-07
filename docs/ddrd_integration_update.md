# DDRD Integration Update (November 2025)

## Overview
This document summarizes the latest round of DDRD integration work. The goal was to
carry the executor-generated DDRD data all the way through the Go pipeline while
removing deprecated hooks.

## Key Changes
- Reworked `pkg/ddrd` to reuse the legacy `MayUAFPair`/`ExtendedUAFPair` structs.
  * `report.go` now converts FlatBuffers payloads directly into these structs and
    provides deep-clone helpers.
  * `types.go` gained `PathDistanceUse`/`PathDistanceFree` so the legacy types can
    carry the new executor metrics.
  * `store.go` deduplicates via `MayUAFPair.UAFPairID()` and guards against nil
    entries.
  * `pair.go` now defers hashing to the existing cover helpers instead of duplicating
    logic.
- Updated fuzzer plumbing to keep DDRD reports alongside queue results while
  cloning, logging, and recording stats.
- Executor serialization now ships path distance and history records through the
  FlatBuffer `DdrdRaw` object.
- Removed the unfinished `PairSyscallSharedData` plumbing and all syscall index
  bookkeeping:
  * Dropped the shared-data forward declaration and syscall matcher export from
    `executor/ddrd/race_detector.h`.
  * Removed the data structure and lookup function from `executor/ddrd/race_detector.c`.
  * Trimmed `may_uaf_pair_t`, the FlatBuffer schema, and `MayUAFPair` so DDRD no
    longer carries syscall indices/IDs at all.
- Added `extern "C"` guards to `executor/ddrd/utils.h` so static linking resolves
  the hashing helpers consistently.

## Build & Test Status
- `make executor` succeeds (the static `gethostbyname` warning remains unchanged).
- `go test ./pkg/ddrd` builds cleanly (no package tests are defined).

## Follow-up Ideas
1. Revisit syscall pairing only if a new data source is introduced in the future.
2. Add regression tests around `pkg/ddrd/report.go` conversion and `Store` dedupe
   behavior using canned FlatBuffer payloads.
3. Extend the dashboard to surface the new DDRD metrics (path distance, history
   counts) if desired.
