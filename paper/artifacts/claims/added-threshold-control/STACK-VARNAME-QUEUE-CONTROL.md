# Stack And VarName Queue Control Follow-up

Status: all three controls implemented. The local PTMX formal run remains on the
submitted binary; the restarted DSP formal run uses the improved binary.

## Motivation

The DSP diagnostic run showed that full MRP identity includes both VarName and
stack context. Different stacks under the same VarName family can therefore
create distinct corpus and validation-queue records. The previous in-memory
stack limit was applied after an entry had already become eligible for manager
persistence, so it did not reliably bound validation input.

## Change 1: Pre-persistence Stack Cap

`handleDiscoveredPairs` now applies `VarNamePairRegistry.FilterRacePairs` before
creating a race-corpus entry. The default and follow-up runner value is 10 stack
variants per canonical unordered VarName family.

Pairs beyond the budget are marked seen by the discovery store but are not
persisted or submitted to the validation queue. History newness is evaluated
before recording retained pairs in the registry.

Configuration:

```json
"max_stacks_per_varname_pair": 10
```

## Change 2: Per-family Active Validation Cap

The existing VarName scheduler can optionally cap concurrently executing tasks
that share a canonical unordered VarName family. Blocked tasks stay in the
internal scheduler and are released when an active task completes; they are not
discarded or acknowledged early.

Configuration:

```json
"experimental": {
  "uaf_validate": {
    "max_concurrent_per_varname": 2
  }
}
```

Zero disables the concurrency cap. The active formal experiments use zero and
the already generated configs unless explicitly enabled by the runner.

## Change 3: Soft Collection-miss Backoff

Collection reproducibility is tracked separately from targeted-scheduling
failure Fp. The first two consecutive misses have no penalty. Later misses use
a weighted task-level defer probability capped at 75%, preserving at least 25%
exploration. A stable collection hit resets the consecutive-miss penalty.

```json
"enable_collection_miss_backoff": true
```

Statistics are stored by canonical unordered VarName family in
`collection_miss_backoff.db` and do not modify `varname_backoff_stats.db`.

## Validation

- A fuzz-side integration test verifies that a third stack is not made
  persistable when the stack budget is two.
- A scheduler test verifies that reversed VarName order maps to the same family,
  a second stack waits while the family slot is occupied, and it becomes
  runnable after completion.
- Reproduction-backoff tests verify the two free misses, weighted probability,
  75% cap, reversed-family sharing, and reset after a collection hit.
- `pkg/racevalidate`, `pkg/mgrconfig`, and `syz-manager` tests pass.
- Targeted `pkg/fuzzer` tests pass.
- A complete temporary manager build succeeds.
- The full `pkg/fuzzer` suite still hits the repository's pre-existing GCC
  `no_sanitize_coverage` warning promoted to an error in `TestFuzz`.

## Experiment Policy

Do not mix old and improved DSP matrices. The corrected old-binary DSP matrix
was interrupted before restart. The improved DSP matrix uses stack cap 10,
family concurrency cap 2, and collection-miss backoff in all four threshold
arms. Primary diagnostics remain validation records/min, pending peak and area,
Dynamic threshold trajectory, unique VarName families, and confirmed races.
