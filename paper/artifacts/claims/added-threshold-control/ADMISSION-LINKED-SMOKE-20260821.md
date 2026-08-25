# Admission-Linked Validation Smoke

Date: 2026-08-21

## Change Under Test

New race-corpus entries persist the fuzz request's admission threshold. The
same threshold is propagated through the pair index and validation queue, then
used as the validation collection threshold. Legacy entries without the field
use an explicit 10000us compatibility fallback.

Validated records now carry admission threshold, collection threshold,
observed `TimeDiff`, origin-match class, and expansion status.

## Fixed-1000 Smoke

- Run: `runs/20260821-ptmx-admission-threshold-smoke-v1`
- Resources: 1 fuzz QEMU and 1 validation QEMU, 2 vCPU and 2 GiB each.
- Duration: 493 seconds.
- Health: pass; 1327 calls executed during the measured interval.
- The first collection logged `collection_threshold=1000us` and
  `admission_threshold=1000us`.
- It returned 5 stable pairs, all 5 associated with the entry's original
  VarName pairs.
- Corpus, pair-index, and queue records all carried `admission_threshold_us=1000`.

## Dynamic Smoke

- Run: `runs/20260821-ptmx-admission-threshold-dynamic-smoke-v1`
- Resources: 1 fuzz QEMU and 1 validation QEMU, 2 vCPU and 2 GiB each.
- Duration: 492 seconds.
- Health: pass; 2141 calls executed during the measured interval.
- The controller changed `1000 -> 500 -> 250 -> 125 -> 62 -> 50us`.
- While the current controller value was already lower, validation processed a
  previously admitted entry with `collection_threshold=1000us`.
- A later entry logged `collection_threshold=250us` and
  `admission_threshold=250us`, confirming per-entry historical binding.
- The 1000us collection returned 5 stable pairs; the observed 250us collection
  returned 3 stable pairs.
- Final corpus thresholds: 1000us (8 records), 500us (5), 250us (3), 125us (3),
  and 50us (2). Pair-index and queue records preserved the same threshold field.

## Interpretation

The propagation works in real QEMU execution and does not read the producer's
current threshold at validation time. A longer pilot is still required to
measure whether narrower collection windows improve steady-state queue drain
and allow the dynamic controller to recover from its early tightening phase.
