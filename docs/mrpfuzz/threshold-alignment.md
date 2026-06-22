# MRPFuzz Threshold Alignment

This note records how the paper-level threshold design maps to the current
repository implementation and to the June 2026 experiment configuration.

## Current Truth Source

For the paper-result lineage under
`paper/results/mrp-24h-comparison/20260609-segfuzz0p5x-llm3way-reference-style`,
the effective MRPFuzz experiment settings are the generated config values, not
the generic code fallbacks:

- `normal_threshold_micros = 10000`
- `enable_dynamic_threshold = true`
- `dynamic_threshold_initial_us = 2500`
- `dynamic_threshold_min_us = 500`
- `dynamic_threshold_max_us = 10000`
- `dynamic_threshold_eval_sec = 120`
- `widened_threshold_micros = 20000`

These are set by `scripts/generate_config.py` and mirrored in
`scripts/defer_followup_experiments.py` and `scripts/EXPERIMENT_RUNBOOK.md`.

If an executor request carries `timing_threshold_us = 0`, the executor fallback
is 10ms. Several old comments still said 2ms; those are stale.

## Paper Model

The paper defines an MRP as a conflicting cross-thread access pair whose
temporal distance satisfies:

```text
Delta t <= tau
```

In Section 3.3, `tau` is described as a dynamic admission-control threshold.
The paper's Algorithm 1 presents an idealized backpressure controller:

- The fuzzer is the producer, the validator/scheduler is the consumer.
- The schedule-worthy corpus is the queue between them.
- At each control interval `Tc`, the controller observes new produced inputs
  `Pk`, consumed inputs `Ck`, and queue length `Qk`.
- It maintains EWMA rates `Pbar` and `Cbar`.
- It shrinks `tau` multiplicatively when workload is above the high watermark
  and production is not below consumption.
- It grows `tau` additively when the queue is empty, or workload is below the
  low watermark and production is not above consumption.

The current PDF text states representative paper parameters:

- `Tc = 30s`
- `Wlow = 10`
- `Whigh = 40`
- `rho = 0.8`
- `epsilon = 1`
- `gamma_shrink = 0.5`
- additive relaxation step `Delta tau = 0.05 * (tau_max - tau_min)`

## Current Implementation

The production implementation is in `pkg/fuzzer/threshold_controller.go`. It is
a backlog-watermark variant of the paper idea rather than a literal
implementation of Algorithm 1.

The controller reads:

- fuzzer side: total discovered MRP count, converted to a discovery rate
- validator side: `pending_count`, `processed_count`, `success_count`,
  `processing_rate_per_min`, `idle`, and `last_update` from
  `threshold-state.json`

When validator stats are fresh, adjustment is mainly driven by backlog:

- If `pending_count > PendingHighWatermark` for two consecutive windows, shrink.
- If `pending_count < PendingLowWatermark` and `idle = true` for three
  consecutive windows, grow.
- Otherwise stay stable.

With the generic fallback config, the watermarks are `5` and `50`. In current
experiment configs only the initial/min/max/eval values are overridden, so these
watermarks remain `5` and `50`.

The implementation deliberately dampens changes:

- configured `GrowFactor = 1.5`, effective validator-backed grow factor `1.25`
- configured `ShrinkFactor = 0.6`, effective validator-backed shrink factor
  `0.8`

When validator stats are absent or stale, the controller enters supply-only
mode:

- It may grow when discovery rate stays below `1 MRP/min` for two windows.
- It does not shrink without validator feedback.

Timing exploration uses a related but separate threshold policy:

- Normal fuzz requests use the current dynamic threshold.
- Timing Phase 1 uses
  `max(current_dynamic_threshold * 8, widened_threshold_micros)`.
- Timing Phase 2 returns to the current dynamic threshold.

For current experiments this means Phase 1 is never below `20000us`, while the
normal dynamic threshold is bounded to `[500us, 10000us]`.

## Mismatches To Track

1. Algorithm shape:
   The paper pseudocode uses EWMA producer/consumer rates and queue length.
   The code uses validator pending/idle state plus fuzzer discovery rate.

2. Control interval and watermarks:
   The paper text says `Tc=30s`, `Wlow=10`, `Whigh=40`.
   Current experiments run `dynamic_threshold_eval_sec=120`; watermarks remain
   the code fallbacks `5` and `50`.

3. Adjustment rule:
   The paper grows additively and shrinks by `gamma_shrink=0.5`.
   The code grows and shrinks multiplicatively, with conservative dampening
   (`1.25x` grow and `0.8x` shrink under validator-backed control).

4. Threshold bounds:
   The generic controller fallback is `[50us, 50000us]`, but the current paper
   experiments use `[500us, 10000us]`.
   Therefore any statement that baselines use `tau_max` should be interpreted
   for the current paper experiments as `tau_max = 10000us`.

5. Executor fallback:
   The actual executor fallback is 10ms when request threshold is zero. Old
   comments saying 2ms are historical residue.

6. Widened threshold:
   The generic timing-exploration fallback is 500ms, while current experiment
   configs use 20ms as the Phase 1 floor.

7. Naming:
   Several code paths still use UAF names (`uaf_mode`, `MayUAFPair`,
   `uaf-corpus.db`) for race/MRP logic. This is naming debt, not a threshold
   behavior difference.

## Recommended Cleanup Direction

For reproducibility, do not change threshold behavior before the current paper
artifact is frozen. The June result lineage depends on the implemented
backlog-watermark controller and the generated config values listed above.

The lowest-risk cleanup is:

- keep `scripts/generate_config.py`, `scripts/defer_followup_experiments.py`,
  and `scripts/EXPERIMENT_RUNBOOK.md` as the experiment truth source;
- keep code fallbacks, but label them as generic fallbacks rather than paper
  experiment defaults;
- remove stale comments that mention 2ms;
- document that the implementation is a production backlog-watermark variant of
  the paper's backpressure algorithm.

If exact paper-code equivalence is required later, treat it as a separate
behavior-changing task:

- add EWMA producer/consumer accounting to `ThresholdSharedState`;
- make the evaluation interval and watermarks match the paper or make the paper
  state the implemented values;
- change grow to additive relaxation;
- add regression tests that pin shrink/grow decisions and experiment config
  generation.
