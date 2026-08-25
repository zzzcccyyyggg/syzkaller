# PTMX Threshold-Control Pilot Interpretation

## Evidence Status

This is an exploratory 30-minute, single-run stress pilot. It is useful for validating the controller and exposing threshold sensitivity, but it is not paper-grade rebuttal evidence.

## Configuration

- Module: PTMX.
- Variants: dynamic `[500, 10000]us` from `2500us`, and fixed `500us`, `2500us`, `10000us`.
- Per variant: 1 fuzz VM plus 1 validation VM, each with 2 vCPUs and 4 GiB RAM.
- Input: the same archived Kimi-2.6 accepted seed set.
- Replay pressure: 12 groups every 10 seconds, up to 72 groups/minute.
- Validation: complete replay/verify path, with queue tasks capped at 8 input pairs. Re-observed stable-pair fanout remained uncapped.

The historical Kimi producer accepted 474 groups over approximately 594 minutes, or about 0.80 group/minute. This pilot therefore replays LLM groups at up to roughly 90 times the historical rate and should be interpreted as an overload stress test.

## Main Results

All valid variants executed a similar number of calls (8,023-8,561), so the pair/backlog differences are not explained by one configuration receiving substantially less execution time.

| Variant | Calls | Pairs | Corpus | Corpus / pair | Pending | Processed | Validated |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Dynamic | 8,322 | 1,765 | 84 | 4.76% | 268 | 1 | 0 |
| Fixed-500 | 8,561 | 1,337 | 103 | 7.70% | 221 | 1 | 0 |
| Fixed-2500 | 8,352 | 3,467 | 137 | 3.95% | 508 | 0 | 0 |
| Fixed-10000 | 8,023 | 4,296 | 123 | 2.86% | 591 | 1 | 0 |

Relative to Fixed-2500, Dynamic admitted 49.1% fewer pairs and ended with 47.2% fewer pending tasks. Relative to Fixed-10000, it admitted 58.9% fewer pairs and ended with 54.7% fewer pending tasks. Fixed-10000 produced fewer corpus entries than Fixed-2500 despite admitting more pairs, indicating additional low-value candidate pressure.

The dynamic trajectory was:

```text
2500us -> 1250us -> 625us -> 500us
```

All three changes were `paper-backpressure-shrink` decisions based on fresh validator state. The controller reached the lower bound in approximately 90 seconds.

## Supported Claims

1. Threshold choice materially affects MRP supply and validation backlog.
2. The repaired cross-process state channel provides live validator observations to the controller.
3. Under overload, the controller quickly tightens admission and avoids the continued queue growth seen with fixed 2500us and 10000us.
4. A very wide threshold can reduce candidate efficiency: Fixed-10000 generated the most pairs and largest backlog without increasing validated races in this pilot.

## Unsupported Claims

1. This pilot does not show that Dynamic outperforms the best fixed threshold. On PTMX, Fixed-500 produced more corpus entries with fewer pairs and a smaller backlog than Dynamic.
2. This pilot does not establish better bug-finding effectiveness. No variant confirmed a validated race within 30 minutes.
3. It does not evaluate the reviewer-requested randomized-threshold baseline.
4. It cannot support a general cross-module conclusion because it uses one module, one repeat, and an intentionally accelerated LLM replay rate.

The defensible interpretation is that Dynamic recovered from an initially unsuitable threshold without prior PTMX-specific tuning. It should not be claimed to beat an oracle fixed threshold selected after observing PTMX.

## Incidents and Data Selection

- The first Fixed-500 launch stalled at 63 calls for 240 seconds and was terminated by the watchdog. Its directory is preserved as `20260821-ptmx-fixed500-kimi-pilot30m-v1` with status `failed-stalled`.
- `retry1` used the same threshold, CPU allocation, Kimi source, and duration, and completed normally. It is the Fixed-500 row in the summary.
- An earlier Kimi burst smoke loaded all 474 groups immediately and demonstrated overload shrink, but it is excluded from the comparison matrix.

## Next Experiment

1. Replay Kimi seeds at the observed historical rate: one group every 60 seconds.
2. For a short quick-look only, cap re-observed stable pairs per entry so that completed validation outcomes are observable; disclose this cap and do not mix it with the final 24-hour configuration.
3. Add a lower pair-density module, such as DSP, to test whether Fixed-500 starves candidate supply while Dynamic relaxes.
4. Implement and pre-register a randomized baseline, including its distribution, update interval, and seed.
5. Freeze the final configuration and run Dynamic, Fixed-min, Fixed-initial, Fixed-max, and Random for 24 hours with independent repeats.
