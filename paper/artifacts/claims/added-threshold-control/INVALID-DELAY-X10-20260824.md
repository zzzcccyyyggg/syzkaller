# Invalid Threshold Runs: Access Delay x10

The following threshold-ablation matrices were stopped on 2026-08-24 and must
not be used as formal results:

- `20260823-local-ptmx-threshold-formal-gpt54api-wave1-6f12v-1g-8h-v3`
- `20260823-remote-dsp-threshold-formal-gpt54api-4arm-6f12v-1g-8h-v1`

## Cause

The matrix runners used manager-level delay values `10000/1000000/1000000us`
and stack delay `10000us`. The experiment kernel applies a fixed x10 multiplier,
so the effective strict/range delay was `100ms-10s` and stack-only delay was
`100ms`, rather than the intended `10ms-1s` and `10ms`.

## Disposition

The runs are retained only as diagnostic evidence. Their race counts, queue
rates, throughput, and token usage must not be mixed with corrected formal runs.
The corrected manager-level values are:

```text
min=1000us
target=100000us
max=100000us
stack=1000us
```

Both PTMX and DSP formal matrices must be restarted from clean workdirs and the
same frozen initial corpora after corrected smoke tests pass.
