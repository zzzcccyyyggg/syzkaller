# DSP Canonical-Family Controller Diagnostic

## Question

Does accounting `P/C/Q` as active canonical VarName-pair families avoid the
Stack-context amplification and rapid threshold oscillation observed with
queue-pair-record accounting?

This is a diagnostic run, not a formal threshold-ablation result.

## Family lifecycle

- `P`: increment when a canonical unordered VarName pair changes from absent
  to present in the persistent validation queue.
- `Q`: number of distinct canonical unordered VarName pairs currently present
  in the queue.
- `C`: increment when the last queued record for an active family is consumed.
- Additional Stack variants do not increment `P` while their family remains
  pending. The validation data path still retains and tests those variants.

## Frozen configuration

```text
run id             = 20260824-local-dsp-family-controller-dynamic-gpt54api-24f24v-12c12c-2h-v2
module             = dsp
duration           = 2h
policy             = dynamic backpressure
counter unit       = queue-varname-family
threshold          = initial 1000us, min 100us, max 2000us
control interval   = 30s
Wlow / Whigh       = 10 / 40

fuzz cpuset        = 0-11
fuzz VMs           = 24 x 2 vCPU, 1GiB, procs=2
validate cpuset    = 12-23
validate VMs       = 24 x 2 vCPU, 1GiB
LLM cpuset         = 24
LLM                = GPT-5.4 direct Responses API, medium
LLM supply         = 6 entries/round, 3 parallel calls

validation repeat  = 2, stable minimum 1
stack cap          = 10 per VarName pair
family concurrency = 1
collection miss backoff = enabled
```

## Collection isolation

```text
collection_threshold_floor_us = 0
```

Validation therefore uses each entry's admission threshold. The separate 2ms
collection-floor change is deliberately disabled so this run isolates the
controller accounting unit.

## Build

```text
manager = bin/syz-manager-family-controller
sha256  = f042fd210fbc29a9fd8a5a9844836bca30da7863b926e05ae8a34a2ef518e301
```

## Health checks

- Both fuzzer and validator sections of `threshold-state.json` report
  `queue-varname-family`.
- Fuzz calls and family production advance after VM boot.
- `P/C/Q` remain in the same unit.
- Pair-record storage totals are retained separately for diagnosis.
- No 2ms collection floor appears in either generated config.
- Memory stays above 8GiB and disk stays above 25GiB.

## Interpretation

The primary signals are threshold trajectory, time at each bound, active
family backlog, family production/consumption, raw pair-record backlog, and
confirmed race families. Raw MRP or Stack-pair counts must not be substituted
for family-level `P/C/Q` when interpreting controller decisions.

## Launch history

- `v1` verified live family accounting but stopped at the disk guard while
  validation images were being created. It is diagnostic-only and not used as
  a result.
- The completed 2ms validation-only run had retained 24 disposable validation
  images. Removing only those images recovered sufficient space without
  deleting its databases or logs.
- `v2` is the fresh run governed by the frozen configuration above.

## Early v2 health checkpoint

At `2026-08-24T20:20:31+12:00`:

```text
calls executed       = 1,389
raw pair records     = 469 total, 276 pending, 193 processed
family activations P = 241
family completions C = 97
active families Q    = 144
invariant            = P = C + Q = 241
threshold            = 100us
QEMU                 = 24 fuzz + 24 validate
available memory     = 54GiB
free disk            = 42GiB
```

The family accounting is internally consistent and compresses the live raw
pair backlog from 276 records to 144 families. It nevertheless crosses the
paper's `Whigh=40` during validator cold start, so family accounting alone does
not prevent an initial drop to the lower threshold at this producer scale.
