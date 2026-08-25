# F2FS 8h Pair-Record Threshold Matrix

## Objective

Compare Dynamic admission against Fixed-100us, Fixed-1000us, and Fixed-5000us
on F2FS while limiting per-family Stack expansion and aggressively deferring
families that repeatedly fail validation collection.

## Four arms

```text
Dynamic     = initial 1000us, range [100us, 5000us]
Fixed-100   = 100us
Fixed-1000  = 1000us
Fixed-5000  = 5000us
duration    = 8h wall clock per arm
```

## Shared configuration

```text
threshold counter unit = queue-pair-record
family-controller      = disabled
P                      = newly activated persistent queue records
C                      = records taken by a validation worker
Q                      = records still waiting in Queued state
Stack cap              = 4 per VarName pair
family concurrency     = 1

collection floor       = 0 (admission-linked)
collection miss backoff:
  free attempts        = 1
  weight               = 0.95
  max defer            = 0.90

validation repeat      = 2
stable minimum         = 1
strict/range delay     = normalized to 100ms userspace / 1s kernel
stack-only delay       = 1ms userspace / 10ms kernel
```

Each arm uses:

```text
fuzz        = 6 VM x 2 vCPU, procs=2, pinned to 6 physical CPUs
validation  = 12 VM x 2 vCPU, pinned to 6 physical CPUs
VM memory   = 1GiB
LLM         = GPT-5.4 direct Responses API, medium reasoning
LLM supply  = 6 entries/round, 3 parallel calls
```

The four arms use disjoint CPU sets and independent workdirs, queue databases,
validation databases, LLM state, and QEMU images. They share only immutable
initial artifacts.

## F2FS VM isolation

The immutable `images/f2fs-2G.raw` image is passed as `-hdb`. The repository's
QEMU layer creates a standalone qcow2 copy for every VM, so neither different
VMs nor different arms write the same F2FS disk. KCOV is disabled for this
F2FS kernel; input generation uses the frozen static corpus and MRP feedback.

## Build and assets

```text
manager = bin/syz-manager-started-consumption
sha256  = 7e94146fda8ada372f13276951a0e709afb80884f8f19fd8de6ad45026462af4
```

Frozen F2FS artifacts are hash-checked by the runner before launch.

## Primary metrics

- unique confirmed VarName families and VarName+Stack pairs;
- MRP supply and validation processed/pending records;
- stable collection tasks and pairs;
- collection-miss defer counts;
- threshold trajectory and bound residence for Dynamic;
- calls executed, LLM accepted programs, model calls, and tokens.

## Launch record

The first four-arm launch at `2026-08-24T22:05:17+12:00` was deliberately
stopped after diagnosing that C was updated only after full task completion.
Those directories are retained as diagnostic data and are not matrix results.

The corrected four arms started on `10.130.157.5` at
`2026-08-24T23:06:07+12:00`; their expected wall-clock cutoff is approximately
`2026-08-25T07:06:07+12:00`.

```text
Dynamic:
  20260824-remote-f2fs-cstarted-pair-stack4-repro095-dynamic-gpt54api-6f12v-1g-8h-v2
Fixed-100:
  20260824-remote-f2fs-cstarted-pair-stack4-repro095-fixed100-gpt54api-6f12v-1g-8h-v2
Fixed-1000:
  20260824-remote-f2fs-cstarted-pair-stack4-repro095-fixed1000-gpt54api-6f12v-1g-8h-v2
Fixed-5000:
  20260824-remote-f2fs-cstarted-pair-stack4-repro095-fixed5000-gpt54api-6f12v-1g-8h-v2
```

The final pre-launch smoke was
`20260824-remote-f2fs-started-consumption-smoke-pair-2f2v-5m-v1`; it passed
with two fuzz and two validation VMs. During startup it reported
`P=92, C=13, Q=79`, preserving `P=C+Q` and avoiding the old implementation's
immediate `C=0` signal. Earlier smoke attempts are startup diagnostics and are
not used as matrix evidence.

## Corrected startup checkpoint

At `2026-08-24T23:09:58+12:00`, all four corrected arms were running:

```text
              P     C_started   Q_waiting   threshold
Dynamic      79        44          35        1000us
Fixed-100    11        11           0         100us
Fixed-1000   46        30          16        1000us
Fixed-5000  258        97         161        5000us
```

Each arm satisfies `P = C_started + Q_waiting`. Dynamic had completed several
control intervals without an adjustment and remained at 1000us. Under the old
completion-based C accounting, the corresponding startup phase reported C=0
and reduced Dynamic from 1000us to 100us in four consecutive intervals.

## Threshold-aware Dynamic rerun

The corrected Dynamic v2 run was stopped at
`2026-08-25T02:36:42+12:00` after showing that high-threshold records retained
normal validation priority after the controller reduced tau. The three Fixed
arms continue unchanged.

A new Dynamic-only 8h run started at `2026-08-25T02:48:29+12:00`:

```text
run id:
  20260825-remote-f2fs-thprio-cstarted-pair-stack4-repro095-dynamic-gpt54api-6f12v-1g-8h-v3
manager:
  bin/syz-manager-threshold-priority
sha256:
  e6b378a19d19098581a4b36eac92ef650c0f707c72f967493b17f1a9a3430fad
expected cutoff:
  2026-08-25T10:48:29+12:00
```

Its validation scheduler recomputes priority whenever a worker requests work:

```text
tier 0 = TimeDiff <= current tau and previously unscheduled family
tier 1 = TimeDiff <= current tau and previously scheduled family
tier 2 = TimeDiff >  current tau and previously unscheduled family
tier 3 = TimeDiff >  current tau and previously scheduled family
```

Within one tier, smaller TimeDiff, shorter history, and then stable entry key
win. Wide candidates remain persistent and regain normal priority when tau
increases; no candidate is deleted by this policy.

The Dynamic-only rerun and the three remaining Fixed arms were subsequently
stopped and retained as diagnostic evidence because their validation delay was
normalized by the admission threshold. Algorithm 2 in the paper instead uses a
fixed `lambda * observed_delta` scheduling delay.

## Paper-lambda four-arm restart

The replacement matrix started together at `2026-08-25T12:25:34+12:00` and is
scheduled to stop at `2026-08-25T20:25:34+12:00`:

```text
Dynamic [500,5000]:
  20260825-remote-f2fs-lambda200-stack40-thprio-dynamic500-5000-gpt54api-6f12v-1g-8h-v1
Fixed-500:
  20260825-remote-f2fs-lambda200-stack40-thprio-fixed500-gpt54api-6f12v-1g-8h-v1
Fixed-5000:
  20260825-remote-f2fs-lambda200-stack40-thprio-fixed5000-gpt54api-6f12v-1g-8h-v1
Random uniform [500,5000]:
  20260825-remote-f2fs-lambda200-stack40-thprio-random500-5000-gpt54api-6f12v-1g-8h-v1
```

All four arms use the same manager and validation configuration:

```text
manager sha256                 = a017dd32672d4dd381999fdd6db7bc599cbb2350bb4e400ab558a645cca78d12
manager precise multiplier     = 200
manager stack-only multiplier  = 40
kernel multiplier              = 10
effective precise lambda       = 2000
effective stack-only lambda    = 400
syscall/program/batch timeout  = 20s / 180s / 900s
threshold-aware priority       = enabled
target report match            = both VarName endpoints required
```

The initial corpus SHA256 is
`6dd501a31fc66dcf0a95e8af26e5888340b4bdf2b5936f5cbfcb3c21160529a9`
for every arm. Generated validation configs were byte-equivalent. The Fixed-5000
smoke `20260825-remote-f2fs-lambda200-stack40-fixed5000-smoke-2f2v-10m-v1`
passed, and the delay stress smoke
`20260825-remote-f2fs-lambda-delay10s-stress-smoke-2f2v-5m-v1` completed an
effective 10-second kernel delay without timeout or RCU stall.

At the startup audit, all four arms entered real verification. Observed examples
matched the frozen multiplier exactly, and Fixed-5000 reached an effective
8.898-second delay without a validation deadline failure.
