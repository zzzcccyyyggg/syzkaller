# F2FS 24-hour four-arm launch record

## Frozen experiment

```text
host date              = 2026-08-25 (Pacific/Auckland)
repository commit      = bec04c6cdf5934dc708de43de5f1b9ba560d1763
manager SHA256         = ef0260f8a6733ee807bab64c8be51639e2167409ee865bacb6cc31a6aec1fe8b
executor SHA256        = 99fd19c794c05765d67f0a5efc24b0098c6309ff41719de9539b83065f3a75cc
initial corpus SHA256  = 6dd501a31fc66dcf0a95e8af26e5888340b4bdf2b5936f5cbfcb3c21160529a9
duration per arm       = 86400s
threshold range        = [50us, 10000us]
manager/kernel precise delay cap = 1s/10s
```

All arms use 2 fuzz physical CPUs with two 2-vCPU fuzz VMs, 2 validation
physical CPUs with four 2-vCPU validation VMs, and one separate LLM CPU.
Validation configuration, manager, executor, kernel, corpus, and GPT-5.4 direct
API budget are identical across arms.

## Runs

```text
arm          run id                                                               running at                    tmux session
Dynamic      20260825-local-f2fs-2core24h-range50-10000-dynamic-gpt54api-v1     2026-08-25 17:17:44 +12:00    f2fs24-dynamic
Random       20260825-local-f2fs-2core24h-range50-10000-random-gpt54api-v1      2026-08-25 17:17:52 +12:00    f2fs24-random
Fixed-50     20260825-local-f2fs-2core24h-fixed50-gpt54api-v1                    2026-08-25 17:18:02 +12:00    f2fs24-fixed50
Fixed-10000  20260825-local-f2fs-2core24h-fixed10000-gpt54api-v1                 2026-08-25 17:18:12 +12:00    f2fs24-fixed10000
```

Each runner stops at its own 24-hour boundary on 2026-08-26. Results are not
drained after that boundary.

## Preflight evidence

The forced-20s precise-delay smoke run kept QEMU alive but completed no
verification in ten minutes (`processed=6`, `pending=215`). It was rejected.

The forced-10s smoke run completed strict, range, and stack-only verification;
at its cutoff the validator was idle with `processed=18`, `pending=0`. It passed
without timeout, guest stall, or panic. The formal runs therefore retain the
50-10000us observation range but cap effective precise delay at 10 seconds.

Before launch, 19.46GiB of stopped-run, reproducible VM snapshots and temporary
F2FS side disks were removed. Corpus databases, pair indexes, logs, and reports
were retained. Free disk before formal launch was 92GiB.

## Startup health

At approximately six minutes, all four runners were alive and each reported
two fuzz and four validation QEMU processes. Calls executed increased in every
arm. Every LLM producer completed at least one GPT-5.4 request, accepted output,
and reported zero API failures.

Dynamic and Fixed-50 each observed one fuzz-guest RCU stall during startup.
Both managers automatically rebooted the affected VM; calls subsequently
resumed (`1049 -> 1798` for Dynamic and `445 -> 502` for Fixed-50). These are
recorded as recoverable fuzz events, not hidden from the result.

```text
arm          calls  tau(us)  produced  processed  pending  LLM calls  accepted
Dynamic       1798      500       127         34       93          3         6
Random        1491     3650       279        107      194          3         6
Fixed-50       502       50         6          6        0          3         6
Fixed-10000   1461    10000       779        105      674          2         4
```

The table is a startup snapshot, not an experiment result. No validated race
had been reported at this early checkpoint.

## Fixed-10000 replacement run

The original Fixed-10000 runner stopped at `2026-08-25 18:01:56 +12:00`
after `calls executed=14922` remained unchanged for the global 240-second
stall window. Its final threshold counters were `P/C/Q=1800/111/1689`.

The direct trigger was fuzz-guest recovery rather than validator exit or a
resource floor: one guest disconnected at 17:59:44, started rebooting at
18:00:04, and reconnected at 18:01:06. Calls had not resumed by 18:01:56, so
the runner stopped both managers. The v1 directory and evidence are retained,
but v1 is not a complete formal arm.

Fixed-10000 was restarted from the frozen initial corpus as a new full 24-hour
run. Experiment semantics are unchanged; only the operational stall watchdog
was raised from 240 to 600 seconds.

```text
run id       = 20260825-local-f2fs-2core24h-fixed10000-gpt54api-v2
running at   = 2026-08-25 18:36:06 +12:00
tmux session = f2fs24-fixed10000-v2
```

During v2 startup, both fuzz guests again rebooted after an RCU stall and a
`panic_on_warn`. They reconnected at 18:38:52 and 18:39:11; calls then resumed
from 181 to 476. At the recovery checkpoint, all `2 fuzz + 4 validate` VMs were
online, `P/C/Q=104/42/62`, and GPT-5.4 had accepted four variants with zero API
failures. This confirms that the longer watchdog prevents a recoverable dual-VM
restart from truncating the arm.

## Operations

Per-run state and watcher records are under:

```text
paper/artifacts/claims/added-threshold-control/runs/<run-id>/state.json
paper/artifacts/claims/added-threshold-control/runs/<run-id>/watcher/ticks.jsonl
paper/artifacts/claims/added-threshold-control/runs/<run-id>/logs/
```

To stop one arm cleanly, send Ctrl-C to its tmux session. Do not kill manager or
QEMU children directly because the runner owns cleanup and final state writing.
