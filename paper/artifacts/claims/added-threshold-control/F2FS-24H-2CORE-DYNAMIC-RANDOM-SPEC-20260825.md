# F2FS threshold ablation: 2+2 physical cores for 24 hours

Status: approved experiment specification; no result is implied by this file.

## Question

Does the paper's backpressure controller outperform a feedback-free Random
threshold policy and the two fixed endpoints when all four arms are evaluated
using the original four-physical-core budget rather than the accelerated
12-core profile?

The controller watermarks and 30-second interval are absolute. Reducing the
producer and consumer rates may keep `Q/max(Cbar, epsilon)` below the high
watermark more often, allowing Dynamic to relax its threshold instead of
remaining at the lower bound. This is a hypothesis, not a promised outcome.

## Arms

```text
Dynamic:
  initial tau = 1000us
  range       = [50us, 10000us]
  policy      = paper backpressure
  relax step  = ceil(0.05 * (10000 - 50)) = 498us

Random:
  initial tau = 1000us
  range       = [50us, 10000us]
  policy      = discrete uniform inclusive sample every 30s
  seed        = 1592594996

Fixed-50:
  tau         = 50us

Fixed-10000:
  tau         = 10000us
```

Random does not read validator feedback. All four arms use the same code,
kernel, corpus, validation behavior, and resource density. Fixed-50 and
Fixed-10000 isolate the strict and broad endpoints of the exact range available
to Dynamic and Random.

## Resource budget per arm

```text
duration             = 24h
fuzz physical CPUs   = 2
fuzz VMs             = 2 x 2 vCPU, 1GiB, procs=2
validate physical CPUs = 2
validate VMs         = 4 x 2 vCPU, 1GiB
LLM CPU              = 1 separate host CPU
VM lifetime          = 1h
```

Each stage consumes 48 core-hours (`2 cores * 24h`), equal to the accelerated
`6 cores * 8h` profile. The validation density follows the completed PTMX
density diagnostic: two validation VMs per physical CPU.

Host allocation:

```text
arm          fuzz CPUs  validate CPUs  LLM CPU  HTTP base
Dynamic      0-1        2-3            4        64700
Random       5-6        7-8            9        64800
Fixed-50     10-11      12-13          14       64900
Fixed-10000  15-16      17-18          19       65000
```

CPUs 20-31 remain available to the host and watcher. Concurrent arms must pass
`--allow-existing-experiments`; disjoint CPU sets, ports, and run directories
provide isolation.

## LLM budget

```text
provider          = direct Responses-compatible HTTP
model             = gpt-5.4
reasoning         = medium
entries/round     = 2
variants/entry    = 2
parallel calls    = 1
poll interval     = 30s
```

This is the 0.5x supply per arm corresponding to the frozen 4-core/12h profile
(`4 entries, 2 parallel`) and the 1/3 supply corresponding to the accelerated
6-core/8h profile (`6 entries, 3 parallel`). Actual calls and tokens must be
reported rather than assumed equivalent.

## Shared validation behavior

This experiment deliberately retains the restored expansion behavior used by
the preceding threshold experiments:

```text
collection threshold       = entry admission threshold
require_origin_match       = false
origin match mode          = varname
novel runtime families     = allowed
threshold-aware priority   = enabled
Stack cap                  = 4 per canonical VarName family
family concurrency         = 1
max tasks per corpus       = 3
collection repeat/stable   = 2/1
verification repeat        = 1
```

Scheduling delay:

```text
manager precise multiplier = 200
manager StackOnly multiplier = 40
kernel multiplier          = 10
effective precise lambda   = 2000
effective StackOnly lambda = 400
manager precise delay cap  = 2000000us
effective precise delay cap = 20s
syscall/program/task/batch timeout = 40s/300s/300s/1200s
```

At the 10ms observation endpoint, precise/range validation can request a 2s
manager delay, which the kernel multiplies to 20s. StackOnly validation can
request at most 400ms at the manager and 4s in the kernel. A short QEMU stress
run at the 20s precise cap is required before the four formal arms start.

## Frozen inputs and builds

```text
initial corpus SHA256 = 6dd501a31fc66dcf0a95e8af26e5888340b4bdf2b5936f5cbfcb3c21160529a9
manager SHA256        = ef0260f8a6733ee807bab64c8be51639e2167409ee865bacb6cc31a6aec1fe8b
executor SHA256       = 99fd19c794c05765d67f0a5efc24b0098c6309ff41719de9539b83065f3a75cc
```

The four arms must use independent workdirs, ports, QEMU images, LLM state, and
CPU sets. They may share only immutable inputs.

## Launch and health contract

Startup is healthy only when each arm has two fuzz QEMU processes and four
validation QEMU processes, both managers remain alive, `calls executed`
increases, and the LLM producer records successful model responses. During the
first 30 minutes, inspect each arm every five minutes for guest stalls,
disconnects, syscall/program timeouts, memory below 25GiB, or disk below 25GiB.
After stabilization, inspect hourly. Any frozen-configuration mismatch requires
stopping and restarting all four arms in new run directories.

Runner:

```text
script = paper/artifacts/claims/added-threshold-control/run_threshold_12h_kimi.py
logs   = paper/artifacts/claims/added-threshold-control/runs/<run-id>/logs/
state  = paper/artifacts/claims/added-threshold-control/runs/<run-id>/state.json
ticks  = paper/artifacts/claims/added-threshold-control/runs/<run-id>/watcher.jsonl
stop   = send SIGINT to the runner process group; it stops managers and QEMU
```

## Metrics

Primary:

- unique validated canonical VarName families at the 24h cutoff;
- unique VarName+Stack pairs;
- exact/VarName/novel provenance;
- threshold trajectory and time at each bound;
- cumulative `P`, consumed `C`, pending `Q`, and queue area over time.

Secondary:

- calls executed and program attempts;
- stable/no-stable collection tasks and verification modes;
- model calls, accepted programs, input/output/reasoning/total tokens;
- guest stalls, disconnects, timeouts, and VM restarts.

## Validity rules

- Stop all four arms at exactly 24 hours; do not drain queues afterward.
- Do not modify one arm after launch.
- A startup failure must be restarted from a new run directory for all four arms if
  it affects frozen configuration or resource symmetry.
- Raw validated families are automatic results, not manually confirmed
  paper-grade races.
- This configuration is not mixed with the abandoned strict-`P_G` diagnostic.
