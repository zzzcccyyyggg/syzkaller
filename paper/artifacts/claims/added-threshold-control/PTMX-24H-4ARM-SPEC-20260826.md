# PTMX 24-hour four-arm formal experiment

Status: approved for launch on the local host on 2026-08-26.

## Question

Compare Dynamic, Random, Fixed-50, and Fixed-10000 on PTMX under equal physical
resources and the same frozen initial corpus, kernel, userspace binaries, LLM
budget, and validation policy.

## Configuration

```text
duration/arm       = 86400s
policies           = Dynamic [50, 10000]us, Random [50, 10000]us,
                     Fixed-50us, Fixed-10000us
fuzz/arm           = 2 VM x 2 vCPU, procs=2, pinned to 2 physical CPUs
validate/arm       = 4 VM x 2 vCPU, pinned to 2 physical CPUs
memory/VM          = 1 GiB
VM lifetime        = 3600s
LLM                = GPT-5.4 direct API, medium reasoning
LLM budget/arm     = 2 entries/round, 2 variants/entry, 1 parallel call
initial threshold  = 1000us for Dynamic and Random
validation repeat  = 2 collections, stable after at least 1 occurrence
verify repeat      = 1
stack budget       = 4 variants per canonical VarName family
family concurrency = 1
```

The four arms use CPU blocks `0-3`, `4-7`, `8-11`, and `12-15`; the first two
CPUs in each block are for fuzzing and the other two for validation. LLM
producers use CPUs `16-19`. CPUs `20-31` remain available to the host.

## Frozen inputs

```text
manager = bin/syz-manager-local-formal-920ea264e
manager SHA256 = 84623419c2aa2577de0abba60facbd63b03de95114a60c629944421c31ef7832
executor SHA256 = 99fd19c794c05765d67f0a5efc24b0098c6309ff41719de9539b83065f3a75cc
PTMX bzImage SHA256 = 35b102dae9fd9645e0059cc3b91d4d877b1ce1bdf63a9579fdd85e5977e7c594
PTMX vmlinux SHA256 = 6fc4ae61e043b031de37549d085a88d750db2be559d9321daa3276dd6b0c648a
initial corpus SHA256 = 9e7aefe1f39f6565fe35501268c6fdc3c2835ba53212289a7e7bfa2be60119c9
```

## Health contract

- Observe startup until all four arms have live fuzz QEMU processes and
  increasing `calls executed` counters.
- Validation VMs may remain below four when an arm has fewer eligible tasks;
  this alone is not a failure.
- A stalled fuzz VM is restarted independently after 120 seconds. A single VM
  stall must not terminate the arm or matrix.
- Treat available memory below 20 GiB or free disk below 30 GiB as an abort
  condition. Review disk below 40 GiB before it reaches the abort boundary.
- Preserve each arm's manifest, state, health, manager logs, validation results,
  LLM usage, and final summary under its run directory.

## Launch

```bash
python3 paper/artifacts/claims/added-threshold-control/run_ptmx_24h_4arm.py \
  --mode launch \
  --run-prefix 20260826-local-ptmx-formal24h-v1
```

The user explicitly approved starting one local PTMX formal matrix after the
remote three-module formal matrix was launched.
