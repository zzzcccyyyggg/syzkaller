# XFS/JFS 24-hour eight-arm formal experiment

Status: approved for isolated deployment on `10.130.156.69`.

```text
remote root        = /home/zzzccc/MRPFuzz-xfs-jfs-20260826
LLM config         = /home/bass/.codex-zzzccc
modules            = XFS, JFS
policies/module    = Dynamic, Random, Fixed-50, Fixed-10000
duration/arm       = 86400s
fuzz/arm           = 2 VM x 2 vCPU on 2 pinned host vCPUs
validate/arm       = 4 VM x 2 vCPU on 2 pinned host vCPUs
memory/VM          = 1 GiB
LLM                = GPT-5.4 direct Responses API, medium reasoning
LLM budget/arm     = 2 entries/round, 2 variants/entry, 1 parallel call
threshold range    = 50-10000us, initial 1000us
source commit      = 1c3300367edb937f37f7fa4a6771b41092468e2a
manager SHA256     = 8fd6a5c2e9d81e675d0e3aee88b3d0b4e3777128034b0ec6d96f8cca5c60726b
executor SHA256    = 287ba03a37f0edbc2151507463fe91892360e0280bd101b30f960af10508bc04
```

The eight arms use host vCPUs `0-31` in four-vCPU blocks. LLM producers use
vCPUs `32-39`; vCPUs `40-55` remain unassigned. All artifacts, workdirs, logs,
and generated VM images stay below the isolated remote root. Existing remote
repositories and the default `~/.codex` are not read or modified.

The expected peak is 48 QEMU processes and approximately 97 GiB effective host
memory. Abort boundaries are 20 GiB available memory and 30 GiB free disk.

## Rejected V1 startup

The first launch was stopped during startup and is excluded from results. All
four XFS arms selected the same deterministic initial barrier input. One
barrier member completed 99 calls while the other entered an RCU stall before
its executing handshake. The per-VM watchdog counted only requests that had
completed that handshake, so it saw no in-flight request and did not promptly
restart the affected VM.

Commit `a9b32edf3` changes the watchdog to count requests from dispatch until
their final result. V2 confirmed that the watchdog restarted each stuck XFS VM
after 120 seconds, but shutdown still classified watchdog-cancelled requests as
`Restarted`, so the queue retried the same bad barrier input. V2 is therefore
also excluded.

Commit `1c3300367` marks watchdog-cancelled requests as `Hanged`, which is a
terminal queue result, while real crashes retain `Crashed` behavior. The
focused watchdog tests passed 100 repetitions, and the runner/barrier test
selection passed. V3 starts from fresh workdirs with a manager and executor
carrying the same revision stamp. No threshold, validation, delay, corpus,
model, or resource parameter changed.

V3 validated the terminal watchdog behavior, but the isolated deployment was
missing the frozen `bin/syz-uaf-corpus` reader used by the LLM producer. Fuzz
and validation progressed, while LLM rounds reported `uaf_corpus_error` and
made no model calls. The reader (SHA256
`9cf22c4992022ac6ead45d2dff9815ab88f0b522a7e66b1ef50a7fc160c43be3`) is
now part of the mandatory frozen-artifact preflight. V3 is excluded; V4 is the
first result-bearing formal run.
