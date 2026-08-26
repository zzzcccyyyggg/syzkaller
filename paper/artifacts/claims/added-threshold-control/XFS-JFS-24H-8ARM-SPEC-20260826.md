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
source commit      = a9b32edf342d23cb0406c57d954cc17b67c15c38
manager SHA256     = 410ee12115ac04912e87e2ca8944112a2cc1e02042613eca85dccf4dd78df353
executor SHA256    = f1cdcb5c86775872a435afd9cdbae1f34369ffe339a3f559ea7239a91ab77cda
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
their final result. The focused watchdog tests passed 100 repetitions, and the
runner/barrier test selection passed. V2 starts from fresh workdirs with a
manager and executor carrying the same revision stamp. No threshold,
validation, delay, corpus, model, or resource parameter changed.
