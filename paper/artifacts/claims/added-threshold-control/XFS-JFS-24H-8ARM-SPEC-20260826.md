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
```

The eight arms use host vCPUs `0-31` in four-vCPU blocks. LLM producers use
vCPUs `32-39`; vCPUs `40-55` remain unassigned. All artifacts, workdirs, logs,
and generated VM images stay below the isolated remote root. Existing remote
repositories and the default `~/.codex` are not read or modified.

The expected peak is 48 QEMU processes and approximately 97 GiB effective host
memory. Abort boundaries are 20 GiB available memory and 30 GiB free disk.
