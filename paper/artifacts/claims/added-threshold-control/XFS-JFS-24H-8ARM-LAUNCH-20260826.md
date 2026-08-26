# XFS/JFS 24-hour eight-arm launch record

## Environment

```text
host             = bass@10.130.156.69
isolated root    = /home/zzzccc/MRPFuzz-xfs-jfs-20260826/repo
isolated LLM     = /home/bass/.codex-zzzccc
host vCPUs       = 56
host memory      = 125 GiB
temporary swap   = 8 GiB plus the existing 2 GiB; not added to fstab
manager SHA256   = 8fd6a5c2e9d81e675d0e3aee88b3d0b4e3777128034b0ec6d96f8cca5c60726b
executor SHA256  = 287ba03a37f0edbc2151507463fe91892360e0280bd101b30f960af10508bc04
```

The deployment does not read or modify the host's existing repositories or
`/home/bass/.codex`. Only `auth.json` and `config.toml` were copied from the
local isolated profile into `.codex-zzzccc`, both mode 0600.

## Effective formal arms

Six effective arms started at approximately `2026-08-26 11:46:18 +08:00`, with cutoff
approximately `2026-08-27 11:46:18 +08:00`:

```text
20260826-remote2-xfs-jfs-formal24h-v4-xfs-random
20260826-remote2-xfs-jfs-formal24h-v4-xfs-fixed50
20260826-remote2-xfs-jfs-formal24h-v4-jfs-dynamic
20260826-remote2-xfs-jfs-formal24h-v4-jfs-random
20260826-remote2-xfs-jfs-formal24h-v4-jfs-fixed50
20260826-remote2-xfs-jfs-formal24h-v4-jfs-fixed10000
```

XFS Dynamic and XFS Fixed-10000 use clean replacement runs because their
original V4 instances produced no MRP or LLM output before startup
failure/stall:

```text
20260826-remote2-xfs-jfs-formal24h-v4retry2-xfs-dynamic
  start  = 2026-08-26 12:04:05 +08:00
  cutoff = approximately 2026-08-27 12:04:05 +08:00

20260826-remote2-xfs-jfs-formal24h-v4retry1-xfs-fixed10000
  start  = 2026-08-26 12:09:13 +08:00
  cutoff = approximately 2026-08-27 12:09:13 +08:00
```

## Startup findings

- KVM, XFS/JFS side images, frozen corpora, syscall allowlists, kernel hashes,
  and all eight config audits passed.
- XFS includes barrier inputs that enter an RCU stall before the executor sends
  its executing handshake. Commits `a9b32edf3` and `1c3300367` make the per-VM
  watchdog count dispatched requests and terminate watchdog-cancelled requests
  as `Hanged`, so bad inputs are skipped rather than retried forever.
- The first three matrix attempts are diagnostic only and excluded: V1 exposed
  the pre-handshake watchdog gap, V2 exposed retry-on-restart, and V3 exposed a
  missing isolated `syz-uaf-corpus` reader.
- The corpus reader is now a frozen preflight artifact. V4 JFS Random and
  Fixed-10000 completed real GPT-5.4 calls, each accepted two programs, and
  recorded token usage during startup validation.
- One original V4 XFS Dynamic VM failed its machine-check coverage probe before
  producing data. Its clean retry passed the same probe.

XFS watchdog restarts and their wall-clock cost remain part of the formal
result. They must not be subtracted from throughput or validation latency.
