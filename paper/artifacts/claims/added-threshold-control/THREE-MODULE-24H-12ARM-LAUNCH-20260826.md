# Three-module 24-hour formal launch record

## Launch

```text
host          = 10.130.157.5
worktree      = /home/zzzccc/BASS/MRPFuzz-rebuttal-b12700b8e
source commit = 63d4fdbfc82
run prefix    = 20260826-remote-formal24h-v1
started       = 2026-08-26 01:52:16 +12:00
cutoff        = approximately 2026-08-27 01:52:16 +12:00
```

All 12 arms use manager SHA256
`44b64d0dd32b381ef9077fca4d2df6a20c8deff59221d71cd2ebee0dcf5474a9`
and executor SHA256
`99fd19c794c05765d67f0a5efc24b0098c6309ff41719de9539b83065f3a75cc`.

The effective run IDs are `20260826-remote-formal24h-v1-<module>-<policy>` for
modules `floppy`, `bt-stack`, and `f2fs`, and policies `dynamic`, `random`,
`fixed50`, and `fixed10000`.

## Resources

```text
physical CPUs      = 0-47 for 12 four-core arm blocks
LLM CPUs           = 48-51, three producers per CPU
host reserve       = 52-55
fuzz VMs           = 24
validation VMs     = up to 48
total QEMU target  = 72
guest memory       = 1GiB per VM
duration           = 86400s per arm
```

An additional non-persistent 32GiB swap file is active, giving about 40GiB
total swap. The preceding 72-VM capacity test completed with minimum
`MemAvailable=38.899GiB`.

## Startup health

At approximately 10 minutes:

- all 12 runners were `running`;
- every arm had two fuzz QEMUs and increasing calls;
- no arm reported a calls-stall warning;
- ten arms had four active validation QEMUs; Floppy Fixed-50 had three and
  F2FS Fixed-50 had one because their pending task counts were smaller;
- 11 LLM producers had completed real GPT-5.4 calls; F2FS Fixed-50 had no
  eligible MRP yet;
- one transient API failure occurred in F2FS Dynamic; all other API calls
  succeeded;
- host `MemAvailable` was about 43GiB, swap used about 3.1/40GiB, and disk free
  about 474GiB.

The formal specification is `THREE-MODULE-24H-12ARM-SPEC-20260826.md`.

## Runtime incident: F2FS Dynamic fuzz VMs

At `2026-08-26 03:30:02 +12:00`, F2FS Dynamic stopped increasing its global
`calls executed` counter after repeated kernel RCU-stall crashes and VM
reboots. The arm, validator, LLM producer, and both fuzz QEMU processes
remained alive, but the counter stayed at 31,096 for about ten minutes. A
single fuzz VM restart did not restore scheduling. Restarting the second fuzz
VM at approximately `03:40` cleared the stale execution state; calls increased
to 31,219 and the watcher returned to `calls_stall_warning=false` by `03:41:46`.

No manager, validation process, LLM producer, workdir, corpus, or queue was
restarted. Final throughput accounting must retain this interval as real wall
clock overhead rather than subtracting it.
