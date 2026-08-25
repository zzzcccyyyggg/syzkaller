# Three-module 72-VM capacity result

Run prefix: `20260826-remote-cap72-v2`

## Verdict

The remote host can run all 12 arms with two fuzz VMs and four validation VMs
per arm, but memory is close to the preferred safety floor. Keep four validation
VMs for the formal run only with expanded swap and active host monitoring.

## Observed peak

```text
arms completed             = 12/12
peak fuzz QEMUs per arm    = 2
peak validate QEMUs/arm    = 4
aggregate QEMU peak        = 72
minimum MemAvailable       = 38.899 GiB
swap used baseline/peak    = 1.2 / 2.9 GiB
disk free baseline/minimum = 576 / 495 GiB
minimum calls delta        = 160
calls stall warnings       = 0
peak observed load average = about 100 on 56 physical CPUs
```

The 10-minute test disabled LLM mutation. Every arm completed normally; no
manager was terminated by memory, disk, VM, or calls-stall checks.

## Swap safety reserve

An additional 32GiB swap file was created at:

```text
/home/zzzccc/BASS/MRPFuzz/.tools/mrpfuzz-32g.swap
```

Total active swap is now about 40GiB, with 38GiB free immediately after the
capacity test. The extra swap is not in `/etc/fstab`; it is an experiment-time
safety reserve and will not survive reboot unless explicitly re-enabled. It
must not be treated as normal working memory: sustained swap growth indicates
that the formal run should be stopped or split.

Capacity-run temporary Floppy/F2FS side disks were removed after completion,
reclaiming about 18.3GiB. Logs, manifests, watcher histories, and databases were
retained.

## Formal-run guardrails

```text
preferred MemAvailable floor = 35 GiB
hard MemAvailable floor      = 20 GiB
disk free floor              = 350 GiB
swap incident                = less than 8 GiB swap remaining, or sustained growth
```

The capacity result supports running all three modules and all four policies
concurrently for 24 hours with 72 VMs and 1GiB per VM.
