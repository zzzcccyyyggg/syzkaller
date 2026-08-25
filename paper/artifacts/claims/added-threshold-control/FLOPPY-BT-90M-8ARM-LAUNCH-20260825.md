# Floppy and Bluetooth 90-minute pilot launch record

## Environment

```text
host                  = 10.130.157.5
worktree              = /home/zzzccc/BASS/MRPFuzz-rebuttal-b12700b8e
Bluetooth source      = f61691e69a
Floppy source         = 420d9317b8
manager SHA256        = 417de16032107de881d509f69ccd17c75b420bcee98cd1d48e9784384d750894
executor SHA256       = 99fd19c794c05765d67f0a5efc24b0098c6309ff41719de9539b83065f3a75cc
QEMU SHA256           = 7d1e85a29e09c49f6a1c60a18713d80a72ef3b8932c4183cc100bce3a01fa64e
QEMU version          = 6.2.0
per-VM stall timeout  = 120s
global stall abort    = false
```

The remote dirty primary checkout was not modified. A detached shared worktree
was used, with frozen large artifacts copied or linked by hash. The host has 56
physical CPUs, 188GiB RAM, and 614GiB free disk before launch.

## Effective runs

The effective comparison set is:

```text
Floppy:
  20260825-remote-fbt90-pervm-v6-floppy-dynamic
  20260825-remote-fbt90-pervm-v6-floppy-random
  20260825-remote-fbt90-pervm-v6-floppy-fixed50
  20260825-remote-fbt90-pervm-v6-floppy-fixed10000

Bluetooth:
  20260825-remote-fbt90-pervm-v5-bt-stack-dynamic
  20260825-remote-fbt90-pervm-v5-bt-stack-random
  20260825-remote-fbt90-pervm-v5-bt-stack-fixed50
  20260825-remote-fbt90-pervm-v5-bt-stack-fixed10000
```

Floppy began at approximately `2026-08-25 22:20:24 +12:00` and should stop at
approximately 23:50:24. Bluetooth began at approximately 21:48:04 and should
stop at approximately 23:18:04. Each runner enforces its own 5400-second cutoff.

## Excluded attempts

- v1 exited before VM creation because the clean worktree manager was built
  before syscall descriptions were generated (`supported: []`).
- v2 exited before VM creation because `syz-execprog` was absent from the clean
  worktree.
- Bluetooth v3/v4 are excluded. The LLM corpus reader was initially absent, so
  v3 did not have symmetric LLM supply; its Dynamic arm also suffered a very
  slow crash reboot. After adding `syz-uaf-corpus`, all four Bluetooth arms were
  stopped and restarted together as v5.
- Floppy v3 is excluded. It used
  `kernels/output-binary-trace-20260630/floppy`: the guest exposed `/dev/fd0`
  and block major 2, but opening the device returned `ENXIO`. All four arms
  produced zero raw pairs after more than 24,000 calls in the fastest arm.
  With the same QEMU and disk image, the historically successful
  `floppy-targetdelay-latest-20260530-135147` kernel reported a 1,474,560-byte
  `/dev/fd0`. Floppy was therefore restarted symmetrically as v6 with that
  kernel frozen by hash.

These directories are retained as startup diagnostics and are not results.

## Startup health

At the accepted checkpoint, all eight fuzz managers had two QEMUs. Bluetooth
v5 had discovered MRPs in every arm and completed real GPT-5.4 calls with zero
API failures. Floppy v6 validated the kernel correction immediately: at about
66 seconds, Dynamic/Random/Fixed-50/Fixed-10000 had produced respectively
469/494/39/943 MRPs and all four validation QEMUs were active in every arm.

## Module kernel audit

The Floppy mismatch was checked against the other configured modules. The
current June-30 PTMX kernel has completed a run with 2617 produced and consumed
MRPs; DSP produced 1849 MRPs; F2FS produced validated race families; and the
current Bluetooth pilot is producing both MRPs and a validated race. No similar
device/kernel mismatch is evident outside Floppy.

The launch specification and CPU matrix are in
`FLOPPY-BT-90M-8ARM-SPEC-20260825.md`.
