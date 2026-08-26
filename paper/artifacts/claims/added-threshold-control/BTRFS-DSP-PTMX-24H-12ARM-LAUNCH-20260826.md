# Btrfs/DSP/PTMX 24-hour 12-arm launch record

## Environment

```text
host             = zzzccc-virtual-machine
isolated root    = /home/zzzccc/BASS/MRPFuzz-local-btrfs-dsp-ptmx-20260826/repo
host vCPUs       = 64
host memory      = 220 GiB
filesystem free  = 278 GiB before isolated deployment and swap
temporary swap   = 16 GiB plus the existing 2 GiB; not added to fstab
manager SHA256   = 8fd6a5c2e9d81e675d0e3aee88b3d0b4e3777128034b0ec6d96f8cca5c60726b
executor SHA256  = 287ba03a37f0edbc2151507463fe91892360e0280bd101b30f960af10508bc04
```

The deployment owns independent copies of every manager, executor, corpus,
kernel, and VM image used by the experiment. Builds in the development
repository cannot mutate these running binaries.

## Effective formal arms

Eleven arms started at approximately `2026-08-26 17:42:10 +12:00`, with cutoff
approximately `2026-08-27 17:42:10 +12:00`:

```text
20260826-local-btrfs-dsp-ptmx-formal24h-v1-btrfs-{dynamic,random,fixed50,fixed10000}
20260826-local-btrfs-dsp-ptmx-formal24h-v1-dsp-{dynamic,random,fixed50,fixed10000}
20260826-local-btrfs-dsp-ptmx-formal24h-v1-ptmx-{random,fixed50,fixed10000}
```

The original PTMX Dynamic arm failed its first VM machine-check coverage probe
before producing any calls, MRP, validation, LLM, or token result. Its clean
replacement is:

```text
run ID = 20260826-local-btrfs-dsp-ptmx-formal24h-v1retry1-ptmx-dynamic
start  = 2026-08-26 17:45:38 +12:00
cutoff = approximately 2026-08-27 17:45:38 +12:00
```

## Startup health

- All 12 effective runners are `running` with two fuzz QEMUs per arm.
- PTMX Dynamic retry passed machine-check, exceeded 900 calls, produced more
  than 400 MRP records, started four validation QEMUs, and loaded accepted
  GPT-5.4 seeds.
- Btrfs, DSP, and PTMX all produced live validation work; direct GPT-5.4 calls
  completed in all three modules with accepted programs and token usage.
- At the startup snapshot, 53 QEMUs were active, with validation pools growing
  on demand toward the 72-QEMU peak.
- Host available memory was approximately 138 GiB, free disk 205 GiB, and the
  temporary swap remained unused.

The failed original PTMX Dynamic directory is diagnostic only and must not be
included in result aggregation.
