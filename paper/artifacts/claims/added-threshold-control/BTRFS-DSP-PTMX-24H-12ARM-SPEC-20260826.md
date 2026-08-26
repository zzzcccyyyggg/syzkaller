# Btrfs/DSP/PTMX 24-hour 12-arm formal experiment

Status: approved for isolated local deployment after CPU, memory, and disk
expansion.

```text
isolated root      = /home/zzzccc/BASS/MRPFuzz-local-btrfs-dsp-ptmx-20260826/repo
modules            = Btrfs, DSP, PTMX
policies/module    = Dynamic, Random, Fixed-50, Fixed-10000
duration/arm       = 86400s
fuzz/arm           = 2 VM x 2 vCPU on 2 pinned host vCPUs
validate/arm       = 4 VM x 2 vCPU on 2 pinned host vCPUs
memory/VM          = 1 GiB
LLM                = GPT-5.4 direct Responses API, medium reasoning
threshold range    = 50-10000us, initial 1000us
manager SHA256     = 8fd6a5c2e9d81e675d0e3aee88b3d0b4e3777128034b0ec6d96f8cca5c60726b
executor SHA256    = 287ba03a37f0edbc2151507463fe91892360e0280bd101b30f960af10508bc04
```

The 12 arms use vCPUs `0-47` in four-vCPU blocks. LLM producers share vCPUs
`48-51`; vCPUs `52-63` remain unassigned. The isolated deployment owns its
binary tree, so builds in the development repository cannot mutate a running
experiment's executor.

Expected peak is 72 QEMU processes, approximately 145 GiB effective memory,
and 86-96 GiB generated VM images. Abort boundaries are 20 GiB available
memory and 100 GiB free disk.
