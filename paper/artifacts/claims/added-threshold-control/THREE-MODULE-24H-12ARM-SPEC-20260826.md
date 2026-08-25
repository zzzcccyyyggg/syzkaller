# Three-module 24-hour threshold experiment

## Scope

```text
modules          = Floppy, Bluetooth, F2FS
policies/module  = Dynamic, Random, Fixed-50, Fixed-10000
arms             = 12
duration         = 86400s per arm
```

## Per-arm resources

```text
fuzz             = 2 physical CPUs, 2 VMs x 2 vCPU
validate         = 2 physical CPUs, 4 VMs x 2 vCPU
memory           = 1GiB per VM
VM lifetime      = 3600s
LLM              = GPT-5.4 direct API, medium
entries/round    = 2
variants/entry   = 2
parallel calls   = 1
```

CPU blocks 0-47 are assigned in four-core arm blocks. Twelve LLM producers are
distributed across CPUs 48-51; CPUs 52-55 are reserved for the host. The total
QEMU target is 72 VMs.

All arms use the per-VM 120-second execution watchdog, no global calls-stall
abort, validation startup threshold fallback, threshold-aware validation
priority, stack cap 4, family concurrency 1, and identical backoff/delay
settings. Floppy uses the historically validated May-30 kernel; Bluetooth and
F2FS use their validated June-30 kernels.

The 72-VM capacity smoke completed all arms with a minimum 38.899GiB
`MemAvailable`. A non-persistent 32GiB safety swap file is active. Formal-run
hard floors are 20GiB available memory and 100GiB free disk; operational
monitoring treats less than 35GiB memory, less than 350GiB disk, or sustained
swap growth as incidents.
