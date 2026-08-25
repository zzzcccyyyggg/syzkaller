# Three-module 72-VM capacity smoke

This is a 10-minute host-capacity test, not a fuzzing result.

```text
modules             = Floppy, Bluetooth, F2FS
arms/module         = Dynamic, Random, Fixed-50, Fixed-10000
total arms          = 12
per arm             = 2 fuzz VMs + 4 validation VMs
total VMs           = 72
guest memory        = 1GiB/VM
physical CPUs       = 0-47 in four-core arm blocks
host-reserved CPUs  = 48-55
LLM                 = disabled
duration            = 600s
```

Pass criteria:

- all arms reach two fuzz VMs;
- arms with pending validation work can reach four validation VMs;
- aggregate QEMU count reaches the workload-dependent target without manager
  exits;
- host `MemAvailable` remains above 40GiB;
- swap use does not grow materially;
- disk free remains above 400GiB;
- calls continue to increase.

Runner hard floors are 20GiB available memory and 100GiB free disk. If the
40GiB preferred memory floor is missed, the test is stopped before changing
swap; swap is expanded only after preserving the first-run evidence.
