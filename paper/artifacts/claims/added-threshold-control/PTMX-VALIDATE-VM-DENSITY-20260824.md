# PTMX validation VM-density run (2026-08-24)

## Purpose

Test whether assigning 12 two-vCPU validation VMs to six physical CPUs hurts
validation progress.  The replacement PTMX Dynamic arm keeps six physical CPUs
for validation but reduces the VM count from 12 to 6.  This changes the density
from four guest vCPUs per physical CPU to two.

## Valid run

- Host: `zzzccc-BASS-2404` (`10.130.157.5`)
- Run ID: `20260824-remote-ptmx-dynamic-gpt54api-6f6v-1g-8h-v3`
- Session: `ptmx-dynamic-6v-v3`
- Duration: 8 hours
- Fuzz: 6 VMs x 2 vCPU, cpuset `26-31`, 1 GiB per VM
- Validate: 6 VMs x 2 vCPU, cpuset `32-37`, 1 GiB per VM
- LLM producer: CPU `38`, GPT-5.4 direct Responses API, 6 entries per
  round, 3 parallel calls, medium reasoning
- Dynamic threshold: 100-2000 us, initial 1000 us
- Manager: `bin/syz-manager`, SHA-256
  `7e12dd9720901174bc0577c92932b3b52074333a8b5727ac7c1b07036eb1649b`
- Initial corpus SHA-256:
  `9e7aefe1f39f6565fe35501268c6fdc3c2835ba53212289a7e7bfa2be60119c9`

All threshold, validation-repeat, delay-normalization, corpus, kernel, and LLM
settings match the corrected PTMX formal experiment.  The validation VM count is
the intended independent change.

## Concurrent arms

The Bluetooth Random arm was removed.  These three Bluetooth arms run in
independent tmux sessions, so one watchdog failure cannot stop the other arms:

- `20260824-remote-bt-stack-threshold-formal-improved-dynamic-gpt54api-6f12v-1g-8h-v3`
- `20260824-remote-bt-stack-threshold-formal-improved-fixed100-gpt54api-6f12v-1g-8h-v3`
- `20260824-remote-bt-stack-threshold-formal-improved-fixed2000-gpt54api-6f12v-1g-8h-v3`

## Excluded startup attempts

- `...bt-stack...dynamic...v2`: rejected before VM launch because the independent
  session did not prepend the frozen repository QEMU to `PATH`.
- `20260824-remote-ptmx-dynamic-gpt54api-6f6v-1g-8h-v2`: fuzz started, but the
  old formal manager rejected an unconditional new config field.  No validation
  result from this run is usable.

The runner was synchronized with the already-tested compatibility fix that emits
new queue-control fields only when enabled.  The valid v3 run passed artifact
hash checks, reached 6 fuzz and 6 validation VMs, increased `calls executed`,
collected stable pairs, and entered target verification.

## Density conclusion

The completed 12-VM arm consumed 2,617 queue records and drained its queue,
while the 6-VM arm consumed 1,649 records and retained 87 pending records on the
same six validation CPUs. Both found five canonical VarName families; the
12-VM arm covered ten Stack pairs versus six. Validation includes substantial
snapshot, SSH, replay, and I/O wait, so two 2-vCPU validation VMs per physical
CPU provide better aggregate utilization despite guest-vCPU oversubscription.

Future scaled configurations should preserve this density:

```text
validation VMs = 2 * validation physical CPUs
fuzz VMs       = 1 * fuzz physical CPUs
```
