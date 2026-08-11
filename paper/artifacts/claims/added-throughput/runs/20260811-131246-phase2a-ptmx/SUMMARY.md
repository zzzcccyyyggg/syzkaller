# Phase 2A ptmx Throughput Summary

- Run id: `20260811-131246-phase2a-ptmx`
- Resource model: each measured case is pinned to an exclusive 2-host-CPU cpuset.
- Sequential part: `mrpfuzz-ptmx-vm1` and `mrpfuzz-ptmx-vm2` ran on `0,1`.
- Parallel part: `mrpfuzz-ptmx-vm4` ran on `2,3`; `segfuzz-ptmx-vm1` ran on `4,5`.
- Metric source: all rows in `metrics_combined.csv` are computed from `-bench` samples using post-warmup `uptime` deltas.
- Warm-up: first 600 seconds discarded.
- Caveat: parallel lanes share memory, disk, and KVM subsystem; this is preliminary fixed-cpuset data.

| case | calls executed/s | exec total/s | calls/exec | preliminary | paper-grade | incidents |
| --- | ---: | ---: | ---: | --- | --- | --- |
| mrpfuzz-ptmx-vm1 | 28.704861 | 1.363542 | 21.051693 | True | True | 0 |
| mrpfuzz-ptmx-vm2 | 20.514894 | 1.645035 | 12.470791 | True | False | 3 |
| mrpfuzz-ptmx-vm4 | 36.413406 | 2.913043 | 12.500124 | True | False | 15 |
| segfuzz-ptmx-vm1 | 69.906597 | 7.841667 | 8.914763 | True | False | 2 |

Interpretation: SegFuzz has the highest post-warmup syscall-level throughput in this ptmx run. MRPFuzz `vm.count=4` improves over `vm.count=1/2` but has repeated RCU-stall/lost-connection incidents, so it is not paper-grade as-is. `vm.count=1` is the only clean MRPFuzz row in this run; `vm.count=2` had lost-connection incidents and lower throughput. The current data supports further MRPFuzz exec-path optimization rather than a throughput advantage claim.
