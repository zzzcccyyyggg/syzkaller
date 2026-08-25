# Threshold-aware validation startup fallback

## Problem

The validation manager may start before the shared fuzzer threshold-state file
is readable. `CurrentThresholdUs()` then returns zero. The scheduler previously
treated `threshold <= 0` as unbounded, so startup validation slots could accept
wide tasks before Dynamic's initial/current threshold was available.

Floppy evidence showed four startup tasks dispatched with
`threshold_us=0`; three had observed gaps of 270.9, 317.1, and 587.6us. Those
non-preemptive tasks occupied validation slots after Dynamic tightened to 50us.

## Fix

Validation config now carries `threshold_priority_initial_us`:

- Dynamic and Random: 1000us;
- Fixed: the configured fixed threshold.

The scheduler uses this value only while the shared live threshold is zero or
unavailable. Once a positive live threshold exists, it takes precedence. If
neither live nor initial threshold is positive, threshold-aware dispatch pauses
instead of treating zero as unlimited.

## Validation

- mgrconfig negative-value test passed;
- scheduler fallback/live-override/no-threshold tests passed;
- generated Dynamic and Fixed-50 validate configs contained 1000us and 50us;
- `20260825-local-floppy-threshold-priority-initial-smoke-v1` passed a three-minute
  QEMU smoke with two fuzz VMs and one validation VM. Its first priority log was
  `tier=0 time_diff_ns=10930 threshold_us=1000`, and calls increased by 700.

This fix is not hot-applied to already-running experiments.
