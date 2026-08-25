# Canonical VarName backoff and single-family concurrency

## Motivation

The completed PTMX Dynamic run confirmed the same unordered VarName family
three times.  Two different stack pairs were already in flight concurrently,
and one of those pairs was later verified again in reverse orientation.  The
old backoff key treated `A-B` and `B-A` as different families.

## Change

- `VarNamePairKey` now uses the existing order-independent family identity.
- A success for `A-B` therefore causes a later `B-A` candidate to be skipped.
- Generated validation configs and the formal threshold runners now default
  `max_concurrent_per_varname` to 1.
- The scheduler already reserved canonical family slots and retained blocked
  tasks in its waiting queue; no scheduler algorithm change was required.

Historical experiment manifests and documentation retain their original cap
of 2.  Running experiments were not hot-switched and continue using their
original binaries and configs.

## Pre-change live baseline

Captured at `2026-08-24T14:23:07+12:00`:

- Remote Bluetooth Dynamic: 344 MRP, 146 processed, 198 pending, 1 success.
- Remote Bluetooth Fixed-100: 209 MRP, 174 processed, 35 pending, 0 success.
- Remote PTMX Dynamic 6+6 VM: 450 MRP, 342 processed, 108 pending, 0 success.
- Remote Bluetooth Fixed-2000: 764 MRP, 158 processed, 606 pending, 3 successes.
- Local PTMX Random: 4164 MRP, 1426 processed, 2738 pending, 3 successes.
- Local PTMX Fixed-2000: 4502 MRP, 1052 processed, 3453 pending, 2 successes.

## Verification

- `go test ./pkg/racevalidate`
- `go test ./pkg/mgrconfig ./syz-manager`
- Focused canonical-key and scheduler tests repeated 100 times.
- Python experiment/config generators passed `py_compile`.
- Generated validation config default was checked as family cap 1.

New binary:

```text
bin/syz-manager-canonical-family1
sha256 e7b8bb8ff11f6413b7e4380347295c1facc5367485c28bf79e33405283c3e7fb
```

The same binary and changed source files were copied to the remote experiment
host.  The remote host does not currently have Go in `PATH`, so compilation and
Go tests were run locally; the copied binary hash and executable help path were
verified remotely.
