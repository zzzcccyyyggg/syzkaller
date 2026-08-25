# Corrected Formal Threshold Experiment Startup Audit

Audit time: 2026-08-24 01:06 NZST.

## Active Matrices

- Local PTMX:
  `20260824-local-ptmx-threshold-formal-corrected-delay-gpt54api-wave1-6f12v-1g-8h-v1`
- Remote DSP:
  `20260824-remote-dsp-threshold-formal-corrected-delay-gpt54api-4arm-6f12v-1g-8h-v1`

The superseded 2026-08-23 matrices are interrupted, have no remaining
processes, and are marked invalid in `INVALID-DELAY-X10-20260824.md`.

## Frozen Inputs

PTMX arms use the same initial corpus SHA256
`9e7aefe1f39f6565fe35501268c6fdc3c2835ba53212289a7e7bfa2be60119c9`
and the same 131-syscall allowlist SHA256
`6133edd722886db88c1a0e9d6424abc78e0fbebb8b31fbe0e5930b7ff77aa170`.

DSP arms use the same initial corpus SHA256
`8cecb1d33ebe04876d5c4ec0d71bcf7de3fc3a76e44481417b0c80f7db669c34`
and the same 48-syscall allowlist SHA256
`b71237409b7af7f2f864d961d37a4874a78bc579a2ea4752cbaa08b6caeb47a8`.

Live workdir corpus databases diverge after startup because each arm fuzzes and
updates its corpus independently. This does not indicate initial-state drift.

## Delay Contract

All six arms record both manager-level and effective kernel values:

```text
manager min/target/max = 1000/100000/100000us
manager stack-only     = 1000us
kernel multiplier      = 10
effective strict/range = 10ms-1s
effective stack-only   = 10ms
```

## Config Equivalence

After removing arm-specific paths and threshold-policy fields:

- PTMX normalized validate SHA256:
  `aa1728eb1dfccbaf5ab308eefc80ed79abf7a914e0b3becd630928997d798654`
- PTMX normalized fuzz-common SHA256:
  `5723c33baf125a4a9460438cabca1901052ca3a3b1ce4990734a65fa75e9d016`
- DSP normalized validate SHA256:
  `643574d0530cf64f1caea59314707a3dddfcf7d3e294919002ac770c3db31301`
- DSP normalized fuzz-common SHA256:
  `86b019d4c4d2c0902478ca12c6b2c702e63a42947af1dba2a886f435022ec756`

Thus arms within each module differ only in intended paths, CPU/port allocation,
and threshold policy.

## Resources And Runtime

- Every arm: fuzz 6 VM, validate 12 VM, 2 vCPU/VM, 1 GiB/VM, procs=2.
- VM running time: 3600 seconds.
- PTMX CPU sets: `0-5/6-11/24` and `12-17/18-23/25`.
- DSP CPU sets:
  `0-5/6-11/12`, `13-18/19-24/25`, `26-31/32-37/38`,
  and `39-44/45-50/51`.
- Actual process affinity matches these allocations.
- QEMU 6.2 binary SHA256 is frozen and identical between hosts.

## LLM Contract

All arms use direct Responses-compatible HTTP calls with model `gpt-5.4`,
reasoning `medium`, 6 entries/round, 2 variants/entry, and parallelism 3.
Output directories are independent. No rate limiting or JSON failures were
observed during startup. Isolated transport failures recovered while producers
continued.

## Startup Health

- All managers and producers remain alive and call counters advance.
- PTMX validation processed counters advance in both arms.
- DSP Dynamic, Random, and Fixed-max process about 8.5-8.8 pair records/min
  after startup; Fixed-min has less input by design.
- Corrected single-arm smoke collection batches completed in about 39-45s.
- At audit time local memory/disk available were about 70/49 GiB; remote were
  about 43/702 GiB. Neither host crossed its abort floor.
- Guest RCU-stall reports are fuzzing outcomes, not host OOM or experiment
  supervisor failures.

Verdict: startup audit passed. Continue monitoring resource floors, producer
failures, queue progress, and effective delay fields through the 8-hour cutoff.
