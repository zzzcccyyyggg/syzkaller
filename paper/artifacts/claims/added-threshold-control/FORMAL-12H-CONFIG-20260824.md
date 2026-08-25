# Frozen 12h threshold-ablation configuration

The formal rebuttal rerun restores the established 12-hour resource profile.
The 8-hour 6-core runs remain diagnostic pilots.

## Per arm

```text
duration                 = 12h
fuzz                     = 4 VMs, 2 vCPU/VM, procs=2, 4 physical CPUs
validate                 = 4 VMs, 2 vCPU/VM, 4 physical CPUs
VM memory                = 1 GiB
VM lifetime              = 1h
LLM entries/round        = 4
LLM parallel calls       = 2
LLM variants/entry       = 2
LLM poll interval        = 30s
threshold interval       = 30s
threshold range          = 100-2000 us
```

Each fuzz and validation stage consumes 48 core-hours, matching the original
`2 cores x 24h` budget.

## Frozen behavior

- All arms start from the same module-specific initial corpus and hash.
- GPT-5.4 uses the direct Responses-compatible API with medium reasoning.
- Dynamic starts at 1000 us; Fixed-min is 100 us; Fixed-max is 2000 us;
  Random samples uniformly from 100-2000 us every 30 seconds.
- Validation uses collection repeat 2, stable minimum 1, and verification repeat 1.
- VarName backoff uses an unordered canonical family key.
- At most one validation task per canonical VarName family may execute at once.
- At most 10 stack variants are persisted per VarName family.
- Runtime stack expansion remains allowed, but every result reports exact-pair,
  stack-extension, and novel-family provenance against the fuzz pair index.

## Binary

```text
bin/syz-manager-canonical-family1
sha256 e7b8bb8ff11f6413b7e4380347295c1facc5367485c28bf79e33405283c3e7fb
```

The authoritative Chinese experiment contract is
`rebuttal/threshold-ablation-experiment-zh-CN.md`.
