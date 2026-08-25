# DSP frozen-corpus collection-threshold A/B

Run ID:

```text
20260824-local-dsp-frozen-fixed100-collection-threshold-ab-12v12c-1h-v1
```

Both arms replay the same 122-entry DSP Fixed-100 corpus copied from the
completed improved-queue experiment.  The source corpus SHA-256 is:

```text
c9f2e6803de64ed6c23ac2eae851fb38dc95653b9f674e6a0b44016617f6d4be
```

Configuration:

```text
mode                     = collection-only
repeat / stable minimum  = 2 / 1
baseline                 = collection follows 100us admission
treatment                = collection floor 2000us
validate per arm         = 12 VMs / 12 physical CPUs
VM memory                = 1 GiB
duration                 = 1h
family concurrency       = 1
collection miss backoff  = disabled
```

The experiment uses `bin/syz-manager-collection2ms`, SHA-256
`72d20f3026e1a4a92b59258954a4ef81ed7f454583a24ea82c97b83ab3235b4a`.
It performs no fuzzing, LLM mutation, or target verification, so collection
reproducibility and cost are the only behavioral differences.
