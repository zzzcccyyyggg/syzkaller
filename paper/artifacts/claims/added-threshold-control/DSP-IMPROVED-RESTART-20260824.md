# DSP Improved Formal Restart

The corrected-delay old-binary matrix
`20260824-remote-dsp-threshold-formal-corrected-delay-gpt54api-4arm-6f12v-1g-8h-v1`
was intentionally stopped at approximately 42 minutes on 2026-08-24. Its
configuration was correct, but the user chose to replace it with the improved
queue-control implementation. It is retained as partial diagnostic evidence and
must not be combined with the restarted formal matrix.

The improved matrix enables the same controls in every threshold arm:

```text
max_stacks_per_varname_pair = 10
max_concurrent_per_varname  = 2
enable_collection_miss_backoff = true
```

The local PTMX corrected formal matrix continues with the submitted binary and
is unaffected by the DSP restart.
