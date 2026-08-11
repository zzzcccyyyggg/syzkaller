# Phase 2B Complete MRPFuzz Diagnostic

- Run id: `20260811-165740-phase2b-complete-ptmx`
- Completed at: `2026-08-11T17:58:40+08:00`
- Duration seconds: `1800`
- Warmup seconds: `300`
- MRPFuzz fuzz cpuset: `8,9`
- MRPFuzz validate cpuset: `10,11`
- SegFuzz cpuset: `8,9,10,11`
- Metrics: `/home/zzzccc/BASS/DDRD-syzkaller/paper/artifacts/claims/added-throughput/runs/20260811-165740-phase2b-complete-ptmx/metrics.csv`

This is a diagnostic run. Treat results as preliminary until repeated.

| case | calls executed/s | exec total/s | notes |
| --- | ---: | ---: | --- |
| mrpfuzz-complete-fuzz | 11.876389 | 0.929167 | complete mode: fuzz VM plus live validate VM |
| segfuzz-4core | 52.989855 | 7.316667 | unstable baseline: 10 crash lines in log |

## Configuration

- MRPFuzz complete: one fuzz VM with 2 vCPUs on cpuset `8,9`, plus one live validate VM with 2 vCPUs on cpuset `10,11`.
- SegFuzz: one VM with 4 vCPUs on cpuset `8,9,10,11`.
- Both cases used the same 30 minute wall-clock duration and 5 minute warmup.
- The syscall-level throughput metric is syzkaller `calls executed/s`.

## Bench-Uptime Windows

| case | uptime window | calls executed/s | exec total/s |
| --- | ---: | ---: | ---: |
| MRPFuzz complete | 0-300s | 618.98 | 28.55 |
| MRPFuzz complete | 300-600s | 11.46 | 0.93 |
| MRPFuzz complete | 600-900s | 12.23 | 0.93 |
| MRPFuzz complete | 900-1200s | 11.74 | 0.93 |
| MRPFuzz complete | 1200-1500s | 11.57 | 0.93 |
| MRPFuzz complete | 1500-1760s | 12.51 | 0.93 |
| SegFuzz | 300-600s | 57.37 | 7.69 |
| SegFuzz | 600-900s | 80.35 | 10.98 |
| SegFuzz | 900-1200s | 53.48 | 8.46 |
| SegFuzz | 1200-1500s | 3.37 | 0.64 |
| SegFuzz | 1500-1712s | 84.22 | 10.00 |

## MRPFuzz Backlog Snapshots

| elapsed | calls executed | ddrd pairs fuzz | uaf corpus | threshold us | storage total | processing | processed | invalid | queue pending |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 300s | 188672 | 184 | 6 | 6775 | 164 | 164 | 0 | 0 | 4 |
| 601s | 196585 | 1389 | 50 | 1693 | 1389 | 1184 | 203 | 2 | 50 |
| 902s | 200111 | 1543 | 61 | 500 | 1543 | 1334 | 203 | 6 | 61 |
| 1202s | 203715 | 1896 | 70 | 500 | 1896 | 1535 | 354 | 7 | 69 |
| 1822s | 210865 | 1915 | 79 | 500 | 1915 | 1554 | 354 | 7 | 78 |

## Interpretation

This run supports the hypothesis that complete MRPFuzz slows after pair/corpus/validate traffic begins. The first five minutes are not representative: pair discovery is still low and throughput is high. After warmup, calls executed stay around 11-12/s while pair storage and validation backlog remain high.

Post-warm consecutive-sample correlations against calls executed/s were:

- `storage processing`: -0.720
- `ddrd pairs fuzz`: -0.689
- `queue pending`: -0.590
- `uaf corpus`: -0.576
- `dynamic threshold`: +0.473

The SegFuzz row is useful as a rough diagnostic comparator, but this specific run is not paper-grade because `segfuzz-4core.log` contains 10 `crash:` lines, including KCSAN data races and one `no output from test machine`.

## Next Optimization Targets

- Keep complete validation enabled for the throughput comparison; do not measure by disabling pair collection or validation.
- Reduce validate-path backpressure: bound the validation queue, prioritize unique/high-signal pairs, and make stale `processing` entries recoverable.
- Decouple dynamic-threshold shrinkage from validation backlog. In this run the threshold collapsed to 500us while validation was still far behind.
- Profile pair/corpus persistence and queue writes under backlog. The likely hot path is not raw executor execution alone.
- Repeat with 1 hour runs and stable SegFuzz settings before using the result as a paper figure.
