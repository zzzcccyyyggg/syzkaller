# Fixed-Resource Throughput Experiment Spec Draft

## Context

- Request: 补完 MRPFuzz 与 SegFuzz 的 throughput 对比，指标从 `exec total` 提升到 syscall-level。
- Problem statement: `exec total` 是 syzkaller program attempt 数，不是 syscall 数；MRPFuzz 的 decouple/may-race-pair 设计需要证明在固定物理资源下足够轻量。
- Hypothesis: 在相同 host CPU 资源下，优化后的 MRPFuzz 在收集 may-race pair 与注入 corpus 的完整 fuzz 路径中，syscall-level overall throughput 不低于 SegFuzz，且可通过 VM 数量选择达到更高资源利用率。

## Goal

- Primary question: 固定 2 个 host CPU 时，MRPFuzz 的总体 `calls executed/s` 相比 SegFuzz 是多少。
- Secondary question: 固定 2 个 host CPU 时，MRPFuzz 开几个 VM 的 overall throughput 最好。
- Primary metric: `delta(calls executed) / delta(wall-clock seconds)`，所有 VM 汇总，不做 per-VM 归一化。
- Secondary metrics: `delta(calls finished)/s`、`delta(calls scheduled)/s`、`delta(exec total)/s`、`calls executed / exec total`、coverage/signal 增长、crash/restart/SSH failure 数。
- Success condition: 至少产出 ptmx 的固定 2-CPU 对比结果；若稳定，再扩展到 8 个论文模块。
- Non-goals: 本实验不评价 bug yield、validate 成功率、阈值策略效果，也不把 `exec total` 称为 syscall throughput。

## Scope

- In scope:
  - MRPFuzz: `/home/zzzccc/BASS/DDRD-syzkaller`, branch `cleanup/throughput-binary-trace`; instrumentation and smoke records verified through `c9986a414e534e98211e9e8d630db84d5eb369d2`.
  - SegFuzz: `/home/zzzccc/BASS/segfuzz`, branch `cleanup/throughput-call-counters`, counter commit `f2e8ee34746e144076130e579295326fe73886e3`.
  - Initial module: `ptmx`.
  - Candidate full module set: `xfs btrfs f2fs jfs floppy bt-stack ptmx dsp`.
- Out of scope:
  - SegFuzz algorithm/code cleanup.
  - MRPFuzz threshold ablation.
  - validate queue throughput.
- Constraints:
  - Use QEMU only; do not run fuzz workloads directly on host.
  - Preserve dirty worktrees; do not reset `corpus` or SegFuzz historical local changes.
  - Long runs require user approval before launch.

## Environment

- Host: AMD Ryzen Threadripper PRO 5975WX, 32 online CPUs, `Thread(s) per core: 1`.
- Fixed CPU resource: `taskset -c 0,1` for each manager process; QEMU children inherit this affinity. On this host, CPUs 0 and 1 are separate hardware execution threads.
- Resource policy: no other fuzzing managers or QEMU processes should be running during measurement.
- MRPFuzz config seed: `exp/ptmx/fuzz-throughput-binary.cfg`.
  - Current ptmx values: `vm.count=2`, `vm.cpu=2`, `procs=2`, `vm_running_time=3600`, `disable_race_validate_queue=true`, `enable_timing_exploration=false`, `enable_solo_filter=false`.
  - Kernel: `/home/zzzccc/BASS/DDRD-syzkaller/kernels/output-binary-trace-20260630/ptmx/bzImage`.
- SegFuzz config seed: `/home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison/ptmx/syzkaller.cfg`.
  - Current ptmx values: `vm.count=1`, `vm.cpu=4`, `procs=1`; VM restart default is 1h from `sys/targets/targets.go`.
  - Kernel: `/home/zzzccc/BASS/segfuzz/kernels/guest/builds/x86_64-6.17-release/arch/x86/boot/bzImage`.
- Shared image/corpus:
  - Image: `/home/zzzccc/BASS/DDRD-syzkaller/images/bookworm.img`.
  - SSH key: `/home/zzzccc/BASS/DDRD-syzkaller/images/bookworm.id_rsa`.
  - ptmx corpus source: `/home/zzzccc/BASS/DDRD-syzkaller/corpus/ptmx-corpus.db`.

## Instrumentation Status

- MRPFuzz counters are implemented in `pkg/rpcserver`: `calls scheduled`, `calls executed`, `calls finished`; QEMU smoke log `exp/ptmx/logs/fuzz-throughput-binary-20260811-113835.log` showed all metrics.
- SegFuzz counters are implemented in `pkg/ipc` and `syz-fuzzer`; pushed to `myrepo/cleanup/throughput-call-counters`.
- SegFuzz manager text heartbeat does not print named stats. Use `syz-manager -bench bench.json` and parse samples with `jq -s`.
- SegFuzz smoke with bench:
  - Run dir: `/home/zzzccc/BASS/segfuzz/tmp/throughput-smoke/20260811-115847-segfuzz-ptmx-call-bench-smoke/`.
  - Last sample: `exec total=1823`, `calls scheduled=15643`, `calls executed=15628`, `calls finished=15628`, `uptime=152`, `fuzzing=150`.

## Experiment Matrix

Phase 2A, required preliminary ptmx matrix:

```text
MRPFuzz ptmx, host cpuset 0,1, vm.count=1, vm.cpu=2, procs=2
MRPFuzz ptmx, host cpuset 0,1, vm.count=2, vm.cpu=2, procs=2
MRPFuzz ptmx, host cpuset 0,1, vm.count=4, vm.cpu=2, procs=2
SegFuzz ptmx, host cpuset 0,1, vm.count=1, vm.cpu=4, procs=1
```

Optional fairness check, if time allows:

```text
SegFuzz ptmx, host cpuset 0,1, vm.count=1, vm.cpu=2, procs=1
MRPFuzz best ptmx variant, repeat once
```

Phase 2B, after ptmx confirms the harness:

```text
Run the chosen MRPFuzz VM count and SegFuzz baseline on xfs btrfs f2fs jfs floppy bt-stack ptmx dsp.
```

## Execution Plan

- Artifact root: `paper/artifacts/claims/added-throughput/runs/<run-id>/`.
- For every run, copy the source config into `configs/`, rewrite only `workdir`, `http`, `vm.count`, and optionally `vm.cpu`.
- Copy seed corpus into the isolated workdir before launch.
- Rebuild before launch:
  - MRPFuzz: `make TARGETOS=linux TARGETARCH=amd64 manager executor`.
  - SegFuzz: `make TARGETOS=linux TARGETARCH=amd64 manager fuzzer executor`.
- Run duration:
  - Preliminary: 60 minutes total.
  - Analysis window: discard first 10 minutes as warm-up, compute deltas over the remaining 50 minutes.
- Runner command shape:

```bash
taskset -c 0,1 timeout --signal=INT --kill-after=30s 3600s <syz-manager> -config <config> [ -bench <bench.json> ]
```

- MRPFuzz collection:
  - Parse manager log timestamps and cumulative stats lines containing `exec total`, `calls scheduled`, `calls executed`, and `calls finished`.
  - Use wall-clock delta between selected log lines.
- SegFuzz collection:
  - Run with `-bench <bench.json>`.
  - Parse all JSON objects with `jq -s`.
  - Use `uptime` delta for wall-clock denominator.
- Stop condition: timeout exit 124 is expected; any non-timeout early exit, revision mismatch, manager fatal, KASAN/BUG/panic, or repeated SSH failure marks the run invalid.

## Health Plan

- Observation window: first 5 minutes boot/fuzzer connection; then every 10 minutes.
- Healthy if:
  - manager process alive;
  - QEMU child alive after boot;
  - stats are increasing;
  - no `revision mismatch`, `SYZFAIL`, `panic`, `BUG:`, `KASAN`, or repeated SSH/lost-connection errors;
  - disk free space remains above 20 GiB.
- Incident if:
  - no stats line or no bench sample after 10 minutes;
  - process exits before timeout;
  - stats stop increasing for two consecutive checks;
  - artifact workdir grows unexpectedly large.
- Evidence sources:
  - manager log;
  - SegFuzz bench file;
  - `ps`/`pgrep` for manager and QEMU;
  - `df -h`;
  - copied config and Git SHA files.

## Data Products

- `configs/*.cfg`: exact configs used.
- `logs/*.log`: manager logs.
- `bench/*.json`: SegFuzz bench output.
- `metadata.json`: host, cpuset, repo SHAs, build times, command lines, dirty status summaries.
- `metrics.csv`: one row per run with deltas and rates.
- `README.md`: interpretation and known caveats.

## Risks and Required Decisions

- SegFuzz dirty tree: current SegFuzz worktree has unrelated uncommitted changes, including `syz-manager/manager.go`. For paper-grade comparison, either approve using this exact local dirty state and archive the diff, or first create a clean/snapshotted SegFuzz baseline.
- Kernel mismatch: MRPFuzz and SegFuzz use different kernel build trees. This matches the current local experimental setup, but weakens pure tool-overhead comparison. A stricter follow-up would align kernels more tightly.
- `vm.cpu` mismatch: existing SegFuzz ptmx uses `vm.cpu=4` while MRPFuzz throughput config uses `vm.cpu=2`. Fixed host cpuset still enforces the physical resource budget, but the optional fairness check should include SegFuzz `vm.cpu=2`.
- Repetition: one 1h run is enough to debug harness, not enough for final claims. Final paper data should use at least 3 repeats or a longer 24h window.

## Approval Gate

- Ready for review: yes.
- User confirmation required before running Phase 2A long experiments.
- Recommended approval decision:
  - Run Phase 2A ptmx first with the required matrix above.
  - Use `taskset -c 0,1`.
  - Accept SegFuzz current dirty local state for preliminary harness data only.
  - Defer 8-module/full-repeat runs until ptmx metrics look sane.
