# Threshold-Control Pilot Spec

## Context

- Request: run a small threshold-sensitivity experiment before committing to the rebuttal's 24-hour matrix.
- Problem statement: the paper motivates dynamic admission control but currently lacks a direct comparison against fixed thresholds.
- Hypothesis: fixed thresholds expose a supply/selectivity tradeoff, while the dynamic controller moves within the configured range in response to the live validation backlog.

## Goal

- Primary question: on one module, do `50us`, `2500us`, `10000us`, and dynamic `[50us, 10000us]` policies produce measurably different MRP supply, queue pressure, and validation outcomes?
- Success condition: all variants run the complete fuzz and validation path, and the dynamic run records fresh producer/consumer state plus at least one evidence-backed threshold decision.
- Non-goals: this pilot is not paper-grade evidence, does not establish statistical significance, and does not yet implement the randomized-threshold baseline requested for the final rebuttal experiment.

## Scope

- Module: PTMX.
- Variants: `dynamic`, `fixed-50`, `fixed-2500`, and `fixed-10000`.
- LLM input: the same archived Kimi-2.6 accepted seed set is injected into every variant.
- Constraints: only the threshold policy and isolated workdir/ports/CPU sets differ.

## Environment

- Repo: `/home/zzzccc/BASS/DDRD-syzkaller`.
- Branch/commit: recorded in each run's `metadata.json`; the pilot includes the local threshold-state locking fix.
- Kernel: `kernels/output-binary-trace-20260630/ptmx/bzImage`.
- Kernel build metadata: `kernels/builds-binary-trace-20260630/x86`.
- Seed corpus: `corpus/ptmx-corpus.db`.
- Kimi seeds: `paper/results/llm-mutate-continuous/ptmx-llm-helper-kimi26-thinking-randrewrite-dev4-fixenv-20260521-1032`.

## Execution Plan

- Duration: 30 minutes per variant, run concurrently.
- Per variant: one fuzz VM and one validation VM; each VM has 2 vCPUs and 4 GiB RAM; manager `procs=2`; validation tasks are capped at 8 pairs to produce observable consumer completions during the short pilot.
- Offline Kimi replay: at most 12 accepted groups are admitted initially and every 10 seconds thereafter, approximating asynchronous LLM arrival instead of injecting the full archive as one burst.
- CPU allocation:
  - dynamic: fuzz `8,9`, validate `10,11`
  - fixed-50: fuzz `12,13`, validate `14,15`
  - fixed-2500: fuzz `16,17`, validate `18,19`
  - fixed-10000: fuzz `20,21`, validate `22,23`
- Runner: `run_threshold_variant.py`, once per variant with disjoint ports and CPU sets.
- Start condition: threshold unit tests and concurrent shared-state stress test pass; no pre-existing syz-manager or QEMU process; at least 20 GiB disk and 15 GiB available memory.
- Stop condition: 30 minutes elapsed or an abort condition is reached.

## Health Plan

- Observation window: startup 5 minutes, then one-minute samples.
- Primary metric: complete-path MRP production, validation queue processing, and confirmed validation outcomes.
- Secondary signals: calls executed, threshold trajectory, P/C/Q state freshness, QEMU liveness, CPU and memory headroom.
- Healthy if: both managers and QEMUs remain alive; calls increase; dynamic fuzzer and validator timestamps are fresh within 90 seconds; queue/storage counters remain readable.
- Incident if: manager/QEMU exits unexpectedly, `SYZFAIL`/panic occurs, state JSON becomes unreadable, or calls stall for 240 seconds.
- Abort if: available memory falls below 10 GiB, disk falls below 15 GiB, or two or more variants fail.
- Expected validation `DATARACE` reports are successful confirmations, not health incidents.
- Watcher cadence: one minute.

## Notification Plan

- No Feishu notification was requested for this local pilot.
- Status is reported in this conversation and persisted under each run directory.

## Risk and Rollback

- Main risk: eight simultaneous VMs may approach memory limits.
- Rollback: send SIGINT to every variant runner; each runner stops its fuzz and validation managers and their QEMU children.
- Shared-state risk: fixed before launch with a cross-process file lock; regression evidence is recorded in the handoff.

## Approval Gate

- Ready for review: yes.
- User confirmation: the user explicitly requested a simple threshold experiment and approved increasing concurrency on one module.
- Evidence status: pilot only; final rebuttal evidence requires frozen settings, randomized threshold policy, independent repeats, and 24-hour runs.
