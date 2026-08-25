# PTMX Threshold Policy 12h Kimi Experiment

> Historical pilot specification retained for provenance. It is not the frozen
> rebuttal experiment contract. The current formal configuration, including the
> manager-level versus effective kernel delay distinction, is documented in
> `rebuttal/threshold-ablation-experiment-zh-CN.md`.

## Evidence Status

- Purpose: preliminary rebuttal experiment before the requested 24h confirmation run.
- Module: PTMX.
- Duration: 12 hours per variant.
- Variants run concurrently from fresh, isolated workdirs.
- This run may guide the final frozen 24h matrix, but is not itself described as the requested 24h evidence.

## Question

Does workload-aware threshold control improve useful MRP admission and race confirmation compared with a frozen threshold and a feedback-free randomized threshold policy?

## Threshold Policies

All policies use microseconds and the same interval/range where applicable.

| Variant | Policy |
| --- | --- |
| Dynamic | Start at `1000`; every 30s apply paper Algorithm 1 within `[50,10000]` |
| Random | Start at `1000`; every 30s independently sample log-uniformly from `[50,10000]` using seed `1592594996` |
| Fixed-1000 | Keep the threshold at `1000` for the entire run |

Dynamic parameters are `Wlow=10`, `Whigh=40`, `rho=0.8`, `epsilon=1`, `gamma=0.5`, and `DeltaTau=0.05*(tau_max-tau_min)`.

Random deliberately does not read validator feedback. Log-uniform sampling is pre-registered because the range spans 200x; linear-uniform sampling would place most probability mass at permissive high thresholds.

## Controller Counters

The shared unit is `queue-pair-record`:

- `P`: cumulative pair records successfully admitted to the validation queue.
- `C`: cumulative pair records successfully acknowledged by validation.
- `Q`: current unacknowledged pair records in the validation queue.

Both sides persist `counter_unit=queue-pair-record` in `threshold-state.json`. Dynamic ignores validator state with a missing or different unit.

## Input Control

- Initial syzkaller corpus: `exp/ptmx/workdir/tuned-prepared-corpus.db`, copied
  independently into each fresh workdir as `corpus.db`.
- Initial corpus size: 184,744 bytes.
- Required SHA-256: `9e7aefe1f39f6565fe35501268c6fdc3c2835ba53212289a7e7bfa2be60119c9`.
- Record-level audit against the successful `20260602-032028` PTMX run found
  exactly the same 637 keys and 637 values; the whole-file hashes differ only
  because of DB serialization.
- No prior `uaf-corpus.db`, pair index, queue, validation, or threshold state is copied.
- Each variant runs its own authenticated local Kimi Code producer and isolated
  output directory. The pinned CLI is version `0.36.1` and the model alias is
  `my-kimi-code/k3`.
- Each Kimi producer reads the live `uaf-corpus.db` produced by its corresponding
  threshold variant. Threshold-dependent discoveries can therefore affect later
  semantic seed mutations as part of the complete end-to-end system.
- Kimi settings: `entries_per_round=4`, `variants_per_entry=2`,
  `parallel_calls=2`, `max_calls=8`, `poll_sec=30`, and `timeout_sec=600`.
- Manager seed polling: every 10s, at most 32 newly accepted groups per poll.

The model, API budget, initial corpus, and producer settings are identical, but
Kimi outputs are not shared. This evaluates complete-system behavior and retains
LLM stochasticity as an explicit threat to validity; the final confirmation run
will require repeats if the three outcomes are close.

## Resources

Host: 32 physical cores, 125 GiB RAM. Existing unrelated host services remain untouched.

Per variant:

- Fuzz: 4 VMs, each 2 vCPU and 2 GiB, `procs=2`, sharing 4 host physical cores.
- Validate: 4 VMs, each 2 vCPU and 2 GiB, `max_concurrent=4`, sharing 4 host physical cores.
- VM restart interval: 600s.

CPU allocation:

| Variant | Fuzz cpuset | Validate cpuset |
| --- | --- | --- |
| Random | `0-3` | `4-7` |
| Dynamic | `8-11` | `12-15` |
| Fixed-1000 | `16-19` | `20-23` |

The three independent Kimi producers share host CPUs `24-27`; CPUs `28-31`
remain available to host services. Total allocation is 24 VMs, 48 guest vCPUs,
about 48 GiB configured guest RAM, and 24 host physical cores for fuzz/validate.
Validation VM count is reduced from the historical eight-per-policy profile
because three simultaneous 4+8 profiles crossed the host memory abort floor
even with 1 GiB validation guests. All threshold policies retain identical
resources and finish within the same 12h wall-clock window.

## Fuzz Configuration

- Binary-trace PTMX kernel from `kernels/output-binary-trace-20260630/ptmx`.
- `race_mode=true`, `barrier_mode=true`, `barrier_procs=[0,1]`.
- `static_input_exploration=true`, seed `1592594996`, built-in seeds skipped.
- `max_stacks_per_varname_pair=20`.
- Timing exploration, solo filter, object linking, coverage triage, and affinity table disabled.
- Validation queue enabled.

## Validation Configuration

- Complete continuous streaming replay/verification path.
- `max_pairs_per_task=8`.
- `max_stable_pairs_per_entry=16`.
- `max_stable_pairs_per_origin=1`.
- `target_match_mode=sn-fallback`, range `2`.
- Replay and VM snapshots enabled.
- History minimization disabled.
- `repeat_count=1`, `verify_repeat_times=1`.
- Task timeout 120s; batch timeout 600s.
- Collection delay and verify delay sweep disabled, matching the earlier successful PTMX configuration.

## Metrics

Primary:

- Unique confirmed data races and validated pair records.
- Unique admitted MRPs.
- Queue-record `P`, `C`, and `Q` over time.
- Threshold trajectory and time at each scale.

Secondary:

- Calls executed and calls/s.
- Corpus records and MRP/corpus conversion ratio.
- Validation processed, skipped, invalid, and no-stable outcomes.
- Manager/VM utilization, memory, disk, and restart counts.
- Kimi CLI calls, accepted/rejected groups, failures, and latency.

## Health Contract

- Startup observation: every 2 minutes for the first 20 minutes.
- Stabilization: every 15 minutes through hour 2.
- Steady state: hourly until completion.
- Healthy: the active fuzz manager, validation manager, and Kimi producer remain
  alive; the fuzz call counter advances; validator state is fresh within 90s;
  queue DBs remain readable; and Kimi state/log files remain parseable.
- Warning: available memory below 12 GiB, disk below 40 GiB, one variant stalls for 240s, or three consecutive Kimi rounds fail.
- Abort: available memory below 8 GiB, disk below 25 GiB, unreadable/corrupt shared
  state, the active variant fails, or host OOM pressure appears.
- DATARACE reports are successful experiment outcomes, not incidents.

## Preflight Gates

1. Unit and manager tests pass.
2. Manager/executor build succeeds.
3. A QEMU smoke confirms the full 4-fuzz/8-validate VM profile is safe with the
   current host memory load.
4. A one-round Kimi smoke confirms local OAuth, parser, checker, and accepted output.
5. Random trajectory is reproducible from its recorded seed.
6. Dynamic logs fresh `P/C/Q` values with `counter_unit=queue-pair-record`.
7. User approves this frozen spec before the 12h launch.

## Stop Procedure

- Send SIGINT to the active fuzz manager, validation manager, and Kimi producer.
- Wait up to 30s, then terminate only the recorded child process groups.
- Preserve configs, logs, DBs, Kimi state, bench samples, watcher history, and the launch manifest.
