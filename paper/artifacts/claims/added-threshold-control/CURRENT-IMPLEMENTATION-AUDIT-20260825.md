# Threshold implementation checkpoint (2026-08-25)

This document freezes the implementation state before changing validation to
strictly reproduce the paper's per-entry candidate set `P_G`.

## Git checkpoint scope

- Baseline commit: `4ab7abd04b529c09694f14275ab605a554789668`.
- Checkpoint branch: `rebuttal/threshold-alignment-checkpoint-20260825`.
- Source, tests, experiment runners, analysis scripts, and compact reports are
  versioned.
- Generated run directories, QEMU images, raw logs, frozen databases, and
  Python caches remain local and are ignored by Git.
- The `corpus` submodule has local database modifications and is deliberately
  excluded from this checkpoint.

## Paper-aligned behavior

- Algorithm 1 equations and constants: `Tc=30s`, `Wlow=10`, `Whigh=40`,
  `rho=0.8`, `epsilon=1`, `gamma=0.5`, and
  `delta_tau=0.05*(tau_max-tau_min)`.
- The controller uses cumulative queue-record counters to derive interval
  `P` and `C`, plus the current queued-record count `Q`.
- Precise validation delay uses `lambda*observed_delta`. The manager-side
  multiplier is 200 and the experiment kernel applies another fixed x10,
  yielding an effective `lambda=2000`.
- A crash-report fallback now requires both target VarName endpoints.

## Deliberate extensions or mismatches

- StackOnly uses one fifth of the precise multiplier (effective x400); the
  paper presents one `lambda*delta` plan for all matching modes.
- Threshold-aware validation priority demotes historical candidates above the
  controller's current threshold. This policy is not specified in Algorithm 1.
- Validation collection currently uses each entry's admission threshold, while
  Section 5.2 says reproduction searches within `tau_max`.
- `require_origin_match=false` permits same-VarName Stack expansion and novel
  VarName families. The paper defines the reproduced set as `P_G^r subset P_G`
  and describes matching the recorded access-site and stack-context pair.

## F2FS provenance audit

At `2026-08-25T15:16+12:00`, direct `validated_uaf.db` metadata reported zero
successful records with `OriginMatch=exact` in both the active and immediately
preceding F2FS matrices. All records were marked `Expanded=true`.

The active matrix was independently checked without trusting that metadata:

1. Parse each successful pair and task corpus ID from `logs/validate.log`.
2. Reconstruct all fuzz-discovered VarName+Stack pairs associated with that
   corpus from `race-pair-index.db`.
3. Canonicalize both access orderings and intersect the sets.

Results at the audit point:

| Arm | Validated records | Same-corpus exact | Same-corpus VarName | Global fuzz exact |
| --- | ---: | ---: | ---: | ---: |
| Dynamic | 10 | 0 | 2 | 1 |
| Fixed-500 | 21 | 0 | 5 | 0 |
| Fixed-5000 | 9 | 0 | 1 | 1 |
| Random | 36 | 0 | 11 | 0 |

The global intersections do not satisfy the paper's per-entry `P_G` condition.
Before enforcing strict matching, the queue materialization path must be audited
to determine whether the expected original pair is genuinely not reproduced or
is lost while constructing `entry.Pairs`.

## Active diagnostic matrix

The following remote runs started together at `2026-08-25T12:25:34+12:00` and
continue unchanged while this checkpoint is prepared:

- `20260825-remote-f2fs-lambda200-stack40-thprio-dynamic500-5000-gpt54api-6f12v-1g-8h-v1`
- `20260825-remote-f2fs-lambda200-stack40-thprio-fixed500-gpt54api-6f12v-1g-8h-v1`
- `20260825-remote-f2fs-lambda200-stack40-thprio-fixed5000-gpt54api-6f12v-1g-8h-v1`
- `20260825-remote-f2fs-lambda200-stack40-thprio-random500-5000-gpt54api-6f12v-1g-8h-v1`

These runs are diagnostic because collection and candidate provenance do not
yet strictly match Section 5.2 and Algorithm 2.

## Next implementation boundary

No strict-`P_G` code change should begin until this checkpoint is pushed and
verified on GitHub. The next branch should first add collection-only provenance
tests, then repair pair propagation if needed, and only then enforce
`P_G^r subset P_G` with a `tau_max` reproduction window.
