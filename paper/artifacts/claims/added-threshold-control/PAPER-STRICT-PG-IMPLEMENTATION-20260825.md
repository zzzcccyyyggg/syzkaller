# Paper-strict per-entry P_G validation

Date: 2026-08-25

Branch: `rebuttal/paper-strict-pg-validation`

## Semantics

The strict mode implements the validation flow described in Section 5.2 and
Algorithm 2:

- collection executes with the experiment's `tau_max` as its temporal window;
- only runtime pairs matching an MRP in the current entry's `P_G` are accepted;
- exact matching includes both VarName and Stack endpoints and permits reversed
  access order;
- an empty `P_G` accepts no runtime pair;
- across collection repeats, the minimum-gap runtime occurrence and its ASN/TID
  metadata are retained;
- `lambda*delta` uses that collection gap rather than the fuzz-time admission
  gap;
- each original MRP contributes at most one accepted runtime occurrence.

The runner option `--paper-strict-pg` atomically sets:

```text
collection_threshold_floor_us = dynamic_threshold_max_us
require_origin_match          = true
origin_match_mode             = exact
max_stable_pairs_per_origin   = 1
```

StackOnly retains the previously approved one-fifth multiplier and therefore
remains an explicitly documented engineering extension to Algorithm 2.

## Pair propagation audit

Queue groups carry complete VarName, Stack, and TimeDiff fields. During
materialization, queued pairs replace unrelated persisted entry pairs and are
copied into `entry.Pairs`; if the persisted corpus record lacks the queued pair,
the queue copy is inserted. A focused test now asserts this behavior.

## Tests

- exact matching accepts reversed access order;
- exact matching rejects Stack drift and an empty `P_G`;
- collection retains the minimum runtime gap across repeats;
- the validation entry receives the complete queued pair;
- manager and executor builds carry the same Git revision.

Go package tests and focused race tests passed for `pkg/racevalidate`,
`pkg/manager`, `pkg/mgrconfig`, and `syz-manager`.

## QEMU evidence

### Collection-only smoke

Run:
`20260825-remote-f2fs-paper-strict-pg-collectiononly-2f2v-10m-v2`

Status: `pass`

The generated config used a 5000us collection window while entries retained
their original admission thresholds. Across 11 completed tasks:

```text
stable runtime pairs = 545
exact P_G matches    = 3
VarName-only matches = 81
novel families       = 461
accepted             = 3
```

Thus exact reproduction was rare (0.55%) but non-zero, and strict mode accepted
only the exact records.

### Full-verification smoke

Run:
`20260825-remote-f2fs-paper-strict-pg-fullverify-2f2v-15m-v1`

Status: `failed-stalled` after `calls executed` remained at 970. Before the
watchdog stopped it, 11 completed collection tasks produced 376 stable runtime
pairs (82 VarName-only and 294 novel) with no exact match, so no verification
attempt was expected or executed. This run is a health failure, not evidence
that strict verification is broken.

## Next experiment

Use the tested strict binary with the normal 6-fuzz/12-validation VM profile.
Report collection provenance separately from confirmed races. Do not compare
the strict run to historical expansion-enabled counts without labeling the
change in candidate semantics.
