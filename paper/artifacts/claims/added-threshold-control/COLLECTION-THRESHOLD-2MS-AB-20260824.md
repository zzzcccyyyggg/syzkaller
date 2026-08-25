# PTMX collection-threshold 2ms A/B

## Question

Does widening validation collection to 2 ms improve natural replay of MRPs
admitted by a tighter fuzz threshold, without changing fuzz admission or
verification-delay normalization?

## Arms

- Admission-linked baseline:
  `20260824-local-ptmx-collection-ab-admission-dynamic-6f6v-1g-2h-v2`
- 2 ms collection floor:
  `20260824-local-ptmx-collection-ab-floor2000-dynamic-6f6v-1g-2h-v2`

Both arms run PTMX Dynamic for two hours with:

```text
fuzz                     = 6 VMs / 6 physical CPUs
validate                 = 6 VMs / 6 physical CPUs
VM memory                = 1 GiB
LLM                      = GPT-5.4 direct API, 6 entries, 3 parallel calls
dynamic threshold        = 100-2000 us, initial 1000 us, interval 30s
collection repeat        = 2
stable minimum           = 1
verification repeat      = 1
stack cap                = 10
family concurrency       = 1
```

The baseline uses the entry admission threshold for collection.  The treatment
uses `collection_threshold_floor_us=2000`, so the actual collection threshold is
`max(admission_threshold, 2000 us)`.  Verification-delay normalization continues
to use the original admission threshold in both arms.

No origin filter or novel-family policy was added. Exact pairs, same-family
stack variants, and first-seen novel families retain the existing validation
behavior.

## Binary

```text
bin/syz-manager-collection2ms
sha256 72d20f3026e1a4a92b59258954a4ef81ed7f454583a24ea82c97b83ab3235b4a
```

The aborted `...-v1` baseline was rejected during preflight before VM launch
because the frozen `generate_config.py` hash still referenced its prior version.
It contains no usable experiment data.

## PTMX 47.7-minute cutoff

```text
                         Admission-linked    Collection floor 2ms
calls                    49,055              56,073
MRP                      1,020               651
processed / pending      864 / 156           330 / 321
stable tasks             75                  29
stable pairs             779                 816
stable pairs per task    10.4                28.1
no-stable tasks          2                   0
collection VM-hours      1.823               0.937
verify VM-hours          2.577               3.491
confirmed races          0                   0
```

The 2 ms floor removed the two observed collection misses, but increased pair
fanout enough that fewer tasks completed and more VM time moved into
verification.  With no confirmed race in either arm, fixed 2 ms collection was
not a net improvement for this PTMX cutoff.
