# MRPFuzz Cleanup Plan

This cleanup pass keeps the paper-facing MRP 24h comparison reproducible while reducing old experiment clutter.

## Retention Rule

Initial retention cutoff: keep result and experiment directories dated on or after `2026-04-20`.

Date classification:

1. Prefer explicit dates in directory names, such as `20260528` or `2026-05-28`.
2. If no date appears in the name, use directory modification time.
3. If a directory is ambiguous or referenced by a paper artifact, keep it until manually reviewed.

## Must Keep

MRP 24h comparison:

- `paper/results/mrp-24h-comparison/20260609-segfuzz0p5x-llm3way-reference-style/`
- `paper/results/mrp-24h-comparison/20260530-5way-plot-artifact/`
- `paper/results/mrp-24h-comparison/20260527-deepseek-v4pro-conzzer-segfuzz/`
- `paper/results/mrp-24h-comparison/MANIFEST.md`

MRPFuzz three-way source for the current paper figure:

- `paper/results/llm-model-comparison/20260603-8module-3way-dynthresh-12h-as24h/`

Raw `exp/` runs referenced by that source:

- `exp/f2fs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-20260528-225619`
- `exp/f2fs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260528-225819`
- `exp/f2fs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260603-100500`
- `exp/jfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-162215`
- `exp/jfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-162215`
- `exp/jfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260601-151816`
- `exp/xfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-005042`
- `exp/xfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-005042`
- `exp/xfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260601-151744`
- `exp/btrfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260531-023241`
- `exp/btrfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260531-023241`
- `exp/btrfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260603-100425`
- `exp/floppy/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-135147`
- `exp/floppy/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-135147`
- `exp/floppy/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-031956`
- `exp/ptmx/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-211541`
- `exp/ptmx/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-211541`
- `exp/ptmx/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-032028`
- `exp/dsp/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-124426`
- `exp/dsp/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-124426`
- `exp/dsp/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-152136`
- `exp/bt-stack/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-042546`
- `exp/bt-stack/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-042546`
- `exp/bt-stack/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-152104`

## Clear Candidates

Older than `2026-04-20` in `exp/`:

- `exp/wifi-stack/workdir`
- `exp/bt-stack/workdir-random`
- `exp/video/logs`
- `exp/wifi/logs`
- `exp/usb-driver/logs`
- `exp/pair-count-comparison/conzzer-btrfs`
- `exp/pair-count-comparison/conzzer-btrfs-fixed`
- `exp/pair-count-comparison/segfuzz-btrfs`
- `exp/pair-count-comparison/conzzer-btrfs-kccwf`
- `exp/pair-count-comparison/data`
- `exp/pair-count-comparison/segfuzz-btrfs-kccwf`
- `exp/ocfs2/logs`
- `exp/bt-stack/workdir-async-test`
- `exp/threshold-sensitivity/dsp`
- `exp/threshold-sensitivity/btrfs`

Approximate total for these `exp/` candidates is about 240M.

Large old `test/` cleanup candidates:

- `test/fs` - about 23G
- `test/DDRD-PairCollector` - about 19G
- `test/DDRD` - about 7.1G
- `test/KCSAN` - about 5.3G
- `test/DDRD-Fuzz` - about 7.8G, mixed old and post-cutoff contents; review before removing the whole directory
- `test/workdir-btrfs`, `test/workdir-video`, `test/workdir-xfs`, `test/workdir-f2fs2` - old standalone workdirs

The `test/` candidates are the largest space recovery opportunity, but should be treated separately from paper results.

Cleanup status:

- `2026-06-22`: ordinary-user deletion was attempted after confirming `test/` has no Git-tracked files.
- `test/` shrank from about 61G to about 32G.
- The remaining contents are root-owned syzkaller workdirs, mostly under `test/DDRD`, `test/DDRD-Fuzz`, `test/KCSAN`, `test/DDRD-PairCollector`, and `test/workdir-f2fs2`.
- `sudo -n rm -rf -- test` failed because sudo requires a password in this shell.
- Complete removal requires running `sudo rm -rf -- /home/zzzccc/BASS/DDRD-syzkaller/test` from an interactive shell.

## Currently Safe To Keep

- `paper/results/`: earliest observed directory timestamp is `2026-04-21`, so the current cutoff does not require deleting it.
- `exp-static/`: observed contents are from May 2026 or later.
- `paper/comparison exp/`: modified on `2026-05-27`; it also contains source data used by earlier comparison artifacts.
- `paper/archive/root-cleanup-20260622/`: preserves old root-level `graph/`, logs, plots, and bundles that were moved out of the repository root on `2026-06-22`.
- `paper/archive/tmp-cleanup-20260622/`: preserves non-sensitive old `tmp/` files moved out of the repository root on `2026-06-22`; DeepSeek helper key/env files were deleted instead of archived.
- `docs/mrpfuzz/threshold-alignment.md`: records the current paper-matched threshold controller and the historical pre-alignment behavior.

## Recommended Execution Order

1. Keep manifests and current paper artifacts in place.
2. Remove accidental tool-state directories from the current artifact:
   - `paper/results/mrp-24h-comparison/20260609-segfuzz0p5x-llm3way-reference-style/.codex`
   - `paper/results/mrp-24h-comparison/20260609-segfuzz0p5x-llm3way-reference-style/.agents`
3. Clear old `exp/` candidates listed above.
4. Review and clear large old `test/` directories if they are no longer needed.
5. Only after the artifact is stable, consider promoting the `20260609` plotting script into top-level `scripts/` and marking the older `scripts/plot_mrp_24h_tool_comparison.py` path as legacy.

## Dry-Run Commands

Review candidates before deletion:

```bash
find exp -maxdepth 2 -mindepth 2 -type d ! -newermt '2026-04-20 00:00:00' -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort
find test -maxdepth 2 -mindepth 1 -type d ! -newermt '2026-04-20 00:00:00' -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort
```

Check sizes:

```bash
find exp -maxdepth 2 -mindepth 2 -type d ! -newermt '2026-04-20 00:00:00' -print0 | xargs -0 -r du -sh | sort -h
du -sh test/fs test/DDRD-PairCollector test/DDRD test/KCSAN test/DDRD-Fuzz test/workdir-* 2>/dev/null | sort -h
```
