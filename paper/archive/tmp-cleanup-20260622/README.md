# Tmp Cleanup Archive 2026-06-22

This archive preserves non-sensitive files moved from the repository-root `tmp/` directory.

## Contents

- `tmp/deferred-followup*`: dry-run layouts and deferred follow-up launch logs from late May and early June 2026.
- `tmp/official-deepseek-smoke-*`: short DeepSeek smoke-test outputs for XFS and JFS.
- `tmp/cleanup/workdir-qcow2-cleanup-20260609-004446.tsv`: old workdir/qcow cleanup candidate list.
- `tmp/stackonly-*`: stale supervisor pid/log files for stack-only validation launches.
- `tmp/site_vs_stack_compare_20260609_latest.json`: temporary site-only versus stack-only comparison output.

## Removed Instead Of Archived

The following files were deleted because they are sensitive credential/helper files:

- `tmp/inferaichat-deepseek-helper.keys`
- `tmp/deepseek-official-helper.keys`
- `tmp/inferaichat-deepseek-helper.env`

All pid files in the archived tmp tree were stale at cleanup time.

## Current Replacements

Paper-facing stack-only and site-only validation outputs are preserved under:

- `paper/results/llm-model-comparison/20260603-8module-3way-dynthresh-12h-as24h/`

The archived tmp files are ignored by this directory's local `.gitignore`; only this README and the ignore rule are intended to be visible to Git.
