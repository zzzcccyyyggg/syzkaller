#!/usr/bin/env python3
"""Extract DeepSeek validate stable-pair accounting for the 20260603 run.

The main processed/skipped columns use verification-phase summaries only.
Those summaries are emitted after collection has produced stable pairs.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_DIR = (
    PROJECT_ROOT
    / "paper/results/llm-model-comparison/20260603-8module-3way-dynthresh-12h-as24h"
)

MODULE_ORDER = ["f2fs", "jfs", "xfs", "btrfs", "floppy", "ptmx", "dsp", "bt-stack"]
VARIANT = "deepseek-v4pro"

PAIR_INDEX_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"race storage\[validate-poll\]: pair_index "
    r"total=(?P<total>\d+) queueable=(?P<queueable>\d+) "
    r"discovered=(?P<discovered>\d+) queued=(?P<queued>\d+) "
    r"processing=(?P<processing>\d+) processed=(?P<processed>\d+) "
    r"validated=(?P<validated>\d+) invalid=(?P<invalid>\d+) "
    r"unknown=(?P<unknown>\d+) with_corpus=(?P<with_corpus>\d+) "
    r"with_history=(?P<with_history>\d+) max_queue_seq=(?P<max_queue_seq>\d+)"
)

SUMMARY_RE = re.compile(
    r"uafvalidate: verification phase summary key=\S+ target_match_mode=\S+ "
    r"pairs=(?P<pairs>\d+) handled=(?P<handled>\d+) "
    r"executed=(?P<executed>\d+) skipped=(?P<skipped>\d+) "
    r"executed_verify_pairs=(?P<executed_verify_pairs>\d+) "
    r"skipped_pairs=(?P<skipped_pairs>\d+) "
    r"skipped_debug=(?P<skipped_debug>\d+) "
    r"skipped_invalid=(?P<skipped_invalid>\d+) "
    r"skipped_validated=(?P<skipped_validated>\d+) "
    r"skipped_backoff=(?P<skipped_backoff>\d+) "
    r"validated=(?P<validated>\d+) failed=(?P<failed>\d+) "
    r"strict_success=(?P<strict_success>\d+) "
    r"fallback_runs=(?P<fallback_runs>\d+) "
    r"fallback_success=(?P<fallback_success>\d+) "
    r"site_only_success=(?P<site_only_success>\d+) "
    r"observed_target=(?P<observed_target>\d+) "
    r"nonblocking_observed=(?P<nonblocking_observed>\d+) "
    r"sn_range_runs=(?P<sn_range_runs>\d+) "
    r"sn_range_success=(?P<sn_range_success>\d+) "
    r"stack_fallback_runs=(?P<stack_fallback_runs>\d+) "
    r"stack_fallback_success=(?P<stack_fallback_success>\d+)"
)

ENTRY_SKIP_RE = re.compile(
    r"uafvalidate: skipping (?:entry|ref) \(all pairs high backoff score\): "
    r"all (?P<pairs>\d+) pairs"
)


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def int_fields(match: re.Match[str], skip: set[str] | None = None) -> dict[str, int | str]:
    skip = skip or set()
    out: dict[str, int | str] = {}
    for key, value in match.groupdict().items():
        out[key] = value if key in skip else int(value)
    return out


def parse_validate_log(path: Path) -> dict[str, int | str]:
    if not path.exists():
        raise FileNotFoundError(path)

    last_pair_index: dict[str, int | str] | None = None
    summary_keys = (
        "pairs",
        "handled",
        "executed",
        "skipped",
        "executed_verify_pairs",
        "skipped_pairs",
        "skipped_debug",
        "skipped_invalid",
        "skipped_validated",
        "skipped_backoff",
        "validated",
        "failed",
        "strict_success",
        "fallback_runs",
        "fallback_success",
        "site_only_success",
        "observed_target",
        "nonblocking_observed",
        "sn_range_runs",
        "sn_range_success",
        "stack_fallback_runs",
        "stack_fallback_success",
    )
    sums = {key: 0 for key in summary_keys}
    phase_summaries = 0
    entry_level_skipped_pairs = 0
    entry_level_skip_events = 0

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            pair_match = PAIR_INDEX_RE.search(line)
            if pair_match:
                last_pair_index = int_fields(pair_match, {"timestamp"})
                continue

            summary_match = SUMMARY_RE.search(line)
            if summary_match:
                phase_summaries += 1
                for key, value in int_fields(summary_match).items():
                    sums[key] += int(value)
                continue

            entry_skip_match = ENTRY_SKIP_RE.search(line)
            if entry_skip_match:
                entry_level_skip_events += 1
                entry_level_skipped_pairs += int(entry_skip_match.group("pairs"))

    if last_pair_index is None:
        raise ValueError(f"no validate-poll pair_index line found in {path}")

    pair_index_processed = int(last_pair_index["processed"])
    pair_index_validated = int(last_pair_index["validated"])
    pair_index_invalid = int(last_pair_index["invalid"])
    pair_index_terminal = pair_index_processed + pair_index_validated + pair_index_invalid

    # Main columns intentionally use only verification-phase accounting:
    # these pairs have passed collection and entered the stable-pair phase.
    # "Processed" follows the paper-facing meaning: actually executed verify
    # pairs plus pairs skipped/deferred by probabilistic backoff. Exact
    # invalid/validated skips are reported separately for audit.
    stable_executed = sums["executed"]
    stable_skipped_backoff = sums["skipped_backoff"]
    return {
        "validate_log": rel(path),
        "last_snapshot_timestamp": str(last_pair_index["timestamp"]),
        "processed_pairs": stable_executed + stable_skipped_backoff,
        "skipped_pairs": stable_skipped_backoff,
        "executed_verify_pairs": stable_executed,
        "phase_summaries": phase_summaries,
        "stable_pairs_seen": sums["pairs"],
        "stable_pairs_handled": sums["handled"],
        "stable_skipped_all_reasons": sums["skipped"],
        "skipped_backoff_pairs": stable_skipped_backoff,
        "skipped_invalid_pairs": sums["skipped_invalid"],
        "skipped_validated_pairs": sums["skipped_validated"],
        "skipped_debug_pairs": sums["skipped_debug"],
        "validated_pairs": sums["validated"],
        "failed_pairs": sums["failed"],
        "strict_success_pairs": sums["strict_success"],
        "sn_range_success_pairs": sums["sn_range_success"],
        "stack_only_success_pairs": sums["stack_fallback_success"],
        "fallback_success_pairs": sums["fallback_success"],
        "site_only_success_pairs": sums["site_only_success"],
        "sn_range_attempt_runs": sums["sn_range_runs"],
        "stack_only_attempt_runs": sums["stack_fallback_runs"],
        "observed_target_pairs": sums["observed_target"],
        "nonblocking_observed_pairs": sums["nonblocking_observed"],
        "entry_level_skip_events_excluded": entry_level_skip_events,
        "entry_level_skipped_pairs_excluded": entry_level_skipped_pairs,
        "pair_index_terminal_pairs_excluded": pair_index_terminal,
        "pair_index_total_excluded": int(last_pair_index["total"]),
        "pair_index_processed_status_excluded": pair_index_processed,
        "pair_index_validated_status_excluded": pair_index_validated,
        "pair_index_invalid_status_excluded": pair_index_invalid,
        "pair_index_processing_excluded": int(last_pair_index["processing"]),
        "pair_index_queued_excluded": int(last_pair_index["queued"]),
        "pair_index_queueable_excluded": int(last_pair_index["queueable"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="CSV output path; defaults to RESULTS_DIR/deepseek_validate_pair_accounting.csv",
    )
    args = parser.parse_args()

    results_dir = args.results_dir
    output = args.output or results_dir / "deepseek_validate_pair_accounting.csv"

    rows: list[dict[str, int | str]] = []
    for module in MODULE_ORDER:
        log = results_dir / "source_data" / module / VARIANT / "logs" / "validate-manager.log"
        row = {
            "module": module,
            "variant": VARIANT,
            **parse_validate_log(log),
        }
        rows.append(row)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(output)
    print("module,processed_pairs,skipped_pairs,executed_verify_pairs,stable_pairs_handled,stable_skipped_all_reasons")
    for row in rows:
        print(
            ",".join(
                str(row[key])
                for key in (
                    "module",
                    "processed_pairs",
                    "skipped_pairs",
                    "executed_verify_pairs",
                    "stable_pairs_handled",
                    "stable_skipped_all_reasons",
                )
            )
        )


if __name__ == "__main__":
    main()
