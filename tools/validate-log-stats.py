#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


SUMMARY_RE = re.compile(
    r"verification phase summary key=(?P<key>\S+) target_match_mode=(?P<mode>\S+) "
    r"pairs=(?P<pairs>\d+) handled=(?P<handled>\d+) executed=(?P<executed>\d+) "
    r"skipped=(?P<skipped>\d+) "
    r"(?:(?:executed_verify_pairs=\d+) (?:skipped_pairs=\d+) )?"
    r"skipped_debug=(?P<skipped_debug>\d+) "
    r"skipped_invalid=(?P<skipped_invalid>\d+) skipped_validated=(?P<skipped_validated>\d+) "
    r"skipped_backoff=(?P<skipped_backoff>\d+) validated=(?P<validated>\d+) "
    r"failed=(?P<failed>\d+) strict_success=(?P<strict_success>\d+) "
    r"fallback_runs=(?P<fallback_runs>\d+) fallback_success=(?P<fallback_success>\d+) "
    r"site_only_success=(?P<site_only_success>\d+)"
)

ENTRY_SKIP_RE = re.compile(
    r"uafvalidate: skipping (?:entry|ref) .*?: all (?P<pairs>\d+) pairs"
)


def add(dst, key, value=1):
    dst[key] = dst.get(key, 0) + value


def parse_log(path):
    stats = {
        "log": str(path),
        "phase_summaries": 0,
        "summary_pairs": 0,
        "executed_verify_pairs": 0,
        "skipped_pairs": 0,
        "skipped_debug": 0,
        "skipped_invalid": 0,
        "skipped_validated": 0,
        "skipped_backoff": 0,
        "validated_pairs": 0,
        "failed_pairs": 0,
        "fallback_runs": 0,
        "fallback_success": 0,
        "site_only_success": 0,
        "strict_success": 0,
        "entry_level_skipped_pairs": 0,
        "partial_verify_pair_started": 0,
        "partial_verify_run_finished": 0,
        "partial_visible_skip_events": 0,
        "pair_validated_log": 0,
        "pair_failed_log": 0,
        "datarace_crash_logs": 0,
        "minimization_logs": 0,
    }

    with path.open("r", errors="replace") as f:
        for line in f:
            m = SUMMARY_RE.search(line)
            if m:
                add(stats, "phase_summaries")
                for name in (
                    "pairs",
                    "executed",
                    "skipped",
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
                ):
                    value = int(m.group(name))
                    mapped = {
                        "pairs": "summary_pairs",
                        "executed": "executed_verify_pairs",
                        "skipped": "skipped_pairs",
                        "validated": "validated_pairs",
                        "failed": "failed_pairs",
                    }.get(name, name)
                    add(stats, mapped, value)
                continue

            m = ENTRY_SKIP_RE.search(line)
            if m:
                add(stats, "entry_level_skipped_pairs", int(m.group("pairs")))
                continue

            if "uafvalidate: verifying pair " in line:
                add(stats, "partial_verify_pair_started")
            if "uafvalidate: verification run finished " in line:
                add(stats, "partial_verify_run_finished")
            if (
                "uafvalidate: L1 skip " in line
                or "uafvalidate: L2 skip " in line
                or "uafvalidate: skipping validated pair " in line
                or "uafvalidate: [debug mode] skipping non-target pair " in line
            ):
                add(stats, "partial_visible_skip_events")
            if "uafvalidate: pair validated after " in line:
                add(stats, "pair_validated_log")
            if "uafvalidate: pair failed verification" in line:
                add(stats, "pair_failed_log")
            if "DATARACE " in line and "crash=" in line:
                add(stats, "datarace_crash_logs")
            if "minimization" in line:
                add(stats, "minimization_logs")

    stats["total_skipped_pairs_including_entry_level"] = (
        stats["skipped_pairs"] + stats["entry_level_skipped_pairs"]
    )
    stats["summary_complete_for_finished_phases"] = (
        stats["phase_summaries"] > 0
        and stats["executed_verify_pairs"] + stats["skipped_pairs"] == stats["summary_pairs"]
    )
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Extract validation pair accounting from syz-manager manager.log files."
    )
    parser.add_argument("logs", nargs="+", help="manager.log paths or validate workdirs")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    rows = []
    for item in args.logs:
        path = Path(item)
        if path.is_dir():
            path = path / "manager.log"
        rows.append(parse_log(path))

    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
        return

    header = (
        "log",
        "phases",
        "executed_verify_pairs",
        "skipped_pairs",
        "entry_skipped_pairs",
        "verify_started",
        "verify_finished",
        "validated_logs",
        "failed_logs",
        "minim_logs",
    )
    print("\t".join(header))
    for row in rows:
        values = (
            row["log"],
            row["phase_summaries"],
            row["executed_verify_pairs"],
            row["skipped_pairs"],
            row["entry_level_skipped_pairs"],
            row["partial_verify_pair_started"],
            row["partial_verify_run_finished"],
            row["pair_validated_log"],
            row["pair_failed_log"],
            row["minimization_logs"],
        )
        print("\t".join(str(v) for v in values))


if __name__ == "__main__":
    main()
