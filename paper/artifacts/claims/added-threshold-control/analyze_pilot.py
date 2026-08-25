#!/usr/bin/env python3
"""Summarize completed threshold-control pilot run directories."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


CLAIM_ROOT = Path(__file__).resolve().parent
STATS_RE = re.compile(r"([A-Za-z][A-Za-z0-9 _()μ/-]*?)=(\d+)")
ADJUST_RE = re.compile(
    r"^(?P<timestamp>\S+ \S+) \[THRESHOLD\] adjusted: "
    r"(?P<old>\d+)μs → (?P<new>\d+)μs .*?reason=(?P<reason>[^,]+), "
    r"P=(?P<p>\d+), C=(?P<c>\d+), Q=(?P<q>\d+), "
    r"Pbar=(?P<pbar>[0-9.]+), Cbar=(?P<cbar>[0-9.]+), W=(?P<w>[0-9.]+)"
)


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    values = []
    for line in path.read_text().splitlines():
        if line.strip():
            values.append(json.loads(line))
    return values


def last_stats(log_path: Path) -> dict[str, int]:
    if not log_path.exists():
        return {}
    for line in reversed(log_path.read_text(errors="replace").splitlines()):
        if "calls executed=" not in line:
            continue
        return {key.strip(): int(value) for key, value in STATS_RE.findall(line)}
    return {}


def validation_activity(log_path: Path) -> dict[str, int]:
    if not log_path.exists():
        return {"task_successes": 0, "verify_completions": 0, "datarace_hits": 0}
    text = log_path.read_text(errors="replace")
    return {
        "task_successes": text.count("uafvalidate: task success"),
        "verify_completions": text.count("[batch] verify: completed"),
        "datarace_hits": text.count("DATARACE"),
    }


def threshold_rows(run_dir: Path, variant: str) -> list[dict[str, object]]:
    log_path = run_dir / "logs/mrpfuzz-complete-fuzz.log"
    rows = []
    if not log_path.exists():
        return rows
    for line in log_path.read_text(errors="replace").splitlines():
        match = ADJUST_RE.search(line)
        if not match:
            continue
        values = match.groupdict()
        rows.append(
            {
                "run_id": run_dir.name,
                "variant": variant,
                "timestamp": values["timestamp"],
                "old_threshold_us": int(values["old"]),
                "new_threshold_us": int(values["new"]),
                "reason": values["reason"],
                "P": int(values["p"]),
                "C": int(values["c"]),
                "Q": int(values["q"]),
                "Pbar": float(values["pbar"]),
                "Cbar": float(values["cbar"]),
                "W": float(values["w"]),
            }
        )
    return rows


def summarize(run_dir: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    policy = read_json(run_dir / "threshold-policy.json")
    variant = str(policy.get("variant", "unknown"))
    fixed = int(policy.get("fixed_threshold_us") or 0)
    samples = read_jsonl(run_dir / "samples/mrpfuzz-complete.jsonl")
    final_sample = samples[-1] if samples else {}
    fuzz_sample = final_sample.get("fuzz", {})
    validate_sample = final_sample.get("validate", {})
    storage = validate_sample.get("storage", {})
    queue = validate_sample.get("queue", {})
    stats = last_stats(run_dir / "logs/mrpfuzz-complete-fuzz.log")
    activity = validation_activity(run_dir / "logs/mrpfuzz-complete-validate.log")
    shared_state = read_json(
        run_dir / "workdirs/mrpfuzz-complete/threshold-state.json"
    )
    validator = shared_state.get("validator", {})
    fuzzer_state = shared_state.get("fuzzer", {})
    runner_state = read_json(run_dir / "state.json")
    adjustments = threshold_rows(run_dir, variant)
    final_threshold = fixed or int(
        fuzzer_state.get("current_threshold_us")
        or stats.get("dynamic threshold (μs)")
        or 0
    )

    row = {
        "run_id": run_dir.name,
        "variant": variant if variant == "dynamic" else f"fixed-{fixed}",
        "status": runner_state.get("status", "unknown"),
        "final": bool(final_sample.get("final", False)),
        "elapsed_seconds": final_sample.get("elapsed_seconds", 0),
        "calls_executed": stats.get("calls executed", 0),
        "exec_total": stats.get("exec total", 0),
        "pairs_fuzz": stats.get("ddrd pairs fuzz", 0),
        "varnames_fuzz": stats.get("ddrd varnames fuzz", 0),
        "uaf_corpus": stats.get("uaf corpus", 0),
        "initial_threshold_us": 2500 if variant == "dynamic" else fixed,
        "final_threshold_us": final_threshold,
        "threshold_adjustments": len(adjustments),
        "validator_pending": validator.get("pending_count", queue.get("last_poll_pending", 0)),
        "validator_processed": validator.get("processed_count", storage.get("processed", 0)),
        "validator_success": validator.get("success_count", storage.get("validated", 0)),
        "validator_task_successes": activity["task_successes"],
        "validator_verify_completions": activity["verify_completions"],
        "validator_datarace_hits": activity["datarace_hits"],
        "storage_total": storage.get("total", 0),
        "storage_processed": storage.get("processed", 0),
        "storage_validated": storage.get("validated", 0),
        "storage_invalid": storage.get("invalid", 0),
        "storage_with_history": storage.get("with_history", 0),
        "fuzz_qemu_alive_at_final": len(fuzz_sample.get("qemu_pids", [])),
        "validate_qemu_alive_at_final": len(validate_sample.get("qemu_pids", [])),
    }
    return row, adjustments


def write_outputs(rows: list[dict[str, object]], adjustments: list[dict[str, object]], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if rows:
        with (output / "pilot_metrics.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    if adjustments:
        with (output / "threshold_trajectory.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(adjustments[0]))
            writer.writeheader()
            writer.writerows(adjustments)

    lines = [
        "# Threshold-Control Pilot Summary",
        "",
        "These runs are exploratory pilot evidence, not the final rebuttal matrix.",
        "",
        "| Variant | Status | Calls | Pairs | Corpus | Final threshold | Pending | Task success | Processed | Validated |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| {variant} | {status} | {calls_executed} | {pairs_fuzz} | "
            "{uaf_corpus} | {final_threshold_us} | {validator_pending} | "
            "{validator_task_successes} | {validator_processed} | {validator_success} |".format(**row)
        )
    lines.append("")
    (output / "SUMMARY.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dirs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = []
    adjustments = []
    for run_dir in args.run_dirs:
        row, trajectory = summarize(run_dir)
        rows.append(row)
        adjustments.extend(trajectory)
    write_outputs(rows, adjustments, args.output)


if __name__ == "__main__":
    main()
