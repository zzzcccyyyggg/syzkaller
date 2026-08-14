#!/usr/bin/env python3
"""Analyze Phase 2B throughput from runner watcher samples.

This is intended for runs where syz-manager's -bench output is a single
periodically rewritten JSON object. The Phase 2B runner records one snapshot per
minute under samples/*.jsonl; those snapshots preserve enough cumulative
counters to compute full-window and post-warmup syscall throughput.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


STAT_KEYS = ["exec total", "calls scheduled", "calls executed", "calls finished"]
FORBIDDEN_PATTERNS = [
    "revision mismatch",
    "SYZFAIL",
    "panic",
    "BUG:",
    "KASAN",
    "KCSAN: data-race",
    "BUG: KCSAN",
    "crash:",
    "no output from test machine",
    "stalled",
    "lost connection",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--warmup", type=float, default=None)
    parser.add_argument("--baseline-metrics", type=Path, default=None)
    parser.add_argument("--sample", default="samples/mrpfuzz-complete.jsonl")
    parser.add_argument("--write", action="store_true", help="Write sample-metrics.json and sample-metrics.md")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    warmup = args.warmup
    state = read_json(run_dir / "state.json")
    metadata = read_json(run_dir / "metadata.json")
    if warmup is None:
        warmup = float(state.get("warmup_seconds") or metadata.get("warmup_seconds") or 3600)

    rows = read_jsonl(run_dir / args.sample)
    result: dict[str, Any] = {
        "run_dir": str(run_dir),
        "sample_path": str(run_dir / args.sample),
        "sample_count": len(rows),
        "warmup_seconds": warmup,
        "status": state.get("status"),
        "current_case": state.get("current_case"),
    }
    if rows:
        result["first_timestamp"] = rows[0].get("timestamp")
        result["last_timestamp"] = rows[-1].get("timestamp")
        result["latest_elapsed_seconds"] = rows[-1].get("elapsed_seconds")
        result["latest_fuzz"] = rows[-1].get("fuzz", {})
        result["latest_validate"] = rows[-1].get("validate", {})

    full = compute_window(rows, None)
    post = compute_window(rows, warmup)
    if full:
        result["full_window"] = full
    if post:
        result["post_warmup_window"] = post
    else:
        result["post_warmup_window"] = None
        result["post_warmup_reason"] = "not enough samples at or after warmup"

    baseline = read_baseline(args.baseline_metrics)
    if baseline is not None:
        result["baseline_rate_calls_executed_per_s"] = baseline
        for key in ["full_window", "post_warmup_window"]:
            window = result.get(key)
            if isinstance(window, dict) and baseline > 0:
                rate = window.get("rate_calls executed_per_s")
                if isinstance(rate, (int, float)):
                    window["vs_baseline_x"] = round(float(rate) / baseline, 6)

    result["log_forbidden_counts"] = {
        "fuzz": forbidden_counts(run_dir / "logs/mrpfuzz-complete-fuzz.log"),
        "validate": forbidden_counts(run_dir / "logs/mrpfuzz-complete-validate.log"),
    }
    result["validate_activity"] = validate_activity(run_dir / "logs/mrpfuzz-complete-validate.log")

    print(json.dumps(result, indent=2, sort_keys=True))
    if args.write:
        write_json(run_dir / "sample-metrics.json", result)
        (run_dir / "sample-metrics.md").write_text(render_markdown(result), encoding="utf-8")


def compute_window(rows: list[dict[str, Any]], min_elapsed: float | None) -> dict[str, Any] | None:
    usable = []
    for row in rows:
        elapsed = row.get("elapsed_seconds")
        if not isinstance(elapsed, (int, float)):
            continue
        if min_elapsed is not None and elapsed < min_elapsed:
            continue
        bench = row.get("fuzz", {}).get("bench", {})
        if not isinstance(bench, dict):
            continue
        if not isinstance(bench.get("calls executed"), (int, float)):
            continue
        usable.append(row)
    if len(usable) < 2:
        return None
    first, last = usable[0], usable[-1]
    start = float(first["elapsed_seconds"])
    end = float(last["elapsed_seconds"])
    seconds = end - start
    out: dict[str, Any] = {
        "measurement_seconds": round(seconds, 3),
        "first_elapsed_seconds": round(start, 3),
        "last_elapsed_seconds": round(end, 3),
        "first_timestamp": first.get("timestamp"),
        "last_timestamp": last.get("timestamp"),
    }
    if seconds <= 0:
        out["valid"] = False
        out["reason"] = "non-positive measurement window"
        return out
    first_stats = first["fuzz"]["bench"]
    last_stats = last["fuzz"]["bench"]
    for key in STAT_KEYS:
        a, b = first_stats.get(key), last_stats.get(key)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            delta = int(b - a)
            out[f"delta_{key}"] = delta
            out[f"rate_{key}_per_s"] = round(delta / seconds, 6)
    exec_total = out.get("delta_exec total")
    calls = out.get("delta_calls executed")
    if isinstance(exec_total, int) and exec_total > 0 and isinstance(calls, int):
        out["calls_executed_per_exec_total"] = round(calls / exec_total, 6)
    out["valid"] = "rate_calls executed_per_s" in out
    return out


def read_baseline(path: Path | None) -> float | None:
    if path is None or not path.exists():
        return None
    rows = list(csv.DictReader(path.open()))
    if not rows:
        return None
    value = rows[0].get("rate_calls executed_per_s")
    return float(value) if value else None


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(errors="replace"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def forbidden_counts(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    text = path.read_text(errors="replace")
    return {pattern: text.count(pattern) for pattern in FORBIDDEN_PATTERNS if text.count(pattern)}


def validate_activity(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    text = path.read_text(errors="replace")
    patterns = [
        "uafvalidate: task start",
        "uafvalidate: task success",
        "uafvalidate: task failed",
        "[batch] completed",
        "[batch] verify: completed",
        "race storage[validate-poll]",
    ]
    return {pattern: text.count(pattern) for pattern in patterns}


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Phase 2B Sample Metrics",
        "",
        f"- Run directory: `{result.get('run_dir')}`",
        f"- Status: `{result.get('status')}`",
        f"- Sample count: `{result.get('sample_count')}`",
        f"- Warmup seconds: `{result.get('warmup_seconds')}`",
        f"- First timestamp: `{result.get('first_timestamp')}`",
        f"- Last timestamp: `{result.get('last_timestamp')}`",
    ]
    baseline = result.get("baseline_rate_calls_executed_per_s")
    if isinstance(baseline, (int, float)):
        lines.append(f"- Baseline calls executed/s: `{baseline}`")
    lines.extend(["", "| window | calls executed/s | exec total/s | measurement seconds | vs baseline |", "| --- | ---: | ---: | ---: | ---: |"])
    for name, label in [("full_window", "full"), ("post_warmup_window", "post-warmup")]:
        window = result.get(name)
        if isinstance(window, dict):
            lines.append(
                "| {label} | {calls} | {execs} | {seconds} | {ratio} |".format(
                    label=label,
                    calls=window.get("rate_calls executed_per_s", ""),
                    execs=window.get("rate_exec total_per_s", ""),
                    seconds=window.get("measurement_seconds", ""),
                    ratio=window.get("vs_baseline_x", ""),
                )
            )
        else:
            lines.append(f"| {label} | pending | pending | pending | pending |")
    lines.extend(
        [
            "",
            "## Validate Activity",
            "",
            "```json",
            json.dumps(result.get("validate_activity", {}), indent=2, sort_keys=True),
            "```",
            "",
            "## Forbidden Log Counts",
            "",
            "```json",
            json.dumps(result.get("log_forbidden_counts", {}), indent=2, sort_keys=True),
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
