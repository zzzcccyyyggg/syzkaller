#!/usr/bin/env python3
"""Compare raw and effective syscall exploration throughput.

The raw metric is syzkaller's cumulative "calls executed" rate.

For SegFuzz, this script also reports an "effective" estimate that excludes
executions spent on SegFuzz's interleaving replay paths:
- exec schedulings: executions of schedule-mutated threaded programs.
- exec threadings: executions used to derive interleaving/threading hints.

Existing SegFuzz bench files do not split syscall counts by stat category, so
the excluded syscall count is estimated with the run-wide average calls/exec.
Use this as an analysis metric for existing artifacts, and prefer an
instrumented SegFuzz run for paper-grade exact per-stat syscall accounting.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


DEFAULT_MRPFUZZ_RUN = Path(
    "paper/artifacts/claims/added-throughput/runs/"
    "20260814-1936-mrpfuzz-seeded2253-scratchreuse-2vm2cpu-procs2-complete-1h"
)
DEFAULT_SEGFUZZ_RUN = Path(
    "paper/artifacts/claims/added-throughput/runs/"
    "20260812-1755-segfuzz-kcsan-4core-24h"
)
SEGFUZZ_STAT_SUFFIXES = [
    "gen",
    "fuzz",
    "candidate",
    "triage",
    "minimize",
    "smash",
    "hints",
    "seeds",
    "threadings",
    "schedulings",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mrpfuzz-run", type=Path, default=DEFAULT_MRPFUZZ_RUN)
    parser.add_argument("--segfuzz-run", type=Path, default=DEFAULT_SEGFUZZ_RUN)
    parser.add_argument("--warmup", type=float, default=None)
    parser.add_argument("--write-json", type=Path, default=None)
    parser.add_argument("--write-md", type=Path, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    mrpfuzz_run = args.mrpfuzz_run.resolve()
    segfuzz_run = args.segfuzz_run.resolve()
    warmup = args.warmup

    if warmup is None:
        warmup = infer_warmup(mrpfuzz_run) or infer_warmup(segfuzz_run) or 300.0

    result = {
        "warmup_seconds": warmup,
        "mrpfuzz": analyze_mrpfuzz(mrpfuzz_run),
        "segfuzz": analyze_segfuzz(segfuzz_run, warmup),
        "method": {
            "raw_metric": "calls executed/s",
            "effective_metric": "MRPFuzz raw calls executed/s compared with SegFuzz calls executed/s after excluding interleaving replay executions.",
            "segfuzz_exactness": "exact when SegFuzz bench has per-stat syscall counters; otherwise estimated from exec-category deltas.",
            "segfuzz_excluded_exec_categories": ["exec schedulings", "exec threadings"],
        },
    }
    add_comparisons(result)

    print(json.dumps(result, indent=2, sort_keys=True))
    if args.write_json:
        args.write_json.parent.mkdir(parents=True, exist_ok=True)
        args.write_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.write_md:
        args.write_md.parent.mkdir(parents=True, exist_ok=True)
        args.write_md.write_text(render_markdown(result), encoding="utf-8")


def infer_warmup(run_dir: Path) -> float | None:
    for name in ["state.json", "metadata.json"]:
        path = run_dir / name
        if not path.exists():
            continue
        obj = read_json(path)
        value = obj.get("warmup_seconds")
        if isinstance(value, (int, float)):
            return float(value)
    return None


def analyze_mrpfuzz(run_dir: Path) -> dict[str, Any]:
    sample = read_json(run_dir / "sample-metrics.json")
    post = sample.get("post_warmup_window")
    if isinstance(post, dict):
        raw = number(post.get("rate_calls executed_per_s"))
        exec_rate = number(post.get("rate_exec total_per_s"))
        return {
            "run_dir": str(run_dir),
            "source": str(run_dir / "sample-metrics.json"),
            "raw_calls_executed_per_s": raw,
            "effective_calls_executed_per_s": raw,
            "exec_total_per_s": exec_rate,
            "notes": "No SegFuzz-style schedule/threading replay category is deducted for MRPFuzz.",
        }

    metrics = run_dir / "metrics.csv"
    rows = list(csv.DictReader(metrics.open())) if metrics.exists() else []
    if not rows:
        raise SystemExit(f"cannot find MRPFuzz metrics in {run_dir}")
    row = rows[0]
    raw = number(row.get("rate_calls executed_per_s"))
    exec_rate = number(row.get("rate_exec total_per_s"))
    return {
        "run_dir": str(run_dir),
        "source": str(metrics),
        "raw_calls_executed_per_s": raw,
        "effective_calls_executed_per_s": raw,
        "exec_total_per_s": exec_rate,
        "notes": "No SegFuzz-style schedule/threading replay category is deducted for MRPFuzz.",
    }


def analyze_segfuzz(run_dir: Path, warmup: float) -> dict[str, Any]:
    bench_path = find_segfuzz_bench(run_dir)
    rows = read_concatenated_json(bench_path)
    usable = [row for row in rows if number(row.get("uptime")) is not None and float(row["uptime"]) >= warmup]
    if len(usable) < 2:
        raise SystemExit(f"not enough SegFuzz bench samples after warmup in {bench_path}")

    first, last = usable[0], usable[-1]
    seconds = float(last["uptime"]) - float(first["uptime"])
    if seconds <= 0:
        raise SystemExit(f"non-positive SegFuzz measurement window in {bench_path}")

    delta_keys = [
        "calls executed",
        "calls finished",
        "calls scheduled",
        "exec total",
        "exec schedulings",
        "exec threadings",
        "exec fuzz",
        "exec gen",
        "exec triage",
        "exec smash",
        "exec candidate",
        "exec minimize",
        "new inputs",
        "new scheduled inputs",
        "interleaving cover",
        "interleaving signal",
        "corpus",
        "scheduled corpus",
    ]
    for suffix in SEGFUZZ_STAT_SUFFIXES:
        delta_keys.append(f"calls executed {suffix}")
        delta_keys.append(f"calls finished {suffix}")

    deltas = {
        key: int(number(last.get(key), 0) - number(first.get(key), 0))
        for key in delta_keys
        if number(first.get(key)) is not None and number(last.get(key)) is not None
    }
    exec_total = deltas.get("exec total", 0)
    calls = deltas.get("calls executed", 0)
    avg_calls_per_exec = calls / exec_total if exec_total > 0 else 0.0
    sched_exec = deltas.get("exec schedulings", 0)
    threading_exec = deltas.get("exec threadings", 0)

    raw_calls_rate = calls / seconds
    sched_calls, sched_call_accounting = excluded_calls(
        deltas, ["schedulings"], sched_exec, avg_calls_per_exec
    )
    sched_thread_calls_excluded, sched_thread_call_accounting = excluded_calls(
        deltas, ["schedulings", "threadings"], sched_exec + threading_exec, avg_calls_per_exec
    )
    sched_only_calls = calls - sched_calls
    sched_thread_calls = calls - sched_thread_calls_excluded

    return {
        "run_dir": str(run_dir),
        "source": str(bench_path),
        "samples": len(rows),
        "post_warmup_samples": len(usable),
        "measurement_seconds": seconds,
        "first_uptime": first.get("uptime"),
        "last_uptime": last.get("uptime"),
        "deltas": deltas,
        "avg_calls_per_exec": avg_calls_per_exec,
        "raw_calls_executed_per_s": raw_calls_rate,
        "exec_total_per_s": exec_total / seconds,
        "effective_excluding_schedulings_per_s": sched_only_calls / seconds,
        "effective_excluding_schedulings_and_threadings_per_s": sched_thread_calls / seconds,
        "excluded_calls_schedulings": sched_calls,
        "excluded_calls_schedulings_and_threadings": sched_thread_calls_excluded,
        "call_accounting_schedulings": sched_call_accounting,
        "call_accounting_schedulings_and_threadings": sched_thread_call_accounting,
        "excluded_exec_fraction_schedulings": sched_exec / exec_total if exec_total else None,
        "excluded_exec_fraction_schedulings_and_threadings": (sched_exec + threading_exec) / exec_total if exec_total else None,
        "notes": "Effective rates use exact per-stat syscall counters when present; otherwise they estimate excluded calls with run-wide average calls/exec.",
    }


def excluded_calls(
    deltas: dict[str, int], suffixes: list[str], fallback_execs: int, avg_calls_per_exec: float
) -> tuple[float, str]:
    keys = [f"calls executed {suffix}" for suffix in suffixes]
    if all(key in deltas for key in keys):
        return float(sum(deltas[key] for key in keys)), "exact"
    return fallback_execs * avg_calls_per_exec, "estimated_from_avg_calls_per_exec"


def find_segfuzz_bench(run_dir: Path) -> Path:
    preferred = run_dir / "bench/segfuzz-4core.json"
    if preferred.exists():
        return preferred
    candidates = sorted((run_dir / "bench").glob("*.json"))
    if not candidates:
        raise SystemExit(f"cannot find SegFuzz bench json under {run_dir / 'bench'}")
    return candidates[0]


def add_comparisons(result: dict[str, Any]) -> None:
    mrp = result["mrpfuzz"]["effective_calls_executed_per_s"]
    seg = result["segfuzz"]
    raw = seg["raw_calls_executed_per_s"]
    sched = seg["effective_excluding_schedulings_per_s"]
    sched_thread = seg["effective_excluding_schedulings_and_threadings_per_s"]
    result["comparison"] = {
        "raw_mrpfuzz_vs_raw_segfuzz_x": mrp / raw if raw else None,
        "mrpfuzz_vs_segfuzz_excluding_schedulings_x": mrp / sched if sched else None,
        "mrpfuzz_vs_segfuzz_excluding_schedulings_and_threadings_x": mrp / sched_thread if sched_thread else None,
    }


def read_concatenated_json(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(errors="replace")
    decoder = json.JSONDecoder()
    pos = 0
    rows: list[dict[str, Any]] = []
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        obj, next_pos = decoder.raw_decode(text, pos)
        if isinstance(obj, dict):
            rows.append(obj)
        pos = next_pos
    return rows


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(errors="replace"))


def number(value: Any, default: float | None = None) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def pct(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value * 100:.2f}%"


def rate(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.6f}"


def ratio(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.6f}x"


def render_markdown(result: dict[str, Any]) -> str:
    mrp = result["mrpfuzz"]
    seg = result["segfuzz"]
    comp = result["comparison"]
    lines = [
        "# Effective Throughput Analysis",
        "",
        f"- Warmup seconds: `{result['warmup_seconds']}`",
        f"- MRPFuzz run: `{mrp['run_dir']}`",
        f"- SegFuzz run: `{seg['run_dir']}`",
        "",
        "## Summary",
        "",
        "| metric | MRPFuzz calls/s | SegFuzz calls/s | MRPFuzz / SegFuzz |",
        "| --- | ---: | ---: | ---: |",
        f"| raw calls executed | {rate(mrp['raw_calls_executed_per_s'])} | {rate(seg['raw_calls_executed_per_s'])} | {ratio(comp['raw_mrpfuzz_vs_raw_segfuzz_x'])} |",
        f"| SegFuzz excluding schedulings | {rate(mrp['effective_calls_executed_per_s'])} | {rate(seg['effective_excluding_schedulings_per_s'])} | {ratio(comp['mrpfuzz_vs_segfuzz_excluding_schedulings_x'])} |",
        f"| SegFuzz excluding schedulings + threadings | {rate(mrp['effective_calls_executed_per_s'])} | {rate(seg['effective_excluding_schedulings_and_threadings_per_s'])} | {ratio(comp['mrpfuzz_vs_segfuzz_excluding_schedulings_and_threadings_x'])} |",
        "",
        "## SegFuzz Replay Share",
        "",
        "| excluded category | exec fraction | excluded execs |",
        "| --- | ---: | ---: |",
        f"| exec schedulings | {pct(seg['excluded_exec_fraction_schedulings'])} | {seg['deltas'].get('exec schedulings', '')} |",
        f"| exec schedulings + exec threadings | {pct(seg['excluded_exec_fraction_schedulings_and_threadings'])} | {seg['deltas'].get('exec schedulings', 0) + seg['deltas'].get('exec threadings', 0)} |",
        "",
        "## Caveat",
        "",
        "For old SegFuzz bench files without per-stat syscall counters, effective syscall rates estimate excluded calls "
        "with the run-wide average calls/exec. For instrumented reruns, the same script uses exact "
        "`calls executed schedulings/threadings` counters.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
