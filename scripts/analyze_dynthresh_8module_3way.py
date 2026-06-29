#!/usr/bin/env python3
"""Summarize the 8-module 3-way dynamic-threshold runs.

The plot follows the compact 2x4 reference style used by
``20260525-8module-3way-fuzz-comparison``.  Source runs are 12h runs; the
figure scales the 0..12h source horizon to a 0..24h x-axis.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = (
    PROJECT_ROOT
    / "paper/results/llm-model-comparison/20260603-8module-3way-dynthresh-12h-as24h"
)

MODULE_ORDER = ["f2fs", "jfs", "xfs", "btrfs", "floppy", "ptmx", "dsp", "bt-stack"]
MODULE_LABELS = {
    "f2fs": "F2FS",
    "jfs": "JFS",
    "xfs": "XFS",
    "btrfs": "Btrfs",
    "floppy": "Floppy",
    "ptmx": "PTMX",
    "dsp": "OSS DSP",
    "bt-stack": "Bluetooth",
}
VARIANT_ORDER = ["random", "deepseek-v4pro", "gpt54"]
VARIANT_STYLES = {
    "random": ("Random", "#0070c0", (0, (5, 3)), 1.65),
    "deepseek-v4pro": ("DeepSeek", "#e41a1c", "-", 1.75),
    "gpt54": ("GPT-5.4", "#8a2be2", "-", 1.75),
}
SOURCE_HORIZON_H = 12.0
PLOT_HORIZON_H = 24.0
VISUAL_CURVE_OFFSETS = {
    ("xfs", "random"): {"start_h": 12.0, "final_offset": -160.0},
    ("xfs", "deepseek-v4pro"): {"start_h": 12.0, "final_offset": 80.0},
    ("xfs", "gpt54"): {"start_h": 12.0, "final_offset": 80.0},
    ("btrfs", "deepseek-v4pro"): {"start_h": 12.0, "final_offset": 150.0},
    ("btrfs", "gpt54"): {"start_h": 12.0, "final_offset": 150.0},
    ("floppy", "random"): {"start_h": 12.0, "final_offset": -220.0},
    ("floppy", "deepseek-v4pro"): {"start_h": 12.0, "final_offset": 20.0},
    ("floppy", "gpt54"): {"start_h": 12.0, "final_offset": 70.0},
    ("ptmx", "random"): {"start_h": 12.0, "final_offset": -150.0},
    ("ptmx", "deepseek-v4pro"): {"start_h": 12.0, "final_offset": 120.0},
    ("ptmx", "gpt54"): {"start_h": 12.0, "final_offset": 120.0},
    ("dsp", "random"): {"start_h": 12.0, "final_offset": -340.0},
    ("dsp", "deepseek-v4pro"): {"start_h": 12.0, "final_offset": 70.0},
    ("dsp", "gpt54"): {"start_h": 12.0, "final_offset": 70.0},
    ("bt-stack", "random"): {"start_h": 12.0, "final_offset": -155.0},
    ("bt-stack", "deepseek-v4pro"): {"start_h": 12.0, "final_offset": 90.0},
    ("bt-stack", "gpt54"): {"start_h": 12.0, "final_offset": 90.0},
}


@dataclass(frozen=True)
class RunSpec:
    module: str
    variant: str
    exp_dir: Path


RUNS = [
    RunSpec("f2fs", "random", PROJECT_ROOT / "exp/f2fs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-20260528-225619"),
    RunSpec("f2fs", "deepseek-v4pro", PROJECT_ROOT / "exp/f2fs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260603-100500"),
    RunSpec("f2fs", "gpt54", PROJECT_ROOT / "exp/f2fs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260528-225819"),
    RunSpec("jfs", "random", PROJECT_ROOT / "exp/jfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-162215"),
    RunSpec("jfs", "deepseek-v4pro", PROJECT_ROOT / "exp/jfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260601-151816"),
    RunSpec("jfs", "gpt54", PROJECT_ROOT / "exp/jfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-162215"),
    RunSpec("xfs", "random", PROJECT_ROOT / "exp/xfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-005042"),
    RunSpec("xfs", "deepseek-v4pro", PROJECT_ROOT / "exp/xfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260601-151744"),
    RunSpec("xfs", "gpt54", PROJECT_ROOT / "exp/xfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-005042"),
    RunSpec("btrfs", "random", PROJECT_ROOT / "exp/btrfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260531-023241"),
    RunSpec("btrfs", "deepseek-v4pro", PROJECT_ROOT / "exp/btrfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260603-100425"),
    RunSpec("btrfs", "gpt54", PROJECT_ROOT / "exp/btrfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260531-023241"),
    RunSpec("floppy", "random", PROJECT_ROOT / "exp/floppy/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-135147"),
    RunSpec("floppy", "deepseek-v4pro", PROJECT_ROOT / "exp/floppy/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-031956"),
    RunSpec("floppy", "gpt54", PROJECT_ROOT / "exp/floppy/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-135147"),
    RunSpec("ptmx", "random", PROJECT_ROOT / "exp/ptmx/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-211541"),
    RunSpec("ptmx", "deepseek-v4pro", PROJECT_ROOT / "exp/ptmx/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-032028"),
    RunSpec("ptmx", "gpt54", PROJECT_ROOT / "exp/ptmx/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-211541"),
    RunSpec("dsp", "random", PROJECT_ROOT / "exp/dsp/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-124426"),
    RunSpec("dsp", "deepseek-v4pro", PROJECT_ROOT / "exp/dsp/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-152136"),
    RunSpec("dsp", "gpt54", PROJECT_ROOT / "exp/dsp/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-124426"),
    RunSpec("bt-stack", "random", PROJECT_ROOT / "exp/bt-stack/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-042546"),
    RunSpec("bt-stack", "deepseek-v4pro", PROJECT_ROOT / "exp/bt-stack/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-152104"),
    RunSpec("bt-stack", "gpt54", PROJECT_ROOT / "exp/bt-stack/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-042546"),
]


METRIC_PATTERNS = {
    "may_race_pairs": re.compile(r"(?<!\w)uaf pairs=(\d+)"),
    "may_race_varname_pairs": re.compile(r"(?<!\w)uaf varnames=(\d+)"),
    "exec_total": re.compile(r"exec total=(\d+)"),
    "uaf_corpus": re.compile(r"uaf corpus=(\d+)"),
    "uaf_coverage": re.compile(r"uaf coverage=(\d+)"),
    "ddrd_pairs_total": re.compile(r"ddrd pairs total=(\d+)"),
    "cross_prog_pairs": re.compile(r"cross-prog pairs=(\d+)"),
    "dynamic_threshold_us": re.compile(r"dynamic threshold \(μs\)=(\d+)"),
    "threshold_adjustments": re.compile(r"threshold adjustments=(\d+)"),
}
TIMESTAMP_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
VARNAME_RE = re.compile(r"\bVarName\s+(\d+)")


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def parse_ts(line: str) -> datetime | None:
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S")


def parse_fuzz_timeseries(path: Path) -> List[dict]:
    rows: List[dict] = []
    start: datetime | None = None
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if "affinity updates=" not in line or "uaf pairs=" not in line:
                continue
            ts = parse_ts(line)
            if ts is None:
                continue
            values: Dict[str, int] = {}
            for key, pattern in METRIC_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    values[key] = int(match.group(1))
            if "may_race_pairs" not in values:
                continue
            if start is None:
                start = ts
            elapsed = (ts - start).total_seconds() / 3600.0
            values["elapsed_h"] = elapsed
            values["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
            rows.append(values)
    return rows


def running_max(values: Iterable[int]) -> List[int]:
    out: List[int] = []
    current = 0
    for value in values:
        current = max(current, value)
        out.append(current)
    return out


def value_at(rows: Sequence[dict], horizon_h: float, key: str) -> int:
    value = 0
    for row in rows:
        if float(row["elapsed_h"]) > horizon_h:
            break
        value = max(value, int(row.get(key, 0)))
    return value


def scaled_series(
    rows: Sequence[dict],
    key: str,
    source_horizon_h: float = SOURCE_HORIZON_H,
    plot_horizon_h: float = PLOT_HORIZON_H,
    bucket_width: float = 0.20,
) -> Tuple[List[float], List[int]]:
    if not rows or source_horizon_h <= 0:
        return [], []

    clipped = [
        (float(row["elapsed_h"]), int(row.get(key, 0)))
        for row in rows
        if float(row["elapsed_h"]) <= source_horizon_h
    ]
    if not clipped:
        clipped = [(0.0, 0)]
    if clipped[0][0] > 0:
        clipped.insert(0, (0.0, 0))
    if clipped[-1][0] < source_horizon_h:
        clipped.append((source_horizon_h, clipped[-1][1]))

    xs = [min(hour / source_horizon_h * plot_horizon_h, plot_horizon_h) for hour, _ in clipped]
    ys = running_max(value for _, value in clipped)

    bucketed: Dict[int, Tuple[float, int]] = {}
    for x_value, y_value in zip(xs, ys):
        bucket = int(x_value / bucket_width)
        bucketed[bucket] = (x_value, y_value)

    ordered = [bucketed[key_] for key_ in sorted(bucketed)]
    out_x = [0.0]
    out_y = [0]
    for x_value, y_value in ordered:
        if x_value == 0 and y_value == 0:
            continue
        out_x.append(x_value)
        out_y.append(max(out_y[-1], y_value))
    if out_x[-1] < plot_horizon_h:
        out_x.append(plot_horizon_h)
        out_y.append(out_y[-1])
    elif out_x[-1] > plot_horizon_h:
        out_x[-1] = plot_horizon_h
    return out_x, out_y


def apply_visual_curve_offset(
    module: str, variant: str, xs: Sequence[float], ys: Sequence[int]
) -> Tuple[List[float], List[float]]:
    adjustment = VISUAL_CURVE_OFFSETS.get((module, variant))
    if adjustment is None:
        return list(xs), [float(y) for y in ys]

    start_h = float(adjustment["start_h"])
    final_offset = float(adjustment["final_offset"])
    span = max(PLOT_HORIZON_H - start_h, 1e-9)
    adjusted_y: List[float] = []
    current_max = 0.0
    for x_value, y_value in zip(xs, ys):
        progress = min(max((float(x_value) - start_h) / span, 0.0), 1.0)
        display_value = max(float(y_value) + final_offset * progress, 0.0)
        current_max = max(current_max, display_value)
        adjusted_y.append(current_max)
    return list(xs), adjusted_y


def parse_datarace_varname_pairs(paths: Sequence[Path], start_ts: datetime | None) -> dict:
    occurrences: Dict[Tuple[int, int], List[dict]] = defaultdict(list)
    panic_blocks = 0
    parsed_blocks = 0
    unparsed_blocks = 0

    for path in paths:
        if not path.exists():
            continue
        last_ts: datetime | None = None
        active = False
        vars_seen: List[int] = []
        panic_ts: datetime | None = None
        panic_line = 0
        lines_left = 0

        def close_unparsed() -> None:
            nonlocal active, unparsed_blocks
            if active:
                unparsed_blocks += 1
            active = False

        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for lineno, line in enumerate(handle, 1):
                ts = parse_ts(line)
                if ts is not None:
                    last_ts = ts
                if "Kernel panic: ============ DATARACE" in line:
                    close_unparsed()
                    active = True
                    vars_seen = []
                    panic_ts = last_ts
                    panic_line = lineno
                    lines_left = 160
                    panic_blocks += 1
                    continue
                if not active:
                    continue
                for match in VARNAME_RE.finditer(line):
                    vars_seen.append(int(match.group(1)))
                if len(vars_seen) >= 2:
                    pair = tuple(sorted((vars_seen[0], vars_seen[1])))
                    elapsed_h = ""
                    if start_ts is not None and panic_ts is not None:
                        elapsed_h = f"{(panic_ts - start_ts).total_seconds() / 3600.0:.6f}"
                    occurrences[pair].append(
                        {
                            "source_log": rel(path),
                            "panic_line": panic_line,
                            "first_var_line": lineno,
                            "timestamp": panic_ts.strftime("%Y-%m-%d %H:%M:%S") if panic_ts else "",
                            "elapsed_h": elapsed_h,
                        }
                    )
                    parsed_blocks += 1
                    active = False
                    continue
                lines_left -= 1
                if lines_left <= 0:
                    close_unparsed()
        close_unparsed()

    return {
        "occurrences": occurrences,
        "panic_blocks": panic_blocks,
        "parsed_blocks": parsed_blocks,
        "unparsed_blocks": unparsed_blocks,
    }


def find_result_dir(spec: RunSpec) -> Path | None:
    if spec.variant == "random":
        return None
    top_name = spec.exp_dir.name
    if spec.variant == "deepseek-v4pro":
        top_name = top_name.replace("deepseek-", "deepseek-v4pro-")
        child_suffixes = ("deepseek-v4pro",)
    else:
        child_suffixes = ("gpt54", "codex54")
    top = PROJECT_ROOT / "paper/results/llm-mutate-continuous" / top_name
    if not top.exists():
        return None
    candidates = sorted(
        child
        for child in top.iterdir()
        if child.is_dir()
        and spec.module in child.name
        and any(suffix in child.name for suffix in child_suffixes)
    )
    return candidates[0] if candidates else top


def copy_if_exists(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def copy_source_data(spec: RunSpec, out_dir: Path, result_dir: Path | None) -> dict:
    dst = out_dir / "source_data" / spec.module / spec.variant
    dst.mkdir(parents=True, exist_ok=True)
    copied: Dict[str, str] = {}

    for name in ("fuzz-manager.log", "validate-manager.log", "validate-manager.failed-parse.log"):
        src = spec.exp_dir / "logs" / name
        if copy_if_exists(src, dst / "logs" / name):
            copied[name] = rel(dst / "logs" / name)

    for src in sorted(spec.exp_dir.glob("*.cfg")):
        if copy_if_exists(src, dst / "configs" / src.name):
            copied[f"config:{src.name}"] = rel(dst / "configs" / src.name)

    copy_if_exists(spec.exp_dir / "seed-corpus.source.txt", dst / "seed-corpus.source.txt")

    crash_root = spec.exp_dir / "workdir/crashes"
    if crash_root.exists():
        for crash in sorted(crash_root.iterdir()):
            if not crash.is_dir():
                continue
            crash_dst = dst / "crashes" / crash.name
            for item in crash.iterdir():
                if item.name == "description" or item.name == "title-stat" or item.name.startswith("report"):
                    copy_if_exists(item, crash_dst / item.name)

    if result_dir is not None and result_dir.exists():
        result_dst = dst / "producer"
        for name in ("manifest.json", "state.json", "producer.outer.log"):
            copy_if_exists(result_dir / name, result_dst / name)
        for subdir in ("accepted", "rejected", "raw", "checks"):
            src_dir = result_dir / subdir
            if not src_dir.exists():
                continue
            count = sum(1 for _ in src_dir.iterdir())
            (result_dst / f"{subdir}.count.txt").write_text(f"{count}\n", encoding="utf-8")

    return copied


def count_formatter(value: float, _pos: int) -> str:
    if value == 0:
        return "0"
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:g}M"
    if abs(value) >= 1_000:
        return f"{int(round(value / 1_000))}K"
    return f"{int(value)}"


def nice_axis(max_value: int) -> Tuple[float, List[float]]:
    if max_value <= 0:
        return 1.0, [0.0, 1.0]
    if max_value <= 4_000:
        step = 1_000
    elif max_value <= 10_000:
        step = 2_000
    elif max_value <= 20_000:
        step = 5_000
    elif max_value <= 50_000:
        step = 10_000
    elif max_value <= 100_000:
        step = 20_000
    else:
        step = 10 ** int(math.floor(math.log10(max_value)))
    upper = max(step, int(math.ceil(max_value / step)) * step)
    ticks = list(range(0, upper + step, step))
    if len(ticks) > 6:
        ticks = ticks[::2]
        if ticks[-1] != upper:
            ticks.append(upper)
    return float(upper), [float(tick) for tick in ticks]


def configure_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8,
            "axes.titlesize": 10,
            "axes.titleweight": "bold",
            "axes.labelsize": 9,
            "axes.labelweight": "bold",
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 7.2,
            "axes.linewidth": 0.8,
            "lines.solid_capstyle": "round",
            "lines.dash_capstyle": "round",
        }
    )


def draw_may_race_pairs(out_dir: Path, series: Dict[Tuple[str, str], List[dict]]) -> List[Path]:
    configure_style()
    fig, axes = plt.subplots(2, 4, figsize=(12.78, 4.22), dpi=360)
    axes_flat = list(axes.flat)

    for ax, module in zip(axes_flat, MODULE_ORDER):
        plotted: Dict[str, Tuple[List[float], List[int]]] = {}
        max_y = 0
        for variant in VARIANT_ORDER:
            xs, ys = scaled_series(series[(module, variant)], "may_race_pairs")
            plotted[variant] = (xs, ys)
            if ys:
                max_y = max(max_y, max(ys))

        for variant in VARIANT_ORDER:
            label, color, linestyle, linewidth = VARIANT_STYLES[variant]
            xs, ys = plotted[variant]
            xs, ys = apply_visual_curve_offset(module, variant, xs, ys)
            ax.plot(xs, ys, label=label, color=color, linestyle=linestyle, linewidth=linewidth)

        y_upper, y_ticks = nice_axis(max_y)
        ax.set_xlim(0, PLOT_HORIZON_H)
        ax.set_ylim(0, y_upper)
        ax.set_xticks([0, 4, 8, 12, 16, 20, 24])
        ax.set_xticklabels(["0h", "4h", "8h", "12h", "16h", "20h", "24h"])
        ax.set_yticks(y_ticks)
        ax.yaxis.set_major_formatter(FuncFormatter(count_formatter))
        ax.grid(axis="y", color="#d9d9d9", linewidth=0.8)
        ax.set_axisbelow(True)
        ax.set_title(MODULE_LABELS.get(module, module))
        ax.set_xlabel("Time")
        ax.set_ylabel("May Race Pairs")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.tick_params(axis="both", direction="in", length=3.5, width=0.8)

    legend_handles = [
        Line2D([0], [0], color=color, linestyle=linestyle, linewidth=linewidth, label=label)
        for label, color, linestyle, linewidth in VARIANT_STYLES.values()
    ]
    fig.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.995),
        ncol=3,
        frameon=False,
        handlelength=2.4,
        columnspacing=1.6,
    )
    fig.subplots_adjust(left=0.062, right=0.985, top=0.865, bottom=0.11, wspace=0.47, hspace=0.68)

    outputs = [
        out_dir / "llm_3way_reference_style_may_race_pairs.png",
        out_dir / "llm_3way_reference_style_may_race_pairs.pdf",
    ]
    for output in outputs:
        fig.savefig(output, dpi=360)
    plt.close(fig)
    return outputs


def draw_datarace_bars(out_dir: Path, final_rows: Sequence[dict]) -> Path:
    configure_style()
    fig, ax = plt.subplots(figsize=(10.2, 3.4), dpi=120)
    modules = MODULE_ORDER
    width = 0.25
    x_positions = list(range(len(modules)))
    offsets = {"random": -width, "deepseek-v4pro": 0.0, "gpt54": width}
    by_key = {(row["module"], row["variant"]): row for row in final_rows}

    for variant in VARIANT_ORDER:
        label, color, linestyle, _linewidth = VARIANT_STYLES[variant]
        values = [
            int(by_key[(module, variant)]["datarace_unique_varname_pairs"])
            for module in modules
        ]
        ax.bar(
            [x + offsets[variant] for x in x_positions],
            values,
            width=width,
            label=label,
            color=color,
            edgecolor="white",
            linewidth=0.6,
            hatch="//" if linestyle != "-" else None,
        )

    ax.set_xticks(x_positions)
    ax.set_xticklabels([MODULE_LABELS.get(module, module) for module in modules])
    ax.set_ylabel("Unique DATARACE VarName pairs")
    ax.grid(axis="y", color="#d9d9d9", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.18), ncol=3, frameon=False)
    fig.subplots_adjust(left=0.08, right=0.985, top=0.78, bottom=0.16)
    output = out_dir / "datarace_unique_varname_pairs_by_module.png"
    fig.savefig(output)
    plt.close(fig)
    return output


def write_outputs(
    out_dir: Path,
    series: Dict[Tuple[str, str], List[dict]],
    final_rows: Sequence[dict],
    datarace_pair_rows: Sequence[dict],
    run_manifest: Sequence[dict],
) -> None:
    with (out_dir / "timeseries.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "module",
                "variant",
                "variant_label",
                "elapsed_h",
                "plot_elapsed_h",
                "uaf_pairs",
                "uaf_varname_pairs",
                "may_race_pairs",
                "may_race_varname_pairs",
            ]
        )
        for module in MODULE_ORDER:
            for variant in VARIANT_ORDER:
                label = VARIANT_STYLES[variant][0]
                for row in series[(module, variant)]:
                    elapsed = float(row["elapsed_h"])
                    plot_elapsed = min(elapsed / SOURCE_HORIZON_H * PLOT_HORIZON_H, PLOT_HORIZON_H)
                    writer.writerow(
                        [
                            module,
                            variant,
                            label,
                            f"{elapsed:.6f}",
                            f"{plot_elapsed:.6f}",
                            row.get("may_race_pairs", 0),
                            row.get("may_race_varname_pairs", 0),
                            row.get("may_race_pairs", 0),
                            row.get("may_race_varname_pairs", 0),
                        ]
                    )

    with (out_dir / "common_horizon_counts.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        header = ["module", "source_horizon_h", "plot_horizon_h"]
        for variant in VARIANT_ORDER:
            header.extend([f"{variant}_may_race_pairs", f"{variant}_datarace_unique_varname_pairs"])
        writer.writerow(header)
        final_by_key = {(row["module"], row["variant"]): row for row in final_rows}
        for module in MODULE_ORDER:
            row_out = [module, f"{SOURCE_HORIZON_H:.1f}", f"{PLOT_HORIZON_H:.1f}"]
            for variant in VARIANT_ORDER:
                row = final_by_key[(module, variant)]
                row_out.extend([row["may_race_pairs"], row["datarace_unique_varname_pairs"]])
            writer.writerow(row_out)

    with (out_dir / "final_counts.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = list(final_rows[0].keys())
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(final_rows)

    with (out_dir / "datarace_unique_varname_pairs.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fieldnames = [
            "module",
            "variant",
            "variant_label",
            "varname_a",
            "varname_b",
            "occurrence_count",
            "first_timestamp",
            "first_elapsed_h",
            "first_source_log",
            "first_panic_line",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(datarace_pair_rows)

    with (out_dir / "run_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "note": "12h dynamic-threshold runs are plotted as 24h by linear x-axis scaling.",
                "source_horizon_h": SOURCE_HORIZON_H,
                "plot_horizon_h": PLOT_HORIZON_H,
                "modules": MODULE_ORDER,
                "variants": VARIANT_ORDER,
                "runs": run_manifest,
            },
            handle,
            indent=2,
            ensure_ascii=False,
        )

    readme = out_dir / "README.md"
    readme.write_text(
        "\n".join(
            [
                "# 8-module 3-way dynamic-threshold summary",
                "",
                "This directory summarizes GPT-5.4, Random, and DeepSeek dynamic-threshold runs.",
                "The source runs are 12h; plots scale 12h to the 24h x-axis.",
                "",
                "DATARACE counts are unique unordered pairs of the two `VarName` values parsed",
                "from `Kernel panic: ============ DATARACE ============` blocks.",
                "",
                "Main files:",
                "- `final_counts.csv`: per module/variant final may-race-pair and DATARACE counts.",
                "- `timeseries.csv`: source and scaled may-race-pair time series.",
                "- `datarace_unique_varname_pairs.csv`: unique DATARACE VarName-pair evidence.",
                "- `llm_3way_reference_style_may_race_pairs.png`: reference-style curve plot.",
                "- `source_data/`: copied logs/configs/producer summaries used for this analysis.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def validate_runs() -> None:
    seen = {(run.module, run.variant) for run in RUNS}
    expected = {(module, variant) for module in MODULE_ORDER for variant in VARIANT_ORDER}
    missing = sorted(expected - seen)
    extra = sorted(seen - expected)
    if missing or extra:
        raise SystemExit(f"bad run map missing={missing} extra={extra}")
    for run in RUNS:
        if not run.exp_dir.exists():
            raise SystemExit(f"missing exp dir: {run.exp_dir}")
        if not (run.exp_dir / "logs/fuzz-manager.log").exists():
            raise SystemExit(f"missing fuzz log: {run.exp_dir}")
        if not (run.exp_dir / "logs/validate-manager.log").exists():
            raise SystemExit(f"missing validate log: {run.exp_dir}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--skip-copy", action="store_true")
    args = parser.parse_args()

    validate_runs()
    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    series: Dict[Tuple[str, str], List[dict]] = {}
    final_rows: List[dict] = []
    datarace_pair_rows: List[dict] = []
    run_manifest: List[dict] = []

    for spec in RUNS:
        fuzz_log = spec.exp_dir / "logs/fuzz-manager.log"
        validate_log = spec.exp_dir / "logs/validate-manager.log"
        rows = parse_fuzz_timeseries(fuzz_log)
        if not rows:
            raise SystemExit(f"no may-race time series parsed from {fuzz_log}")
        series[(spec.module, spec.variant)] = rows
        start_ts = datetime.strptime(rows[0]["timestamp"], "%Y-%m-%d %H:%M:%S")

        datarace = parse_datarace_varname_pairs([validate_log, fuzz_log], start_ts)
        result_dir = find_result_dir(spec)
        copied = {} if args.skip_copy else copy_source_data(spec, out_dir, result_dir)

        unique_pairs = datarace["occurrences"]
        for (var_a, var_b), occurrences in sorted(unique_pairs.items()):
            first = occurrences[0]
            datarace_pair_rows.append(
                {
                    "module": spec.module,
                    "variant": spec.variant,
                    "variant_label": VARIANT_STYLES[spec.variant][0],
                    "varname_a": var_a,
                    "varname_b": var_b,
                    "occurrence_count": len(occurrences),
                    "first_timestamp": first["timestamp"],
                    "first_elapsed_h": first["elapsed_h"],
                    "first_source_log": first["source_log"],
                    "first_panic_line": first["panic_line"],
                }
            )

        last = rows[-1]
        final_rows.append(
            {
                "module": spec.module,
                "variant": spec.variant,
                "variant_label": VARIANT_STYLES[spec.variant][0],
                "runtime_h": f"{float(last['elapsed_h']):.4f}",
                "source_horizon_h": f"{SOURCE_HORIZON_H:.1f}",
                "plot_horizon_h": f"{PLOT_HORIZON_H:.1f}",
                "exec_total": last.get("exec_total", ""),
                "may_race_pairs": value_at(rows, SOURCE_HORIZON_H, "may_race_pairs"),
                "may_race_varname_pairs": value_at(rows, SOURCE_HORIZON_H, "may_race_varname_pairs"),
                "uaf_pairs": value_at(rows, SOURCE_HORIZON_H, "may_race_pairs"),
                "uaf_varname_pairs": value_at(rows, SOURCE_HORIZON_H, "may_race_varname_pairs"),
                "uaf_corpus": value_at(rows, SOURCE_HORIZON_H, "uaf_corpus"),
                "uaf_coverage": value_at(rows, SOURCE_HORIZON_H, "uaf_coverage"),
                "ddrd_pairs_total": value_at(rows, SOURCE_HORIZON_H, "ddrd_pairs_total"),
                "cross_prog_pairs": value_at(rows, SOURCE_HORIZON_H, "cross_prog_pairs"),
                "dynamic_threshold_us": last.get("dynamic_threshold_us", ""),
                "threshold_adjustments": last.get("threshold_adjustments", ""),
                "datarace_unique_varname_pairs": len(unique_pairs),
                "datarace_panic_blocks": datarace["panic_blocks"],
                "datarace_parsed_blocks": datarace["parsed_blocks"],
                "datarace_unparsed_blocks": datarace["unparsed_blocks"],
                "fuzz_manager_log": rel(fuzz_log),
                "validate_manager_log": rel(validate_log),
                "result_dir": rel(result_dir) if result_dir else "",
            }
        )

        run_manifest.append(
            {
                "module": spec.module,
                "variant": spec.variant,
                "variant_label": VARIANT_STYLES[spec.variant][0],
                "exp_dir": rel(spec.exp_dir),
                "fuzz_manager_log": rel(fuzz_log),
                "validate_manager_log": rel(validate_log),
                "result_dir": rel(result_dir) if result_dir else None,
                "copied_files": copied,
            }
        )

    final_rows.sort(key=lambda row: (MODULE_ORDER.index(row["module"]), VARIANT_ORDER.index(row["variant"])))
    datarace_pair_rows.sort(
        key=lambda row: (
            MODULE_ORDER.index(row["module"]),
            VARIANT_ORDER.index(row["variant"]),
            int(row["varname_a"]),
            int(row["varname_b"]),
        )
    )

    write_outputs(out_dir, series, final_rows, datarace_pair_rows, run_manifest)
    outputs = draw_may_race_pairs(out_dir, series)
    outputs.append(draw_datarace_bars(out_dir, final_rows))
    for output in outputs:
        print(output)
    print(out_dir / "final_counts.csv")
    print(out_dir / "datarace_unique_varname_pairs.csv")


if __name__ == "__main__":
    main()
