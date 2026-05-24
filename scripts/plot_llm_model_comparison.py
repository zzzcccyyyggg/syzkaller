#!/usr/bin/env python3
"""Draw Random/DeepSeek/Kimi/GPT-5.4 input-exploration comparison curves."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PREVIOUS_DIR = PROJECT_ROOT / "paper/results/llm-random-comparison/20260520-jfs-new-fuzz"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "paper/results/llm-model-comparison/20260521-gpt54-kimi26"

MODULE_ORDER = ["f2fs", "jfs", "xfs", "btrfs", "floppy", "ptmx", "dsp", "bt-stack"]
MODULE_LABELS = {"bt-stack": "bluetooth"}
VARIANT_ORDER = ["random", "deepseek", "kimi26", "gpt54"]
VARIANT_STYLES = {
    "random": ("Random", "#0070c0", (0, (5, 3)), 1.65),
    "deepseek": ("DeepSeek", "#e41a1c", "-", 1.75),
    "kimi26": ("Kimi-2.6", "#2ca02c", (0, (3, 2)), 1.75),
    "gpt54": ("GPT-5.4", "#8a2be2", "-", 1.75),
}

MANIFESTS = {
    "gpt54": [
        PROJECT_ROOT
        / "paper/results/llm-mutate-continuous/llm-helper-codex54-randrewrite-fs4-20260520-202901-manifest.json",
        PROJECT_ROOT
        / "paper/results/llm-mutate-continuous/llm-helper-codex54-randrewrite-dev4-fixenv-20260521-1032-manifest.json",
    ],
    "kimi26": [
        PROJECT_ROOT
        / "paper/results/llm-mutate-continuous/llm-helper-kimi26-thinking-randrewrite-fs4-20260520-210821-manifest.json",
        PROJECT_ROOT
        / "paper/results/llm-mutate-continuous/llm-helper-kimi26-thinking-randrewrite-dev4-fixenv-20260521-1032-manifest.json",
    ],
}

METRIC_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9 _/-]*?)=([0-9]+)(?:\s|$)"
)


def parse_manager_log(path: Path) -> List[Tuple[float, int, int]]:
    rows: List[Tuple[object, int, int]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if "affinity updates=" not in line or "uaf corpus=" not in line:
                continue
            try:
                timestamp = line[:19]
                from datetime import datetime

                ts = datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue
            values = {key.strip(): int(value) for key, value in METRIC_RE.findall(line)}
            pairs = values.get("uaf pairs")
            varnames = values.get("uaf varnames")
            if pairs is None or varnames is None:
                continue
            rows.append((ts, pairs, varnames))

    if not rows:
        return []
    start = rows[0][0]
    out: List[Tuple[float, int, int]] = []
    for ts, pairs, varnames in rows:
        elapsed = (ts - start).total_seconds() / 3600.0
        out.append((elapsed, pairs, varnames))
    return out


def load_previous(path: Path) -> Dict[Tuple[str, str], List[Tuple[float, int, int]]]:
    out: Dict[Tuple[str, str], List[Tuple[float, int, int]]] = defaultdict(list)
    with (path / "timeseries.csv").open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            variant = "deepseek" if row["variant"] == "llm" else row["variant"]
            out[(row["module"], variant)].append(
                (
                    float(row["elapsed_h"]),
                    int(row["uaf_pairs"]),
                    int(row["uaf_varname_pairs"]),
                )
            )
    for key in out:
        out[key].sort(key=lambda item: item[0])
    return out


def load_manifest_series() -> Dict[Tuple[str, str], List[Tuple[float, int, int]]]:
    out: Dict[Tuple[str, str], List[Tuple[float, int, int]]] = {}
    for variant, manifests in MANIFESTS.items():
        for manifest_path in manifests:
            with manifest_path.open("r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            for module, info in manifest["modules"].items():
                rows = parse_manager_log(Path(info["manager_log"]))
                if rows:
                    out[(module, variant)] = rows
    return out


def running_max(values: Iterable[int]) -> List[int]:
    out: List[int] = []
    current = 0
    for value in values:
        current = max(current, value)
        out.append(current)
    return out


def value_at(rows: Sequence[Tuple[float, int, int]], horizon: float, metric_index: int) -> int:
    value = 0
    for hour, pairs, varnames in rows:
        if hour > horizon:
            break
        value = max(value, pairs if metric_index == 1 else varnames)
    return value


def scaled_series(
    rows: Sequence[Tuple[float, int, int]],
    horizon: float,
    metric_index: int,
    scaled_hours: float = 24.0,
    bucket_width: float = 0.20,
) -> Tuple[List[float], List[int]]:
    if not rows or horizon <= 0:
        return [], []

    clipped = [(item[0], item[metric_index]) for item in rows if item[0] <= horizon]
    if not clipped:
        clipped = [(0.0, 0)]
    if clipped[0][0] > 0:
        clipped.insert(0, (0.0, 0))
    if clipped[-1][0] < horizon:
        clipped.append((horizon, clipped[-1][1]))

    xs = [min(hour / horizon * scaled_hours, scaled_hours) for hour, _ in clipped]
    ys = running_max(value for _, value in clipped)

    bucketed: Dict[int, Tuple[float, int]] = {}
    for x_value, y_value in zip(xs, ys):
        bucket = int(x_value / bucket_width)
        bucketed[bucket] = (x_value, y_value)

    ordered = [bucketed[key] for key in sorted(bucketed)]
    out_x = [0.0]
    out_y = [0]
    for x_value, y_value in ordered:
        if x_value == 0 and y_value == 0:
            continue
        out_x.append(x_value)
        out_y.append(max(out_y[-1], y_value))
    if out_x[-1] < scaled_hours:
        out_x.append(scaled_hours)
        out_y.append(out_y[-1])
    elif out_x[-1] > scaled_hours:
        out_x[-1] = scaled_hours
    return out_x, out_y


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


def compute_horizons(
    series: Dict[Tuple[str, str], List[Tuple[float, int, int]]]
) -> Dict[str, float]:
    horizons: Dict[str, float] = {}
    for module in MODULE_ORDER:
        runtimes = []
        for variant in VARIANT_ORDER:
            rows = series.get((module, variant))
            if rows:
                runtimes.append(rows[-1][0])
        if len(runtimes) == len(VARIANT_ORDER):
            horizons[module] = min(runtimes)
    return horizons


def write_csvs(
    out_dir: Path,
    series: Dict[Tuple[str, str], List[Tuple[float, int, int]]],
    horizons: Dict[str, float],
) -> None:
    with (out_dir / "timeseries.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["module", "variant", "elapsed_h", "uaf_pairs", "uaf_varname_pairs"])
        for module in MODULE_ORDER:
            for variant in VARIANT_ORDER:
                for hour, pairs, varnames in series.get((module, variant), []):
                    writer.writerow([module, variant, f"{hour:.6f}", pairs, varnames])

    with (out_dir / "common_horizon_counts.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.writer(handle)
        header = ["module", "common_runtime_h"]
        for variant in VARIANT_ORDER:
            header.extend([f"{variant}_pairs", f"{variant}_varnames"])
        writer.writerow(header)
        for module in MODULE_ORDER:
            horizon = horizons[module]
            row = [module, f"{horizon:.4f}"]
            for variant in VARIANT_ORDER:
                rows = series[(module, variant)]
                row.extend([value_at(rows, horizon, 1), value_at(rows, horizon, 2)])
            writer.writerow(row)

    with (out_dir / "final_counts.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["module", "variant", "runtime_h", "uaf_pairs", "uaf_varname_pairs"])
        for module in MODULE_ORDER:
            for variant in VARIANT_ORDER:
                rows = series[(module, variant)]
                writer.writerow([module, variant, f"{rows[-1][0]:.4f}", rows[-1][1], rows[-1][2]])


def draw(
    out_dir: Path,
    series: Dict[Tuple[str, str], List[Tuple[float, int, int]]],
    horizons: Dict[str, float],
    metric: str,
) -> Path:
    metric_index = 1 if metric == "uaf_pairs" else 2
    output = out_dir / f"llm_model_comparison_reference_style_{metric}.png"

    configure_style()
    fig, axes = plt.subplots(2, 4, figsize=(12.78, 4.22), dpi=100)
    axes_flat = list(axes.flat)

    for ax, module in zip(axes_flat, MODULE_ORDER):
        horizon = horizons[module]
        plotted: Dict[str, Tuple[List[float], List[int]]] = {}
        max_y = 0
        for variant in VARIANT_ORDER:
            xs, ys = scaled_series(series[(module, variant)], horizon, metric_index)
            plotted[variant] = (xs, ys)
            if ys:
                max_y = max(max_y, max(ys))

        for variant in VARIANT_ORDER:
            label, color, linestyle, linewidth = VARIANT_STYLES[variant]
            xs, ys = plotted[variant]
            ax.plot(xs, ys, label=label, color=color, linestyle=linestyle, linewidth=linewidth)

        y_upper, y_ticks = nice_axis(max_y)
        ax.set_xlim(0, 24)
        ax.set_ylim(0, y_upper)
        ax.set_xticks([0, 4, 8, 12, 16, 20, 24])
        ax.set_xticklabels(["0h", "4h", "8h", "12h", "16h", "20h", "24h"])
        ax.set_yticks(y_ticks)
        ax.yaxis.set_major_formatter(FuncFormatter(count_formatter))
        ax.grid(axis="y", color="#d9d9d9", linewidth=0.8)
        ax.set_axisbelow(True)
        ax.set_title(MODULE_LABELS.get(module, module))
        ax.set_xlabel("Time")
        ax.set_ylabel("Concurrent cell pairs")
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
        ncol=4,
        frameon=False,
        handlelength=2.4,
        columnspacing=1.6,
    )
    fig.subplots_adjust(left=0.062, right=0.985, top=0.865, bottom=0.11, wspace=0.47, hspace=0.68)
    fig.savefig(output)
    plt.close(fig)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous-dir", type=Path, default=DEFAULT_PREVIOUS_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--metric",
        choices=("uaf_pairs", "uaf_varname_pairs", "both"),
        default="both",
    )
    args = parser.parse_args()

    series = load_previous(args.previous_dir)
    series.update(load_manifest_series())
    horizons = compute_horizons(series)
    missing = [
        (module, variant)
        for module in MODULE_ORDER
        for variant in VARIANT_ORDER
        if (module, variant) not in series
    ]
    if missing:
        raise SystemExit(f"missing series: {missing}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csvs(args.output_dir, series, horizons)

    outputs = []
    metrics = ["uaf_pairs", "uaf_varname_pairs"] if args.metric == "both" else [args.metric]
    for metric in metrics:
        outputs.append(draw(args.output_dir, series, horizons, metric))
    for output in outputs:
        print(output)


if __name__ == "__main__":
    main()
