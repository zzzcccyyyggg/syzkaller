#!/usr/bin/env python3
"""Draw LLM-vs-random curves in the compact 2x4 paper style."""

from __future__ import annotations

import argparse
import csv
import math
import os
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_INPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "paper",
    "results",
    "llm-random-comparison",
    "20260519-latest",
)
DEFAULT_OUTPUT = os.path.join(
    DEFAULT_INPUT_DIR,
    "llm_vs_random_reference_style_uaf_pairs.png",
)

MODULE_ORDER = ["f2fs", "jfs", "xfs", "btrfs", "floppy", "ptmx", "dsp", "bt-stack"]
MODULE_LABELS = {
    "bt-stack": "bluetooth",
}
VARIANT_STYLES = {
    "llm": ("LLM", "#ff0000", "-", 1.8),
    "random": ("Random", "#0070c0", (0, (5, 3)), 1.8),
}


def load_common_horizons(path: str) -> Dict[str, float]:
    horizons: Dict[str, float] = {}
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            horizons[row["module"]] = float(row["common_runtime_h"])
    return horizons


def load_timeseries(path: str, metric: str) -> Dict[Tuple[str, str], List[Tuple[float, int]]]:
    grouped: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            grouped[(row["module"], row["variant"])].append(
                (float(row["elapsed_h"]), int(row[metric]))
            )
    for key in grouped:
        grouped[key].sort(key=lambda item: item[0])
    return grouped


def running_max(values: Iterable[int]) -> List[int]:
    out: List[int] = []
    current = 0
    for value in values:
        current = max(current, value)
        out.append(current)
    return out


def scaled_series(
    rows: Sequence[Tuple[float, int]],
    horizon: float,
    scaled_hours: float = 24.0,
    bucket_width: float = 0.20,
) -> Tuple[List[float], List[int]]:
    if not rows or horizon <= 0:
        return [], []

    clipped = [(hour, value) for hour, value in rows if hour <= horizon]
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
    abs_value = abs(value)
    if abs_value >= 1_000_000:
        return f"{value / 1_000_000:g}M"
    if abs_value >= 1_000:
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
        exponent = 10 ** int(math.floor(math.log10(max_value)))
        step = exponent
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
            "legend.fontsize": 7,
            "axes.linewidth": 0.8,
            "lines.solid_capstyle": "round",
            "lines.dash_capstyle": "round",
        }
    )


def draw(input_dir: str, output: str, metric: str) -> None:
    timeseries_path = os.path.join(input_dir, "timeseries.csv")
    horizon_path = os.path.join(input_dir, "common_horizon_counts.csv")
    horizons = load_common_horizons(horizon_path)
    series = load_timeseries(timeseries_path, metric)

    configure_style()
    fig, axes = plt.subplots(2, 4, figsize=(12.78, 4.22), dpi=100)
    axes_flat = list(axes.flat)

    for ax, module in zip(axes_flat, MODULE_ORDER):
        max_y = 0
        plotted: Dict[str, Tuple[List[float], List[int]]] = {}
        horizon = horizons.get(module)
        if horizon is None:
            continue
        for variant in ("llm", "random"):
            xs, ys = scaled_series(series.get((module, variant), []), horizon)
            plotted[variant] = (xs, ys)
            if ys:
                max_y = max(max_y, max(ys))

        for variant in ("llm", "random"):
            label, color, linestyle, linewidth = VARIANT_STYLES[variant]
            xs, ys = plotted.get(variant, ([], []))
            if not xs:
                continue
            ax.plot(
                xs,
                ys,
                label=label,
                color=color,
                linestyle=linestyle,
                linewidth=linewidth,
            )

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
        ncol=2,
        frameon=False,
        handlelength=2.4,
        columnspacing=1.8,
    )
    fig.subplots_adjust(left=0.062, right=0.985, top=0.865, bottom=0.11, wspace=0.47, hspace=0.68)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    fig.savefig(output)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--metric",
        choices=("uaf_pairs", "uaf_varname_pairs"),
        default="uaf_pairs",
    )
    args = parser.parse_args()
    draw(args.input_dir, args.output, args.metric)
    print(args.output)


if __name__ == "__main__":
    main()
