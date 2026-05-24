#!/usr/bin/env python3

"""Plot static ablation curves from frozen DDRD logs.

By default this script reads the archived dataset frozen under:
paper/results/static-ablation/manifests/2026-05-14-static-4way-freeze/

It emits two figures per module:
1. UAF Pair Count
2. VarName Pair Count

The static ablation campaign is normalized to a 12-hour budget even if some
experiments were stopped later, so figures clip all series to the first 12h.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Sequence, Tuple

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter, MaxNLocator
except ImportError:
    raise SystemExit("please install matplotlib first: pip install matplotlib")


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_ARCHIVE_ROOT = os.path.join(
    PROJECT_ROOT,
    "paper",
    "results",
    "static-ablation",
    "manifests",
    "2026-05-14-static-4way-freeze",
)
DEFAULT_OUTPUT_ROOT = os.path.join(DEFAULT_ARCHIVE_ROOT, "plots")
SUMMARY_CSV_NAME = "static_ablation_final_counts.csv"

TARGET_MODULES = ["xfs", "btrfs", "f2fs", "jfs", "ptmx", "floppy", "dsp", "bt-stack"]
VARIANTS = ["static-full", "static-no-timing", "static-no-objlink", "static-random"]

PLOT_MAX_HOURS = 12.0
RESAMPLE_BUCKET_MINUTES = 5
FIGURE_SIZE = (7.4, 4.5)
SAVE_DPI = 320

LOG_PATTERN = re.compile(
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?uaf pairs=(\d+).*?uaf varnames=(\d+)"
)
LOG_PATTERN_ALT = re.compile(
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?uaf varnames=(\d+).*?uaf pairs=(\d+)"
)


@dataclass(frozen=True)
class VariantStyle:
    label: str
    color: str
    linestyle: str
    marker: str


VARIANT_STYLES: Dict[str, VariantStyle] = {
    "static-full": VariantStyle("Full", "#1f77b4", "-", "o"),
    "static-no-timing": VariantStyle("No Timing", "#ff7f0e", "--", "s"),
    "static-no-objlink": VariantStyle("No ObjLink", "#2ca02c", "-.", "^"),
    "static-random": VariantStyle("Random", "#d62728", ":", "D"),
}


def module_display_name(module: str) -> str:
    if module == "bt-stack":
        return "BT-STACK"
    if module in {"xfs", "f2fs", "jfs", "dsp", "ptmx"}:
        return module.upper()
    return module.capitalize()


def parse_log(log_path: str) -> List[Tuple[datetime, int, int]]:
    rows: List[Tuple[datetime, int, int]] = []
    with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            match = LOG_PATTERN.search(line)
            if match:
                rows.append(
                    (
                        datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S"),
                        int(match.group(2)),
                        int(match.group(3)),
                    )
                )
                continue
            match = LOG_PATTERN_ALT.search(line)
            if match:
                rows.append(
                    (
                        datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S"),
                        int(match.group(3)),
                        int(match.group(2)),
                    )
                )
    rows.sort(key=lambda item: item[0])
    return rows


def running_max(values: Sequence[int]) -> List[int]:
    if not values:
        return []
    result = [values[0]]
    for value in values[1:]:
        result.append(max(result[-1], value))
    return result


def minute_resample(rows: Sequence[Tuple[datetime, int, int]]) -> Tuple[List[float], List[int], List[int]]:
    if not rows:
        return [], [], []
    start = rows[0][0]
    minute_data: Dict[datetime, Tuple[int, int]] = {}
    for timestamp, pairs, varnames in rows:
        minute_key = timestamp.replace(second=0, microsecond=0)
        minute_data[minute_key] = (pairs, varnames)
    ordered = sorted(minute_data.items())
    hours = [(minute - start).total_seconds() / 3600.0 for minute, _ in ordered]
    pairs = [item[1][0] for item in ordered]
    varnames = [item[1][1] for item in ordered]
    return hours, running_max(pairs), running_max(varnames)


def bucket_resample(
    hours: Sequence[float],
    pairs: Sequence[int],
    varnames: Sequence[int],
    bucket_minutes: int = RESAMPLE_BUCKET_MINUTES,
) -> Tuple[List[float], List[int], List[int]]:
    if not hours:
        return [], [], []
    bucket_hours = bucket_minutes / 60.0
    grouped: Dict[int, Tuple[float, int, int]] = {}
    for hour, pair_count, varname_count in zip(hours, pairs, varnames):
        bucket = int(hour / bucket_hours)
        grouped[bucket] = (hour, pair_count, varname_count)
    ordered = [grouped[key] for key in sorted(grouped)]
    out_hours = [item[0] for item in ordered]
    out_pairs = running_max([item[1] for item in ordered])
    out_varnames = running_max([item[2] for item in ordered])
    return out_hours, out_pairs, out_varnames


def clip_series(
    hours: Sequence[float],
    pairs: Sequence[int],
    varnames: Sequence[int],
    max_hours: float,
) -> Tuple[List[float], List[int], List[int]]:
    clipped_hours: List[float] = []
    clipped_pairs: List[int] = []
    clipped_varnames: List[int] = []
    for hour, pair_count, varname_count in zip(hours, pairs, varnames):
        if hour > max_hours:
            break
        clipped_hours.append(hour)
        clipped_pairs.append(pair_count)
        clipped_varnames.append(varname_count)
    if clipped_hours and clipped_hours[-1] < max_hours:
        clipped_hours.append(max_hours)
        clipped_pairs.append(clipped_pairs[-1])
        clipped_varnames.append(clipped_varnames[-1])
    return clipped_hours, clipped_pairs, clipped_varnames


def load_series(log_path: str, max_hours: float) -> Tuple[List[float], List[int], List[int]]:
    raw = parse_log(log_path)
    hours, pairs, varnames = minute_resample(raw)
    hours, pairs, varnames = bucket_resample(hours, pairs, varnames)
    return clip_series(hours, pairs, varnames, max_hours)


def series_marker_every(length: int) -> int:
    if length <= 12:
        return 1
    return max(3, length // 10)


def archive_log_path(archive_root: str, module: str, variant: str) -> str:
    return os.path.join(archive_root, "logs", module, f"{variant}.log")


def configure_plot_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.labelsize": 12,
            "axes.titlesize": 14,
            "axes.titleweight": "bold",
            "legend.fontsize": 10,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


def thousands_formatter(value: float, _pos: int) -> str:
    return f"{int(value):,}"


def plot_metric(
    module: str,
    metric_key: str,
    series_by_variant: Dict[str, Tuple[List[float], List[int], List[int]]],
    output_dir: str,
    max_hours: float,
    formats: Iterable[str],
) -> List[str]:
    metric_title = "UAF Pair Count" if metric_key == "pairs" else "VarName Pair Count"
    metric_index = 1 if metric_key == "pairs" else 2

    fig, ax = plt.subplots(figsize=FIGURE_SIZE)
    for variant in VARIANTS:
        hours, pairs, varnames = series_by_variant[variant]
        values = pairs if metric_index == 1 else varnames
        if not hours:
            continue
        style = VARIANT_STYLES[variant]
        legend_label = f"{style.label} ({values[-1]:,})"
        ax.step(
            hours,
            values,
            where="post",
            label=legend_label,
            color=style.color,
            linestyle=style.linestyle,
            linewidth=2.2,
            alpha=0.96,
        )
        ax.plot(
            hours,
            values,
            linestyle="None",
            marker=style.marker,
            markersize=4.2,
            color=style.color,
            markevery=series_marker_every(len(hours)),
            alpha=0.92,
        )

    ax.set_title(f"{module_display_name(module)}: {metric_title}")
    ax.set_xlabel("Elapsed Time (hours)")
    ax.set_ylabel(metric_title)
    ax.set_xlim(0, max_hours)
    ax.set_xticks(range(0, int(max_hours) + 1, 2))
    ax.yaxis.set_major_locator(MaxNLocator(nbins=6, integer=True))
    ax.yaxis.set_major_formatter(FuncFormatter(thousands_formatter))
    ax.grid(True, linestyle=":", linewidth=0.8, alpha=0.55)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left", frameon=False, ncol=2, columnspacing=1.0, handlelength=2.4)
    ax.margins(x=0.01, y=0.05)

    subtitle = f"Static ablation, clipped to first {max_hours:.0f}h"
    ax.text(
        0.99,
        0.02,
        subtitle,
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=9,
        color="#555555",
    )

    fig.tight_layout()

    base_name = f"{module}_{metric_key}"
    saved_paths: List[str] = []
    for fmt in formats:
        path = os.path.join(output_dir, f"{base_name}.{fmt}")
        fig.savefig(path, dpi=SAVE_DPI if fmt == "png" else None, bbox_inches="tight")
        saved_paths.append(path)
    plt.close(fig)
    return saved_paths


def write_summary_csv(
    output_dir: str,
    results: Dict[str, Dict[str, Tuple[List[float], List[int], List[int]]]],
) -> str:
    path = os.path.join(output_dir, SUMMARY_CSV_NAME)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["module", "variant", "hours", "uaf_pairs", "varname_pairs"])
        for module in TARGET_MODULES:
            if module not in results:
                continue
            for variant in VARIANTS:
                hours, pairs, varnames = results[module][variant]
                if hours:
                    writer.writerow([module, variant, f"{hours[-1]:.2f}", pairs[-1], varnames[-1]])
                else:
                    writer.writerow([module, variant, "", "", ""])
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot 4-way static ablation curves from frozen DDRD logs")
    parser.add_argument(
        "-i",
        "--archive-root",
        default=DEFAULT_ARCHIVE_ROOT,
        help="Archive root that contains logs/<module>/<variant>.log",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=DEFAULT_OUTPUT_ROOT,
        help="Directory for generated figures and summary CSV",
    )
    parser.add_argument(
        "-t",
        "--targets",
        nargs="+",
        default=TARGET_MODULES,
        help="Modules to plot",
    )
    parser.add_argument(
        "--max-hours",
        type=float,
        default=PLOT_MAX_HOURS,
        help="Clip all curves to the first N hours",
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["png", "pdf"],
        choices=["png", "pdf", "svg"],
        help="Output formats",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_plot_style()
    os.makedirs(args.output_dir, exist_ok=True)

    all_results: Dict[str, Dict[str, Tuple[List[float], List[int], List[int]]]] = {}
    generated_paths: List[str] = []

    for module in args.targets:
        series_by_variant: Dict[str, Tuple[List[float], List[int], List[int]]] = {}
        for variant in VARIANTS:
            log_path = archive_log_path(args.archive_root, module, variant)
            if not os.path.isfile(log_path):
                raise SystemExit(f"missing archived log: {log_path}")
            series_by_variant[variant] = load_series(log_path, args.max_hours)
        all_results[module] = series_by_variant
        generated_paths.extend(plot_metric(module, "pairs", series_by_variant, args.output_dir, args.max_hours, args.formats))
        generated_paths.extend(plot_metric(module, "varnames", series_by_variant, args.output_dir, args.max_hours, args.formats))

    summary_path = write_summary_csv(args.output_dir, all_results)

    print(f"archive root: {args.archive_root}")
    print(f"output dir:   {args.output_dir}")
    print(f"summary csv:  {summary_path}")
    print(f"generated {len(generated_paths)} files")
    for path in generated_paths:
        print(path)


if __name__ == "__main__":
    main()