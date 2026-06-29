#!/usr/bin/env python3
"""Draw 24h MRP count comparison for MRPFuzz variants, Conzzer, and SegFuzz."""

from __future__ import annotations

import argparse
import csv
import io
import json
import tarfile
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LLM_DIR = (
    PROJECT_ROOT
    / "paper/results/llm-model-comparison/20260525-8module-3way-fuzz-comparison"
)
DEFAULT_CONZZER_BUNDLE = (
    PROJECT_ROOT
    / "paper/comparison exp/mrp10ms_8module_plot_bundle_2026-05-27_09-52-17.tar.gz"
)
DEFAULT_SEGFUZZ_CSV = PROJECT_ROOT / "paper/comparison exp/segfuzz_mrp_timeseries_24h.csv"
DEFAULT_OUTPUT_DIR = (
    PROJECT_ROOT
    / "paper/results/mrp-24h-comparison/20260527-deepseek-v4pro-conzzer-segfuzz"
)

MODULE_ORDER = ["f2fs", "jfs", "xfs", "btrfs", "floppy", "ptmx", "dsp", "bt-stack"]
MODULE_LABELS = {
    "f2fs": "F2FS",
    "jfs": "JFS",
    "xfs": "XFS",
    "btrfs": "Btrfs",
    "floppy": "Floppy",
    "ptmx": "PTMX",
    "dsp": "DSP",
    "bt-stack": "Bluetooth",
}
TOOL_ORDER = ["Random", "GPT-5.4", "DeepSeek-V4Pro", "SegFuzz", "Conzzer"]
TOOL_LABELS = {
    "Random": "Random",
    "GPT-5.4": "GPT-5.4",
    "DeepSeek-V4Pro": "DeepSeek-V4Pro",
    "SegFuzz": "SegFuzz",
    "Conzzer": "Conzzer",
}
TOOL_COLORS = {
    "Random": "#0070c0",
    "GPT-5.4": "#8a2be2",
    "DeepSeek-V4Pro": "#e41a1c",
    "SegFuzz": "#2ca02c",
    "Conzzer": "#7f7f7f",
}
CURVE_STYLES = {
    "Random": ("Random", "#0070c0", (0, (5, 3)), 1.65),
    "GPT-5.4": ("GPT-5.4", "#8a2be2", "-", 1.75),
    "DeepSeek-V4Pro": ("DeepSeek-V4Pro", "#e41a1c", "-", 1.75),
    "SegFuzz": ("SegFuzz", "#2ca02c", (0, (3, 2)), 1.65),
    "Conzzer": ("Conzzer", "#7f7f7f", "-", 1.45),
}


LLM_VARIANT_TO_TOOL = {
    "random": "Random",
    "codex54": "GPT-5.4",
    "deepseek-v4pro": "DeepSeek-V4Pro",
}


def parse_mrpfuzz_counts(llm_dir: Path) -> Tuple[Dict[str, Dict[str, int]], Dict[str, float]]:
    """Return MRPFuzz variant pair counts at the common horizon used by the 3-way plot."""
    path = llm_dir / "common_horizon_counts.csv"
    counts: Dict[str, Dict[str, int]] = {tool: {} for tool in LLM_VARIANT_TO_TOOL.values()}
    horizons: Dict[str, float] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            module = row["module"]
            horizons[module] = float(row["common_runtime_h"])
            counts["Random"][module] = int(row["random_pairs"])
            counts["GPT-5.4"][module] = int(row["codex54_pairs"])
            counts["DeepSeek-V4Pro"][module] = int(row["deepseek-v4pro_pairs"])
    return counts, horizons


def running_max(values: List[int]) -> List[int]:
    out: List[int] = []
    current = 0
    for value in values:
        current = max(current, int(value))
        out.append(current)
    return out


def normalize_series(rows: List[Tuple[float, int]]) -> List[Tuple[float, int]]:
    if not rows:
        return [(0.0, 0), (24.0, 0)]
    rows = sorted(rows, key=lambda item: item[0])
    out: List[Tuple[float, int]] = []
    current = 0
    last_hour: float | None = None
    for hour, value in rows:
        hour = max(0.0, min(24.0, float(hour)))
        current = max(current, int(value))
        if last_hour is not None and abs(hour - last_hour) < 1e-9:
            out[-1] = (hour, current)
        else:
            out.append((hour, current))
            last_hour = hour
    if out[0][0] > 0:
        out.insert(0, (0.0, 0))
    if out[-1][0] < 24.0:
        out.append((24.0, out[-1][1]))
    return out


def scaled_series(rows: List[Tuple[float, int]], horizon: float, scaled_hours: float = 24.0) -> List[Tuple[float, int]]:
    if not rows or horizon <= 0:
        return [(0.0, 0), (scaled_hours, 0)]
    clipped = [(h, v) for h, v in sorted(rows) if h <= horizon]
    if not clipped:
        clipped = [(0.0, 0)]
    if clipped[0][0] > 0:
        clipped.insert(0, (0.0, 0))
    if clipped[-1][0] < horizon:
        clipped.append((horizon, clipped[-1][1]))
    xs = [min(hour / horizon * scaled_hours, scaled_hours) for hour, _ in clipped]
    ys = running_max([value for _, value in clipped])
    bucket_width = 0.08
    bucketed: Dict[int, Tuple[float, int]] = {}
    for x_value, y_value in zip(xs, ys):
        bucketed[int(x_value / bucket_width)] = (x_value, y_value)
    out = [(0.0, 0)]
    for key in sorted(bucketed):
        x_value, y_value = bucketed[key]
        if x_value == 0 and y_value == 0:
            continue
        out.append((x_value, max(out[-1][1], y_value)))
    if out[-1][0] < scaled_hours:
        out.append((scaled_hours, out[-1][1]))
    return out


def parse_mrpfuzz_series(llm_dir: Path) -> Dict[str, Dict[str, List[Tuple[float, int]]]]:
    """Return MRPFuzz variant curves scaled to 24h, matching the 3-way plot convention."""
    endpoint, horizons = parse_mrpfuzz_counts(llm_dir)
    raw: Dict[str, Dict[str, List[Tuple[float, int]]]] = {
        tool: {module: [] for module in MODULE_ORDER}
        for tool in LLM_VARIANT_TO_TOOL.values()
    }
    with (llm_dir / "timeseries.csv").open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            tool = LLM_VARIANT_TO_TOOL.get(row["variant"])
            if tool is None:
                continue
            module = row["module"]
            if module in raw[tool]:
                raw[tool][module].append((float(row["elapsed_h"]), int(row["uaf_pairs"])))
    out: Dict[str, Dict[str, List[Tuple[float, int]]]] = {
        tool: {} for tool in LLM_VARIANT_TO_TOOL.values()
    }
    for tool in LLM_VARIANT_TO_TOOL.values():
        for module in MODULE_ORDER:
            out[tool][module] = scaled_series(raw[tool][module], horizons[module])
            if out[tool][module][-1][1] != endpoint[tool][module]:
                out[tool][module].append((24.0, endpoint[tool][module]))
    return out


def parse_conzzer_counts(bundle: Path) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Return capped and raw MRP counts from the final Conzzer bundle."""
    final_name = "mrp10ms_8module_plot_bundle_2026-05-27_09-52-17/final_results.csv"
    capped: Dict[str, int] = {}
    raw: Dict[str, int] = {}
    with tarfile.open(bundle, "r:gz") as archive:
        member = archive.extractfile(final_name)
        if member is None:
            raise FileNotFoundError(final_name)
        text = member.read().decode("utf-8", errors="replace")
    for row in csv.DictReader(io.StringIO(text)):
        capped[row["module"]] = int(row["capped_mrp"])
        raw[row["module"]] = int(row["raw_mrp"])
    return capped, raw


def parse_conzzer_series(bundle: Path) -> Dict[str, List[Tuple[float, int]]]:
    name = "mrp10ms_8module_plot_bundle_2026-05-27_09-52-17/timeseries_1min.csv"
    out: Dict[str, List[Tuple[float, int]]] = {module: [] for module in MODULE_ORDER}
    with tarfile.open(bundle, "r:gz") as archive:
        member = archive.extractfile(name)
        if member is None:
            raise FileNotFoundError(name)
        text = member.read().decode("utf-8", errors="replace")
    for row in csv.DictReader(io.StringIO(text)):
        module = row["module"]
        if module not in out:
            continue
        hour = float(row["elapsed_h"])
        if hour <= 24.05:
            out[module].append((min(hour, 24.0), int(row["capped_mrp"])))
    return {module: normalize_series(rows) for module, rows in out.items()}


def parse_segfuzz_counts(path: Path) -> Tuple[Dict[str, int], Dict[str, str], Dict[str, float]]:
    """Return the latest projected/observed SegFuzz MRP count within the 24h window."""
    counts: Dict[str, int] = {}
    status: Dict[str, str] = {}
    elapsed_h: Dict[str, float] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            module = row["module"]
            hour = float(row["elapsed_sec"]) / 3600.0
            if hour > 24.05:
                continue
            if module not in elapsed_h or hour >= elapsed_h[module]:
                elapsed_h[module] = hour
                counts[module] = int(row["raw_mrp_pair_count"] or 0)
                status[module] = row.get("status", "")
    return counts, status, elapsed_h


def parse_segfuzz_series(path: Path) -> Dict[str, List[Tuple[float, int]]]:
    out: Dict[str, List[Tuple[float, int]]] = {module: [] for module in MODULE_ORDER}
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            module = row["module"]
            if module not in out:
                continue
            hour = float(row["elapsed_sec"]) / 3600.0
            if hour <= 24.05:
                out[module].append((min(hour, 24.0), int(row["raw_mrp_pair_count"] or 0)))
    return {module: normalize_series(rows) for module, rows in out.items()}


def fmt_count(value: float, _pos: int | None = None) -> str:
    if abs(value) >= 1000:
        return f"{value / 1000:.0f}K"
    return str(int(value))


def short_count(value: int) -> str:
    if value >= 1000:
        return f"{value / 1000:.1f}K"
    return str(value)


def collect_rows(args: argparse.Namespace) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    mrpfuzz_counts, horizons = parse_mrpfuzz_counts(args.llm_dir)
    conzzer, conzzer_raw = parse_conzzer_counts(args.conzzer_bundle)
    segfuzz, seg_status, seg_elapsed = parse_segfuzz_counts(args.segfuzz_csv)

    rows: List[Dict[str, object]] = []
    for module in MODULE_ORDER:
        rows.append(
            {
                "module": module,
                "module_label": MODULE_LABELS[module],
                "mrpfuzz_random_pairs": mrpfuzz_counts["Random"][module],
                "mrpfuzz_gpt54_pairs": mrpfuzz_counts["GPT-5.4"][module],
                "mrpfuzz_deepseek_v4pro_pairs": mrpfuzz_counts["DeepSeek-V4Pro"][module],
                "mrpfuzz_common_runtime_h": horizons[module],
                "segfuzz_raw_mrp_pairs": segfuzz[module],
                "segfuzz_elapsed_h": seg_elapsed[module],
                "segfuzz_status": seg_status[module],
                "conzzer_capped_mrp": conzzer[module],
                "conzzer_raw_mrp": conzzer_raw[module],
                "deepseek_vs_segfuzz_ratio": mrpfuzz_counts["DeepSeek-V4Pro"][module] / max(segfuzz[module], 1),
                "deepseek_vs_conzzer_ratio": mrpfuzz_counts["DeepSeek-V4Pro"][module] / max(conzzer[module], 1),
            }
        )

    totals = {
        "Random": sum(int(row["mrpfuzz_random_pairs"]) for row in rows),
        "GPT-5.4": sum(int(row["mrpfuzz_gpt54_pairs"]) for row in rows),
        "DeepSeek-V4Pro": sum(int(row["mrpfuzz_deepseek_v4pro_pairs"]) for row in rows),
        "SegFuzz": sum(int(row["segfuzz_raw_mrp_pairs"]) for row in rows),
        "Conzzer": sum(int(row["conzzer_capped_mrp"]) for row in rows),
    }
    return rows, totals


def write_summary(
    rows: List[Dict[str, object]],
    totals: Dict[str, int],
    out_dir: Path,
    args: argparse.Namespace,
) -> None:
    csv_path = out_dir / "mrp_24h_summary.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    totals_path = out_dir / "mrp_24h_totals.json"
    totals_path.write_text(json.dumps(totals, indent=2) + "\n", encoding="utf-8")

    readme = out_dir / "README.md"
    readme.write_text(
        "# MRP 24h Tool Comparison\n\n"
        "This directory compares MRPFuzz variants, SegFuzz, and Conzzer on 24h MRP counts.\n\n"
        "Data sources:\n"
        f"- MRPFuzz variants: `random_pairs`, `codex54_pairs`, and `deepseek-v4pro_pairs` from `{args.llm_dir / 'common_horizon_counts.csv'}`. "
        "This is the endpoint used by the 3-way LLM comparison plot after scaling each module's common runtime horizon to 24h.\n"
        f"- Conzzer: `capped_mrp` from `{args.conzzer_bundle}`.\n"
        f"- SegFuzz: final 24h `raw_mrp_pair_count` from `{args.segfuzz_csv}`.\n\n"
        "Generated artifacts:\n"
        "- `mrp_24h_reference_style_broken_curves.png/.pdf`\n"
        "- `mrp_24h_count_comparison_broken_axis.png/.pdf`\n"
        "- `mrp_24h_count_comparison_linear.png/.pdf`\n"
        "- `mrp_24h_reference_style_timeseries.csv`\n"
        "- `mrp_24h_summary.csv`\n"
        "- `mrp_24h_totals.json`\n\n"
        "Totals: "
        f"Random={totals['Random']}, GPT-5.4={totals['GPT-5.4']}, "
        f"DeepSeek-V4Pro={totals['DeepSeek-V4Pro']}, "
        f"SegFuzz={totals['SegFuzz']}, Conzzer={totals['Conzzer']}.\n",
        encoding="utf-8",
    )


def write_reference_timeseries(
    series: Dict[str, Dict[str, List[Tuple[float, int]]]],
    out_dir: Path,
) -> None:
    path = out_dir / "mrp_24h_reference_style_timeseries.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["module", "tool", "elapsed_h", "mrp_pairs"])
        for module in MODULE_ORDER:
            for tool in TOOL_ORDER:
                for hour, value in series[tool][module]:
                    writer.writerow([module, tool, f"{hour:.6f}", value])


def value_for(row: Dict[str, object], tool: str) -> int:
    if tool == "Random":
        return int(row["mrpfuzz_random_pairs"])
    if tool == "GPT-5.4":
        return int(row["mrpfuzz_gpt54_pairs"])
    if tool == "DeepSeek-V4Pro":
        return int(row["mrpfuzz_deepseek_v4pro_pairs"])
    if tool == "SegFuzz":
        return int(row["segfuzz_raw_mrp_pairs"])
    if tool == "Conzzer":
        return int(row["conzzer_capped_mrp"])
    raise KeyError(tool)


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


def draw_bars(ax, rows: List[Dict[str, object]], annotate: bool = False) -> None:
    x = np.arange(len(rows))
    width = 0.16
    offsets = {
        "Random": -2 * width,
        "GPT-5.4": -width,
        "DeepSeek-V4Pro": 0.0,
        "SegFuzz": width,
        "Conzzer": 2 * width,
    }
    for tool in TOOL_ORDER:
        values = [value_for(row, tool) for row in rows]
        bars = ax.bar(
            x + offsets[tool],
            values,
            width,
            color=TOOL_COLORS[tool],
            edgecolor="white",
            linewidth=0.45,
            label=TOOL_LABELS[tool],
            zorder=3,
        )
        if annotate:
            ax.bar_label(bars, labels=[short_count(v) for v in values], fontsize=6.1, rotation=90, padding=1.2)


def finish_axis(ax, rows: List[Dict[str, object]]) -> None:
    ax.grid(axis="y", color="#d9d9d9", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.yaxis.set_major_formatter(FuncFormatter(fmt_count))
    ax.set_xticks(np.arange(len(rows)))
    ax.set_xticklabels([str(row["module_label"]) for row in rows], rotation=25, ha="right")


def draw_linear(rows: List[Dict[str, object]], out_dir: Path) -> None:
    configure_style()
    fig, ax = plt.subplots(figsize=(10.4, 4.35), dpi=160)
    draw_bars(ax, rows, annotate=False)
    finish_axis(ax, rows)
    ax.set_ylabel("MRP count (24h)")
    ax.set_title("MRP Count Comparison Across Tools (24h)")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.20), ncol=5, frameon=False)
    fig.tight_layout()
    for suffix in ("png", "pdf"):
        fig.savefig(out_dir / f"mrp_24h_count_comparison_linear.{suffix}", bbox_inches="tight")
    plt.close(fig)


def draw_broken(rows: List[Dict[str, object]], out_dir: Path) -> None:
    configure_style()
    fig, (ax_hi, ax_lo) = plt.subplots(
        2,
        1,
        sharex=True,
        figsize=(10.4, 5.15),
        dpi=160,
        gridspec_kw={"height_ratios": [1.25, 1.0], "hspace": 0.055},
    )
    draw_bars(ax_hi, rows, annotate=False)
    draw_bars(ax_lo, rows, annotate=False)

    low_upper = 5000
    high_lower = 12000
    high_upper = 28000
    ax_lo.set_ylim(0, low_upper)
    ax_hi.set_ylim(high_lower, high_upper)

    for ax in (ax_hi, ax_lo):
        finish_axis(ax, rows)

    ax_hi.spines["bottom"].set_visible(False)
    ax_lo.spines["top"].set_visible(False)
    ax_hi.tick_params(labelbottom=False, bottom=False)
    ax_lo.set_xlabel("Module")
    ax_hi.set_ylabel("MRP count")
    ax_lo.set_ylabel("MRP count")
    ax_hi.set_title("MRP Count Comparison Across Tools (24h, Broken Y Axis)")

    # Broken-axis marks.
    kwargs = dict(marker=[(-1, -0.55), (1, 0.55)], markersize=7, linestyle="none", color="black", mec="black", mew=0.8, clip_on=False)
    ax_hi.plot([0, 1], [0, 0], transform=ax_hi.transAxes, **kwargs)
    ax_lo.plot([0, 1], [1, 1], transform=ax_lo.transAxes, **kwargs)

    # Annotate high bars on the top axis and low bars on the lower axis.
    x = np.arange(len(rows))
    width = 0.16
    offsets = {
        "Random": -2 * width,
        "GPT-5.4": -width,
        "DeepSeek-V4Pro": 0.0,
        "SegFuzz": width,
        "Conzzer": 2 * width,
    }
    for row_i, row in enumerate(rows):
        for tool in TOOL_ORDER:
            value = value_for(row, tool)
            axis = ax_hi if value >= high_lower else ax_lo
            y = value + (350 if axis is ax_hi else 90)
            axis.text(
                x[row_i] + offsets[tool],
                y,
                short_count(value),
                ha="center",
                va="bottom",
                rotation=90,
                fontsize=6.0,
                color="#222222",
                clip_on=True,
            )

    handles, labels = ax_hi.get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.015), ncol=5, frameon=False)
    fig.subplots_adjust(top=0.86, bottom=0.14, left=0.075, right=0.99)
    for suffix in ("png", "pdf"):
        fig.savefig(out_dir / f"mrp_24h_count_comparison_broken_axis.{suffix}", bbox_inches="tight")
    plt.close(fig)


def module_broken_limits(series_by_tool: Dict[str, List[Tuple[float, int]]]) -> Tuple[float, float, float]:
    finals = [values[-1][1] for values in series_by_tool.values()]
    max_value = max(finals)
    low_value = min([value for value in finals if value > 0] or [1])

    def snap_low(value: float) -> float:
        for step in [10, 20, 25, 50, 100, 150, 200, 250, 300, 400, 500]:
            if value <= step:
                return float(step)
        return float(int(np.ceil(value / 100.0) * 100))

    def snap_high(value: float) -> float:
        for step in [50, 100, 150, 200, 300, 400, 500, 600, 750, 1000]:
            if value <= step:
                return float(step)
        return float(int(np.ceil(value / 500.0) * 500))

    low_upper = snap_low(low_value * 1.12)
    mid_values = [value for value in finals if value > low_upper]
    if not mid_values or max_value <= low_upper * 2.2:
        upper = max_value * 1.08
        return upper, upper, max_value * 1.10
    high_lower = snap_high(max(low_upper * 1.45, min(mid_values) * 0.10))
    if high_lower <= low_upper:
        high_lower = snap_high(low_upper * 1.6)
    high_upper = max_value * 1.08
    return low_upper, high_lower, high_upper


def draw_axis_break_marks(ax_hi, ax_lo) -> None:
    fig = ax_hi.figure
    hi_box = ax_hi.get_position()
    lo_box = ax_lo.get_position()
    y0 = lo_box.y1 + 0.001
    y1 = hi_box.y0 - 0.001
    if y1 <= y0:
        return
    # Match the compact left-spine zigzag used by the reference plots. The mark
    # lives in the inter-axis gap, just inside the y spine, so it cannot collide
    # with tick labels.
    x0 = lo_box.x0 + 0.001
    amp = min(0.006, lo_box.width * 0.030)
    ys = np.linspace(y0, y1, 9)
    xs = [x0 + (amp if i % 2 else 0.0) for i in range(len(ys))]
    fig.add_artist(
        Line2D(xs, ys, transform=fig.transFigure, color="black", linewidth=0.75, clip_on=False, zorder=10)
    )


def top_ticks(high_lower: float, high_upper: float) -> List[float]:
    max_value = high_upper / 1.08
    if max_value <= 4_500:
        step = 1000
    elif max_value <= 12_000:
        step = 3000
    elif max_value <= 18_000:
        step = 5000
    else:
        step = 6000
    ticks = [high_lower]
    first = int(np.ceil(high_lower / step) * step)
    for tick in range(first, int(high_upper) + step, step):
        if tick > high_lower * 1.04 and tick <= high_upper:
            ticks.append(float(tick))
    if len(ticks) <= 2:
        ticks.append(float(int(np.ceil(max_value / step) * step)))
    return ticks


def low_ticks(low_upper: float) -> List[float]:
    if low_upper <= 25:
        return [0.0, low_upper]
    if low_upper <= 100:
        return [0.0, low_upper]
    return [0.0, low_upper]


def low_axis_lower_bound(low_upper: float) -> float:
    """Leave visible room under y=0 so low curves are not glued to the axis."""
    if low_upper <= 0:
        return -1.0
    return -max(1.0, low_upper * 0.24)


def plot_reference_module(ax_hi, ax_lo, module: str, series: Dict[str, Dict[str, List[Tuple[float, int]]]]) -> None:
    module_series = {tool: series[tool][module] for tool in TOOL_ORDER}
    low_upper, high_lower, high_upper = module_broken_limits(module_series)
    use_break = high_lower > low_upper * 1.05

    for axis in (ax_hi, ax_lo):
        for tool in TOOL_ORDER:
            label, color, linestyle, linewidth = CURVE_STYLES[tool]
            rows = module_series[tool]
            axis.plot(
                [hour for hour, _ in rows],
                [value for _, value in rows],
                color=color,
                linestyle=linestyle,
                linewidth=linewidth,
                label=label,
            )
        axis.grid(axis="y", color="#d9d9d9", linewidth=0.8)
        axis.set_axisbelow(True)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.set_xlim(0, 24)
        axis.set_xticks([0, 4, 8, 12, 16, 20, 24])
        axis.set_xticklabels(["0h", "4h", "8h", "12h", "16h", "20h", "24h"])
        axis.yaxis.set_major_formatter(FuncFormatter(fmt_count))
        axis.tick_params(axis="both", direction="in", length=3.5, width=0.8)
        axis.tick_params(axis="y", pad=1.0)

    if use_break:
        ax_lo.set_ylim(low_axis_lower_bound(low_upper), low_upper)
        ax_hi.set_ylim(high_lower, high_upper)
        ax_lo.set_yticks(low_ticks(low_upper))
        ax_hi.set_yticks(top_ticks(high_lower, high_upper))
        ax_hi.spines["bottom"].set_visible(False)
        ax_lo.spines["top"].set_visible(False)
        ax_hi.tick_params(bottom=False, labelbottom=False)
        draw_axis_break_marks(ax_hi, ax_lo)
    else:
        ax_lo.set_ylim(low_axis_lower_bound(low_upper), low_upper)
        ax_hi.set_visible(False)

    title = "bluetooth" if module == "bt-stack" else module
    ax_hi.set_title(title)
    ax_lo.set_xlabel("Time", labelpad=1.5)


def draw_reference_style_broken_curves(args: argparse.Namespace, out_dir: Path) -> None:
    series = parse_mrpfuzz_series(args.llm_dir)
    series["SegFuzz"] = parse_segfuzz_series(args.segfuzz_csv)
    series["Conzzer"] = parse_conzzer_series(args.conzzer_bundle)
    write_reference_timeseries(series, out_dir)

    configure_style()
    fig = plt.figure(figsize=(15.14, 5.00), dpi=360)
    outer = fig.add_gridspec(
        2,
        4,
        left=0.062,
        right=0.985,
        top=0.875,
        bottom=0.105,
        wspace=0.47,
        hspace=0.36,
    )

    for index, module in enumerate(MODULE_ORDER):
        inner = outer[index // 4, index % 4].subgridspec(2, 1, height_ratios=[5.35, 1.15], hspace=0.22)
        ax_hi = fig.add_subplot(inner[0])
        ax_lo = fig.add_subplot(inner[1], sharex=ax_hi)
        plot_reference_module(ax_hi, ax_lo, module, series)
        if index % 4 == 0:
            ax_hi.set_ylabel("MRP pairs")

    legend_handles = [
        Line2D([0], [0], color=color, linestyle=linestyle, linewidth=linewidth, label=label)
        for label, color, linestyle, linewidth in CURVE_STYLES.values()
    ]
    fig.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.995),
        ncol=5,
        frameon=False,
        handlelength=2.4,
        columnspacing=1.1,
    )
    for suffix in ("png", "pdf"):
        fig.savefig(out_dir / f"mrp_24h_reference_style_broken_curves.{suffix}")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm-dir", type=Path, default=DEFAULT_LLM_DIR)
    parser.add_argument("--conzzer-bundle", type=Path, default=DEFAULT_CONZZER_BUNDLE)
    parser.add_argument("--segfuzz-csv", type=Path, default=DEFAULT_SEGFUZZ_CSV)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows, totals = collect_rows(args)
    write_summary(rows, totals, args.output_dir, args)
    draw_reference_style_broken_curves(args, args.output_dir)
    draw_broken(rows, args.output_dir)
    draw_linear(rows, args.output_dir)
    print(args.output_dir)
    for row in rows:
        print(
            row["module"],
            row["mrpfuzz_random_pairs"],
            row["mrpfuzz_gpt54_pairs"],
            row["mrpfuzz_deepseek_v4pro_pairs"],
            row["segfuzz_raw_mrp_pairs"],
            row["conzzer_capped_mrp"],
        )
    print("totals", totals)


if __name__ == "__main__":
    main()
