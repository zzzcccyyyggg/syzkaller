#!/usr/bin/env python3
"""Plot Δt-bucketed validation analysis results.

Usage:
    python3 tools/plot_deltat_analysis.py --csv deltat_buckets.csv --pair-csv deltat_pairs.csv -o output_dir/
"""

import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

try:
    import pandas as pd
except ImportError:
    print("ERROR: pandas is required.  pip install pandas matplotlib", file=sys.stderr)
    sys.exit(1)


def plot_hit_rate(df, outdir):
    """Bar chart: hit rate per Δt bucket with count annotations."""
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(df))
    bars = ax.bar(x, df["hit_rate"] * 100, color="#4C72B0", edgecolor="black", linewidth=0.5)

    # Annotate with n=... on each bar
    for i, (bar, row) in enumerate(zip(bars, df.itertuples())):
        resolved = row.validated + row.invalid
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"n={resolved}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(df["bucket"], rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Hit Rate (%)")
    ax.set_xlabel("Initial Δt Bucket")
    ax.set_title("Validation Hit Rate by Initial Temporal Gap (Δt)")
    ax.set_ylim(0, min(100, df["hit_rate"].max() * 100 + 15))
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = os.path.join(outdir, "deltat_hit_rate.pdf")
    fig.savefig(path, dpi=300)
    fig.savefig(path.replace(".pdf", ".png"), dpi=150)
    print(f"  -> {path}")
    plt.close(fig)


def plot_hit_rate_resolved(df, outdir):
    """Bar chart: hit rate among resolved (validated+invalid) pairs."""
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(df))
    bars = ax.bar(x, df["hit_rate_resolved"] * 100, color="#55A868", edgecolor="black", linewidth=0.5)

    for i, (bar, row) in enumerate(zip(bars, df.itertuples())):
        resolved = row.validated + row.invalid
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"n={resolved}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(df["bucket"], rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Hit Rate (%) [resolved only]")
    ax.set_xlabel("Initial Δt Bucket")
    ax.set_title("Validation Hit Rate (Resolved Pairs) by Initial Δt")
    ax.set_ylim(0, min(100, df["hit_rate_resolved"].max() * 100 + 15))
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = os.path.join(outdir, "deltat_hit_rate_resolved.pdf")
    fig.savefig(path, dpi=300)
    fig.savefig(path.replace(".pdf", ".png"), dpi=150)
    print(f"  -> {path}")
    plt.close(fig)


def plot_median_attempts(df, outdir):
    """Bar chart: median attempts to confirm per bucket."""
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(df))
    vals = df["median_attempts_confirmed"].fillna(0)
    bars = ax.bar(x, vals, color="#C44E52", edgecolor="black", linewidth=0.5)

    for i, (bar, row) in enumerate(zip(bars, df.itertuples())):
        if row.validated > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                    f"n={row.validated}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(df["bucket"], rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Median Attempts to Confirm")
    ax.set_xlabel("Initial Δt Bucket")
    ax.set_title("Verification Cost by Initial Temporal Gap (Δt)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = os.path.join(outdir, "deltat_median_attempts.pdf")
    fig.savefig(path, dpi=300)
    fig.savefig(path.replace(".pdf", ".png"), dpi=150)
    print(f"  -> {path}")
    plt.close(fig)


def plot_distribution(df, outdir):
    """Stacked bar: distribution of validated/invalid/pending per bucket."""
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(df))
    w = 0.6

    ax.bar(x, df["validated"], w, label="Validated", color="#55A868")
    ax.bar(x, df["invalid"], w, bottom=df["validated"], label="Invalid", color="#C44E52")
    ax.bar(x, df["pending"], w, bottom=df["validated"] + df["invalid"], label="Pending", color="#8C8C8C")

    ax.set_xticks(x)
    ax.set_xticklabels(df["bucket"], rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Number of Pairs")
    ax.set_xlabel("Initial Δt Bucket")
    ax.set_title("Pair Distribution by Initial Δt and Validation Status")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = os.path.join(outdir, "deltat_distribution.pdf")
    fig.savefig(path, dpi=300)
    fig.savefig(path.replace(".pdf", ".png"), dpi=150)
    print(f"  -> {path}")
    plt.close(fig)


def plot_scatter(pair_df, outdir):
    """Scatter plot: log10(Δt) vs validation outcome."""
    if pair_df is None or pair_df.empty:
        return

    fig, ax = plt.subplots(figsize=(12, 4))
    validated = pair_df[pair_df["validated"] == 1]
    invalid = pair_df[pair_df["invalid"] == 1]
    pending = pair_df[(pair_df["validated"] == 0) & (pair_df["invalid"] == 0)]

    if not pending.empty:
        ax.scatter(pending["log10_timediff_us"], [0.5] * len(pending),
                   c="#8C8C8C", alpha=0.2, s=8, label="Pending")
    if not invalid.empty:
        ax.scatter(invalid["log10_timediff_us"], [0] * len(invalid),
                   c="#C44E52", alpha=0.4, s=12, label="Invalid")
    if not validated.empty:
        ax.scatter(validated["log10_timediff_us"], [1] * len(validated),
                   c="#55A868", alpha=0.4, s=12, label="Validated")

    ax.set_xlabel("log₁₀(Δt / μs)")
    ax.set_ylabel("Outcome")
    ax.set_yticks([0, 0.5, 1])
    ax.set_yticklabels(["Invalid", "Pending", "Validated"])
    ax.set_title("Per-Pair Validation Outcome vs Initial Δt")
    ax.legend(loc="upper right")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    path = os.path.join(outdir, "deltat_scatter.pdf")
    fig.savefig(path, dpi=300)
    fig.savefig(path.replace(".pdf", ".png"), dpi=150)
    print(f"  -> {path}")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Plot Δt-bucketed validation analysis")
    parser.add_argument("--csv", required=True, help="Per-bucket CSV from syz-deltat-analysis")
    parser.add_argument("--pair-csv", default="", help="Per-pair CSV from syz-deltat-analysis")
    parser.add_argument("-o", "--outdir", default=".", help="Output directory for plots")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    df = pd.read_csv(args.csv)
    print(f"Loaded {len(df)} buckets from {args.csv}")

    plot_hit_rate(df, args.outdir)
    plot_hit_rate_resolved(df, args.outdir)
    plot_median_attempts(df, args.outdir)
    plot_distribution(df, args.outdir)

    if args.pair_csv and os.path.exists(args.pair_csv):
        pair_df = pd.read_csv(args.pair_csv)
        print(f"Loaded {len(pair_df)} pairs from {args.pair_csv}")
        plot_scatter(pair_df, args.outdir)

    print(f"\nAll plots saved to {args.outdir}/")


if __name__ == "__main__":
    main()
