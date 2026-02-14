#!/usr/bin/env python3
"""
Plot DDRD fuzzing metrics over time from syz-manager log.
Each metric group is drawn on a separate subplot to avoid Y-axis scale conflicts.

Usage:
    python3 tools/plot_uaf_pairs.py xfs.2.14.log
    python3 tools/plot_uaf_pairs.py xfs.2.14.log -o result.png
    python3 tools/plot_uaf_pairs.py xfs.2.14.log -p ddrd_pairs,uaf_pairs,coverage
    python3 tools/plot_uaf_pairs.py xfs.2.14.log -p all
    python3 tools/plot_uaf_pairs.py xfs.2.14.log -s   # summary only
"""

import re
import sys
import argparse
from datetime import datetime
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')  # non-interactive backend by default
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    print("Error: matplotlib is required. Install with: pip install matplotlib")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Metric definitions: key -> (log_field_regex, display_label)
# The regexes use word-boundary tricks to avoid cross-matching
# (e.g. "uaf pairs" vs "ddrd pairs", "corpus" vs "uaf corpus").
# ---------------------------------------------------------------------------
METRIC_DEFS = {
    # -- DDRD pair discovery --
    'ddrd_pairs_total':   (r'ddrd pairs total=(\d+)',          'DDRD Pairs Total'),
    'ddrd_pairs_fuzz':    (r'ddrd pairs fuzz=(\d+)',           'DDRD Pairs Fuzz'),
    'ddrd_pairs_timing':  (r'ddrd pairs timing=(\d+)',         'DDRD Pairs Timing'),
    'ddrd_varnames_fuzz': (r'ddrd varnames fuzz=(\d+)',        'DDRD VarNames Fuzz'),
    'ddrd_varnames_timing': (r'ddrd varnames timing=(\d+)',    'DDRD VarNames Timing'),
    # -- UAF (deduplicated) --
    'uaf_pairs':          (r'(?<!\w)uaf pairs=(\d+)',          'UAF Pairs'),
    'uaf_pairs_fuzz':     (r'uaf pairs fuzz=(\d+)',            'UAF Pairs Fuzz'),
    'uaf_pairs_timing':   (r'uaf pairs timing=(\d+)',          'UAF Pairs Timing'),
    'uaf_varnames':       (r'(?<!\w)uaf varnames=(\d+)',       'UAF VarNames'),
    'uaf_varnames_fuzz':  (r'uaf varnames fuzz=(\d+)',         'UAF VarNames Fuzz'),
    'uaf_varnames_timing': (r'uaf varnames timing=(\d+)',      'UAF VarNames Timing'),
    'uaf_corpus':         (r'(?<!\w)uaf corpus=(\d+)',         'UAF Corpus'),
    'uaf_corpus_history': (r'uaf corpus with history=(\d+)',   'UAF Corpus w/ History'),
    'uaf_coverage':       (r'uaf coverage=(\d+)',              'UAF Coverage'),
    # -- General fuzzer --
    'corpus':             (r'(?<!uaf )(?<!\w)corpus=(\d+)',    'Corpus'),
    'coverage':           (r'(?<!uaf )(?<!new )(?<!\w)coverage=(\d+)', 'Coverage'),
    'new_coverage_pairs': (r'new coverage pairs=(\d+)',        'New Coverage Pairs'),
    'exec_total':         (r'exec total=(\d+)',                'Exec Total'),
    'candidates':         (r'(?<!\w)candidates=(\d+)',         'Candidates'),
    # -- Race selections --
    'race_explore':       (r'race explore selections=(\d+)',   'Race Explore'),
    'race_high_yield':    (r'race high yield selections=(\d+)','Race High Yield'),
    'race_partner':       (r'race partner selections=(\d+)',   'Race Partner'),
    'race_prior':         (r'race prior selections=(\d+)',     'Race Prior'),
    'race_random':        (r'race random selections=(\d+)',    'Race Random'),
    'race_shared_ns':     (r'race shared ns selections=(\d+)', 'Race Shared NS'),
    'race_total_yield':   (r'race total yield=(\d+)',          'Race Total Yield'),
    # -- Misc --
    'coverage_boosts':    (r'coverage boosts=(\d+)',           'Coverage Boosts'),
    'cross_prog_pairs':   (r'cross-prog pairs=(\d+)',          'Cross-Prog Pairs'),
    'affinity_updates':   (r'affinity updates=(\d+)',          'Affinity Updates'),
    'object_linkings':    (r'object linkings=(\d+)',           'Object Linkings'),
    'solo_filter_jobs':   (r'solo filter jobs=(\d+)',          'Solo Filter Jobs'),
    'solo_cache_hits':    (r'solo cache hits=(\d+)',           'Solo Cache Hits'),
    'coverage_triage':    (r'coverage triage jobs=(\d+)',      'Coverage Triage Jobs'),
}

# ---------------------------------------------------------------------------
# Panel definitions: name -> (title, [metric_keys], {key: color})
# ---------------------------------------------------------------------------
PANEL_DEFS = {
    'ddrd_pairs': (
        'DDRD Pair Discovery',
        ['ddrd_pairs_total', 'ddrd_pairs_fuzz', 'ddrd_pairs_timing'],
        {'ddrd_pairs_total': '#e74c3c', 'ddrd_pairs_fuzz': '#3498db', 'ddrd_pairs_timing': '#2ecc71'},
    ),
    'ddrd_varnames': (
        'DDRD VarName Discovery',
        ['ddrd_varnames_fuzz', 'ddrd_varnames_timing'],
        {'ddrd_varnames_fuzz': '#3498db', 'ddrd_varnames_timing': '#2ecc71'},
    ),
    'uaf_pairs': (
        'UAF Pairs (Deduplicated)',
        ['uaf_pairs', 'uaf_pairs_fuzz', 'uaf_pairs_timing'],
        {'uaf_pairs': '#e74c3c', 'uaf_pairs_fuzz': '#3498db', 'uaf_pairs_timing': '#2ecc71'},
    ),
    'uaf_varnames': (
        'UAF VarNames (Deduplicated)',
        ['uaf_varnames', 'uaf_varnames_fuzz', 'uaf_varnames_timing'],
        {'uaf_varnames': '#e74c3c', 'uaf_varnames_fuzz': '#3498db', 'uaf_varnames_timing': '#2ecc71'},
    ),
    'coverage': (
        'Coverage',
        ['coverage', 'uaf_coverage', 'new_coverage_pairs'],
        {'coverage': '#8e44ad', 'uaf_coverage': '#e67e22', 'new_coverage_pairs': '#1abc9c'},
    ),
    'corpus': (
        'Corpus',
        ['corpus', 'uaf_corpus', 'uaf_corpus_history'],
        {'corpus': '#8e44ad', 'uaf_corpus': '#e74c3c', 'uaf_corpus_history': '#f39c12'},
    ),
    'race_selections': (
        'Race Selection Strategy',
        ['race_explore', 'race_high_yield', 'race_partner', 'race_prior', 'race_random', 'race_shared_ns'],
        {
            'race_explore': '#e74c3c', 'race_high_yield': '#2ecc71', 'race_partner': '#3498db',
            'race_prior': '#f39c12', 'race_random': '#9b59b6', 'race_shared_ns': '#1abc9c',
        },
    ),
    'yield': (
        'Yield & Efficiency',
        ['race_total_yield', 'coverage_boosts', 'cross_prog_pairs', 'affinity_updates'],
        {
            'race_total_yield': '#e74c3c', 'coverage_boosts': '#2ecc71',
            'cross_prog_pairs': '#3498db', 'affinity_updates': '#f39c12',
        },
    ),
    'solo_triage': (
        'Solo Filter & Triage',
        ['solo_filter_jobs', 'solo_cache_hits', 'coverage_triage'],
        {'solo_filter_jobs': '#e74c3c', 'solo_cache_hits': '#3498db', 'coverage_triage': '#2ecc71'},
    ),
    'execution': (
        'Execution Progress',
        ['exec_total', 'candidates'],
        {'exec_total': '#2c3e50', 'candidates': '#e67e22'},
    ),
}

DEFAULT_PANELS = ['ddrd_pairs', 'uaf_pairs', 'coverage', 'corpus', 'race_selections', 'yield']


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def parse_log(logfile: str) -> dict:
    """Parse syz-manager log and extract all metrics over time."""
    timestamp_re = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})')
    compiled = {k: re.compile(pat) for k, (pat, _) in METRIC_DEFS.items()}

    metrics = {k: [] for k in METRIC_DEFS}
    metrics['time'] = []

    with open(logfile, 'r') as f:
        for line in f:
            ts_match = timestamp_re.match(line)
            if not ts_match:
                continue
            # Identify stats lines by presence of key fields
            if 'exec total=' not in line or 'corpus=' not in line:
                continue
            try:
                timestamp = datetime.strptime(ts_match.group(1), '%Y/%m/%d %H:%M:%S')
            except ValueError:
                continue

            row = {}
            for key, pattern in compiled.items():
                m = pattern.search(line)
                row[key] = int(m.group(1)) if m else 0

            metrics['time'].append(timestamp)
            for key in compiled:
                metrics[key].append(row[key])

    return metrics


def elapsed_minutes(times: list) -> list:
    """Convert datetime list to elapsed minutes from start."""
    if not times:
        return []
    start = times[0]
    return [(t - start).total_seconds() / 60.0 for t in times]


# ---------------------------------------------------------------------------
# Plotting – each panel on its own subplot
# ---------------------------------------------------------------------------
def plot_panels(metrics: dict, output: str = None, panels: list = None, interactive: bool = False):
    """Draw each selected panel as an independent subplot in a vertical grid."""
    if not metrics['time']:
        print("Error: No data points found in log file")
        sys.exit(1)

    if interactive:
        matplotlib.use('TkAgg')
        import importlib
        importlib.reload(plt)

    elapsed = elapsed_minutes(metrics['time'])
    if panels is None:
        panels = list(DEFAULT_PANELS)

    # Filter out panels where all metrics are zero (nothing to show)
    active_panels = []
    for pname in panels:
        if pname not in PANEL_DEFS:
            print(f"Warning: Unknown panel '{pname}', skipping. Available: {list(PANEL_DEFS.keys())}")
            continue
        _, keys, _ = PANEL_DEFS[pname]
        if any(max(metrics.get(k, [0])) > 0 for k in keys if k in metrics):
            active_panels.append(pname)
        else:
            print(f"  Panel '{pname}' skipped (all zeros)")

    if not active_panels:
        print("Error: No panels with non-zero data to plot")
        sys.exit(1)

    n = len(active_panels)
    fig, axes = plt.subplots(n, 1, figsize=(16, 4.5 * n), sharex=True)
    if n == 1:
        axes = [axes]

    for idx, pname in enumerate(active_panels):
        title, keys, colors = PANEL_DEFS[pname]
        ax = axes[idx]
        for key in keys:
            data = metrics.get(key, [])
            if not data or max(data) == 0:
                continue
            label = METRIC_DEFS[key][1]
            color = colors.get(key, None)
            ax.plot(elapsed, data, '-', color=color, linewidth=1.8, label=label, alpha=0.9)
        ax.set_title(title, fontsize=13, fontweight='bold', loc='left')
        ax.set_ylabel('Count', fontsize=10)
        ax.legend(loc='upper left', fontsize=9, framealpha=0.8)
        ax.grid(True, alpha=0.25)
        ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: _fmt_num(x)))
        # Shade the area under curves for visual clarity (only for ≤3 lines)
        visible_keys = [k for k in keys if k in metrics and max(metrics[k]) > 0]
        if len(visible_keys) <= 2:
            for key in visible_keys:
                ax.fill_between(elapsed, metrics[key], alpha=0.08, color=colors.get(key))

    axes[-1].set_xlabel('Time (minutes)', fontsize=12)

    # Suptitle
    duration = elapsed[-1] if elapsed else 0
    n_pts = len(elapsed)
    suptitle = f'DDRD Fuzzing Metrics  |  Duration: {duration:.1f} min  |  {n_pts} samples'
    fig.suptitle(suptitle, fontsize=15, fontweight='bold', y=1.0)
    fig.tight_layout()

    if output:
        fig.savefig(output, dpi=150, bbox_inches='tight')
        print(f"Saved plot to {output}")
    else:
        plt.show()


def _fmt_num(x: float) -> str:
    """Format axis tick number: 1000 -> 1K, 1000000 -> 1M."""
    if abs(x) >= 1_000_000:
        return f'{x/1_000_000:.1f}M'
    if abs(x) >= 1_000:
        return f'{x/1_000:.1f}K'
    return f'{int(x)}'


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(metrics: dict):
    """Print summary statistics for all parsed metrics."""
    if not metrics['time']:
        print("No data found")
        return

    elapsed = elapsed_minutes(metrics['time'])
    duration = elapsed[-1]

    print(f"\n{'='*70}")
    print(f"  DDRD Fuzzing Summary")
    print(f"{'='*70}")
    print(f"  Duration:      {duration:.1f} minutes ({duration/60:.2f} hours)")
    print(f"  Data points:   {len(elapsed)}")
    print(f"  Start time:    {metrics['time'][0]}")
    print(f"  End time:      {metrics['time'][-1]}")

    # Group metrics for display
    groups = [
        ("DDRD Discovery", [
            'ddrd_pairs_total', 'ddrd_pairs_fuzz', 'ddrd_pairs_timing',
            'ddrd_varnames_fuzz', 'ddrd_varnames_timing',
        ]),
        ("UAF (Deduplicated)", [
            'uaf_pairs', 'uaf_pairs_fuzz', 'uaf_pairs_timing',
            'uaf_varnames', 'uaf_varnames_fuzz', 'uaf_varnames_timing',
            'uaf_corpus', 'uaf_corpus_history', 'uaf_coverage',
        ]),
        ("General Fuzzer", [
            'corpus', 'coverage', 'new_coverage_pairs', 'exec_total',
        ]),
        ("Race Selections", [
            'race_explore', 'race_high_yield', 'race_partner',
            'race_prior', 'race_random', 'race_shared_ns', 'race_total_yield',
        ]),
        ("Misc", [
            'coverage_boosts', 'cross_prog_pairs', 'affinity_updates',
            'object_linkings', 'solo_filter_jobs', 'solo_cache_hits', 'coverage_triage',
        ]),
    ]

    for gname, keys in groups:
        has_data = any(metrics.get(k) and metrics[k][-1] > 0 for k in keys)
        if not has_data:
            continue
        print(f"\n  [{gname}]")
        for k in keys:
            data = metrics.get(k, [])
            if not data:
                continue
            label = METRIC_DEFS[k][1]
            val = data[-1]
            print(f"    {label:<30s} {val:>10,}")

    # Growth rate
    if duration > 10:
        target = duration - 10
        idx = next((i for i, e in enumerate(elapsed) if e >= target), len(elapsed) - 1)
        for key, label in [('ddrd_pairs_total', 'DDRD Pairs'), ('uaf_pairs', 'UAF Pairs')]:
            data = metrics.get(key, [])
            if data and data[-1] > 0:
                rate = (data[-1] - data[idx]) / max(duration - elapsed[idx], 1)
                print(f"\n  Growth rate (last {duration - elapsed[idx]:.0f} min):  {label} = {rate:.1f}/min")

    # Pairs / VarName ratio
    for pair_k, vn_k, label in [
        ('ddrd_pairs_total', 'ddrd_varnames_fuzz', 'DDRD'),
        ('uaf_pairs', 'uaf_varnames', 'UAF'),
    ]:
        dp = metrics.get(pair_k, [])
        dv = metrics.get(vn_k, [])
        if dp and dv and dv[-1] > 0:
            # Use total ddrd varnames = fuzz + timing
            total_vn = dv[-1]
            if label == 'DDRD':
                timing_vn = metrics.get('ddrd_varnames_timing', [])
                if timing_vn:
                    total_vn = dv[-1] + timing_vn[-1]
            print(f"  {label} Pairs/VarName ratio: {dp[-1] / total_vn:.1f}")

    print(f"\n{'='*70}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Plot DDRD fuzzing metrics from syz-manager log (separate subplots per group)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available panels:
  ddrd_pairs      DDRD pair discovery (total/fuzz/timing)
  ddrd_varnames   DDRD varname discovery (fuzz/timing)
  uaf_pairs       UAF deduplicated pairs (total/fuzz/timing)
  uaf_varnames    UAF deduplicated varnames (total/fuzz/timing)
  coverage        Coverage (general, uaf, new coverage pairs)
  corpus          Corpus (general, uaf, uaf w/ history)
  race_selections Race selection strategy breakdown
  yield           Yield & efficiency (yield, boosts, cross-prog, affinity)
  solo_triage     Solo filter & triage jobs
  execution       Execution progress (exec total, candidates)

Examples:
  %(prog)s log.txt -o plot.png
  %(prog)s log.txt -p ddrd_pairs,uaf_pairs,coverage,race_selections
  %(prog)s log.txt -p all -o full.png
        """,
    )
    parser.add_argument('logfile', help='Path to syz-manager log file')
    parser.add_argument('-o', '--output', help='Output image file (default: show interactive)')
    parser.add_argument(
        '-p', '--panels',
        default=','.join(DEFAULT_PANELS),
        help=f'Comma-separated panel names to plot, or "all" (default: {",".join(DEFAULT_PANELS)})',
    )
    parser.add_argument('-s', '--summary', action='store_true', help='Print summary only, no plot')
    parser.add_argument('--interactive', action='store_true', help='Use interactive matplotlib backend')

    args = parser.parse_args()

    if not Path(args.logfile).exists():
        print(f"Error: File not found: {args.logfile}")
        sys.exit(1)

    print(f"Parsing {args.logfile}...")
    metrics = parse_log(args.logfile)

    print_summary(metrics)

    if not args.summary:
        if args.panels.strip().lower() == 'all':
            panels = list(PANEL_DEFS.keys())
        else:
            panels = [p.strip() for p in args.panels.split(',') if p.strip()]
        plot_panels(metrics, args.output, panels, interactive=args.interactive)


if __name__ == '__main__':
    main()
