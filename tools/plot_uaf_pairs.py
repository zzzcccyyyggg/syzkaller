#!/usr/bin/env python3
"""
Plot UAF pairs, varnames, corpus and coverage over time from syz-manager log.

Usage:
    python3 tools/plot_uaf_pairs.py ptmx.log
    python3 tools/plot_uaf_pairs.py ptmx.log -o uaf_pairs.png
    python3 tools/plot_uaf_pairs.py ptmx.log --metrics pairs,varnames,corpus
"""

import re
import sys
import argparse
from datetime import datetime
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
except ImportError:
    print("Error: matplotlib is required. Install with: pip install matplotlib")
    sys.exit(1)


def parse_log(logfile: str) -> dict:
    """Parse syz-manager log and extract metrics over time."""
    
    # Regex pattern for log lines with metrics
    # Example: 2026/01/02 23:22:48 candidates=0 corpus=719 coverage=10239 ... uaf pairs=14 uaf varnames=7
    timestamp_pattern = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})')
    
    metrics = {
        'time': [],
        'pairs': [],
        'varnames': [],
        'corpus': [],
        'coverage': [],
        'uaf_corpus': [],
        'uaf_coverage': [],
        'exec_total': [],
        'race_explore': [],
        'race_high_yield': [],
        'race_partner': [],
        'race_random': [],
        'race_total_yield': [],
    }
    
    metric_patterns = {
        'pairs': re.compile(r'uaf pairs=(\d+)'),
        'varnames': re.compile(r'uaf varnames=(\d+)'),
        'corpus': re.compile(r'(?<!uaf )corpus=(\d+)'),
        'coverage': re.compile(r'(?<!uaf )coverage=(\d+)'),
        'uaf_corpus': re.compile(r'uaf corpus=(\d+)'),
        'uaf_coverage': re.compile(r'uaf coverage=(\d+)'),
        'exec_total': re.compile(r'exec total=(\d+)'),
        'race_explore': re.compile(r'race explore selections=(\d+)'),
        'race_high_yield': re.compile(r'race high yield selections=(\d+)'),
        'race_partner': re.compile(r'race partner selections=(\d+)'),
        'race_random': re.compile(r'race random selections=(\d+)'),
        'race_total_yield': re.compile(r'race total yield=(\d+)'),
    }
    
    with open(logfile, 'r') as f:
        for line in f:
            # Check if line has timestamp and metrics
            ts_match = timestamp_pattern.match(line)
            if not ts_match:
                continue
            
            # Must have at least uaf pairs to be a stats line
            if 'uaf pairs=' not in line:
                continue
            
            try:
                timestamp = datetime.strptime(ts_match.group(1), '%Y/%m/%d %H:%M:%S')
            except ValueError:
                continue
            
            # Extract all metrics
            row = {'time': timestamp}
            for name, pattern in metric_patterns.items():
                match = pattern.search(line)
                if match:
                    row[name] = int(match.group(1))
                else:
                    row[name] = None
            
            # Only add if we got uaf pairs
            if row.get('pairs') is not None:
                metrics['time'].append(row['time'])
                for name in metric_patterns:
                    metrics[name].append(row.get(name, 0) or 0)
    
    return metrics


def calculate_elapsed_minutes(times: list) -> list:
    """Convert datetime list to elapsed minutes from start."""
    if not times:
        return []
    start = times[0]
    return [(t - start).total_seconds() / 60 for t in times]


def plot_metrics(metrics: dict, output: str = None, selected_metrics: list = None):
    """Plot selected metrics over time."""
    
    if not metrics['time']:
        print("Error: No data points found in log file")
        sys.exit(1)
    
    elapsed = calculate_elapsed_minutes(metrics['time'])
    
    # Available metrics for plotting
    available = {
        'pairs': ('UAF Pairs', 'tab:red', '-'),
        'varnames': ('UAF VarNames', 'tab:orange', '-'),
        'uaf_corpus': ('UAF Corpus', 'tab:green', '-'),
        'uaf_coverage': ('UAF Coverage', 'tab:blue', '--'),
        'corpus': ('Corpus', 'tab:purple', '--'),
        'coverage': ('Coverage', 'tab:brown', ':'),
        'race_explore': ('Race Explore', 'tab:cyan', ':'),
        'race_high_yield': ('Race High Yield', 'tab:pink', ':'),
        'race_total_yield': ('Race Total Yield', 'tab:olive', ':'),
    }
    
    # Default metrics to show
    if selected_metrics is None:
        selected_metrics = ['pairs', 'varnames', 'uaf_corpus']
    
    # Validate selected metrics
    for m in selected_metrics:
        if m not in available:
            print(f"Warning: Unknown metric '{m}', available: {list(available.keys())}")
    
    selected_metrics = [m for m in selected_metrics if m in available]
    
    if not selected_metrics:
        print("Error: No valid metrics selected")
        sys.exit(1)
    
    # Create figure with multiple y-axes if needed
    fig, ax1 = plt.subplots(figsize=(14, 8))
    
    # Determine if we need secondary y-axis (for coverage which has different scale)
    primary_metrics = [m for m in selected_metrics if m not in ['coverage', 'uaf_coverage']]
    secondary_metrics = [m for m in selected_metrics if m in ['coverage', 'uaf_coverage']]
    
    lines = []
    labels = []
    
    # Plot primary metrics
    for m in primary_metrics:
        label, color, style = available[m]
        line, = ax1.plot(elapsed, metrics[m], style, color=color, linewidth=2, label=label)
        lines.append(line)
        labels.append(label)
    
    ax1.set_xlabel('Time (minutes)', fontsize=12)
    ax1.set_ylabel('Count', fontsize=12)
    ax1.tick_params(axis='y')
    ax1.grid(True, alpha=0.3)
    
    # Plot secondary metrics on secondary y-axis
    if secondary_metrics:
        ax2 = ax1.twinx()
        for m in secondary_metrics:
            label, color, style = available[m]
            line, = ax2.plot(elapsed, metrics[m], style, color=color, linewidth=2, label=label)
            lines.append(line)
            labels.append(label)
        ax2.set_ylabel('Coverage', fontsize=12)
        ax2.tick_params(axis='y')
    
    # Title and legend
    duration_min = elapsed[-1] if elapsed else 0
    num_points = len(elapsed)
    final_pairs = metrics['pairs'][-1] if metrics['pairs'] else 0
    final_varnames = metrics['varnames'][-1] if metrics['varnames'] else 0
    
    title = f'UAF Fuzzing Progress\n'
    title += f'Duration: {duration_min:.1f} min | Data points: {num_points} | '
    title += f'Final: {final_pairs} pairs, {final_varnames} varnames'
    plt.title(title, fontsize=14)
    
    ax1.legend(lines, labels, loc='upper left', fontsize=10)
    
    plt.tight_layout()
    
    if output:
        plt.savefig(output, dpi=150, bbox_inches='tight')
        print(f"Saved plot to {output}")
    else:
        plt.show()


def print_summary(metrics: dict):
    """Print summary statistics."""
    if not metrics['time']:
        print("No data found")
        return
    
    elapsed = calculate_elapsed_minutes(metrics['time'])
    duration = elapsed[-1]
    
    print(f"\n{'='*60}")
    print(f"UAF Fuzzing Summary")
    print(f"{'='*60}")
    print(f"Duration:      {duration:.1f} minutes ({duration/60:.2f} hours)")
    print(f"Data points:   {len(elapsed)}")
    print(f"Start time:    {metrics['time'][0]}")
    print(f"End time:      {metrics['time'][-1]}")
    print(f"")
    print(f"Final Metrics:")
    print(f"  UAF Pairs:     {metrics['pairs'][-1]:,}")
    print(f"  UAF VarNames:  {metrics['varnames'][-1]:,}")
    print(f"  UAF Corpus:    {metrics['uaf_corpus'][-1]:,}")
    print(f"  UAF Coverage:  {metrics['uaf_coverage'][-1]:,}")
    print(f"  Corpus:        {metrics['corpus'][-1]:,}")
    print(f"  Coverage:      {metrics['coverage'][-1]:,}")
    print(f"")
    
    # Growth rate (pairs per minute in last 10 min)
    if duration > 10:
        # Find index of 10 minutes ago
        target = duration - 10
        idx = next((i for i, e in enumerate(elapsed) if e >= target), len(elapsed) - 1)
        pairs_10min_ago = metrics['pairs'][idx]
        pairs_now = metrics['pairs'][-1]
        rate = (pairs_now - pairs_10min_ago) / 10
        print(f"Growth rate (last 10 min):")
        print(f"  Pairs:     {rate:.1f}/min")
    
    # Pairs per varname ratio
    if metrics['varnames'][-1] > 0:
        ratio = metrics['pairs'][-1] / metrics['varnames'][-1]
        print(f"\nPairs/VarName ratio: {ratio:.1f}")
    
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Plot UAF pairs and related metrics from syz-manager log'
    )
    parser.add_argument('logfile', help='Path to syz-manager log file')
    parser.add_argument('-o', '--output', help='Output image file (default: show interactive)')
    parser.add_argument(
        '-m', '--metrics',
        default='pairs,varnames,uaf_corpus',
        help='Comma-separated metrics to plot (default: pairs,varnames,uaf_corpus). '
             'Available: pairs,varnames,uaf_corpus,uaf_coverage,corpus,coverage,'
             'race_explore,race_high_yield,race_total_yield'
    )
    parser.add_argument('-s', '--summary', action='store_true', help='Print summary only, no plot')
    
    args = parser.parse_args()
    
    if not Path(args.logfile).exists():
        print(f"Error: File not found: {args.logfile}")
        sys.exit(1)
    
    print(f"Parsing {args.logfile}...")
    metrics = parse_log(args.logfile)
    
    print_summary(metrics)
    
    if not args.summary:
        selected = args.metrics.split(',')
        plot_metrics(metrics, args.output, selected)


if __name__ == '__main__':
    main()
