#!/usr/bin/env python3
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

"""
plot_comparison.py - 绘制 DDRD / Conzzer / SegFuzz 并发对数对比图

生成与论文图片一致的双子图对比图:
  - 上图: VarName Pair Count (或等效指标) vs Time
  - 下图: Pair Count (或等效指标) vs Time

输入统一格式 CSV (由 collect_*_pairs.py 或 run-with-collector.sh 生成):
  timestamp, elapsed_sec, elapsed_min, elapsed_hour, pair_count, varname_pair_count

用法:
  # 对比 DDRD vs Conzzer
  python3 plot_comparison.py \\
    --ddrd data/ddrd_btrfs.csv \\
    --conzzer data/conzzer_btrfs.csv \\
    -o comparison_btrfs.png --target btrfs

  # 对比 DDRD vs SegFuzz
  python3 plot_comparison.py \\
    --ddrd data/ddrd_dsp.csv \\
    --segfuzz data/segfuzz_dsp.csv \\
    -o comparison_dsp.png --target dsp

  # 三者同时对比
  python3 plot_comparison.py \\
    --ddrd data/ddrd_btrfs.csv \\
    --conzzer data/conzzer_btrfs.csv \\
    --segfuzz data/segfuzz_btrfs.csv \\
    -o comparison_all.png --target btrfs

  # 也支持通用输入 (不限定工具名)
  python3 plot_comparison.py \\
    -i exp1.csv exp2.csv exp3.csv \\
    --labels "DDRD" "Conzzer" "SegFuzz" \\
    -o comparison.png
"""

import argparse
import csv
import os
import sys
from typing import List, Dict, Tuple, Optional

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator, AutoMinorLocator
    import matplotlib.ticker as mticker
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not found. Install with: pip install matplotlib", file=sys.stderr)


# ============================================================
# 样式配置
# ============================================================

# 论文级颜色和线型
TOOL_STYLES = {
    'DDRD': {
        'color': '#1f77b4',      # 蓝色 (实线)
        'linestyle': '-',
        'linewidth': 2.0,
        'label': 'DDRD (normal)',
    },
    'Conzzer': {
        'color': '#d62728',      # 红色 (虚线)
        'linestyle': '--',
        'linewidth': 2.0,
        'label': 'Conzzer',
    },
    'SegFuzz': {
        'color': '#2ca02c',      # 绿色 (点划线)
        'linestyle': '-.',
        'linewidth': 2.0,
        'label': 'SegFuzz',
    },
    'Random': {
        'color': '#d62728',      # 红色 (虚线)
        'linestyle': '--',
        'linewidth': 2.0,
        'label': 'Random baseline',
    },
}

# 通用颜色序列 (当使用 -i 模式时)
GENERIC_COLORS = ['#1f77b4', '#d62728', '#2ca02c', '#ff7f0e', '#9467bd', '#8c564b']
GENERIC_STYLES = ['-', '--', '-.', ':', '-', '--']


def setup_paper_style():
    """论文级图表样式"""
    plt.rcParams.update({
        'font.family': 'serif',
        'font.serif': ['Times New Roman', 'DejaVu Serif', 'serif'],
        'font.size': 12,
        'axes.labelsize': 14,
        'axes.titlesize': 14,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'legend.fontsize': 11,
        'figure.dpi': 150,
        'savefig.dpi': 300,
        'savefig.bbox': 'tight',
        'axes.grid': True,
        'grid.alpha': 0.3,
        'grid.linestyle': '--',
        'lines.linewidth': 2,
    })


# ============================================================
# 数据读取
# ============================================================

def read_timeseries(filepath: str) -> Dict:
    """
    读取统一格式的 CSV 文件。

    支持的列名:
      - elapsed_hour / elapsed_min / elapsed_sec → 时间
      - pair_count / unique_signals / unique_races → Pair Count
      - varname_pair_count / unique_varname_pairs → VarName Pair Count
    """
    hours = []
    pair_counts = []
    varname_counts = []

    with open(filepath, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # 时间 (优先使用 hour, 然后 min, 然后 sec)
                if 'elapsed_hour' in row and row['elapsed_hour']:
                    h = float(row['elapsed_hour'])
                elif 'elapsed_min' in row and row['elapsed_min']:
                    h = float(row['elapsed_min']) / 60
                elif 'elapsed_sec' in row and row['elapsed_sec']:
                    h = float(row['elapsed_sec']) / 3600
                else:
                    continue

                # Pair Count
                pc = 0
                for key in ['pair_count', 'unique_signals', 'unique_races', 'unique_race_pairs']:
                    if key in row and row[key]:
                        pc = int(row[key])
                        break

                # VarName Pair Count
                vpc = 0
                for key in ['varname_pair_count', 'unique_varname_pairs']:
                    if key in row and row[key]:
                        vpc = int(row[key])
                        break

                hours.append(h)
                pair_counts.append(pc)
                varname_counts.append(vpc)
            except (ValueError, KeyError):
                continue

    return {
        'hours': hours,
        'pair_counts': pair_counts,
        'varname_counts': varname_counts,
    }


# ============================================================
# 绘图函数
# ============================================================

def plot_dual_comparison(datasets: List[Tuple[Dict, dict]],
                         output_path: str,
                         target: str = '',
                         max_hours: Optional[float] = None):
    """
    绘制论文级双子图对比图。

    datasets: [(data_dict, style_dict), ...]
    """
    if not HAS_MATPLOTLIB:
        print("Error: matplotlib required for plotting", file=sys.stderr)
        sys.exit(1)

    setup_paper_style()

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)
    fig.subplots_adjust(hspace=0.25)

    for data, style in datasets:
        hours = data['hours']
        if not hours:
            continue

        if max_hours is not None:
            # 截断到指定时长
            mask = [h <= max_hours for h in hours]
            hours = [h for h, m in zip(hours, mask) if m]
            vpc = [v for v, m in zip(data['varname_counts'], mask) if m]
            pc = [p for p, m in zip(data['pair_counts'], mask) if m]
        else:
            vpc = data['varname_counts']
            pc = data['pair_counts']

        # 上图: VarName Pair Count
        ax1.plot(hours, vpc,
                 color=style['color'],
                 linestyle=style['linestyle'],
                 linewidth=style['linewidth'],
                 label=style['label'])

        # 下图: Pair Count
        ax2.plot(hours, pc,
                 color=style['color'],
                 linestyle=style['linestyle'],
                 linewidth=style['linewidth'],
                 label=style['label'])

    # 上图配置
    title_prefix = f"{target} — " if target else ""
    ax1.set_title(f"{title_prefix}VarName Pair Count: Comparison")
    ax1.set_ylabel("VarName Pair Count")
    ax1.legend(loc='upper left', framealpha=0.9)
    ax1.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=8))

    # 下图配置
    ax2.set_title(f"{title_prefix}Pair Count: Comparison")
    ax2.set_xlabel("Elapsed Time (hours)")
    ax2.set_ylabel("Pair Count")
    ax2.legend(loc='upper left', framealpha=0.9)
    ax2.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=8))

    # 保存
    plt.savefig(output_path, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")


def plot_single_metric(datasets: List[Tuple[Dict, dict]],
                       output_path: str,
                       metric: str = 'pair_count',
                       target: str = '',
                       max_hours: Optional[float] = None):
    """绘制单指标对比图"""
    if not HAS_MATPLOTLIB:
        print("Error: matplotlib required for plotting", file=sys.stderr)
        sys.exit(1)

    setup_paper_style()

    fig, ax = plt.subplots(figsize=(10, 5))

    metric_key = 'pair_counts' if metric == 'pair_count' else 'varname_counts'
    ylabel = 'Pair Count' if metric == 'pair_count' else 'VarName Pair Count'

    for data, style in datasets:
        hours = data['hours']
        values = data[metric_key]
        if not hours:
            continue

        if max_hours is not None:
            mask = [h <= max_hours for h in hours]
            hours = [h for h, m in zip(hours, mask) if m]
            values = [v for v, m in zip(values, mask) if m]

        ax.plot(hours, values,
                color=style['color'],
                linestyle=style['linestyle'],
                linewidth=style['linewidth'],
                label=style['label'])

    title_prefix = f"{target} — " if target else ""
    ax.set_title(f"{title_prefix}{ylabel}: Comparison")
    ax.set_xlabel("Elapsed Time (hours)")
    ax.set_ylabel(ylabel)
    ax.legend(loc='upper left', framealpha=0.9)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=8))

    plt.savefig(output_path, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")


# ============================================================
# 摘要打印
# ============================================================

def print_comparison_summary(datasets: List[Tuple[Dict, dict, str]]):
    """打印各工具的统计对比"""
    print(f"\n{'='*70}")
    print(f"{'Tool':<15} {'Duration(h)':>12} {'Pair Count':>12} {'VarName Pair':>12}")
    print(f"{'='*70}")

    for data, style, filepath in datasets:
        if not data['hours']:
            print(f"{style['label']:<15} {'N/A':>12} {'N/A':>12} {'N/A':>12}")
            continue

        duration_h = data['hours'][-1]
        final_pc = data['pair_counts'][-1] if data['pair_counts'] else 0
        final_vpc = data['varname_counts'][-1] if data['varname_counts'] else 0

        print(f"{style['label']:<15} {duration_h:>12.2f} {final_pc:>12,} {final_vpc:>12,}")

    print(f"{'='*70}\n")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Plot Pair Count comparison between DDRD, Conzzer, and SegFuzz',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Named input mode (recommended):
  python3 plot_comparison.py \\
    --ddrd ddrd_btrfs.csv \\
    --conzzer conzzer_btrfs.csv \\
    --segfuzz segfuzz_btrfs.csv \\
    -o comparison.png --target btrfs

Generic input mode:
  python3 plot_comparison.py \\
    -i exp1.csv exp2.csv \\
    --labels "Tool A" "Tool B" \\
    -o comparison.png

Options:
  --metric pair_count       Plot only Pair Count
  --metric varname          Plot only VarName Pair Count
  --metric both             Plot dual subplot (default)
  --max-hours 24            Truncate x-axis to 24 hours
  --format png|pdf|svg      Output format (from extension or explicit)
"""
    )

    # 命名输入
    parser.add_argument('--ddrd', help='DDRD timeseries CSV')
    parser.add_argument('--conzzer', help='Conzzer timeseries CSV')
    parser.add_argument('--segfuzz', help='SegFuzz timeseries CSV')
    parser.add_argument('--random', help='Random baseline timeseries CSV')

    # 通用输入
    parser.add_argument('-i', '--inputs', nargs='*', help='Generic input CSV files')
    parser.add_argument('--labels', nargs='*', help='Labels for generic inputs')

    # 输出配置
    parser.add_argument('-o', '--output', default='pair_comparison.png',
                        help='Output file (default: pair_comparison.png)')
    parser.add_argument('--target', default='',
                        help='Target module name (e.g., btrfs, dsp) for title')
    parser.add_argument('--metric', choices=['pair_count', 'varname', 'both'],
                        default='both',
                        help='Which metric(s) to plot (default: both)')
    parser.add_argument('--max-hours', type=float,
                        help='Maximum hours to show on x-axis')
    parser.add_argument('--format', choices=['png', 'pdf', 'svg'],
                        help='Output format (auto-detected from extension)')
    parser.add_argument('--no-summary', action='store_true',
                        help='Skip printing summary table')

    args = parser.parse_args()

    if not HAS_MATPLOTLIB:
        print("Error: matplotlib required. Install: pip install matplotlib", file=sys.stderr)
        sys.exit(1)

    # 收集所有数据集
    datasets = []  # [(data, style, filepath)]

    # 命名输入
    for tool_key, filepath in [('DDRD', args.ddrd), ('Conzzer', args.conzzer),
                                ('SegFuzz', args.segfuzz), ('Random', args.random)]:
        if filepath:
            if not os.path.exists(filepath):
                print(f"Error: File not found: {filepath}", file=sys.stderr)
                sys.exit(1)
            data = read_timeseries(filepath)
            style = TOOL_STYLES[tool_key]
            datasets.append((data, style, filepath))

    # 通用输入
    if args.inputs:
        for i, filepath in enumerate(args.inputs):
            if not os.path.exists(filepath):
                print(f"Error: File not found: {filepath}", file=sys.stderr)
                sys.exit(1)
            data = read_timeseries(filepath)
            label = args.labels[i] if args.labels and i < len(args.labels) else f"Exp{i+1}"
            style = {
                'color': GENERIC_COLORS[i % len(GENERIC_COLORS)],
                'linestyle': GENERIC_STYLES[i % len(GENERIC_STYLES)],
                'linewidth': 2.0,
                'label': label,
            }
            datasets.append((data, style, filepath))

    if not datasets:
        print("Error: No input data provided. Use --ddrd, --conzzer, --segfuzz, or -i",
              file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # 打印摘要
    if not args.no_summary:
        print_comparison_summary(datasets)

    # 绘图
    plot_datasets = [(d, s) for d, s, _ in datasets]

    if args.metric == 'both':
        plot_dual_comparison(plot_datasets, args.output,
                             target=args.target, max_hours=args.max_hours)
    else:
        metric_name = 'pair_count' if args.metric == 'pair_count' else 'varname_pair_count'
        plot_single_metric(plot_datasets, args.output,
                           metric=metric_name, target=args.target,
                           max_hours=args.max_hours)


if __name__ == '__main__':
    main()
