#!/usr/bin/env python3
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

"""
plot_races.py - 绘制 Race Pair 时间序列图

用法:
    python3 plot_races.py race_timeseries.csv
    python3 plot_races.py race_timeseries.csv -o output.pdf
    python3 plot_races.py race_timeseries.csv --format svg --style paper
    
    # 对比多个实验
    python3 plot_races.py exp1/race_timeseries.csv exp2/race_timeseries.csv --labels "DDRD" "Vanilla"

输出:
    - 累计曲线图 (Cumulative Race Pairs vs Time)
    - 支持 PNG, PDF, SVG 格式
    - 论文样式支持
"""

import argparse
import csv
import sys
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# 尝试导入 matplotlib
try:
    import matplotlib
    matplotlib.use('Agg')  # 非交互式后端
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def read_timeseries(filepath: str) -> Tuple[List[float], List[int]]:
    """
    读取时间序列 CSV 文件
    
    Returns:
        (elapsed_minutes, unique_races) 两个列表
    """
    elapsed_mins = []
    unique_races = []
    
    with open(filepath, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # 支持 elapsed_min 或 elapsed_sec
                if 'elapsed_min' in row:
                    mins = float(row['elapsed_min'])
                elif 'elapsed_sec' in row:
                    mins = float(row['elapsed_sec']) / 60
                else:
                    continue
                    
                races = int(row.get('unique_races', 0))
                elapsed_mins.append(mins)
                unique_races.append(races)
            except (ValueError, KeyError):
                continue
    
    return elapsed_mins, unique_races


def setup_paper_style():
    """设置论文级别的图表样式"""
    plt.rcParams.update({
        'font.family': 'serif',
        'font.size': 12,
        'axes.labelsize': 14,
        'axes.titlesize': 16,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'legend.fontsize': 11,
        'figure.figsize': (8, 5),
        'figure.dpi': 150,
        'savefig.dpi': 300,
        'savefig.bbox': 'tight',
        'axes.grid': True,
        'grid.alpha': 0.3,
        'lines.linewidth': 2,
        'lines.markersize': 4,
    })


def setup_default_style():
    """设置默认样式"""
    plt.rcParams.update({
        'font.size': 10,
        'figure.figsize': (10, 6),
        'figure.dpi': 100,
        'savefig.dpi': 150,
        'axes.grid': True,
        'grid.alpha': 0.3,
        'lines.linewidth': 1.5,
    })


def plot_single(elapsed_mins: List[float], unique_races: List[int], 
                output_path: str, title: str = "Race Pair Discovery Over Time",
                xlabel: str = "Time (minutes)", ylabel: str = "Unique Race Pairs"):
    """绘制单个时间序列"""
    fig, ax = plt.subplots()
    
    ax.plot(elapsed_mins, unique_races, 'b-', marker='o', markersize=3, 
            markevery=max(1, len(elapsed_mins) // 20))
    
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    
    # 确保 y 轴使用整数刻度
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    
    # 添加最终值标注
    if elapsed_mins and unique_races:
        final_x = elapsed_mins[-1]
        final_y = unique_races[-1]
        ax.annotate(f'{final_y}', xy=(final_x, final_y), 
                   xytext=(5, 5), textcoords='offset points',
                   fontsize=10, color='blue')
    
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Saved: {output_path}")


def plot_comparison(data_list: List[Tuple[List[float], List[int]]], 
                   labels: List[str], output_path: str,
                   title: str = "Race Pair Discovery Comparison",
                   xlabel: str = "Time (minutes)", ylabel: str = "Unique Race Pairs"):
    """绘制多个时间序列对比图"""
    fig, ax = plt.subplots()
    
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']
    markers = ['o', 's', '^', 'D', 'v', '<']
    
    for i, ((elapsed_mins, unique_races), label) in enumerate(zip(data_list, labels)):
        color = colors[i % len(colors)]
        marker = markers[i % len(markers)]
        
        ax.plot(elapsed_mins, unique_races, color=color, marker=marker,
                markersize=3, markevery=max(1, len(elapsed_mins) // 15),
                label=label)
    
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(loc='lower right')
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Saved: {output_path}")


def print_summary(elapsed_mins: List[float], unique_races: List[int], name: str = ""):
    """打印统计摘要"""
    if not elapsed_mins:
        print(f"{name}: No data")
        return
    
    prefix = f"{name}: " if name else ""
    print(f"{prefix}Duration: {elapsed_mins[-1]:.1f} minutes")
    print(f"{prefix}Total unique race pairs: {unique_races[-1]}")
    print(f"{prefix}Data points: {len(elapsed_mins)}")
    
    if len(elapsed_mins) >= 2:
        # 计算平均发现速率
        total_time = elapsed_mins[-1] - elapsed_mins[0]
        if total_time > 0:
            rate = unique_races[-1] / total_time
            print(f"{prefix}Average discovery rate: {rate:.2f} races/min")


def generate_ascii_chart(elapsed_mins: List[float], unique_races: List[int], 
                         width: int = 60, height: int = 15) -> str:
    """生成 ASCII 图表（无 matplotlib 时使用）"""
    if not elapsed_mins or not unique_races:
        return "No data to plot"
    
    max_y = max(unique_races)
    max_x = max(elapsed_mins)
    min_x = min(elapsed_mins)
    
    if max_y == 0:
        max_y = 1
    if max_x == min_x:
        max_x = min_x + 1
    
    # 创建画布
    canvas = [[' ' for _ in range(width)] for _ in range(height)]
    
    # 绘制数据点
    for x, y in zip(elapsed_mins, unique_races):
        col = int((x - min_x) / (max_x - min_x) * (width - 1))
        row = height - 1 - int(y / max_y * (height - 1))
        col = max(0, min(width - 1, col))
        row = max(0, min(height - 1, row))
        canvas[row][col] = '*'
    
    # 生成输出
    lines = []
    lines.append(f"Race Pairs vs Time (ASCII)")
    lines.append(f"{'=' * (width + 10)}")
    
    for i, row in enumerate(canvas):
        y_val = max_y * (height - 1 - i) / (height - 1)
        lines.append(f"{y_val:>7.0f} |{''.join(row)}|")
    
    lines.append(f"        +{'-' * width}+")
    lines.append(f"        {min_x:<{width//2}.1f}{max_x:>{width//2}.1f}")
    lines.append(f"        {'Time (minutes)':^{width}}")
    lines.append(f"\nFinal: {unique_races[-1]} unique race pairs at {elapsed_mins[-1]:.1f} min")
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Plot Race Pair time series for research papers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 基本用法
  python3 plot_races.py race_timeseries.csv
  
  # 指定输出格式和路径
  python3 plot_races.py race_timeseries.csv -o figure.pdf --format pdf
  
  # 论文样式
  python3 plot_races.py race_timeseries.csv --style paper -o fig.pdf
  
  # 对比多个实验
  python3 plot_races.py exp1/ts.csv exp2/ts.csv --labels "DDRD" "Vanilla"
"""
    )
    
    parser.add_argument('inputs', nargs='+', help='Input race_timeseries.csv file(s)')
    parser.add_argument('-o', '--output', help='Output file path (default: race_plot.png)')
    parser.add_argument('--format', choices=['png', 'pdf', 'svg'], default='png',
                       help='Output format (default: png)')
    parser.add_argument('--style', choices=['default', 'paper'], default='default',
                       help='Plot style (default: default)')
    parser.add_argument('--labels', nargs='*', help='Labels for each input file')
    parser.add_argument('--title', default='Race Pair Discovery Over Time',
                       help='Plot title')
    parser.add_argument('--no-plot', action='store_true',
                       help='Only print summary, do not generate plot')
    parser.add_argument('--ascii', action='store_true',
                       help='Generate ASCII chart (no matplotlib needed)')
    
    args = parser.parse_args()
    
    # 读取所有数据
    data_list = []
    for filepath in args.inputs:
        if not os.path.exists(filepath):
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        data = read_timeseries(filepath)
        data_list.append(data)
    
    # 准备标签
    if args.labels:
        labels = args.labels
    else:
        labels = [os.path.basename(os.path.dirname(f)) or f"Exp{i+1}" 
                  for i, f in enumerate(args.inputs)]
    
    # 打印摘要
    for (elapsed, races), label in zip(data_list, labels):
        print_summary(elapsed, races, label)
    print()
    
    if args.no_plot:
        return
    
    # ASCII 模式
    if args.ascii or not HAS_MATPLOTLIB:
        if not HAS_MATPLOTLIB:
            print("Note: matplotlib not installed, using ASCII chart\n")
        for (elapsed, races), label in zip(data_list, labels):
            print(f"\n=== {label} ===")
            print(generate_ascii_chart(elapsed, races))
        return
    
    # 设置样式
    if args.style == 'paper':
        setup_paper_style()
    else:
        setup_default_style()
    
    # 确定输出路径
    if args.output:
        output_path = args.output
    else:
        output_path = f"race_plot.{args.format}"
    
    # 确保输出路径有正确的扩展名
    if not output_path.endswith(f'.{args.format}'):
        output_path = f"{output_path}.{args.format}"
    
    # 绘图
    if len(data_list) == 1:
        elapsed, races = data_list[0]
        plot_single(elapsed, races, output_path, title=args.title)
    else:
        plot_comparison(data_list, labels, output_path, title=args.title)


if __name__ == '__main__':
    main()
