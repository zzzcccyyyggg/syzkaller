#!/usr/bin/env python3
"""
统计并绘制 UAF pairs 随时间变化的图表
从 logs 目录读取各目标的日志文件，提取 uaf pairs 数据，绘制 24 小时变化曲线
"""

import os
import re
import glob
from datetime import datetime, timedelta
from collections import defaultdict
import argparse

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
except ImportError:
    print("请先安装 matplotlib: pip install matplotlib")
    exit(1)

# 日志目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")

# 日志行正则表达式
# 格式: 2025/12/29 16:45:11 candidates=0 corpus=938 coverage=35857 exec total=21144 (58/min) pending=0 reproducing=0 uaf corpus=3829 uaf coverage=27568 uaf pairs=223032
LOG_PATTERN = re.compile(
    r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*uaf pairs=(\d+)'
)


def parse_log_file(log_path):
    """解析单个日志文件，提取时间和 uaf pairs 数据"""
    data = []
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = LOG_PATTERN.search(line)
                if match:
                    time_str = match.group(1)
                    uaf_pairs = int(match.group(2))
                    try:
                        timestamp = datetime.strptime(time_str, '%Y/%m/%d %H:%M:%S')
                        data.append((timestamp, uaf_pairs))
                    except ValueError:
                        continue
    except Exception as e:
        print(f"读取 {log_path} 时出错: {e}")
    
    return data


def resample_to_minutes(data, interval_minutes=1):
    """将数据重采样为每 N 分钟一个点"""
    if not data:
        return [], []
    
    # 按时间排序
    data.sort(key=lambda x: x[0])
    
    # 按分钟分组，取每分钟最后一个值
    minute_data = {}
    for timestamp, value in data:
        # 截断到分钟
        minute_key = timestamp.replace(second=0, microsecond=0)
        minute_data[minute_key] = value
    
    # 排序并返回
    sorted_times = sorted(minute_data.keys())
    times = []
    values = []
    
    for t in sorted_times:
        times.append(t)
        values.append(minute_data[t])
    
    return times, values


def get_all_logs():
    """获取所有日志文件"""
    log_files = glob.glob(os.path.join(LOG_DIR, "*.log"))
    logs = {}
    
    for log_path in log_files:
        basename = os.path.basename(log_path)
        target_name = os.path.splitext(basename)[0]
        logs[target_name] = log_path
    
    return logs


def plot_uaf_pairs(output_file=None, targets=None, last_hours=24):
    """绘制 UAF pairs 随时间变化图"""
    logs = get_all_logs()
    
    if not logs:
        print(f"在 {LOG_DIR} 中没有找到日志文件")
        return
    
    # 筛选目标
    if targets:
        logs = {k: v for k, v in logs.items() if k in targets}
    
    if not logs:
        print("没有找到指定的目标日志")
        return
    
    print(f"找到 {len(logs)} 个日志文件:")
    for name in sorted(logs.keys()):
        print(f"  - {name}")
    print()
    
    # 解析所有日志
    all_data = {}
    for target_name, log_path in logs.items():
        print(f"解析 {target_name}...")
        data = parse_log_file(log_path)
        if data:
            times, values = resample_to_minutes(data)
            if times:
                all_data[target_name] = (times, values)
                print(f"  找到 {len(times)} 个数据点, 时间范围: {times[0]} ~ {times[-1]}")
                print(f"  UAF pairs 范围: {min(values)} ~ {max(values)}")
            else:
                print(f"  没有有效数据")
        else:
            print(f"  没有找到 uaf pairs 数据")
    
    if not all_data:
        print("\n没有可绘制的数据")
        return
    
    # 创建图表
    fig, ax = plt.subplots(figsize=(16, 8))
    
    # 定义颜色
    colors = plt.cm.tab10.colors
    
    # 绘制每个目标的曲线
    for idx, (target_name, (times, values)) in enumerate(sorted(all_data.items())):
        color = colors[idx % len(colors)]
        ax.plot(times, values, label=target_name, color=color, linewidth=1.5, marker='', markersize=2)
    
    # 设置图表属性
    ax.set_xlabel('Time', fontsize=12)
    ax.set_ylabel('UAF Pairs Count', fontsize=12)
    ax.set_title('UAF Pairs Over Time (Sampled per Minute)', fontsize=14)
    
    # 设置 x 轴格式
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=2))
    ax.xaxis.set_minor_locator(mdates.HourLocator(interval=1))
    
    # 旋转 x 轴标签
    plt.xticks(rotation=45, ha='right')
    
    # 添加网格
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.grid(True, which='minor', linestyle=':', alpha=0.4)
    
    # 添加图例
    ax.legend(loc='upper left', fontsize=10)
    
    # 调整布局
    plt.tight_layout()
    
    # 保存或显示
    if output_file:
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"\n图表已保存到: {output_file}")
    else:
        plt.show()
    
    plt.close()


def print_summary(targets=None):
    """打印统计摘要"""
    logs = get_all_logs()
    
    if targets:
        logs = {k: v for k, v in logs.items() if k in targets}
    
    print("\n" + "=" * 70)
    print("UAF Pairs 统计摘要")
    print("=" * 70)
    
    for target_name, log_path in sorted(logs.items()):
        data = parse_log_file(log_path)
        if data:
            times, values = resample_to_minutes(data)
            if times:
                duration = times[-1] - times[0]
                hours = duration.total_seconds() / 3600
                growth = values[-1] - values[0] if len(values) > 1 else 0
                growth_rate = growth / hours if hours > 0 else 0
                
                print(f"\n{target_name}:")
                print(f"  时间范围: {times[0]} ~ {times[-1]}")
                print(f"  运行时长: {hours:.2f} 小时")
                print(f"  数据点数: {len(times)}")
                print(f"  UAF Pairs: {values[0]} -> {values[-1]} (增长: {growth})")
                print(f"  平均增长率: {growth_rate:.1f} pairs/小时")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description='统计并绘制 UAF pairs 随时间变化的图表')
    parser.add_argument('-o', '--output', type=str, default='uaf_pairs_plot.png',
                        help='输出图片文件名 (默认: uaf_pairs_plot.png)')
    parser.add_argument('-t', '--targets', type=str, nargs='+',
                        help='指定要统计的目标 (如: btrfs xfs f2fs)')
    parser.add_argument('--hours', type=int, default=24,
                        help='显示最近多少小时的数据 (默认: 24)')
    parser.add_argument('--summary', action='store_true',
                        help='打印统计摘要')
    parser.add_argument('--show', action='store_true',
                        help='显示图表而不保存')
    parser.add_argument('--list', action='store_true',
                        help='列出所有可用的日志文件')
    
    args = parser.parse_args()
    
    if args.list:
        logs = get_all_logs()
        print("可用的日志文件:")
        for name in sorted(logs.keys()):
            print(f"  - {name}")
        return
    
    if args.summary:
        print_summary(args.targets)
    
    output_file = None if args.show else args.output
    plot_uaf_pairs(output_file=output_file, targets=args.targets, last_hours=args.hours)


if __name__ == '__main__':
    main()
