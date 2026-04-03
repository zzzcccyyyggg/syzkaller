#!/usr/bin/env python3
"""
绘制各模块 VarName Pair 总数 和 Pair 总数 随时间变化的双坐标轴图表。
从 exp/<module>/logs/ 下读取最新的日志文件，自动发现所有模块。

用法:
  python3 scripts/plot_pairs.py                    # 保存到 pairs_plot.png
  python3 scripts/plot_pairs.py -o result.png       # 指定输出文件
  python3 scripts/plot_pairs.py --show              # 直接显示不保存
  python3 scripts/plot_pairs.py -t btrfs xfs f2fs   # 只画指定模块
  python3 scripts/plot_pairs.py --summary            # 打印统计摘要
"""

import os
import re
import glob
from datetime import datetime
from collections import defaultdict
import argparse

try:
    import matplotlib
    matplotlib.use('Agg')  # 无头模式，可被 --show 覆盖
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
except ImportError:
    print("请先安装 matplotlib: pip install matplotlib")
    exit(1)

# 项目根目录 / exp 目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
EXP_DIR = os.path.join(PROJECT_ROOT, "exp")

# 日志正则：提取时间、uaf varnames、uaf pairs
LOG_PATTERN = re.compile(
    r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'  # 时间戳
    r'.*?uaf pairs=(\d+)'                       # uaf pairs (总数)
    r'.*?uaf varnames=(\d+)'                    # uaf varnames (总数)
)

# 备选：字段顺序可能不同 (varnames 在 pairs 前面)
LOG_PATTERN_ALT = re.compile(
    r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r'.*?uaf varnames=(\d+)'
    r'.*?uaf pairs=(\d+)'
)


def parse_log_file(log_path):
    """解析日志文件，提取 (时间, uaf_pairs, uaf_varnames) 三元组"""
    data = []
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # 尝试两种字段顺序
                m = LOG_PATTERN.search(line)
                if m:
                    ts = datetime.strptime(m.group(1), '%Y/%m/%d %H:%M:%S')
                    pairs = int(m.group(2))
                    varnames = int(m.group(3))
                    data.append((ts, pairs, varnames))
                    continue
                m = LOG_PATTERN_ALT.search(line)
                if m:
                    ts = datetime.strptime(m.group(1), '%Y/%m/%d %H:%M:%S')
                    varnames = int(m.group(2))
                    pairs = int(m.group(3))
                    data.append((ts, pairs, varnames))
    except Exception as e:
        print(f"读取 {log_path} 出错: {e}")
    return data


def resample_to_minutes(data):
    """按分钟重采样，每分钟取最后一个值"""
    if not data:
        return [], [], []
    data.sort(key=lambda x: x[0])
    minute_data = {}
    for ts, pairs, varnames in data:
        key = ts.replace(second=0, microsecond=0)
        minute_data[key] = (pairs, varnames)
    sorted_keys = sorted(minute_data.keys())
    times = sorted_keys
    pairs_vals = [minute_data[k][0] for k in sorted_keys]
    varnames_vals = [minute_data[k][1] for k in sorted_keys]
    return times, pairs_vals, varnames_vals


def find_latest_log(module_dir, random_mode=False):
    """在 module_dir/logs/ 下找到最新的 fuzz 日志。
    random_mode=True 时只匹配 exp-fuzz-random-*.log,
    False 时排除 random 日志。
    """
    log_dir = os.path.join(module_dir, "logs")
    if not os.path.isdir(log_dir):
        return None
    if random_mode:
        candidates = glob.glob(os.path.join(log_dir, "exp-fuzz-random-*.log"))
    else:
        # 匹配 fuzz 日志，排除 random
        candidates = [p for p in glob.glob(os.path.join(log_dir, "exp-fuzz*.log"))
                      if '-random-' not in os.path.basename(p)]
    if not candidates:
        return None
    # 按修改时间取最新
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def discover_modules(targets=None, random_mode=False):
    """发现 exp/ 下所有模块，返回 {name: latest_log_path}"""
    if not os.path.isdir(EXP_DIR):
        print(f"实验目录不存在: {EXP_DIR}")
        return {}
    modules = {}
    for entry in sorted(os.listdir(EXP_DIR)):
        mod_dir = os.path.join(EXP_DIR, entry)
        if not os.path.isdir(mod_dir):
            continue
        if targets and entry not in targets:
            continue
        log_path = find_latest_log(mod_dir, random_mode=random_mode)
        if log_path:
            modules[entry] = log_path
    return modules


def plot_pairs(output_file=None, targets=None, random_mode=False):
    """绘制双坐标轴图：上 = VarName 总数，下 = Pair 总数"""
    mode_label = " (random baseline)" if random_mode else ""
    modules = discover_modules(targets, random_mode=random_mode)
    if not modules:
        print("没有找到可用的日志文件")
        return

    print(f"找到 {len(modules)} 个模块:")
    for name, path in sorted(modules.items()):
        print(f"  {name}: {os.path.basename(path)}")
    print()

    # 解析
    all_data = {}
    for name, path in modules.items():
        print(f"解析 {name} ...")
        raw = parse_log_file(path)
        if not raw:
            print(f"  无有效数据")
            continue
        times, pairs, varnames = resample_to_minutes(raw)
        if times:
            all_data[name] = (times, pairs, varnames)
            hrs = (times[-1] - times[0]).total_seconds() / 3600
            print(f"  {len(times)} 个数据点, {hrs:.1f}h, "
                  f"pairs {pairs[0]}->{pairs[-1]}, varnames {varnames[0]}->{varnames[-1]}")
        else:
            print(f"  无有效数据")

    if not all_data:
        print("\n没有可绘制的数据")
        return

    # --- 为每个模块单独画图，保存到对应 workdir ---
    for name, (times, pairs, varnames) in sorted(all_data.items()):
        workdir_name = "workdir-random" if random_mode else "workdir"
        plot_filename = "pairs_plot_random.png" if random_mode else "pairs_plot.png"
        mod_workdir = os.path.join(EXP_DIR, name, workdir_name)
        # 若 workdir 不存在或无写权限, 回退到 logs/ 目录
        try:
            if not os.path.isdir(mod_workdir):
                os.makedirs(mod_workdir, exist_ok=True)
            # 写权限测试
            if not os.access(mod_workdir, os.W_OK):
                raise PermissionError
            save_dir = mod_workdir
        except (PermissionError, OSError):
            save_dir = os.path.join(EXP_DIR, name, "logs")
        per_fig, (per_top, per_bot) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)

        per_top.plot(times, varnames, color='tab:blue', linewidth=1.5)
        per_top.set_ylabel('VarName Pair Count', fontsize=12)
        per_top.set_title(f'{name}{mode_label} — VarName Pair Count Over Time', fontsize=13)
        per_top.grid(True, linestyle='--', alpha=0.7)

        per_bot.plot(times, pairs, color='tab:orange', linewidth=1.5)
        per_bot.set_xlabel('Time', fontsize=12)
        per_bot.set_ylabel('Pair Count', fontsize=12)
        per_bot.set_title(f'{name}{mode_label} — Pair Count Over Time', fontsize=13)
        per_bot.grid(True, linestyle='--', alpha=0.7)

        per_bot.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        per_bot.xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.setp(per_bot.xaxis.get_majorticklabels(), rotation=45, ha='right')
        per_fig.tight_layout()

        per_path = os.path.join(save_dir, plot_filename)
        per_fig.savefig(per_path, dpi=150, bbox_inches='tight')
        plt.close(per_fig)
        print(f"  [{name}] 单独图表 -> {per_path}")

    # --- 总图：所有模块叠加 ---
    colors = plt.cm.tab10.colors
    sorted_names = sorted(all_data.keys())

    fig, (ax_top, ax_bot) = plt.subplots(2, 1, figsize=(16, 10), sharex=True)

    for idx, name in enumerate(sorted_names):
        times, pairs, varnames = all_data[name]
        color = colors[idx % len(colors)]
        ax_top.plot(times, varnames, label=name, color=color, linewidth=1.5)
        ax_bot.plot(times, pairs, label=name, color=color, linewidth=1.5)

    # 上图: VarName Pair 总数
    ax_top.set_ylabel('VarName Pair Count', fontsize=12)
    ax_top.set_title(f'VarName Pair Count Over Time{mode_label}', fontsize=14)
    ax_top.legend(loc='upper left', fontsize=9, ncol=2)
    ax_top.grid(True, linestyle='--', alpha=0.7)
    ax_top.grid(True, which='minor', linestyle=':', alpha=0.4)

    # 下图: Pair 总数
    ax_bot.set_xlabel('Time', fontsize=12)
    ax_bot.set_ylabel('Pair Count', fontsize=12)
    ax_bot.set_title(f'Pair Count Over Time{mode_label}', fontsize=14)
    ax_bot.legend(loc='upper left', fontsize=9, ncol=2)
    ax_bot.grid(True, linestyle='--', alpha=0.7)
    ax_bot.grid(True, which='minor', linestyle=':', alpha=0.4)

    # X 轴格式
    ax_bot.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
    ax_bot.xaxis.set_major_locator(mdates.HourLocator(interval=2))
    ax_bot.xaxis.set_minor_locator(mdates.HourLocator(interval=1))
    plt.setp(ax_bot.xaxis.get_majorticklabels(), rotation=45, ha='right')

    plt.tight_layout()

    if output_file:
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"\n总图表已保存到: {output_file}")
    else:
        plt.show()
    plt.close()


def _to_elapsed_hours(times):
    """将绝对时间列表转为从 0 开始的经过小时数"""
    if not times:
        return []
    t0 = times[0]
    return [(t - t0).total_seconds() / 3600 for t in times]


def _writable_dir(path):
    """返回 path 若可写，否则返回 None"""
    try:
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
        if os.access(path, os.W_OK):
            return path
    except (PermissionError, OSError):
        pass
    return None


def plot_compare(output_file=None, targets=None):
    """绘制 normal vs random 对比图"""
    normal_modules = discover_modules(targets, random_mode=False)
    random_modules = discover_modules(targets, random_mode=True)

    # 只取两边都有的模块
    common = sorted(set(normal_modules) & set(random_modules))
    if not common:
        print("没有同时拥有 normal 和 random 日志的模块")
        return

    print(f"对比模块 ({len(common)}):")
    for name in common:
        print(f"  {name}:")
        print(f"    normal: {os.path.basename(normal_modules[name])}")
        print(f"    random: {os.path.basename(random_modules[name])}")
    print()

    # 解析
    normal_data = {}  # name -> (times, pairs, varnames)
    random_data = {}
    for name in common:
        # normal
        raw = parse_log_file(normal_modules[name])
        if raw:
            t, p, v = resample_to_minutes(raw)
            if t:
                normal_data[name] = (t, p, v)
        # random
        raw = parse_log_file(random_modules[name])
        if raw:
            t, p, v = resample_to_minutes(raw)
            if t:
                random_data[name] = (t, p, v)

    both = sorted(set(normal_data) & set(random_data))
    if not both:
        print("没有同时拥有有效数据的模块")
        return

    # --- 每个模块的对比图 ---
    for name in both:
        nt, np_, nv = normal_data[name]
        rt, rp, rv = random_data[name]
        nh = _to_elapsed_hours(nt)
        rh = _to_elapsed_hours(rt)

        fig, (ax_top, ax_bot) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)

        # VarName
        ax_top.plot(nh, nv, color='tab:blue', linewidth=1.5, label='DDRD (normal)')
        ax_top.plot(rh, rv, color='tab:red', linewidth=1.5, linestyle='--', label='Random baseline')
        ax_top.set_ylabel('VarName Pair Count', fontsize=12)
        ax_top.set_title(f'{name} — VarName Pair Count: Normal vs Random', fontsize=13)
        ax_top.legend(fontsize=10)
        ax_top.grid(True, linestyle='--', alpha=0.7)

        # Pairs
        ax_bot.plot(nh, np_, color='tab:blue', linewidth=1.5, label='DDRD (normal)')
        ax_bot.plot(rh, rp, color='tab:red', linewidth=1.5, linestyle='--', label='Random baseline')
        ax_bot.set_xlabel('Elapsed Time (hours)', fontsize=12)
        ax_bot.set_ylabel('Pair Count', fontsize=12)
        ax_bot.set_title(f'{name} — Pair Count: Normal vs Random', fontsize=13)
        ax_bot.legend(fontsize=10)
        ax_bot.grid(True, linestyle='--', alpha=0.7)

        fig.tight_layout()

        # 保存位置: workdir > logs
        save_dir = _writable_dir(os.path.join(EXP_DIR, name, "workdir")) or \
                   os.path.join(EXP_DIR, name, "logs")
        per_path = os.path.join(save_dir, "pairs_compare.png")
        fig.savefig(per_path, dpi=150, bbox_inches='tight')
        plt.close(fig)

        n_hrs = nh[-1] if nh else 0
        r_hrs = rh[-1] if rh else 0
        print(f"  [{name}] normal {n_hrs:.1f}h pairs={np_[-1]} varnames={nv[-1]}  |  "
              f"random {r_hrs:.1f}h pairs={rp[-1]} varnames={rv[-1]}")
        print(f"    -> {per_path}")

    # --- 总对比图: 每模块一行, 左=VarName 右=Pairs ---
    n_mods = len(both)
    fig, axes = plt.subplots(n_mods, 2, figsize=(18, 4 * n_mods), squeeze=False)

    for row, name in enumerate(both):
        nt, np_, nv = normal_data[name]
        rt, rp, rv = random_data[name]
        nh = _to_elapsed_hours(nt)
        rh = _to_elapsed_hours(rt)

        ax_v, ax_p = axes[row]

        # VarName
        ax_v.plot(nh, nv, color='tab:blue', linewidth=1.2, label='DDRD')
        ax_v.plot(rh, rv, color='tab:red', linewidth=1.2, linestyle='--', label='Random')
        ax_v.set_ylabel('VarName', fontsize=9)
        ax_v.set_title(f'{name} — VarName', fontsize=11)
        ax_v.legend(fontsize=8, loc='upper left')
        ax_v.grid(True, linestyle='--', alpha=0.5)

        # Pairs
        ax_p.plot(nh, np_, color='tab:blue', linewidth=1.2, label='DDRD')
        ax_p.plot(rh, rp, color='tab:red', linewidth=1.2, linestyle='--', label='Random')
        ax_p.set_ylabel('Pairs', fontsize=9)
        ax_p.set_title(f'{name} — Pairs', fontsize=11)
        ax_p.legend(fontsize=8, loc='upper left')
        ax_p.grid(True, linestyle='--', alpha=0.5)

        if row == n_mods - 1:
            ax_v.set_xlabel('Elapsed Time (hours)', fontsize=10)
            ax_p.set_xlabel('Elapsed Time (hours)', fontsize=10)

    fig.suptitle('DDRD vs Random Baseline — All Modules', fontsize=15, y=1.0)
    fig.tight_layout()

    if output_file:
        fig.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"\n对比总图已保存到: {output_file}")
    else:
        plt.show()
    plt.close(fig)

    # --- 汇总柱状图: 最终 pairs/varnames ---
    bar_names = both
    n_pairs_final = [normal_data[n][1][-1] for n in bar_names]
    r_pairs_final = [random_data[n][1][-1] for n in bar_names]
    n_vars_final  = [normal_data[n][2][-1] for n in bar_names]
    r_vars_final  = [random_data[n][2][-1] for n in bar_names]

    import numpy as np_arr
    x = np_arr.arange(len(bar_names))
    w = 0.35

    fig2, (bx_v, bx_p) = plt.subplots(1, 2, figsize=(16, 6))

    bx_v.bar(x - w/2, n_vars_final, w, label='DDRD', color='tab:blue', alpha=0.8)
    bx_v.bar(x + w/2, r_vars_final, w, label='Random', color='tab:red', alpha=0.8)
    bx_v.set_xticks(x)
    bx_v.set_xticklabels(bar_names, rotation=45, ha='right', fontsize=9)
    bx_v.set_ylabel('VarName Pair Count')
    bx_v.set_title('Final VarName Count: DDRD vs Random')
    bx_v.legend()
    bx_v.grid(axis='y', linestyle='--', alpha=0.5)

    bx_p.bar(x - w/2, n_pairs_final, w, label='DDRD', color='tab:blue', alpha=0.8)
    bx_p.bar(x + w/2, r_pairs_final, w, label='Random', color='tab:red', alpha=0.8)
    bx_p.set_xticks(x)
    bx_p.set_xticklabels(bar_names, rotation=45, ha='right', fontsize=9)
    bx_p.set_ylabel('Pair Count')
    bx_p.set_title('Final Pair Count: DDRD vs Random')
    bx_p.legend()
    bx_p.grid(axis='y', linestyle='--', alpha=0.5)

    fig2.tight_layout()
    bar_file = output_file.replace('.png', '_bar.png') if output_file else None
    if bar_file:
        fig2.savefig(bar_file, dpi=150, bbox_inches='tight')
        print(f"对比柱状图已保存到: {bar_file}")
    else:
        plt.show()
    plt.close(fig2)


def print_summary(targets=None, random_mode=False):
    """打印统计摘要"""
    modules = discover_modules(targets, random_mode=random_mode)
    print("\n" + "=" * 72)
    print("VarName / Pair 统计摘要")
    print("=" * 72)

    for name, path in sorted(modules.items()):
        raw = parse_log_file(path)
        if not raw:
            continue
        times, pairs, varnames = resample_to_minutes(raw)
        if not times:
            continue
        hrs = (times[-1] - times[0]).total_seconds() / 3600
        p_growth = pairs[-1] - pairs[0]
        v_growth = varnames[-1] - varnames[0]
        p_rate = p_growth / hrs if hrs > 0 else 0
        v_rate = v_growth / hrs if hrs > 0 else 0

        print(f"\n{name}:")
        print(f"  日志文件  : {os.path.basename(path)}")
        print(f"  时间范围  : {times[0]} ~ {times[-1]}")
        print(f"  运行时长  : {hrs:.2f} h")
        print(f"  数据点数  : {len(times)}")
        print(f"  Pairs     : {pairs[0]} -> {pairs[-1]}  (Δ{p_growth}, {p_rate:.1f}/h)")
        print(f"  VarNames  : {varnames[0]} -> {varnames[-1]}  (Δ{v_growth}, {v_rate:.1f}/h)")

    print("\n" + "=" * 72)


def main():
    parser = argparse.ArgumentParser(
        description='绘制各模块 VarName Pair 总数和 Pair 总数随时间变化图')
    parser.add_argument('-o', '--output', default=None,
                        help='输出图片文件名 (默认: pairs_plot.png 或 pairs_plot_random.png)')
    parser.add_argument('-t', '--targets', nargs='+',
                        help='指定模块 (如: btrfs xfs f2fs)')
    parser.add_argument('--random', action='store_true',
                        help='绘制 random baseline 日志 (exp-fuzz-random-*.log)')
    parser.add_argument('--compare', action='store_true',
                        help='绘制 normal vs random 对比图')
    parser.add_argument('--show', action='store_true',
                        help='显示图表而不保存')
    parser.add_argument('--summary', action='store_true',
                        help='打印统计摘要')
    parser.add_argument('--list', action='store_true',
                        help='列出所有可用模块')

    args = parser.parse_args()

    if args.show:
        matplotlib.use('TkAgg')
        import importlib
        importlib.reload(plt)

    if args.list:
        modules = discover_modules(random_mode=args.random)
        label = " (random baseline)" if args.random else ""
        print(f"可用模块{label}:")
        for name in sorted(modules.keys()):
            print(f"  {name}")
        return

    if args.summary:
        print_summary(args.targets, random_mode=args.random)
        if not args.compare:
            return

    if args.compare:
        if args.show:
            cmp_out = None
        elif args.output:
            cmp_out = args.output
        else:
            cmp_out = 'pairs_compare.png'
        plot_compare(output_file=cmp_out, targets=args.targets)
        return

    if args.show:
        output_file = None
    elif args.output:
        output_file = args.output
    else:
        output_file = 'pairs_plot_random.png' if args.random else 'pairs_plot.png'
    plot_pairs(output_file=output_file, targets=args.targets, random_mode=args.random)


if __name__ == '__main__':
    main()
