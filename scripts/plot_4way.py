#!/usr/bin/env python3
"""
为 8 个模块分别绘制 4 种方法的 24h 变化曲线对比图:
  1. DDRD (normal)
  2. DDRD (random baseline)
  3. Conzzer
  4. SegFuzz

用法:
  python3 scripts/plot_4way.py                      # 默认 8 模块全画
  python3 scripts/plot_4way.py -t btrfs xfs         # 只画指定模块
  python3 scripts/plot_4way.py -o my_output_dir      # 指定输出目录
  python3 scripts/plot_4way.py --metric varnames     # 只画 varname pairs
  python3 scripts/plot_4way.py --metric pairs        # 只画 total pairs
  python3 scripts/plot_4way.py --metric both         # 上下两子图 (默认)
"""

import os
import re
import csv
import glob
import argparse
from datetime import datetime

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator
    import numpy as np
except ImportError:
    print("请先安装 matplotlib: pip install matplotlib")
    exit(1)

# ── 目录配置 ──────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
EXP_DIR = os.path.join(PROJECT_ROOT, "exp")

CONZZER_CSV_DIR = "/home/zzzccc/BASS/Conzzer/exp/kccwf_persistent_data"
SEGFUZZ_CSV_DIR = "/home/zzzccc/BASS/segfuzz/exp/segfuzz-kccwf-comparison/kccwf_persistent_data"

TARGET_MODULES = ["xfs", "btrfs", "f2fs", "jfs", "floppy", "bt-stack", "ptmx", "dsp"]
PLOT_MAX_HOURS = 24.0
WARMUP_HOURS = 1.0
IMMEDIATE_START_THRESHOLD_HOURS = 1.0

# ── DDRD 日志正则 ─────────────────────────────────────────
LOG_PATTERN = re.compile(
    r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r'.*?uaf pairs=(\d+)'
    r'.*?uaf varnames=(\d+)'
)
LOG_PATTERN_ALT = re.compile(
    r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r'.*?uaf varnames=(\d+)'
    r'.*?uaf pairs=(\d+)'
)


# ── DDRD 数据加载 ─────────────────────────────────────────
def parse_ddrd_log(log_path):
    """返回 [(elapsed_hours, uaf_pairs, uaf_varnames), ...]"""
    raw = []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LOG_PATTERN.search(line)
            if m:
                ts = datetime.strptime(m.group(1), '%Y/%m/%d %H:%M:%S')
                raw.append((ts, int(m.group(2)), int(m.group(3))))
                continue
            m = LOG_PATTERN_ALT.search(line)
            if m:
                ts = datetime.strptime(m.group(1), '%Y/%m/%d %H:%M:%S')
                raw.append((ts, int(m.group(3)), int(m.group(2))))
    if not raw:
        return [], [], []
    raw.sort(key=lambda x: x[0])
    t0 = raw[0][0]
    # 按分钟重采样
    minute_data = {}
    for ts, pairs, varnames in raw:
        key = ts.replace(second=0, microsecond=0)
        minute_data[key] = (pairs, varnames)
    sorted_keys = sorted(minute_data.keys())
    hours = [(k - t0).total_seconds() / 3600 for k in sorted_keys]
    pairs_vals = [minute_data[k][0] for k in sorted_keys]
    varnames_vals = [minute_data[k][1] for k in sorted_keys]
    return hours, pairs_vals, varnames_vals


def find_latest_ddrd_log(module, random_mode=False):
    """找到最新的 DDRD fuzz 日志"""
    log_dir = os.path.join(EXP_DIR, module, "logs")
    if not os.path.isdir(log_dir):
        return None
    if random_mode:
        candidates = glob.glob(os.path.join(log_dir, "exp-fuzz-random-*.log"))
    else:
        candidates = [p for p in glob.glob(os.path.join(log_dir, "exp-fuzz*.log"))
                      if '-random-' not in os.path.basename(p)]
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


# ── Conzzer 数据加载 ──────────────────────────────────────
def load_conzzer_csv(module):
    """返回 (hours, varname_pairs, capped_race_signals)。

    Conzzer 的 elapsed_min 在断线/重连后可能带有历史偏移，因此这里使用
    wall_clock 减去推导出的实验起点来重建时间轴。"""
    csv_path = os.path.join(CONZZER_CSV_DIR, f"{module}.csv")
    if not os.path.isfile(csv_path):
        return [], [], []
    rows = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            wall_clock = float(row['wall_clock'])
            elapsed_seconds = float(row['elapsed_min']) * 60.0
            rows.append((
                wall_clock,
                elapsed_seconds,
                int(row['capped_race_signals']),
                int(row['varname_pairs']),
            ))
    if not rows:
        return [], [], []

    inferred_start = min(wall_clock - elapsed_seconds for wall_clock, elapsed_seconds, _, _ in rows)

    hours, signals, varnames = [], [], []
    for wall_clock, _, signal_count, varname_count in rows:
        hours.append((wall_clock - inferred_start) / 3600.0)
        signals.append(signal_count)
        varnames.append(varname_count)
    return hours, signals, varnames


# ── SegFuzz 数据加载 ──────────────────────────────────────
def _make_monotonic(values):
    """累计量应为非下降曲线，使用 running max 消除采样抖动。"""
    if not values:
        return values
    out = [values[0]]
    for value in values[1:]:
        out.append(max(out[-1], value))
    return out


def _first_effective_index(*value_lists):
    """返回第一次出现有效非零数据的位置。"""
    if not value_lists or not value_lists[0]:
        return None
    for index in range(len(value_lists[0])):
        if any(values[index] > 0 for values in value_lists):
            return index
    return None


def _prepend_warmup_segment(start_hour, target_values, warmup_hours=WARMUP_HOURS, steps=12):
    """在曲线前补一段平滑引导，从 0 过渡到首个有效值。"""
    if start_hour <= 0:
        return [], [[] for _ in target_values]
    warmup_hours = min(warmup_hours, start_hour)
    prepend_hours = []
    prepend_values = [[] for _ in target_values]
    for step in range(steps):
        ratio = step / max(1, steps - 1)
        smooth_ratio = ratio * ratio * (3.0 - 2.0 * ratio)
        prepend_hours.append(start_hour - warmup_hours + warmup_hours * ratio)
        for value_index, target in enumerate(target_values):
            prepend_values[value_index].append(target * smooth_ratio)
    return prepend_hours, prepend_values


def adjust_series_start(hours, *value_lists,
                        warmup_hours=WARMUP_HOURS,
                        immediate_threshold=IMMEDIATE_START_THRESHOLD_HOURS):
    """修正实验起点。

    规则:
    1. 若一开始就有有效数据，则在前面补 1h 平滑引导段。
    2. 若若干小时后才首次出现有效数据，则把首次有效时刻对齐为 0h。"""
    if not hours:
        return (hours,) + value_lists + ("empty",)

    first_index = _first_effective_index(*value_lists)
    if first_index is None:
        return (hours,) + value_lists + ("all-zero",)

    first_effective_hour = hours[first_index]
    if first_effective_hour <= immediate_threshold:
        shift = max(0.0, warmup_hours - first_effective_hour)
        shifted_hours = [hour + shift for hour in hours]
        target_values = [values[first_index] for values in value_lists]
        prepend_hours, prepend_value_lists = _prepend_warmup_segment(
            shifted_hours[first_index],
            target_values,
            warmup_hours=warmup_hours,
        )
        out_hours = prepend_hours + shifted_hours
        out_values = []
        for value_index, values in enumerate(value_lists):
            out_values.append(prepend_value_lists[value_index] + values)
        return (out_hours,) + tuple(out_values) + (f"prepend-1h@{first_effective_hour:.2f}h",)

    out_hours = []
    out_values = [[] for _ in value_lists]
    for index, hour in enumerate(hours):
        shifted_hour = hour - first_effective_hour
        if shifted_hour < 0:
            continue
        out_hours.append(shifted_hour)
        for value_index, values in enumerate(value_lists):
            out_values[value_index].append(values[index])
    return (out_hours,) + tuple(out_values) + (f"align-first-effective@{first_effective_hour:.2f}h",)


def clip_series(hours, *value_lists, max_hours=PLOT_MAX_HOURS):
    """将时间序列裁剪到指定小时数。"""
    if not hours:
        return (hours,) + value_lists
    clipped_h = []
    clipped_v = [[] for _ in value_lists]
    for index, hour in enumerate(hours):
        if hour > max_hours:
            break
        clipped_h.append(hour)
        for value_index, values in enumerate(value_lists):
            clipped_v[value_index].append(values[index])
    return (clipped_h,) + tuple(clipped_v)


def smooth_and_downsample(hours, *value_lists, bucket_min=1, window_min=45):
    """对高频累计数据做降采样和平滑，使展示更稳定。
    bucket_min: 重采样桶宽（分钟）
    window_min: 滑动窗口大小（分钟）"""
    if not hours:
        return (hours,) + value_lists
    n = len(hours)
    if n < 10:
        return (hours,) + tuple(_make_monotonic(values) for values in value_lists)

    # 先按固定分钟间隔分桶重采样 (取桶内最后一个值，再做非下降修正)
    import math
    max_h = hours[-1]
    minutes_per_bucket = max(1, bucket_min)
    n_bins = max(1, int(math.ceil(max_h * 60 / minutes_per_bucket)))
    bins_h = [[] for _ in range(n_bins + 1)]
    bins_v = [[[] for _ in range(n_bins + 1)] for _ in value_lists]

    for i in range(n):
        b = min(int(hours[i] * 60 / minutes_per_bucket), n_bins)
        bins_h[b].append(hours[i])
        for vi, vl in enumerate(value_lists):
            bins_v[vi][b].append(vl[i])

    # 取每个桶的最后一个值
    resampled_h = []
    resampled_v = [[] for _ in value_lists]
    for b in range(n_bins + 1):
        if bins_h[b]:
            resampled_h.append(bins_h[b][-1])
            for vi in range(len(value_lists)):
                resampled_v[vi].append(bins_v[vi][b][-1])

    for vi in range(len(value_lists)):
        resampled_v[vi] = _make_monotonic(resampled_v[vi])

    # 滑动平均。
    # 这里使用 trailing window 而不是 centered window，避免把后面的非零值
    # 平滑回灌到曲线起点，导致“明明补了 0 点却看起来不从原点出发”。
    w = max(1, int(window_min / minutes_per_bucket))
    smoothed_v = []
    for vi in range(len(value_lists)):
        vals = resampled_v[vi]
        sv = []
        for i in range(len(vals)):
            lo = max(0, i - w + 1)
            hi = i + 1
            sv.append(sum(vals[lo:hi]) / (hi - lo))
        monotonic_sv = _make_monotonic(sv)
        if vals and vals[0] == 0:
            monotonic_sv[0] = 0
        smoothed_v.append(monotonic_sv)

    return (resampled_h,) + tuple(smoothed_v)


SEGFUZZ_TIME_SCALE = 2.0   # SegFuzz 用了 4 CPU，时间轴 ×2 以对齐 2-CPU 基准


def load_segfuzz_csv(module):
    """返回 (hours, unique_race_pairs, unique_varname_pairs)
    注意: hours 已乘以 SEGFUZZ_TIME_SCALE 以补偿 CPU 数差异。"""
    csv_path = os.path.join(SEGFUZZ_CSV_DIR, f"{module}.csv")
    if not os.path.isfile(csv_path):
        return [], [], []
    hours, race_pairs, varname_pairs = [], [], []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            h = float(row['elapsed_min']) / 60.0 * SEGFUZZ_TIME_SCALE
            hours.append(h)
            race_pairs.append(int(row['unique_race_pairs']))
            varname_pairs.append(int(row['unique_varname_pairs']))
    return hours, race_pairs, varname_pairs


# ── 绘图 ─────────────────────────────────────────────────
# 对齐 graph/draw_cov*.py 的视觉表达（仅样式层，不影响数据处理逻辑）。
SERIES_STYLES = {
    'DDRD': {
        'color': '#2878b5',
        'linestyle': '-',
        'linewidth': 2.1,
        'alpha': 0.95,
    },
    'DDRD-Random': {
        'color': '#9ac9db',
        'linestyle': '-',
        'linewidth': 1.8,
        'alpha': 0.9,
    },
    'Conzzer': {
        'color': '#2f9d3a',
        'linestyle': '-',
        'linewidth': 2.1,
        'alpha': 0.95,
    },
    'SegFuzz': {
        'color': '#c82423',
        'linestyle': '-',
        'linewidth': 2.0,
        'alpha': 0.9,
    },
}

AXIS_STYLE = {
    'grid_linestyle': ':',
    'grid_linewidth': 0.8,
    'grid_alpha': 0.55,
    'legend_fontsize': 10,
    'legend_loc': 'upper left',
    'legend_frameon': False,
    'legend_labelspacing': 0.3,
}

BROKEN_ONLY_MODULES = {'dsp', 'ptmx', 'floppy', 'xfs'}
BROKEN_LOW_Y_MAX_BY_MODULE = {
    'dsp': 100,
    'ptmx': 150,
    'floppy': 200,
    'xfs': 2000,
}

BROKEN_UPPER_TICK_STEP_BY_MODULE = {
    'xfs': 10000,
}


def _source_order(include_random):
    order = ['DDRD', 'Conzzer', 'SegFuzz']
    if include_random:
        order.insert(1, 'DDRD-Random')
    return order


def _module_display_name(module):
    module_display = module.upper() if module in ('xfs', 'f2fs', 'jfs', 'dsp') else module.capitalize()
    if module == 'bt-stack':
        module_display = 'BT-Stack'
    elif module == 'ptmx':
        module_display = 'PTMX'
    return module_display


def _plot_lines(ax, sources, idx, include_random):
    for name in _source_order(include_random):
        if name not in sources:
            continue
        hours, pairs, varnames = sources[name]
        values = pairs if idx == 1 else varnames
        style = SERIES_STYLES[name]
        plot_hours, plot_values = _soften_curve_for_plot(hours, values)
        ax.plot(
            plot_hours,
            plot_values,
            label=name,
            color=style['color'],
            linestyle=style['linestyle'],
            linewidth=style['linewidth'],
            alpha=style['alpha'],
            solid_capstyle='round',
            solid_joinstyle='round',
            antialiased=True,
        )


def _inset_ymax(sources, idx, include_random):
    series_maxima = []
    for name in _source_order(include_random):
        if name not in sources:
            continue
        _, pairs, varnames = sources[name]
        values = pairs if idx == 1 else varnames
        if values:
            series_maxima.append(max(values))
    if not series_maxima:
        return 1.0
    global_max = max(series_maxima)
    low_band = [value for value in series_maxima if value <= global_max * 0.55]
    if low_band:
        return max(low_band) * 1.15
    return global_max * 0.35


def _broken_axis_limits(sources, idx, include_random):
    """为断裂轴选择相对保守的上下显示区间。"""
    series_maxima = []
    for name in _source_order(include_random):
        if name not in sources:
            continue
        _, pairs, varnames = sources[name]
        values = pairs if idx == 1 else varnames
        if values:
            series_maxima.append(max(values))
    if len(series_maxima) < 2:
        return None
    global_max = max(series_maxima)
    low_max = _inset_ymax(sources, idx, include_random)
    if low_max >= global_max * 0.7:
        return None
    high_min = max(low_max * 1.35, global_max * 0.58)
    if high_min >= global_max * 0.95:
        return None
    return 0.0, low_max, high_min, global_max * 1.05


def _decorate_axis(ax, title, ylabel, with_legend=True, log_scale=False):
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=13, fontweight='bold')
    if with_legend:
        ax.legend(
            fontsize=AXIS_STYLE['legend_fontsize'],
            loc=AXIS_STYLE['legend_loc'],
            frameon=AXIS_STYLE['legend_frameon'],
            labelspacing=AXIS_STYLE['legend_labelspacing'],
        )
    ax.grid(
        True,
        linestyle=AXIS_STYLE['grid_linestyle'],
        linewidth=AXIS_STYLE['grid_linewidth'],
        alpha=AXIS_STYLE['grid_alpha'],
    )
    ax.set_axisbelow(True)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_xlim(0, PLOT_MAX_HOURS)
    ax.set_xticks(range(0, int(PLOT_MAX_HOURS) + 1, 4))
    if log_scale:
        ax.set_yscale('symlog', linthresh=1.0, linscale=1.0, base=2)


def _decorate_broken_axis(ax, ylabel=None, title=None, with_legend=False):
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=12)
    if title:
        ax.set_title(title, fontsize=13, fontweight='bold')
    if with_legend:
        ax.legend(
            fontsize=AXIS_STYLE['legend_fontsize'],
            loc=AXIS_STYLE['legend_loc'],
            frameon=AXIS_STYLE['legend_frameon'],
            labelspacing=AXIS_STYLE['legend_labelspacing'],
        )
    ax.grid(
        True,
        linestyle=AXIS_STYLE['grid_linestyle'],
        linewidth=AXIS_STYLE['grid_linewidth'],
        alpha=AXIS_STYLE['grid_alpha'],
    )
    ax.set_axisbelow(True)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_xlim(0, PLOT_MAX_HOURS)
    ax.set_xticks(range(0, int(PLOT_MAX_HOURS) + 1, 4))


def _plot_conzzer_only(ax, sources, idx):
    if 'Conzzer' not in sources:
        return
    hours, pairs, varnames = sources['Conzzer']
    values = pairs if idx == 1 else varnames
    style = SERIES_STYLES['Conzzer']
    plot_hours, plot_values = _soften_curve_for_plot(hours, values)
    ax.plot(
        plot_hours,
        plot_values,
        label='Conzzer',
        color=style['color'],
        linestyle=style['linestyle'],
        linewidth=style['linewidth'],
        alpha=style['alpha'],
        solid_capstyle='round',
        solid_joinstyle='round',
        antialiased=True,
    )


def _soften_curve_for_plot(hours, values, smooth_window=9):
    """仅用于显示层的轻微平滑，保留总体单调趋势与终点值。"""
    if not hours or len(hours) < 8:
        return hours, values

    arr = np.asarray(values, dtype=float)
    if smooth_window % 2 == 0:
        smooth_window += 1
    if smooth_window >= len(arr):
        smooth_window = max(3, len(arr) // 2 * 2 - 1)
    if smooth_window < 3:
        return hours, values

    kernel = np.ones(smooth_window, dtype=float) / float(smooth_window)
    smoothed = np.convolve(arr, kernel, mode='same')
    smoothed = np.maximum.accumulate(smoothed)
    smoothed[0] = arr[0]
    smoothed[-1] = arr[-1]
    return hours, smoothed.tolist()


def _draw_zigzag_separator(ax_sep):
    """在分隔条 ax_sep 中画锯齿波，模仿 draw_cov4.py 的断轴风格。"""
    t = np.linspace(0.25, 0.75, 600)
    key_x, key_y = [], []
    for k in range(3):
        s = k / 3
        key_x.extend([s, s+1/12, s+1/6, s+1/4, s+1/3])
        key_y.extend([0.0, 0.06, 0.0, -0.06, 0.0])
    zigzag = np.interp(t, key_x, key_y)   # 值域 -0.45~0.45，用作 x 坐标（小时）
    ax_sep.plot(zigzag, t, color='black', linewidth=0.6, clip_on=False)
    # 隐藏所有装饰
    for spine in ax_sep.spines.values():
        spine.set_visible(False)
    ax_sep.tick_params(left=False, right=False, bottom=False,
                       labelleft=False, labelbottom=False)
    ax_sep.set_ylim(0, 1)


def plot_module(module, output_dir, metric='both', include_random=True,
                generate_log=False, generate_inset=False, generate_broken=False):
    """为单个模块画 4-way 对比图"""
    # 加载数据: 每个源返回 (hours, pairs_metric, varnames_metric)
    sources = {}

    # DDRD normal
    log = find_latest_ddrd_log(module, random_mode=False)
    if log:
        h, p, v = parse_ddrd_log(log)
        if h:
            h, p, v = clip_series(h, _make_monotonic(p), _make_monotonic(v))
            sources['DDRD'] = (h, p, v)
            print(f"  DDRD normal:  {len(h)} pts, {h[-1]:.1f}h, pairs={p[-1]}, varnames={v[-1]}")

    # DDRD random
    if include_random:
        log = find_latest_ddrd_log(module, random_mode=True)
        if log:
            h, p, v = parse_ddrd_log(log)
            if h:
                h, p, v = clip_series(h, _make_monotonic(p), _make_monotonic(v))
                sources['DDRD-Random'] = (h, p, v)
                print(f"  DDRD random:  {len(h)} pts, {h[-1]:.1f}h, pairs={p[-1]}, varnames={v[-1]}")

    # Conzzer
    h, sig, vn = load_conzzer_csv(module)
    if h:
        h, sig, vn, start_mode = adjust_series_start(h, sig, vn)
        h, sig, vn = smooth_and_downsample(h, sig, vn, bucket_min=2, window_min=60)
        h, sig, vn = clip_series(h, sig, vn)
        sources['Conzzer'] = (h, sig, vn)
        print(f"  Conzzer:      {len(h)} pts, {h[-1]:.1f}h, signals={sig[-1]:.0f}, varnames={vn[-1]:.0f}, mode={start_mode}")

    # SegFuzz
    h, rp, vp = load_segfuzz_csv(module)
    if h:
        h, rp, vp, start_mode = adjust_series_start(h, rp, vp)
        h, rp, vp = clip_series(h, _make_monotonic(rp), _make_monotonic(vp))
        sources['SegFuzz'] = (h, rp, vp)
        print(f"  SegFuzz:      {len(h)} pts, {h[-1]:.1f}h, race_pairs={rp[-1]}, varnames={vp[-1]}, mode={start_mode}")

    if not sources:
        print(f"  !! 无任何数据")
        return None

    module_display = _module_display_name(module)

    def _render_variant(variant_name, filename_suffix='', log_scale=False, with_inset=False):
        if with_inset:
            data_index = 2 if metric == 'varnames' else 1
            title = 'VarName Pair Count' if metric == 'varnames' else 'Pair / Signal Count'
            fig, (ax_main, ax_conzzer) = plt.subplots(
                2, 1, figsize=(12, 7.8), sharex=True,
                gridspec_kw={'height_ratios': [3, 1]},
                constrained_layout=True,
            )
            _plot_lines(ax_main, sources, data_index, include_random)
            _decorate_axis(
                ax_main,
                f'{module_display} — {title} (24h{variant_name})',
                title,
                log_scale=log_scale,
            )
            _plot_conzzer_only(ax_conzzer, sources, data_index)
            _decorate_axis(
                ax_conzzer,
                'Conzzer Zoom',
                'Conzzer',
                with_legend=True,
                log_scale=False,
            )
            ax_conzzer.set_ylim(0, max(1.0, _inset_ymax(sources, data_index, include_random)))
            ax_conzzer.set_xlabel('Elapsed Time (hours)', fontsize=12)
        elif metric == 'both':
            fig, (ax_top, ax_bot) = plt.subplots(
                2, 1, figsize=(12, 9), sharex=True, constrained_layout=with_inset)
            _plot_lines(ax_top, sources, 2, include_random)
            _decorate_axis(
                ax_top,
                f'{module_display} — VarName Pair Count (24h{variant_name})',
                'VarName Pair Count',
                log_scale=log_scale,
            )
            _plot_lines(ax_bot, sources, 1, include_random)
            _decorate_axis(
                ax_bot,
                f'{module_display} — Pair / Signal Count (24h{variant_name})',
                'Pair / Signal Count',
                log_scale=log_scale,
            )
            ax_bot.set_xlabel('Elapsed Time (hours)', fontsize=12)
        else:
            fig, ax_single = plt.subplots(1, 1, figsize=(12, 5.5), constrained_layout=with_inset)
            data_index = 2 if metric == 'varnames' else 1
            title = 'VarName Pair Count' if metric == 'varnames' else 'Pair / Signal Count'
            _plot_lines(ax_single, sources, data_index, include_random)
            _decorate_axis(
                ax_single,
                f'{module_display} — {title} (24h{variant_name})',
                title,
                log_scale=log_scale,
            )
            ax_single.set_xlabel('Elapsed Time (hours)', fontsize=12)

        if not with_inset:
            fig.tight_layout()
        out_path = os.path.join(output_dir, f"{module}_4way{filename_suffix}.png")
        fig.savefig(out_path, dpi=150, bbox_inches='tight')
        plt.close(fig)
        print(f"  => {out_path}")
        return out_path

    def _render_broken_variant():
        """用 draw_cov4.py 同款锯齿波断轴风格渲染。
        每组 3 行: 上(高值区) / 中(锯齿分隔) / 下(低值区)，高度比 [6,1,1]。"""

        if module not in BROKEN_ONLY_MODULES:
            print(f"  .. 跳过断裂图（仅为 {', '.join(sorted(BROKEN_ONLY_MODULES))} 生成）")
            return None

        def _build_broken_panel(fig, outer_cell, data_index, metric_title, ylabel, first_group):
            """在 outer_cell (SubplotSpec) 内创建 3 子图断轴组，返回 (ax_hi, ax_sep, ax_lo) 或 None。"""
            limits = _broken_axis_limits(sources, data_index, include_random)
            if not limits:
                return None
            low_min, low_max, high_min, high_max = limits

            inner = outer_cell.subgridspec(3, 1, height_ratios=[6, 0.55, 1], hspace=0)
            if first_group:
                ax_hi  = fig.add_subplot(inner[0])
                ax_sep = fig.add_subplot(inner[1], sharex=ax_hi)
                ax_lo  = fig.add_subplot(inner[2], sharex=ax_hi)
            else:
                # 与第一组共享 x 轴以便对齐
                ax_hi  = fig.add_subplot(inner[0], sharex=_shared_x_ref)
                ax_sep = fig.add_subplot(inner[1], sharex=ax_hi)
                ax_lo  = fig.add_subplot(inner[2], sharex=ax_hi)

            # ── 画数据线 ──
            _plot_lines(ax_hi, sources, data_index, include_random)
            _plot_lines(ax_lo, sources, data_index, include_random)

            # ── 装饰上面板 ──
            _decorate_broken_axis(ax_hi, ylabel=ylabel, title=f'{module_display} — {metric_title}', with_legend=True)
            low_max_for_module = BROKEN_LOW_Y_MAX_BY_MODULE.get(module, low_max)
            upper_start = low_max_for_module * 2
            ax_hi.set_ylim(upper_start, high_max)
            upper_tick_step = BROKEN_UPPER_TICK_STEP_BY_MODULE.get(module, 1000)
            ax_hi.yaxis.set_major_locator(MultipleLocator(upper_tick_step))
            ax_hi.spines['bottom'].set_visible(False)
            ax_hi.spines['right'].set_visible(False)
            ax_hi.tick_params(bottom=False, labelbottom=False)

            # ── 锯齿分隔条 ──
            _draw_zigzag_separator(ax_sep)

            # ── 装饰下面板 ──
            _decorate_broken_axis(ax_lo, ylabel=ylabel, title=None, with_legend=False)
            if module in BROKEN_ONLY_MODULES:
                low_max = BROKEN_LOW_Y_MAX_BY_MODULE.get(module, 200)
                ax_lo.set_ylim(0, low_max)
                if low_max == 100:
                    ax_lo.set_yticks([0, 25, 50, 75, 100])
                elif low_max == 150:
                    ax_lo.set_yticks([0, 50, 100, 150])
                elif low_max == 1000:
                    ax_lo.set_yticks([0, 250, 500, 750, 1000])
                elif low_max == 2000:
                    ax_lo.set_yticks([0, 500, 1000, 1500, 2000])
                else:
                    ax_lo.set_yticks([0, 50, 100, 150, 200])
            else:
                ax_lo.set_ylim(low_min, low_max)
            ax_lo.spines['top'].set_visible(False)
            ax_lo.spines['right'].set_visible(False)

            return ax_hi, ax_sep, ax_lo

        if metric == 'both':
            fig = plt.figure(figsize=(12, 9.6))
            outer = fig.add_gridspec(2, 1, height_ratios=[1, 1], hspace=0.22)
            _shared_x_ref = None  # 第一组先建，第二组共享

            res1 = _build_broken_panel(
                fig, outer[0], 2, 'VarName Pair Count (24h — Broken Y)', 'VarName Pair Count', True)
            if res1 is None:
                plt.close(fig)
                return None
            _shared_x_ref = res1[0]  # ax_hi of first group

            res2 = _build_broken_panel(
                fig, outer[1], 1, 'Pair / Signal Count (24h — Broken Y)', 'Pair / Signal Count', False)
            if res2 is None:
                plt.close(fig)
                return None

            ax_lo2 = res2[2]
            ax_lo2.set_xlabel('Elapsed Time (hours)', fontsize=12)
        else:
            fig = plt.figure(figsize=(10.8, 5.2))
            outer = fig.add_gridspec(1, 1)
            _shared_x_ref = None
            data_index = 2 if metric == 'varnames' else 1
            metric_title = ('VarName Pair Count (24h — Broken Y)'
                            if metric == 'varnames' else 'Pair / Signal Count (24h — Broken Y)')
            ylabel = 'VarName Pair Count' if metric == 'varnames' else 'Pair / Signal Count'

            res = _build_broken_panel(fig, outer[0], data_index, metric_title, ylabel, True)
            if res is None:
                plt.close(fig)
                return None
            ax_lo = res[2]
            ax_lo.set_xlabel('Elapsed Time (hours)', fontsize=12)

        out_path = os.path.join(output_dir, f"{module}_4way_broken.png")
        fig.savefig(out_path, dpi=150, bbox_inches='tight')
        plt.close(fig)
        print(f"  => {out_path}")
        return out_path

    saved_paths = [_render_variant('')]
    if generate_log:
        saved_paths.append(_render_variant(' — Symlog Y', '_log', log_scale=True))
    if generate_inset:
        saved_paths.append(_render_variant(' — Inset Zoom', '_inset', with_inset=True))
    if generate_broken:
        broken_path = _render_broken_variant()
        if broken_path:
            saved_paths.append(broken_path)
    return saved_paths


def main():
    parser = argparse.ArgumentParser(description='4-way 24h 对比图: DDRD / DDRD-Random / Conzzer / SegFuzz')
    parser.add_argument('-t', '--targets', nargs='+', default=None,
                        help='指定模块 (默认: 全部 8 个)')
    parser.add_argument('-o', '--output-dir', default=None,
                        help='输出目录 (默认: exp/4way_compare/)')
    parser.add_argument('--metric', choices=['both', 'varnames', 'pairs'], default='both',
                        help='绘制指标 (默认: both)')
    parser.add_argument('--no-random', action='store_true',
                        help='不绘制 DDRD random baseline')
    parser.add_argument('--with-log', action='store_true',
                        help='额外输出 symlog Y 轴版本')
    parser.add_argument('--with-inset', action='store_true',
                        help='额外输出局部放大窗版本')
    parser.add_argument('--with-broken', action='store_true',
                        help='额外输出断裂 Y 轴版本')
    args = parser.parse_args()

    modules = args.targets or TARGET_MODULES
    output_dir = args.output_dir or os.path.join(EXP_DIR, "4way_compare")
    os.makedirs(output_dir, exist_ok=True)

    print(f"输出目录: {output_dir}")
    print(f"目标模块: {', '.join(modules)}")
    print(f"指标: {args.metric}")
    print(f"包含 random: {'否' if args.no_random else '是'}")
    print(f"输出对数版: {'是' if args.with_log else '否'}")
    print(f"输出局部放大版: {'是' if args.with_inset else '否'}")
    print(f"输出断裂轴版: {'是' if args.with_broken else '否'}")
    print()

    saved = []
    for mod in modules:
        print(f"[{mod}]")
        results = plot_module(
            mod,
            output_dir,
            metric=args.metric,
            include_random=not args.no_random,
            generate_log=args.with_log,
            generate_inset=args.with_inset,
            generate_broken=args.with_broken,
        )
        if results:
            saved.extend(results)
        print()

    print("=" * 60)
    print(f"完成! 共生成 {len(saved)} 张图表:")
    for p in saved:
        print(f"  {p}")


if __name__ == '__main__':
    main()
