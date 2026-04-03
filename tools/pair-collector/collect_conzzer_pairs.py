#!/usr/bin/env python3
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

"""
collect_conzzer_pairs.py - 从 Conzzer 的 plot-curve 文件提取并发对数时间序列

Conzzer 的 Fuzzer 在运行时会写出 plot-curve 文件，每行包含以下列（空格分隔）：
  列1:  GetCurTimeUs()       -> 微秒级 Unix 时间戳
  列2:  ShowCoverage(pct%)   -> 边覆盖（如 9040(0.86%)）
  列3:  unique_crash/total   -> 崩溃计数
  列4:  unique_ex_crash      -> 并发崩溃计数
  列5:  total_travel.size()  -> 上下文不敏感并发对数 (insen_travel)
  列6:  total_another_travel -> 上下文敏感并发对数 (sen_travel)
  列7:  concurrency_test_time
  列8:  unreachable_count
  列9:  total_generate_num
  列10: skip_since_travel
  列11: skip_since_unreachable
  列12: queue.size()
  列13: stage (可能含空格)

本脚本提取列1（转换为 elapsed 时间）、列5（pair_count）、列6（varname_pair_count），
输出与 DDRD 一致的 race_timeseries.csv 格式。

两种运行模式:
  1. Post-hoc: 解析已有的 plot-curve 文件
     python3 collect_conzzer_pairs.py /path/to/plot-curve -o timeseries.csv

  2. Live: 持续监控 plot-curve 文件的增长
     python3 collect_conzzer_pairs.py /path/to/plot-curve -o timeseries.csv --live
"""

import argparse
import csv
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import List, Tuple, Optional


def parse_plot_curve_line(line: str) -> Optional[dict]:
    """
    解析 Conzzer plot-curve 的一行。

    格式: 前4列用 3空格 分隔，后面用 1空格 分隔。
    示例:
      1773305013213096   9040(0.862122%)   0/0   0   2156 1823 0 0 0 0 0 2 Concurrency fuzzing
    """
    line = line.strip()
    if not line:
        return None

    # 用3空格 split 得到前4个 token
    parts_3sp = line.split('   ')
    if len(parts_3sp) < 4:
        return None

    try:
        timestamp_us = int(parts_3sp[0].strip())
    except (ValueError, IndexError):
        return None

    # 从第4个 token 开始，剩余部分用1空格继续拆分
    # parts_3sp[3] 至少包含: "unique_ex_crash   travel travel2 ..."
    # 但 unique_ex_crash 之后可能只有1空格分隔
    # 更安全的做法：取 parts_3sp[3:] 合并后用空格 split
    remaining = '   '.join(parts_3sp[3:]).strip()
    remaining_parts = remaining.split()

    if len(remaining_parts) < 9:
        return None

    try:
        # remaining_parts[0] = unique_ex_crash
        # remaining_parts[1] = total_travel.size() (pair_count)
        # remaining_parts[2] = total_another_travel.size() (varname_pair_count)
        pair_count = int(remaining_parts[1])
        varname_pair_count = int(remaining_parts[2])
    except (ValueError, IndexError):
        return None

    return {
        'timestamp_us': timestamp_us,
        'pair_count': pair_count,
        'varname_pair_count': varname_pair_count,
    }


def parse_plot_curve(filepath: str) -> List[dict]:
    """解析整个 plot-curve 文件"""
    records = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            rec = parse_plot_curve_line(line)
            if rec is not None:
                records.append(rec)
    return records


def records_to_timeseries(records: List[dict]) -> List[dict]:
    """
    将解析后的记录转换为时间序列格式。
    elapsed 时间以第一条记录为基准。
    """
    if not records:
        return []

    start_us = records[0]['timestamp_us']
    timeseries = []

    for rec in records:
        elapsed_us = rec['timestamp_us'] - start_us
        elapsed_sec = elapsed_us / 1_000_000
        elapsed_min = elapsed_sec / 60
        elapsed_hour = elapsed_sec / 3600

        # 转换 timestamp_us 为 ISO 格式 (近似)
        ts_sec = rec['timestamp_us'] / 1_000_000
        try:
            iso_ts = datetime.fromtimestamp(ts_sec, tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            iso_ts = str(ts_sec)

        timeseries.append({
            'timestamp': iso_ts,
            'elapsed_sec': f'{elapsed_sec:.2f}',
            'elapsed_min': f'{elapsed_min:.2f}',
            'elapsed_hour': f'{elapsed_hour:.4f}',
            'pair_count': rec['pair_count'],
            'varname_pair_count': rec['varname_pair_count'],
        })

    return timeseries


def write_timeseries_csv(timeseries: List[dict], output_path: str, append: bool = False):
    """写入时间序列 CSV"""
    fieldnames = ['timestamp', 'elapsed_sec', 'elapsed_min', 'elapsed_hour',
                  'pair_count', 'varname_pair_count']

    mode = 'a' if append else 'w'
    write_header = not append or not os.path.exists(output_path) or os.path.getsize(output_path) == 0

    with open(output_path, mode, newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerows(timeseries)


def live_monitor(filepath: str, output_path: str, poll_interval: float = 5.0):
    """
    实时监控 plot-curve 文件增长，增量提取并追加到输出 CSV。
    """
    print(f"[live] Monitoring {filepath} (poll every {poll_interval}s)")
    print(f"[live] Writing to {output_path}")
    print(f"[live] Press Ctrl+C to stop\n")

    last_line_count = 0
    start_us = None
    all_records = []

    # 初始化输出文件
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        fieldnames = ['timestamp', 'elapsed_sec', 'elapsed_min', 'elapsed_hour',
                      'pair_count', 'varname_pair_count']
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

    try:
        while True:
            if not os.path.exists(filepath):
                time.sleep(poll_interval)
                continue

            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            if len(lines) <= last_line_count:
                time.sleep(poll_interval)
                continue

            # 处理新增的行
            new_lines = lines[last_line_count:]
            new_records = []
            for line in new_lines:
                rec = parse_plot_curve_line(line)
                if rec is not None:
                    new_records.append(rec)

            if new_records:
                if start_us is None:
                    if all_records:
                        start_us = all_records[0]['timestamp_us']
                    else:
                        start_us = new_records[0]['timestamp_us']

                # 转换并追加
                new_ts = []
                for rec in new_records:
                    elapsed_us = rec['timestamp_us'] - start_us
                    elapsed_sec = elapsed_us / 1_000_000
                    elapsed_min = elapsed_sec / 60
                    elapsed_hour = elapsed_sec / 3600
                    ts_sec = rec['timestamp_us'] / 1_000_000
                    try:
                        iso_ts = datetime.fromtimestamp(ts_sec, tz=timezone.utc).isoformat()
                    except (ValueError, OSError):
                        iso_ts = str(ts_sec)

                    new_ts.append({
                        'timestamp': iso_ts,
                        'elapsed_sec': f'{elapsed_sec:.2f}',
                        'elapsed_min': f'{elapsed_min:.2f}',
                        'elapsed_hour': f'{elapsed_hour:.4f}',
                        'pair_count': rec['pair_count'],
                        'varname_pair_count': rec['varname_pair_count'],
                    })

                write_timeseries_csv(new_ts, output_path, append=True)
                all_records.extend(new_records)

                latest = new_records[-1]
                elapsed_h = (latest['timestamp_us'] - start_us) / 1_000_000 / 3600
                print(f"[live] +{len(new_records)} records | "
                      f"elapsed={elapsed_h:.2f}h | "
                      f"pair_count={latest['pair_count']} | "
                      f"varname_pair_count={latest['varname_pair_count']} | "
                      f"total_records={len(all_records)}")

            last_line_count = len(lines)
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print(f"\n[live] Stopped. Total records: {len(all_records)}")
        if all_records:
            print(f"[live] Final pair_count: {all_records[-1]['pair_count']}")
            print(f"[live] Final varname_pair_count: {all_records[-1]['varname_pair_count']}")


def print_summary(records: List[dict]):
    """打印摘要信息"""
    if not records:
        print("No valid records found.")
        return

    start_us = records[0]['timestamp_us']
    end_us = records[-1]['timestamp_us']
    duration_h = (end_us - start_us) / 1_000_000 / 3600

    print(f"\n{'='*60}")
    print(f"Conzzer Pair Collection Summary")
    print(f"{'='*60}")
    print(f"  Records:              {len(records)}")
    print(f"  Duration:             {duration_h:.2f} hours")
    print(f"  Final pair_count:     {records[-1]['pair_count']}")
    print(f"  Final varname_pair:   {records[-1]['varname_pair_count']}")
    print(f"  Max pair_count:       {max(r['pair_count'] for r in records)}")
    print(f"  Max varname_pair:     {max(r['varname_pair_count'] for r in records)}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract Pair Count timeseries from Conzzer plot-curve file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Post-hoc analysis of existing plot-curve file
  python3 collect_conzzer_pairs.py /path/to/exp/btrfs/fuzz/output/plot-curve -o conzzer_btrfs.csv

  # Live monitoring during experiment
  python3 collect_conzzer_pairs.py /path/to/plot-curve -o conzzer_live.csv --live

  # Monitor with custom poll interval (10s)
  python3 collect_conzzer_pairs.py /path/to/plot-curve -o out.csv --live --poll 10

  # Just print summary
  python3 collect_conzzer_pairs.py /path/to/plot-curve --summary-only
"""
    )

    parser.add_argument('input', help='Path to Conzzer plot-curve file')
    parser.add_argument('-o', '--output', default='conzzer_timeseries.csv',
                        help='Output CSV file (default: conzzer_timeseries.csv)')
    parser.add_argument('--live', action='store_true',
                        help='Live monitoring mode (continuous poll)')
    parser.add_argument('--poll', type=float, default=5.0,
                        help='Poll interval in seconds for live mode (default: 5)')
    parser.add_argument('--summary-only', action='store_true',
                        help='Only print summary, do not write CSV')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    if args.live:
        live_monitor(args.input, args.output, poll_interval=args.poll)
        return

    if not os.path.exists(args.input):
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    records = parse_plot_curve(args.input)

    if args.verbose:
        print(f"Parsed {len(records)} records from {args.input}")

    if args.summary_only:
        print_summary(records)
        return

    timeseries = records_to_timeseries(records)
    write_timeseries_csv(timeseries, args.output)
    print(f"Wrote {len(timeseries)} records to {args.output}")
    print_summary(records)


if __name__ == '__main__':
    main()
