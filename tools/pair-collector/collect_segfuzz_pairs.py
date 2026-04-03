#!/usr/bin/env python3
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

"""
collect_segfuzz_pairs.py - 从 SegFuzz 的 log / bench 文件提取并发对数时间序列

SegFuzz (基于 syzkaller 修改) 的 syz-manager 运行时会输出两种包含并发对信息的数据:

1. Log 文件 (默认 workdir/log):
   每 10 秒一行，格式如:
     [2026-03-13 15:17:31] VMs 1, executed 26, cover 1032, signal 1306/1265,
     interleaving 509671/513730, comm 292, blacklist 0, crashes 0, repro 0

   关键字段:
   - interleaving A/B: A = corpusInterleaving, B = maxInterleaving
   - comm: maxCommunication

2. Bench 文件 (-bench 参数, JSONL 格式):
   每分钟一条 JSON，包含:
     { "max interleaving": N, "max communication": M, "uptime": T, "fuzzing": F, ... }

指标映射关系:
  DDRD               Conzzer              SegFuzz
  ──────────────     ──────────────       ──────────────────────
  Pair Count         total_travel         max interleaving (Knot)
  VarName Pair       total_another_travel max communication (Communication)

用法:
  # 从 log 文件提取 (post-hoc)
  python3 collect_segfuzz_pairs.py log /path/to/workdir/log -o segfuzz_btrfs.csv

  # 从 bench 文件提取
  python3 collect_segfuzz_pairs.py bench /path/to/bench.txt -o segfuzz_btrfs.csv

  # 实时监控 log 文件
  python3 collect_segfuzz_pairs.py log /path/to/workdir/log -o segfuzz_live.csv --live
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple


# ============================================================
# Log 文件解析器
# ============================================================

# SegFuzz log 格式:
#   可能有 `ts` 前缀 (Mar 13 15:17:31)
#   [YYYY-MM-DD HH:MM:SS] 开头（可选）
#   然后: VMs N, executed N, cover N, signal N/N, interleaving N/N, comm N, ...
LOG_PATTERN = re.compile(
    r'VMs\s+(\d+),\s*'
    r'executed\s+(\d+),\s*'
    r'cover\s+(\d+),\s*'
    r'signal\s+(\d+)/(\d+),\s*'
    r'interleaving\s+(\d+)/(\d+),\s*'
    r'comm\s+(\d+),\s*'
    r'blacklist\s+(\d+),\s*'
    r'crashes\s+(\d+),\s*'
    r'repro\s+(\d+)'
)

# 时间戳模式: [YYYY-MM-DD HH:MM:SS] 或 ts 格式 "Mar 13 15:17:31"
TIMESTAMP_BRACKET_PATTERN = re.compile(r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]')
TIMESTAMP_TS_PATTERN = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})')


def parse_log_timestamp(line: str) -> Optional[datetime]:
    """从 log 行中提取时间戳"""
    # 尝试 [YYYY-MM-DD HH:MM:SS] 格式
    m = TIMESTAMP_BRACKET_PATTERN.search(line)
    if m:
        try:
            return datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass

    # 尝试 ts 格式 "Mar 13 15:17:31 ..."
    m = TIMESTAMP_TS_PATTERN.match(line)
    if m:
        try:
            ts_str = m.group(1)
            # ts 不包含年份，添加当前年份
            current_year = datetime.now().year
            return datetime.strptime(f'{current_year} {ts_str}', '%Y %b %d %H:%M:%S')
        except ValueError:
            pass

    return None


def parse_log_line(line: str) -> Optional[dict]:
    """解析 SegFuzz log 的一行，提取并发对统计"""
    m = LOG_PATTERN.search(line)
    if not m:
        return None

    ts = parse_log_timestamp(line)

    return {
        'timestamp': ts,
        'vms': int(m.group(1)),
        'executed': int(m.group(2)),
        'cover': int(m.group(3)),
        'corpus_signal': int(m.group(4)),
        'max_signal': int(m.group(5)),
        'corpus_interleaving': int(m.group(6)),
        'max_interleaving': int(m.group(7)),
        'max_communication': int(m.group(8)),
        'blacklist': int(m.group(9)),
        'crashes': int(m.group(10)),
        'repro': int(m.group(11)),
    }


def parse_log_file(filepath: str) -> List[dict]:
    """解析整个 log 文件"""
    records = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            rec = parse_log_line(line)
            if rec is not None:
                records.append(rec)
    return records


# ============================================================
# Bench 文件解析器
# ============================================================

def parse_bench_file(filepath: str) -> List[dict]:
    """
    解析 SegFuzz bench 文件 (JSONL 格式，每条 JSON 对象可能跨多行)。
    """
    records = []
    content = ''

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    # bench 文件格式: JSON 对象一个接一个，每个由 { } 包裹
    # 使用简单的 brace 匹配来分割
    depth = 0
    start_idx = -1

    for i, ch in enumerate(content):
        if ch == '{':
            if depth == 0:
                start_idx = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start_idx >= 0:
                json_str = content[start_idx:i + 1]
                try:
                    obj = json.loads(json_str)
                    records.append({
                        'uptime': obj.get('uptime', 0),
                        'fuzzing': obj.get('fuzzing', 0),
                        'max_interleaving': obj.get('max interleaving', 0),
                        'max_communication': obj.get('max communication', 0),
                        'corpus_interleaving': obj.get('interleaving signal', 0),
                        'cover': obj.get('coverage', 0),
                        'max_signal': obj.get('max signal', 0),
                        'corpus_signal': obj.get('signal', 0),
                        'executed': obj.get('exec total', 0),
                        'crashes': obj.get('crash types', 0),
                    })
                except json.JSONDecodeError:
                    pass
                start_idx = -1

    return records


# ============================================================
# 时间序列转换
# ============================================================

def log_records_to_timeseries(records: List[dict]) -> List[dict]:
    """
    将 log 解析结果转换为时间序列。
    elapsed 时间基于第一条记录的时间戳。
    """
    if not records:
        return []

    # 找到第一条有时间戳的记录
    start_ts = None
    for rec in records:
        if rec['timestamp'] is not None:
            start_ts = rec['timestamp']
            break

    timeseries = []
    for i, rec in enumerate(records):
        if rec['timestamp'] is not None and start_ts is not None:
            elapsed_sec = (rec['timestamp'] - start_ts).total_seconds()
            iso_ts = rec['timestamp'].isoformat()
        else:
            # 无时间戳时，用记录索引估算 (每10秒一条)
            elapsed_sec = i * 10
            iso_ts = ''

        elapsed_min = elapsed_sec / 60
        elapsed_hour = elapsed_sec / 3600

        timeseries.append({
            'timestamp': iso_ts,
            'elapsed_sec': f'{elapsed_sec:.2f}',
            'elapsed_min': f'{elapsed_min:.2f}',
            'elapsed_hour': f'{elapsed_hour:.4f}',
            'pair_count': rec['max_interleaving'],
            'varname_pair_count': rec['max_communication'],
        })

    return timeseries


def bench_records_to_timeseries(records: List[dict]) -> List[dict]:
    """
    将 bench 解析结果转换为时间序列。
    bench 文件自带 uptime 字段（秒）。
    """
    if not records:
        return []

    timeseries = []
    for rec in records:
        elapsed_sec = rec['uptime']
        elapsed_min = elapsed_sec / 60
        elapsed_hour = elapsed_sec / 3600

        timeseries.append({
            'timestamp': '',
            'elapsed_sec': f'{elapsed_sec:.2f}',
            'elapsed_min': f'{elapsed_min:.2f}',
            'elapsed_hour': f'{elapsed_hour:.4f}',
            'pair_count': rec['max_interleaving'],
            'varname_pair_count': rec['max_communication'],
        })

    return timeseries


# ============================================================
# CSV 输出
# ============================================================

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


# ============================================================
# Live 监控模式
# ============================================================

def live_monitor_log(filepath: str, output_path: str, poll_interval: float = 10.0):
    """实时监控 SegFuzz log 文件"""
    print(f"[live] Monitoring {filepath} (poll every {poll_interval}s)")
    print(f"[live] Writing to {output_path}")
    print(f"[live] Press Ctrl+C to stop\n")

    last_offset = 0
    start_ts = None
    record_count = 0

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

            file_size = os.path.getsize(filepath)
            if file_size <= last_offset:
                time.sleep(poll_interval)
                continue

            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(last_offset)
                new_content = f.read()
                last_offset = f.tell()

            new_lines = new_content.split('\n')
            new_records = []
            for line in new_lines:
                rec = parse_log_line(line)
                if rec is not None:
                    new_records.append(rec)

            if new_records:
                if start_ts is None:
                    for rec in new_records:
                        if rec['timestamp'] is not None:
                            start_ts = rec['timestamp']
                            break

                new_ts = []
                for rec in new_records:
                    if rec['timestamp'] is not None and start_ts is not None:
                        elapsed_sec = (rec['timestamp'] - start_ts).total_seconds()
                        iso_ts = rec['timestamp'].isoformat()
                    else:
                        elapsed_sec = record_count * 10
                        iso_ts = ''

                    elapsed_min = elapsed_sec / 60
                    elapsed_hour = elapsed_sec / 3600

                    new_ts.append({
                        'timestamp': iso_ts,
                        'elapsed_sec': f'{elapsed_sec:.2f}',
                        'elapsed_min': f'{elapsed_min:.2f}',
                        'elapsed_hour': f'{elapsed_hour:.4f}',
                        'pair_count': rec['max_interleaving'],
                        'varname_pair_count': rec['max_communication'],
                    })
                    record_count += 1

                write_timeseries_csv(new_ts, output_path, append=True)

                latest = new_records[-1]
                elapsed_h = 0
                if latest['timestamp'] and start_ts:
                    elapsed_h = (latest['timestamp'] - start_ts).total_seconds() / 3600

                print(f"[live] +{len(new_records)} records | "
                      f"elapsed={elapsed_h:.2f}h | "
                      f"max_interleaving={latest['max_interleaving']} | "
                      f"max_communication={latest['max_communication']} | "
                      f"total_records={record_count}")

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print(f"\n[live] Stopped. Total records: {record_count}")


def live_monitor_bench(filepath: str, output_path: str, poll_interval: float = 60.0):
    """实时监控 SegFuzz bench 文件"""
    print(f"[live] Monitoring bench file {filepath} (poll every {poll_interval}s)")
    print(f"[live] Writing to {output_path}")
    print(f"[live] Press Ctrl+C to stop\n")

    last_size = 0
    record_count = 0

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

            current_size = os.path.getsize(filepath)
            if current_size <= last_size:
                time.sleep(poll_interval)
                continue

            # 重新解析整个文件（bench JSONL 可能跨行）
            all_records = parse_bench_file(filepath)
            new_records = all_records[record_count:]

            if new_records:
                new_ts = bench_records_to_timeseries(new_records)
                # 修正: 需要保证 elapsed 基于整个实验的 uptime
                write_timeseries_csv(new_ts, output_path, append=True)
                record_count = len(all_records)

                latest = new_records[-1]
                elapsed_h = latest['uptime'] / 3600

                print(f"[live] +{len(new_records)} records | "
                      f"elapsed={elapsed_h:.2f}h | "
                      f"max_interleaving={latest['max_interleaving']} | "
                      f"max_communication={latest['max_communication']} | "
                      f"total_records={record_count}")

            last_size = current_size
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print(f"\n[live] Stopped. Total records: {record_count}")


# ============================================================
# 摘要
# ============================================================

def print_summary(records: List[dict], source_type: str):
    """打印摘要信息"""
    if not records:
        print("No valid records found.")
        return

    if source_type == 'log':
        # 估算时间
        if records[-1]['timestamp'] and records[0]['timestamp']:
            duration_h = (records[-1]['timestamp'] - records[0]['timestamp']).total_seconds() / 3600
        else:
            duration_h = len(records) * 10 / 3600
    else:
        duration_h = records[-1]['uptime'] / 3600

    max_interleaving = max(r['max_interleaving'] for r in records)
    max_communication = max(r['max_communication'] for r in records)

    print(f"\n{'='*60}")
    print(f"SegFuzz Pair Collection Summary")
    print(f"{'='*60}")
    print(f"  Source type:            {source_type}")
    print(f"  Records:                {len(records)}")
    print(f"  Duration:               {duration_h:.2f} hours")
    print(f"  Final max_interleaving: {records[-1]['max_interleaving']}")
    print(f"  Final max_communication:{records[-1]['max_communication']}")
    print(f"  Peak max_interleaving:  {max_interleaving}")
    print(f"  Peak max_communication: {max_communication}")
    print(f"{'='*60}")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Extract Pair Count timeseries from SegFuzz log/bench files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Source types:
  log    - Parse syz-manager log file (10-second intervals)
  bench  - Parse bench JSON file (1-minute intervals)

Metric mapping:
  SegFuzz max_interleaving  →  pair_count (analogous to DDRD Pair Count)
  SegFuzz max_communication →  varname_pair_count (analogous to DDRD VarName Pair)

Examples:
  # Parse existing log
  python3 collect_segfuzz_pairs.py log /path/to/workdir/log -o segfuzz_btrfs.csv

  # Parse bench file
  python3 collect_segfuzz_pairs.py bench /path/to/bench.txt -o segfuzz_btrfs.csv

  # Live monitoring of log
  python3 collect_segfuzz_pairs.py log /path/to/log -o out.csv --live

  # Live monitoring of bench
  python3 collect_segfuzz_pairs.py bench /path/to/bench.txt -o out.csv --live --poll 60

  # Summary only
  python3 collect_segfuzz_pairs.py log /path/to/log --summary-only
"""
    )

    parser.add_argument('source', choices=['log', 'bench'],
                        help='Data source type: log or bench')
    parser.add_argument('input', help='Path to SegFuzz log or bench file')
    parser.add_argument('-o', '--output', default='segfuzz_timeseries.csv',
                        help='Output CSV file (default: segfuzz_timeseries.csv)')
    parser.add_argument('--live', action='store_true',
                        help='Live monitoring mode')
    parser.add_argument('--poll', type=float, default=None,
                        help='Poll interval in seconds (default: 10 for log, 60 for bench)')
    parser.add_argument('--summary-only', action='store_true',
                        help='Only print summary')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    if args.live:
        poll = args.poll
        if args.source == 'log':
            live_monitor_log(args.input, args.output, poll_interval=poll or 10.0)
        else:
            live_monitor_bench(args.input, args.output, poll_interval=poll or 60.0)
        return

    if not os.path.exists(args.input):
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if args.source == 'log':
        records = parse_log_file(args.input)
    else:
        records = parse_bench_file(args.input)

    if args.verbose:
        print(f"Parsed {len(records)} records from {args.input}")

    if args.summary_only:
        print_summary(records, args.source)
        return

    if args.source == 'log':
        timeseries = log_records_to_timeseries(records)
    else:
        timeseries = bench_records_to_timeseries(records)

    write_timeseries_csv(timeseries, args.output)
    print(f"Wrote {len(timeseries)} records to {args.output}")
    print_summary(records, args.source)


if __name__ == '__main__':
    main()
