#!/usr/bin/env python3
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

"""
dedup_races.py - 根据 signal 对 race pair 数据进行去重

用法:
    # 去重统计格式 CSV (races.csv)
    python3 dedup_races.py input.csv output.csv
    
    # 去重 signals 格式 CSV (signals.csv) - 用于大规模收集
    python3 dedup_races.py input.csv output.csv --format signals
    
    # JSON 格式
    python3 dedup_races.py input.json output.json --format json
    
    # 从标准输入读取，输出到标准输出
    cat *.csv | python3 dedup_races.py - -

Signal 去重逻辑:
    - 对于统计格式 CSV: 使用 signal 列作为去重键
    - 对于 signals 格式 CSV: 使用 signal_hash 列作为去重键
    - 对于 JSON: 使用 signal 字段作为去重键
    - 保留每个唯一 signal 的第一次出现

Signals 格式 (signals.csv):
    signal_hash,var1,stack1,var2,stack2,addr1,addr2,delta_ns,type
    - signal_hash: 唯一的 race signal 哈希值
    - var1, var2: 两个访问的变量名哈希
    - stack1, stack2: 两个访问的调用栈哈希
    - addr1, addr2: 两个访问的内存地址
    - delta_ns: 两次访问的时间差（纳秒）
    - type: R=Race Pair, U=UAF Pair
"""

import argparse
import csv
import json
import sys
from collections import OrderedDict
from typing import Dict, List, Any, TextIO


def dedup_csv(input_file: TextIO, output_file: TextIO, 
              signal_column: str = 'signal',
              keep: str = 'first',
              stats: bool = True) -> Dict[str, int]:
    """
    对 CSV 格式的 race 数据进行去重
    
    Args:
        input_file: 输入文件对象
        output_file: 输出文件对象
        signal_column: signal 列名
        keep: 'first' 保留第一条, 'last' 保留最后一条
        stats: 是否返回统计信息
    
    Returns:
        统计信息字典
    """
    reader = csv.DictReader(input_file)
    
    if reader.fieldnames is None:
        return {'total': 0, 'unique': 0, 'duplicates': 0}
    
    # 检查 signal 列是否存在
    if signal_column not in reader.fieldnames:
        # 尝试查找可能的 signal 列名
        possible_names = ['signal', 'signal_hash', 'race_signal', 'sig', 'hash']
        signal_column = None
        for name in possible_names:
            if name in reader.fieldnames:
                signal_column = name
                break
        
        if signal_column is None:
            sys.stderr.write(f"Warning: No signal column found. Available columns: {reader.fieldnames}\n")
            sys.stderr.write("Using all columns for dedup (may be slow)\n")
            signal_column = None
    
    seen_signals: Dict[str, dict] = OrderedDict()
    total_count = 0
    
    for row in reader:
        total_count += 1
        
        # 清理 row 中的 None 键（CSV 解析可能产生）
        row = {k: v for k, v in row.items() if k is not None}
        
        # 获取 signal 值
        if signal_column:
            signal = row.get(signal_column, '')
        else:
            # 没有 signal 列，使用整行内容作为 key
            signal = '|'.join(str(v) for v in row.values())
        
        if not signal:
            # 空 signal，跳过或使用其他字段
            continue
        
        if keep == 'first':
            if signal not in seen_signals:
                seen_signals[signal] = row
        else:  # keep == 'last'
            seen_signals[signal] = row
    
    # 写入去重后的数据
    # 过滤掉 fieldnames 中的 None
    fieldnames = [f for f in reader.fieldnames if f is not None] if reader.fieldnames else []
    writer = csv.DictWriter(output_file, fieldnames=fieldnames)
    writer.writeheader()
    
    for row in seen_signals.values():
        writer.writerow(row)
    
    unique_count = len(seen_signals)
    
    return {
        'total': total_count,
        'unique': unique_count,
        'duplicates': total_count - unique_count
    }


def dedup_json(input_file: TextIO, output_file: TextIO,
               signal_field: str = 'signal',
               keep: str = 'first',
               stats: bool = True) -> Dict[str, int]:
    """
    对 JSON 格式的 race 数据进行去重
    
    支持的 JSON 格式:
    1. JSON Lines (每行一个 JSON 对象)
    2. JSON 数组
    """
    content = input_file.read().strip()
    
    if not content:
        output_file.write('[]')
        return {'total': 0, 'unique': 0, 'duplicates': 0}
    
    # 尝试解析为 JSON 数组
    try:
        data = json.loads(content)
        if isinstance(data, list):
            records = data
        else:
            records = [data]
    except json.JSONDecodeError:
        # 尝试 JSON Lines 格式
        records = []
        for line in content.split('\n'):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    
    seen_signals: Dict[str, Any] = OrderedDict()
    total_count = len(records)
    
    for record in records:
        if not isinstance(record, dict):
            continue
        
        signal = record.get(signal_field, '')
        if not signal:
            # 尝试其他可能的字段名
            for name in ['race_signal', 'sig', 'hash']:
                signal = record.get(name, '')
                if signal:
                    break
        
        if not signal:
            continue
        
        signal = str(signal)
        
        if keep == 'first':
            if signal not in seen_signals:
                seen_signals[signal] = record
        else:
            seen_signals[signal] = record
    
    # 输出去重后的数据
    unique_records = list(seen_signals.values())
    json.dump(unique_records, output_file, indent=2)
    
    return {
        'total': total_count,
        'unique': len(unique_records),
        'duplicates': total_count - len(unique_records)
    }


def merge_and_dedup_csv_files(input_files: List[str], output_file: str,
                               signal_column: str = 'signal') -> Dict[str, int]:
    """
    合并多个 CSV 文件并去重
    """
    seen_signals: Dict[str, dict] = OrderedDict()
    fieldnames = None
    total_count = 0
    
    for filepath in input_files:
        try:
            with open(filepath, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if fieldnames is None:
                    fieldnames = reader.fieldnames
                
                for row in reader:
                    total_count += 1
                    signal = row.get(signal_column, '')
                    if signal and signal not in seen_signals:
                        seen_signals[signal] = row
        except Exception as e:
            sys.stderr.write(f"Warning: Error reading {filepath}: {e}\n")
    
    if fieldnames is None:
        return {'total': 0, 'unique': 0, 'duplicates': 0}
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in seen_signals.values():
            writer.writerow(row)
    
    return {
        'total': total_count,
        'unique': len(seen_signals),
        'duplicates': total_count - len(seen_signals)
    }


def main():
    parser = argparse.ArgumentParser(
        description='Deduplicate race pair data based on signal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Deduplicate a single CSV file
  %(prog)s races.csv deduped_races.csv
  
  # Deduplicate JSON file
  %(prog)s races.json deduped_races.json --format json
  
  # Use stdin/stdout
  cat vm*.csv | %(prog)s - - > merged.csv
  
  # Merge and deduplicate multiple files
  %(prog)s --merge vm0.csv vm1.csv vm2.csv -o merged.csv
  
  # Specify signal column name
  %(prog)s races.csv deduped.csv --signal-column race_signal
'''
    )
    
    parser.add_argument('input', nargs='?', default='-',
                        help='Input file (- for stdin)')
    parser.add_argument('output', nargs='?', default='-',
                        help='Output file (- for stdout)')
    parser.add_argument('-f', '--format', choices=['csv', 'json', 'signals'], default='csv',
                        help='Data format: csv, json, or signals (default: csv)')
    parser.add_argument('-s', '--signal-column', default=None,
                        help='Name of the signal column/field (default: auto-detect)')
    parser.add_argument('-k', '--keep', choices=['first', 'last'], default='first',
                        help='Which duplicate to keep (default: first)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress statistics output')
    parser.add_argument('--merge', nargs='+', metavar='FILE',
                        help='Merge multiple input files and deduplicate')
    parser.add_argument('-o', '--output-file',
                        help='Output file for --merge mode')
    
    args = parser.parse_args()
    
    # 合并模式
    if args.merge:
        if not args.output_file:
            sys.stderr.write("Error: --output-file is required with --merge\n")
            sys.exit(1)
        
        stats = merge_and_dedup_csv_files(args.merge, args.output_file, args.signal_column)
        
        if not args.quiet:
            sys.stderr.write(f"Merged {len(args.merge)} files\n")
            sys.stderr.write(f"Total records: {stats['total']}\n")
            sys.stderr.write(f"Unique signals: {stats['unique']}\n")
            sys.stderr.write(f"Duplicates removed: {stats['duplicates']}\n")
        
        return
    
    # 单文件模式
    if args.input == '-':
        input_file = sys.stdin
    else:
        input_file = open(args.input, 'r', newline='', encoding='utf-8')
    
    if args.output == '-':
        output_file = sys.stdout
    else:
        output_file = open(args.output, 'w', newline='', encoding='utf-8')
    
    try:
        # 确定 signal 列名
        signal_col = args.signal_column
        if signal_col is None:
            if args.format == 'signals':
                signal_col = 'signal_hash'
            else:
                signal_col = 'signal'
        
        if args.format == 'csv' or args.format == 'signals':
            stats = dedup_csv(input_file, output_file, signal_col, args.keep)
        else:
            stats = dedup_json(input_file, output_file, signal_col, args.keep)
        
        if not args.quiet:
            sys.stderr.write(f"Total records: {stats['total']}\n")
            sys.stderr.write(f"Unique signals: {stats['unique']}\n")
            sys.stderr.write(f"Duplicates removed: {stats['duplicates']}\n")
    
    finally:
        if args.input != '-':
            input_file.close()
        if args.output != '-':
            output_file.close()


if __name__ == '__main__':
    main()
