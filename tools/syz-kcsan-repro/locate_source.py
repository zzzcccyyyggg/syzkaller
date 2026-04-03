#!/usr/bin/env python3
"""
locate_source.py - Locate kernel source file:line for crash report data.

Two strategies:
  1. Analyzer (preferred): Uses DDRD Analyzer with VarName hashes + .ll files
  2. addr2line (fallback): Uses vmlinux debug symbols with function+offset

Usage:
    python3 locate_source.py <record_dir> [options]
    
Options:
    --vmlinux <path>         Path to vmlinux with debug info
    --analyzer <path>        Path to DDRD Analyzer binary
    --ll-dir <path>          Path to directory with .instrumented.ll files
    --addr2line <path>       Path to addr2line binary (default: addr2line)
    --output <path>          Output JSON path (default: <record_dir>/source_locations.json)

Output: source_locations.json with file:line for each racing access.
"""

import json
import os
import re
import subprocess
import sys


def load_metadata(record_dir):
    """Load metadata.json from record directory."""
    path = os.path.join(record_dir, "metadata.json")
    with open(path) as f:
        return json.load(f)


def load_crash_report(record_dir):
    """Load crash_report.txt."""
    path = os.path.join(record_dir, "crash_report.txt")
    with open(path) as f:
        return f.read()


def locate_via_analyzer(analyzer_bin, ll_dir, varnames):
    """
    Use DDRD Analyzer to map VarName hash -> source file:line.
    
    Analyzer mode 1: ./analyzer <ll_dir> <hash>
    Searches .instrumented.ll files for kccwf_rec_mem_access calls
    with matching VarName hash constant.
    """
    results = []
    for vn in varnames:
        varname_hash = str(vn['varname'])
        try:
            proc = subprocess.run(
                [analyzer_bin, ll_dir, varname_hash],
                capture_output=True, text=True, timeout=60
            )
            output = proc.stdout.strip()
            if proc.returncode == 0 and output:
                # Analyzer outputs: file:line:column
                lines = output.strip().split('\n')
                for line in lines:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        results.append({
                            "varname": vn['varname'],
                            "block_line": vn['block_line'],
                            "ir_line": vn['ir_line'],
                            "source_file": parts[0],
                            "source_line": int(parts[1]),
                            "source_col": int(parts[2]) if len(parts) > 2 else 0,
                            "method": "analyzer",
                        })
            else:
                print(f"  [locate] Analyzer returned no result for hash {varname_hash}", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print(f"  [locate] Analyzer timed out for hash {varname_hash}", file=sys.stderr)
        except FileNotFoundError:
            print(f"  [locate] Analyzer binary not found: {analyzer_bin}", file=sys.stderr)
            break
    
    return results


def locate_via_addr2line(addr2line_bin, vmlinux, crash_report):
    """
    Use addr2line to resolve function+offset -> file:line.
    
    Parses crash report for patterns like:
        Function: record_root_in_trans+0x806/0xab0
    Then uses addr2line with vmlinux to resolve.
    """
    results = []
    
    # Extract function+offset pairs from crash report
    # Group them by stack (DATARACE vs OTHER_INFO)
    stacks = []
    current_label = None
    current_funcs = []
    
    for line in crash_report.split('\n'):
        if 'DATARACE' in line:
            if current_funcs:
                stacks.append((current_label, current_funcs))
            current_label = 'DATARACE'
            current_funcs = []
        elif 'OTHER_INFO' in line:
            if current_funcs:
                stacks.append((current_label, current_funcs))
            current_label = 'OTHER_INFO'
            current_funcs = []
        elif 'END' in line and '====' in line:
            if current_funcs:
                stacks.append((current_label, current_funcs))
            current_label = None
            current_funcs = []
        elif line.startswith('Function:'):
            func_str = line.split('Function:')[1].strip()
            current_funcs.append(func_str)
    
    if current_funcs:
        stacks.append((current_label, current_funcs))
    
    # For each stack, find the first non-infrastructure function
    # (skip watchpoints_monitor, kccwf_rec_mem_access, set_report_info)
    infra_funcs = {
        'watchpoints_monitor', 'kccwf_rec_mem_access', 'kccwf_rec_free',
        'set_report_info', 'do_syscall_64', 'entry_SYSCALL_64_after_hwframe',
        'process_scheduled_works', 'worker_thread', 'kthread',
        'ret_from_fork', 'ret_from_fork_asm',
    }
    
    for label, funcs in stacks:
        for func_str in funcs:
            # Parse function+offset, e.g. record_root_in_trans+0x806/0xab0
            m = re.match(r'(\w+)\+0x([0-9a-fA-F]+)/0x([0-9a-fA-F]+)', func_str)
            if not m:
                continue
            func_name = m.group(1)
            if func_name in infra_funcs:
                continue
            
            # Use addr2line to resolve
            try:
                # First, find function address using nm or objdump
                # Then add offset
                loc = resolve_addr2line(addr2line_bin, vmlinux, func_str)
                if loc:
                    results.append({
                        "function": func_name,
                        "func_offset": func_str,
                        "source_file": loc['file'],
                        "source_line": loc['line'],
                        "label": label or "UNKNOWN",
                        "method": "addr2line",
                    })
                    break  # Only need first real function per stack
            except Exception as e:
                print(f"  [locate] addr2line error for {func_str}: {e}", file=sys.stderr)
    
    return results


def resolve_addr2line(addr2line_bin, vmlinux, func_offset_str):
    """
    Resolve a function+offset string to source location using addr2line.
    
    Steps:
    1. Use `nm vmlinux | grep ' func_name$'` to get base address
    2. Add offset to get absolute address
    3. Use addr2line to resolve
    """
    m = re.match(r'(\w+)\+0x([0-9a-fA-F]+)/0x([0-9a-fA-F]+)', func_offset_str)
    if not m:
        return None
    
    func_name = m.group(1)
    offset = int(m.group(2), 16)
    
    # Find function base address via nm
    try:
        nm_proc = subprocess.run(
            ["nm", vmlinux],
            capture_output=True, text=True, timeout=120
        )
        # Search for the function line: <addr> T func_name or <addr> t func_name
        pattern = re.compile(r'^([0-9a-fA-F]+)\s+[tTwW]\s+' + re.escape(func_name) + r'$', re.MULTILINE)
        nm_match = pattern.search(nm_proc.stdout)
        if not nm_match:
            # Try alternative: lowercase
            pattern2 = re.compile(r'^([0-9a-fA-F]+)\s+[tTwWrR]\s+' + re.escape(func_name) + r'\b', re.MULTILINE)
            nm_match = pattern2.search(nm_proc.stdout)
        
        if not nm_match:
            print(f"  [locate] Cannot find {func_name} in vmlinux symbol table", file=sys.stderr)
            return None
        
        base_addr = int(nm_match.group(1), 16)
        target_addr = base_addr + offset
        addr_hex = format(target_addr, 'x')
        
        # Use addr2line
        a2l_proc = subprocess.run(
            [addr2line_bin, "-e", vmlinux, "-f", "-i", addr_hex],
            capture_output=True, text=True, timeout=30
        )
        
        # Parse output: function\nfile:line  (pairs, innermost inline first)
        # When -i is used, multiple frames appear; prefer a .c file over headers.
        # addr2line may append " (discriminator N)" — strip that before parsing.
        lines = a2l_proc.stdout.strip().split('\n')
        candidates = []
        for i in range(0, len(lines) - 1, 2):
            file_line = lines[i + 1] if i + 1 < len(lines) else ""
            # Remove discriminator suffix, e.g. "file.c:123 (discriminator 2)"
            file_line = re.sub(r'\s*\(discriminator \d+\)\s*$', '', file_line)
            if ':' in file_line and '?' not in file_line:
                parts = file_line.split(':')
                fpath = parts[0]
                fline = int(parts[1]) if parts[1].isdigit() else 0
                candidates.append({'file': fpath, 'line': fline})

        if not candidates:
            return None

        # Prefer .c files over headers to avoid over-broad inline patching
        for c in candidates:
            if c['file'].endswith('.c'):
                return c
        # Fallback: return first (innermost) candidate
        return candidates[0]
        
    except subprocess.TimeoutExpired:
        print(f"  [locate] nm/addr2line timed out for {func_name}", file=sys.stderr)
        return None


def extract_source_files(locations):
    """Extract unique source .c files from locations (for KCSAN instrumentation targets)."""
    files = set()
    for loc in locations:
        src = loc.get('source_file', '')
        if src.endswith('.c') or src.endswith('.h'):
            # Normalize path: strip leading ./ or absolute prefix
            basename = os.path.basename(src)
            # Keep relative path from kernel src root
            files.add(src)
    return sorted(files)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Locate kernel source for crash reports")
    parser.add_argument("record_dir", help="Path to parsed record directory")
    parser.add_argument("--vmlinux", help="Path to vmlinux with debug symbols")
    parser.add_argument("--analyzer", help="Path to DDRD Analyzer binary")
    parser.add_argument("--ll-dir", help="Path to .instrumented.ll files directory")
    parser.add_argument("--addr2line", default="addr2line", help="Path to addr2line")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()
    
    record_dir = args.record_dir
    output_path = args.output or os.path.join(record_dir, "source_locations.json")
    
    metadata = load_metadata(record_dir)
    crash_report = load_crash_report(record_dir)
    varnames = metadata.get('varnames', [])
    
    all_locations = []
    
    # Strategy 1: Analyzer (if ll files available)
    if args.analyzer and args.ll_dir:
        if os.path.isfile(args.analyzer) and os.path.isdir(args.ll_dir):
            print(f"[locate] Trying Analyzer: {args.analyzer}")
            analyzer_results = locate_via_analyzer(args.analyzer, args.ll_dir, varnames)
            if analyzer_results:
                all_locations.extend(analyzer_results)
                print(f"[locate] Analyzer found {len(analyzer_results)} locations")
    
    # Strategy 2: addr2line (if vmlinux available)
    if args.vmlinux:
        if os.path.isfile(args.vmlinux):
            print(f"[locate] Trying addr2line with vmlinux: {args.vmlinux}")
            a2l_results = locate_via_addr2line(args.addr2line, args.vmlinux, crash_report)
            if a2l_results:
                all_locations.extend(a2l_results)
                print(f"[locate] addr2line found {len(a2l_results)} locations")
    
    if not all_locations:
        # Fallback: extract function names only (useful for targeting KCSAN)
        print("[locate] No precise locations found, extracting function names only")
        for func in metadata.get('kernel_functions', []):
            if func not in {'watchpoints_monitor', 'kccwf_rec_mem_access',
                           'set_report_info', 'do_syscall_64',
                           'entry_SYSCALL_64_after_hwframe', '0x0',
                           'process_scheduled_works', 'worker_thread',
                           'kthread', 'ret_from_fork', 'ret_from_fork_asm',
                           'kccwf_rec_free'}:
                all_locations.append({
                    "function": func,
                    "method": "function_name_only",
                })
    
    # Extract target source files for KCSAN instrumentation
    source_files = extract_source_files(all_locations)
    
    result = {
        "locations": all_locations,
        "source_files": source_files,
        "varnames": varnames,
    }
    
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"[locate] Results saved to {output_path}")
    print(f"[locate] Source files for KCSAN: {source_files}")
    
    return result


if __name__ == "__main__":
    main()
