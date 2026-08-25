#!/usr/bin/env python3
"""
parse_validated_db.py - Parse validated_uaf.db and extract records.

Usage:
    python3 parse_validated_db.py <db_path> <output_dir> [--syz-db /path/to/syz-db]

Extracts from each record:
  - crash_report.txt   : The CRASH REPORT section
  - prog0.syz          : TRIGGERING PROGRAM 0
  - prog1.syz          : TRIGGERING PROGRAM 1
  - barrier_info.json  : BARRIER INFO (GroupSize, ProcList, etc.)
  - replay_plan.json   : REPLAY PLAN (Delays)
  - metadata.json      : VarName hashes, callstacks, functions
  - history/            : REPLAY HISTORY programs (hist_N_prog0.syz, hist_N_prog1.syz, ...)
"""

import json
import os
import re
import subprocess
import sys
import tempfile


def run_syz_db_print(syz_db_bin, db_path):
    """Run syz-db print and return raw output."""
    # syz-db print needs write permission, so copy to temp
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        subprocess.run(["cp", db_path, tmp.name], check=True)
        result = subprocess.run(
            [syz_db_bin, "print", tmp.name],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print(f"[ERROR] syz-db print failed: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        return result.stdout
    finally:
        os.unlink(tmp.name)


def split_records(raw_text):
    """Split syz-db print output into individual records.
    
    Each record starts with a hex key line (e.g., 1251ba177afd338f-27d5952dff89cc64-...)
    """
    # Pattern for record key: 16hex-16hex-16hex-16hex
    key_pattern = re.compile(r'^([0-9a-f]{16}-[0-9a-f]{16}-[0-9a-f]{16}-[0-9a-f]{16})$', re.MULTILINE)
    
    keys = []
    positions = []
    for m in key_pattern.finditer(raw_text):
        keys.append(m.group(1))
        positions.append(m.start())
    
    records = []
    for i, (key, pos) in enumerate(zip(keys, positions)):
        end = positions[i + 1] if i + 1 < len(positions) else len(raw_text)
        body = raw_text[pos + len(key):end].strip()
        records.append((key, body))
    
    return records


def parse_crash_report(body):
    """Extract CRASH REPORT section."""
    m = re.search(r'=== CRASH REPORT ===\n(.*?)(?==== TRIGGERING PROGRAMS ===)', body, re.DOTALL)
    if not m:
        return ""
    return m.group(1).strip()


def parse_varnames(crash_report):
    """Extract VarName info from crash report."""
    varnames = []
    pattern = re.compile(
        r'VarName\s+(\d+),\s*BlockLineNumber\s+(\d+),\s*IrLineNumber\s+(\d+)(?:,\s*(?:is write|watchpoint index)\s+(\d+))?'
    )
    for m in pattern.finditer(crash_report):
        varnames.append({
            "varname": int(m.group(1)),
            "block_line": int(m.group(2)),
            "ir_line": int(m.group(3)),
            "extra": int(m.group(4)) if m.group(4) else None,
        })
    return varnames


def parse_callstacks(crash_report):
    """Extract function callstacks from crash report."""
    stacks = []
    current_stack = []
    in_stack = False
    stack_label = None

    for line in crash_report.split('\n'):
        if line.startswith('Function:'):
            func = line.split('Function:')[1].strip()
            current_stack.append(func)
            in_stack = True
        elif line.startswith('============') and 'DATARACE' in line:
            stack_label = 'DATARACE'
            current_stack = []
            in_stack = True
        elif line.startswith('============') and 'OTHER_INFO' in line:
            if current_stack:
                stacks.append({"label": stack_label or "STACK", "functions": current_stack})
            stack_label = 'OTHER_INFO'
            current_stack = []
            in_stack = True
        elif line.startswith('=====') and 'END' in line:
            if current_stack:
                stacks.append({"label": stack_label or "STACK", "functions": current_stack})
            current_stack = []
            in_stack = False
            stack_label = None
        elif in_stack and not line.startswith('VarName') and not line.startswith('Callstack') and not line.startswith('Found') and not line.startswith('Function:'):
            # Possibly auxiliary data in crash report, skip
            pass
    
    if current_stack:
        stacks.append({"label": stack_label or "STACK", "functions": current_stack})
    
    return stacks


def parse_callstack_hashes(crash_report):
    """Extract callstack hash pair."""
    m = re.search(r'Callstack hash 1.*?:\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)', crash_report)
    if m:
        return [m.group(1), m.group(2)]
    return []


def parse_kernel_functions(crash_report):
    """Extract actual kernel functions (strip offset) from stacks."""
    funcs = set()
    pattern = re.compile(r'Function:\s+(\w+)\+0x')
    for m in pattern.finditer(crash_report):
        funcs.add(m.group(1))
    return sorted(funcs)


def parse_programs(body):
    """Extract PROGRAM 0 and PROGRAM 1 from TRIGGERING PROGRAMS section."""
    m = re.search(r'=== TRIGGERING PROGRAMS ===(.*?)(?==== BARRIER INFO ===)', body, re.DOTALL)
    if not m:
        return "", ""
    
    programs_text = m.group(1)
    
    # Split on --- PROGRAM N ---
    prog0_match = re.search(r'--- PROGRAM 0 ---\n(.*?)(?=--- PROGRAM 1 ---)', programs_text, re.DOTALL)
    prog1_match = re.search(r'--- PROGRAM 1 ---\n(.*?)$', programs_text, re.DOTALL)
    
    prog0 = prog0_match.group(1).strip() if prog0_match else ""
    prog1 = prog1_match.group(1).strip() if prog1_match else ""
    
    return prog0, prog1


def parse_barrier_info(body):
    """Extract BARRIER INFO section."""
    m = re.search(r'=== BARRIER INFO ===(.*?)(?==== REPLAY PLAN ===)', body, re.DOTALL)
    if not m:
        return {}
    
    text = m.group(1)
    info = {}
    
    for line in text.strip().split('\n'):
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip()
            val = val.strip()
            if key == 'Participants':
                info['participants'] = int(val, 0)
            elif key == 'GroupID':
                info['group_id'] = int(val)
            elif key == 'GroupSize':
                info['group_size'] = int(val)
            elif key == 'ProcList':
                # Parse [0 1] format
                m2 = re.search(r'\[([\d\s]+)\]', val)
                if m2:
                    info['proc_list'] = [int(x) for x in m2.group(1).split()]
    
    return info


def parse_replay_plan(body):
    """Extract REPLAY PLAN section."""
    m = re.search(r'=== REPLAY PLAN ===(.*?)(?==== REPLAY HISTORY ===)', body, re.DOTALL)
    if not m:
        return {}
    
    text = m.group(1).strip()
    plan = {}
    
    for line in text.split('\n'):
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip()
            val = val.strip()
            if key == 'Delays':
                if val == '<none>':
                    plan['delays'] = []
                else:
                    plan['delays'] = val
    
    return plan


def parse_validation_metadata(body):
    """Extract threshold and origin provenance from new validated records."""
    match = re.search(
        r'=== VALIDATION METADATA ===\n(.*?)(?==== REPLAY PLAN ===)',
        body,
        re.DOTALL,
    )
    if not match:
        return {}
    result = {}
    integer_fields = {
        'AdmissionThresholdUs': 'admission_threshold_us',
        'CollectionThresholdUs': 'collection_threshold_us',
        'ObservedTimeDiffNs': 'observed_time_diff_ns',
    }
    for field, key in integer_fields.items():
        value = re.search(rf'^{field}:\s*(\d+)$', match.group(1), re.MULTILINE)
        if value:
            result[key] = int(value.group(1))
    origin = re.search(r'^OriginMatch:\s*(\S+)$', match.group(1), re.MULTILINE)
    if origin:
        result['origin_match'] = origin.group(1)
    expanded = re.search(r'^Expanded:\s*(true|false)$', match.group(1), re.MULTILINE)
    if expanded:
        result['expanded'] = expanded.group(1) == 'true'
    return result


def parse_replay_history(body):
    """Extract REPLAY HISTORY section.
    
    Returns a list of history entries, each with:
      - group_id: int
      - timestamp: str
      - vm_index: int
      - programs: list of str (syzkaller program text)
    """
    m = re.search(r'=== REPLAY HISTORY ===(.*)', body, re.DOTALL)
    if not m:
        return []
    
    text = m.group(1)
    entries = []
    
    # Split by history entry markers
    parts = re.split(r'--- HISTORY (\d+) ---', text)
    # parts[0] is header info (HistoryCount, OriginalCount, etc.)
    # parts[1] is index "0", parts[2] is body of history 0, etc.
    
    i = 1
    while i + 1 < len(parts):
        hist_idx = int(parts[i])
        hist_body = parts[i + 1]
        
        entry = {
            'index': hist_idx,
            'group_id': 0,
            'timestamp': '',
            'vm_index': 0,
            'programs': [],
        }
        
        # Parse header fields
        gid_m = re.search(r'GroupID:\s*(\d+)', hist_body)
        if gid_m:
            entry['group_id'] = int(gid_m.group(1))
        ts_m = re.search(r'Timestamp:\s*(\S+)', hist_body)
        if ts_m:
            entry['timestamp'] = ts_m.group(1)
        vm_m = re.search(r'VMIndex:\s*(\d+)', hist_body)
        if vm_m:
            entry['vm_index'] = int(vm_m.group(1))
        
        # Parse programs within this history entry
        prog_parts = re.split(r'-- HISTORY PROGRAM (\d+) --', hist_body)
        j = 1
        while j + 1 < len(prog_parts):
            prog_idx = int(prog_parts[j])
            prog_text = prog_parts[j + 1].strip()
            # Remove trailing metadata that might be from next section
            # Programs end before the next "---" marker or EOF
            lines = []
            for line in prog_text.split('\n'):
                if line.startswith('---') or line.startswith('==='):
                    break
                lines.append(line)
            prog_text = '\n'.join(lines).strip()
            if prog_text:
                entry['programs'].append(prog_text)
            j += 2
        
        entries.append(entry)
        i += 2
    
    return entries


def parse_one_record(key, body):
    """Parse a single record into structured data."""
    crash_report = parse_crash_report(body)
    prog0, prog1 = parse_programs(body)
    barrier_info = parse_barrier_info(body)
    validation_metadata = parse_validation_metadata(body)
    replay_plan = parse_replay_plan(body)
    replay_history = parse_replay_history(body)
    
    varnames = parse_varnames(crash_report)
    callstacks = parse_callstacks(crash_report)
    callstack_hashes = parse_callstack_hashes(crash_report)
    kernel_functions = parse_kernel_functions(crash_report)
    
    metadata = {
        "key": key,
        "varnames": varnames,
        "callstack_hashes": callstack_hashes,
        "kernel_functions": kernel_functions,
        "callstacks": callstacks,
        "validation": validation_metadata,
    }
    
    return {
        "key": key,
        "crash_report": crash_report,
        "prog0": prog0,
        "prog1": prog1,
        "barrier_info": barrier_info,
        "replay_plan": replay_plan,
        "replay_history": replay_history,
        "metadata": metadata,
    }


def save_record(record, output_dir, index):
    """Save parsed record to disk."""
    rec_dir = os.path.join(output_dir, f"record_{index:04d}_{record['key'][:16]}")
    os.makedirs(rec_dir, exist_ok=True)
    
    with open(os.path.join(rec_dir, "crash_report.txt"), 'w') as f:
        f.write(record['crash_report'])
    
    with open(os.path.join(rec_dir, "prog0.syz"), 'w') as f:
        f.write(record['prog0'])
    
    with open(os.path.join(rec_dir, "prog1.syz"), 'w') as f:
        f.write(record['prog1'])
    
    with open(os.path.join(rec_dir, "barrier_info.json"), 'w') as f:
        json.dump(record['barrier_info'], f, indent=2)
    
    with open(os.path.join(rec_dir, "replay_plan.json"), 'w') as f:
        json.dump(record['replay_plan'], f, indent=2)
    
    with open(os.path.join(rec_dir, "metadata.json"), 'w') as f:
        json.dump(record['metadata'], f, indent=2)
    
    # Save replay history programs
    replay_history = record.get('replay_history', [])
    if replay_history:
        hist_dir = os.path.join(rec_dir, "history")
        os.makedirs(hist_dir, exist_ok=True)
        for entry in replay_history:
            for pidx, prog_text in enumerate(entry['programs']):
                fname = f"hist_{entry['index']:03d}_prog{pidx}.syz"
                with open(os.path.join(hist_dir, fname), 'w') as f:
                    f.write(prog_text + '\n')
        # Save history metadata
        hist_meta = [{
            'index': e['index'],
            'group_id': e['group_id'],
            'timestamp': e['timestamp'],
            'vm_index': e['vm_index'],
            'num_programs': len(e['programs']),
        } for e in replay_history]
        with open(os.path.join(hist_dir, "history_meta.json"), 'w') as f:
            json.dump(hist_meta, f, indent=2)
        print(f"  Saved {len(replay_history)} history entries ({sum(len(e['programs']) for e in replay_history)} programs)")
    
    return rec_dir


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <db_path> <output_dir> [--syz-db /path/to/syz-db]")
        sys.exit(1)
    
    db_path = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Default syz-db path (relative to DDRD-syzkaller)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    syzkaller_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    syz_db_bin = os.path.join(syzkaller_root, "bin", "syz-db")
    
    # Parse --syz-db option
    for i, arg in enumerate(sys.argv):
        if arg == "--syz-db" and i + 1 < len(sys.argv):
            syz_db_bin = sys.argv[i + 1]
    
    if not os.path.isfile(db_path):
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isfile(syz_db_bin):
        print(f"[ERROR] syz-db binary not found: {syz_db_bin}", file=sys.stderr)
        sys.exit(1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[parse_validated_db] Reading database: {db_path}")
    raw = run_syz_db_print(syz_db_bin, db_path)
    records = split_records(raw)
    
    print(f"[parse_validated_db] Found {len(records)} records")
    
    all_records = []
    for i, (key, body) in enumerate(records):
        record = parse_one_record(key, body)
        rec_dir = save_record(record, output_dir, i)
        all_records.append({
            "index": i,
            "key": key,
            "dir": rec_dir,
            "kernel_functions": record['metadata']['kernel_functions'],
            "varnames": record['metadata']['varnames'],
        })
        print(f"  [{i}] key={key[:16]}... funcs={record['metadata']['kernel_functions'][:3]}...")
    
    # Write summary
    summary_path = os.path.join(output_dir, "summary.json")
    with open(summary_path, 'w') as f:
        json.dump(all_records, f, indent=2)
    
    print(f"[parse_validated_db] Summary written to {summary_path}")
    return all_records


if __name__ == "__main__":
    main()
