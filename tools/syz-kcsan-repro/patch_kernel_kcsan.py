#!/usr/bin/env python3
"""
patch_kernel_kcsan.py - Patch kernel source for targeted KCSAN detection.

Uses DeepSeek LLM to precisely analyze source code and determine:
  1. Which variable is being raced (from crash report + source context)
  2. Whether the access is a read or write
  3. The exact __kcsan_check_access() call to insert

Pipeline:
  1. Disables global KCSAN compiler instrumentation (CFLAGS_KCSAN := empty)
  2. For each source location, sends code context + crash report to LLM
  3. LLM returns the precise __kcsan_check_access() line
  4. Inserts the check and adds #include <linux/kcsan-checks.h>

Usage:
    python3 patch_kernel_kcsan.py <kernel_src> <source_locations.json> [options]

Options:
    --record-dir <path>      Record directory (to read crash_report.txt)
    --dry-run                Show what would be patched without modifying files
    --restore                Restore original files from .orig backups
    --context-lines <n>      Lines of context around target (default: 40)
    --api-key <key>          DeepSeek API key (or env DEEPSEEK_API_KEY)
    --output-log <path>      Write patch log to file

Environment:
    DEEPSEEK_API_KEY         DeepSeek API key
"""

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path


KCSAN_INCLUDE = '#include <linux/kcsan-checks.h>'

# Files that should never be patched
SKIP_FILES = {
    'kernel/kcsan/core.c',
    'kernel/kcsan/report.c',
    'kernel/kcsan/debugfs.c',
    'kernel/kcsan/selftest.c',
    'kernel/kcsan/kcsan_test.c',
}

# Widely-included kernel headers: patching these would instrument EVERY caller
# across the entire kernel, producing over-broad KCSAN reports from unrelated
# subsystems.  addr2line often resolves to these because the racing instruction
# is inside an inlined helper (list_add, spin_lock, etc.).  We skip them and
# let the record rely on the OTHER location (which is usually in a .c file).
SKIP_HEADERS = {
    'include/linux/list.h',
    'include/linux/hlist.h',
    'include/linux/llist.h',
    'include/linux/rculist.h',
    'include/linux/spinlock.h',
    'include/linux/rwlock.h',
    'include/linux/mutex.h',
    'include/linux/seqlock.h',
    'include/linux/atomic.h',
    'include/linux/refcount.h',
    'include/linux/kref.h',
    'include/linux/wait.h',
    'include/linux/completion.h',
    'include/linux/workqueue.h',
    'include/linux/sched.h',
    'include/linux/sched/signal.h',
    'include/linux/percpu-refcount.h',
    'include/linux/rcupdate.h',
    'include/linux/rbtree.h',
    'include/asm-generic/atomic-instrumented.h',
    'include/asm-generic/bitops/instrumented-atomic.h',
    'include/asm-generic/bitops/instrumented-non-atomic.h',
    'include/asm-generic/bitops/instrumented-lock.h',
}

# ============================================================
# LLM-based source analysis
# ============================================================

SYSTEM_PROMPT = """\
You are a Linux kernel concurrency expert. Your task is to analyze a data race \
report and the corresponding kernel source code, then generate the precise \
`__kcsan_check_access()` call to insert before the racing memory access.

## KCSAN API
```c
#include <linux/kcsan-checks.h>

// Check a read access:
__kcsan_check_access(&variable, sizeof(variable), 0);

// Check a write access:
__kcsan_check_access(&variable, sizeof(variable), KCSAN_ACCESS_WRITE);
```

## Rules
1. Identify the **exact shared variable** being raced on (e.g., `root->last_trans`),
   NOT a function argument or unrelated variable.
2. If the target line calls a function (like `btrfs_set_root_last_trans(root, val)`),
   look INSIDE that function (or its inline definition in headers) to find the
   actual variable being written/read.
3. For inline functions using READ_ONCE/WRITE_ONCE, the raced variable is the
   argument to READ_ONCE/WRITE_ONCE.
4. Match the indentation of the surrounding code exactly.
5. The check must be inserted BEFORE the racing access line.
6. Use tabs for indentation (kernel style), not spaces.

## Output format
Reply with ONLY a JSON object (no markdown fencing, no explanation):
{
  "variable": "root->last_trans",
  "is_write": true,
  "check_line": "\\t\\t__kcsan_check_access(&root->last_trans, sizeof(root->last_trans), KCSAN_ACCESS_WRITE); /* KCSAN targeted */",
  "reasoning": "brief one-line explanation"
}
"""


def call_deepseek(api_key, source_context, crash_excerpt, location_info, context_lines=40):
    """
    Call DeepSeek to analyze a source location and generate __kcsan_check_access().

    Returns dict with 'variable', 'is_write', 'check_line', 'reasoning' or None.
    """
    from openai import OpenAI

    user_prompt = f"""\
## Data Race Report (excerpt)
```
{crash_excerpt}
```

## Target Location
- File: {location_info['source_file']}
- Line: {location_info['source_line']}
- Function: {location_info.get('function', 'unknown')}
- Role: {location_info.get('label', 'UNKNOWN')} (DATARACE = typically the write side, OTHER_INFO = the conflicting access)

## Source Code (around line {location_info['source_line']}, marked with >>>)
```c
{source_context}
```

Analyze the data race and generate the precise `__kcsan_check_access()` call.
Output ONLY the JSON object as specified.
"""

    client = OpenAI(api_key=api_key, base_url='https://api.deepseek.com')

    try:
        resp = client.chat.completions.create(
            model='deepseek-chat',
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': user_prompt},
            ],
            max_tokens=500,
            temperature=0.1,  # Low temperature for precise code generation
            timeout=30,
        )

        content = resp.choices[0].message.content.strip()

        # Strip markdown code fencing if present
        if content.startswith('```'):
            content = re.sub(r'^```\w*\n?', '', content)
            content = re.sub(r'\n?```$', '', content)
            content = content.strip()

        result = json.loads(content)

        # Validate required fields
        if 'check_line' not in result or 'variable' not in result:
            print(f"  [llm] Invalid response: missing required fields", file=sys.stderr)
            return None

        return result

    except json.JSONDecodeError as e:
        print(f"  [llm] Failed to parse JSON response: {e}", file=sys.stderr)
        print(f"  [llm] Raw response: {content}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [llm] API error: {e}", file=sys.stderr)
        return None


# ============================================================
# File utilities
# ============================================================

def normalize_source_path(source_file, kernel_src):
    """Extract relative kernel path from source_file."""
    if not os.path.isabs(source_file):
        return source_file

    top_dirs = ['fs/', 'drivers/', 'net/', 'kernel/', 'mm/', 'block/', 'lib/',
                'crypto/', 'security/', 'sound/', 'arch/', 'include/']

    for td in top_dirs:
        idx = source_file.find('/' + td)
        if idx >= 0:
            return source_file[idx + 1:]

    return os.path.basename(source_file)


def find_file_in_kernel(kernel_src, rel_path):
    """Find the actual file in the kernel source tree."""
    candidate = os.path.join(kernel_src, rel_path)
    if os.path.isfile(candidate):
        return candidate

    if '/' not in rel_path:
        for root, dirs, files in os.walk(kernel_src):
            if rel_path in files:
                return os.path.join(root, rel_path)

    return None


def get_source_context(filepath, line_num, context_lines=40):
    """Read source code around target line with line numbers."""
    with open(filepath, 'r') as f:
        lines = f.readlines()

    start = max(0, line_num - 1 - context_lines)
    end = min(len(lines), line_num + context_lines)

    result = []
    for i in range(start, end):
        marker = " >>> " if i == line_num - 1 else "     "
        result.append(f"{i + 1:5d}{marker}{lines[i].rstrip()}")

    return '\n'.join(result)


def get_crash_excerpt(record_dir, max_lines=60):
    """Read crash report excerpt from record directory."""
    crash_path = os.path.join(record_dir, 'crash_report.txt')
    if not os.path.isfile(crash_path):
        return "(crash report not available)"

    with open(crash_path, 'r') as f:
        lines = f.readlines()

    return ''.join(lines[:max_lines]).strip()


def ensure_kcsan_include(lines):
    """Ensure #include <linux/kcsan-checks.h> is present."""
    for line in lines:
        if 'kcsan-checks.h' in line:
            return lines

    last_include_idx = -1
    for i, line in enumerate(lines):
        if line.strip().startswith('#include'):
            last_include_idx = i

    if last_include_idx >= 0:
        new_lines = lines[:last_include_idx + 1]
        new_lines.append(KCSAN_INCLUDE + '\n')
        new_lines.extend(lines[last_include_idx + 1:])
        return new_lines

    return [KCSAN_INCLUDE + '\n'] + lines


# ============================================================
# Makefile patching
# ============================================================

def patch_makefile_kcsan(kernel_src, dry_run=False):
    """Disable global KCSAN instrumentation."""
    makefile_path = os.path.join(kernel_src, 'scripts', 'Makefile.kcsan')
    if not os.path.isfile(makefile_path):
        print(f"[patch] ERROR: {makefile_path} not found", file=sys.stderr)
        return False

    with open(makefile_path, 'r') as f:
        content = f.read()

    if 'export CFLAGS_KCSAN :=' in content and '$(kcsan-cflags)' not in content:
        print(f"[patch] Makefile.kcsan already patched (CFLAGS_KCSAN empty)")
        return True

    orig = makefile_path + '.orig'
    if not os.path.exists(orig):
        shutil.copy2(makefile_path, orig)

    new_content = re.sub(
        r'export CFLAGS_KCSAN\s*:=\s*\$\(kcsan-cflags\)',
        'export CFLAGS_KCSAN :=',
        content
    )

    if new_content == content:
        print(f"[patch] WARNING: Could not find CFLAGS_KCSAN export line")
        return False

    if dry_run:
        print(f"[patch] DRY RUN: Would empty CFLAGS_KCSAN in Makefile.kcsan")
        return True

    with open(makefile_path, 'w') as f:
        f.write(new_content)

    print(f"[patch] Patched Makefile.kcsan: CFLAGS_KCSAN := (empty)")
    return True


def patch_core_targeted_filter(kernel_src, dry_run=False):
    """
    Patch kernel/kcsan/core.c to add the targeted-mode filter.

    Three changes:
    1. Add per-CPU bool kcsan_manual_check variable
    2. In check_access(): skip if kcsan_manual_check is false (compiler-instrumented)
    3. In __kcsan_check_access(): set kcsan_manual_check=true before calling check_access

    This ensures only manually inserted __kcsan_check_access() calls trigger
    watchpoints; all compiler-instrumented __tsan_* calls are silently skipped.
    """
    core_path = os.path.join(kernel_src, 'kernel', 'kcsan', 'core.c')
    if not os.path.isfile(core_path):
        print(f"[patch] ERROR: {core_path} not found", file=sys.stderr)
        return False

    with open(core_path, 'r') as f:
        content = f.read()

    # Check if already patched
    if 'kcsan_manual_check' in content:
        print(f"[patch] core.c already patched (targeted filter present)")
        return True

    # Backup
    orig = core_path + '.kcsan_orig'
    if not os.path.exists(orig):
        shutil.copy2(core_path, orig)

    # Patch 1: Add per-CPU variable after kcsan_skip definition
    old_skip_decl = 'static DEFINE_PER_CPU(long, kcsan_skip);\n\n/* For kcsan_prandom_u32_max(). */'
    new_skip_decl = (
        'static DEFINE_PER_CPU(long, kcsan_skip);\n'
        '\n'
        '/*\n'
        ' * Targeted-mode filter: when true, only manually inserted\n'
        ' * __kcsan_check_access() calls are processed; all compiler-instrumented\n'
        ' * __tsan_* calls are silently skipped.  Set by __kcsan_check_access()\n'
        ' * and cleared by check_access() after use.\n'
        ' */\n'
        'static DEFINE_PER_CPU(bool, kcsan_manual_check);\n'
        '\n'
        '/* For kcsan_prandom_u32_max(). */'
    )
    content = content.replace(old_skip_decl, new_skip_decl, 1)

    # Patch 2: Add targeted filter in check_access() after ASSERT filter
    old_assert_block = (
        '\tif (type & KCSAN_ACCESS_ASSERT)\n'
        '\t\treturn;\n'
        '\n'
        'again:'
    )
    new_assert_block = (
        '\tif (type & KCSAN_ACCESS_ASSERT)\n'
        '\t\treturn;\n'
        '\n'
        '\t/*\n'
        '\t * Targeted-mode filter: skip compiler-instrumented __tsan_* accesses.\n'
        '\t * Only __kcsan_check_access() sets kcsan_manual_check before calling\n'
        '\t * here, so all other callers (compiler instrumentation) are blocked.\n'
        '\t * This makes CFLAGS_KCSAN emptying a "belt" and this filter the\n'
        '\t * "suspenders" \u2014 together they guarantee only targeted watchpoints.\n'
        '\t */\n'
        '\tif (!this_cpu_read(kcsan_manual_check))\n'
        '\t\treturn;\n'
        '\tthis_cpu_write(kcsan_manual_check, false);\n'
        '\n'
        'again:'
    )
    content = content.replace(old_assert_block, new_assert_block, 1)

    # Patch 3: Set flag in __kcsan_check_access()
    old_check_fn = (
        'void __kcsan_check_access(const volatile void *ptr, size_t size, int type)\n'
        '{\n'
        '\tcheck_access(ptr, size, type, _RET_IP_);\n'
        '}\n'
        'EXPORT_SYMBOL(__kcsan_check_access);'
    )
    new_check_fn = (
        'void __kcsan_check_access(const volatile void *ptr, size_t size, int type)\n'
        '{\n'
        '\tthis_cpu_write(kcsan_manual_check, true);\n'
        '\tcheck_access(ptr, size, type, _RET_IP_);\n'
        '}\n'
        'EXPORT_SYMBOL(__kcsan_check_access);'
    )
    content = content.replace(old_check_fn, new_check_fn, 1)

    # Verify all patches applied
    if 'kcsan_manual_check' not in content:
        print(f"[patch] ERROR: Failed to apply core.c targeted filter patches", file=sys.stderr)
        # Restore backup
        if os.path.exists(orig):
            shutil.copy2(orig, core_path)
            os.remove(orig)
        return False

    if dry_run:
        print(f"[patch] DRY RUN: Would add targeted filter to kernel/kcsan/core.c")
        # Restore backup for dry-run
        if os.path.exists(orig):
            shutil.copy2(orig, core_path)
            os.remove(orig)
        return True

    with open(core_path, 'w') as f:
        f.write(content)

    print(f"[patch] Patched kernel/kcsan/core.c: targeted-mode filter added")
    return True


# ============================================================
# Source file patching
# ============================================================

def patch_source_file(filepath, locations, kernel_src, api_key, record_dir,
                      context_lines=40, dry_run=False):
    """
    Patch a single source file using LLM to generate precise check_access calls.
    """
    rel_path = os.path.relpath(filepath, kernel_src)

    if rel_path in SKIP_FILES:
        print(f"[patch] Skipping KCSAN runtime file: {rel_path}")
        return []

    if rel_path in SKIP_HEADERS:
        print(f"[patch] Skipping widely-included header: {rel_path}")
        print(f"[patch]   (patching this would instrument ALL callers across the kernel)")
        return []

    with open(filepath, 'r') as f:
        lines = f.readlines()

    orig = filepath + '.kcsan_orig'
    if not os.path.exists(orig) and not dry_run:
        shutil.copy2(filepath, orig)

    crash_excerpt = get_crash_excerpt(record_dir) if record_dir else ""

    patches = []
    sorted_locs = sorted(locations, key=lambda x: x.get('source_line', 0), reverse=True)

    for loc in sorted_locs:
        line_num = loc.get('source_line', 0)
        if line_num <= 0:
            continue

        func_name = loc.get('function', 'unknown')
        source_context = get_source_context(filepath, line_num, context_lines)

        print(f"[patch] Analyzing {rel_path}:{line_num} ({func_name}) via LLM...")

        # Call LLM
        llm_result = call_deepseek(
            api_key, source_context, crash_excerpt,
            {**loc, 'source_file': rel_path},
            context_lines
        )

        if llm_result is None:
            print(f"[patch] WARNING: LLM analysis failed for {rel_path}:{line_num}")
            patches.append(f"  L{line_num} ({func_name}): [LLM FAILED - needs manual review]")
            continue

        variable = llm_result.get('variable', '?')
        is_write = llm_result.get('is_write', False)
        check_line = llm_result.get('check_line', '')
        reasoning = llm_result.get('reasoning', '')

        # Ensure check_line ends with newline
        if not check_line.endswith('\n'):
            check_line += '\n'

        access_type = 'W' if is_write else 'R'
        patch_desc = f"  L{line_num} ({func_name}): {variable} [{access_type}] — {reasoning}"

        if dry_run:
            print(f"[patch] DRY RUN: {rel_path}:{line_num}")
            print(f"  Variable: {variable} [{'write' if is_write else 'read'}]")
            print(f"  Insert:   {check_line.rstrip()}")
            print(f"  Before:   {lines[line_num - 1].rstrip()}")
            print(f"  Reason:   {reasoning}")
        else:
            line_idx = line_num - 1
            lines.insert(line_idx, check_line)

        patches.append(patch_desc)

    if patches and not dry_run:
        lines = ensure_kcsan_include(lines)

        with open(filepath, 'w') as f:
            f.writelines(lines)

        print(f"[patch] Patched {rel_path}: {len(patches)} check(s) inserted")

    return patches


# ============================================================
# Restore
# ============================================================

def restore_originals(kernel_src, patched_files):
    """Restore .kcsan_orig backups."""
    restored = 0

    makefile_orig = os.path.join(kernel_src, 'scripts', 'Makefile.kcsan.orig')
    if os.path.exists(makefile_orig):
        shutil.copy2(makefile_orig, makefile_orig.replace('.orig', ''))
        os.remove(makefile_orig)
        print(f"[restore] Restored scripts/Makefile.kcsan")
        restored += 1

    for f in patched_files:
        orig = f + '.kcsan_orig'
        if os.path.exists(orig):
            shutil.copy2(orig, f)
            os.remove(orig)
            print(f"[restore] Restored {os.path.basename(f)}")
            restored += 1

    # Also search for any remaining .kcsan_orig files
    for root, dirs, files in os.walk(kernel_src):
        for fname in files:
            if fname.endswith('.kcsan_orig'):
                orig_path = os.path.join(root, fname)
                real_path = orig_path.replace('.kcsan_orig', '')
                if os.path.exists(orig_path):
                    shutil.copy2(orig_path, real_path)
                    os.remove(orig_path)
                    print(f"[restore] Restored {real_path}")
                    restored += 1

    print(f"[restore] Restored {restored} files total")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Patch kernel for targeted KCSAN (LLM-assisted)")
    parser.add_argument("kernel_src", help="Path to kernel source tree")
    parser.add_argument("source_locations", help="Path to source_locations.json")
    parser.add_argument("--record-dir", help="Record directory (for crash_report.txt)")
    parser.add_argument("--dry-run", action="store_true", help="Show patches without applying")
    parser.add_argument("--restore", action="store_true", help="Restore original files")
    parser.add_argument("--context-lines", type=int, default=40, help="Context lines for LLM")
    parser.add_argument("--api-key", help="DeepSeek API key")
    parser.add_argument("--output-log", help="Write patch log to file")
    args = parser.parse_args()

    kernel_src = os.path.abspath(args.kernel_src)

    if not os.path.isdir(kernel_src):
        print(f"ERROR: Kernel source not found: {kernel_src}", file=sys.stderr)
        sys.exit(1)

    with open(args.source_locations) as f:
        data = json.load(f)

    locations = data.get('locations', [])
    if not locations:
        print("[patch] No source locations to patch")
        sys.exit(0)

    # Restore mode
    if args.restore:
        patched_files = []
        for loc in locations:
            rel = normalize_source_path(loc.get('source_file', ''), kernel_src)
            fp = find_file_in_kernel(kernel_src, rel)
            if fp:
                patched_files.append(fp)
        restore_originals(kernel_src, patched_files)
        sys.exit(0)

    # Get API key
    api_key = args.api_key or os.environ.get('DEEPSEEK_API_KEY', '')
    if not api_key:
        print("ERROR: DeepSeek API key required. Use --api-key or DEEPSEEK_API_KEY env var",
              file=sys.stderr)
        sys.exit(1)

    # Auto-detect record-dir from source_locations path
    record_dir = args.record_dir
    if not record_dir:
        candidate = os.path.dirname(os.path.abspath(args.source_locations))
        if os.path.isfile(os.path.join(candidate, 'crash_report.txt')):
            record_dir = candidate

    print(f"[patch] Kernel source: {kernel_src}")
    print(f"[patch] Locations to patch: {len(locations)}")
    print(f"[patch] Record dir: {record_dir or '(none)'}")
    print(f"[patch] LLM: DeepSeek (context={args.context_lines} lines)")
    if args.dry_run:
        print(f"[patch] DRY RUN MODE")

    # Step 1: Patch Makefile.kcsan
    print()
    print("[patch] === Step 1: Disable global KCSAN instrumentation ===")
    patch_makefile_kcsan(kernel_src, dry_run=args.dry_run)

    # Step 1b: Patch core.c targeted filter
    print()
    print("[patch] === Step 1b: Add targeted-mode filter to core.c ===")
    patch_core_targeted_filter(kernel_src, dry_run=args.dry_run)

    # Step 2: Group locations by file and patch with LLM
    print()
    print("[patch] === Step 2: Insert targeted __kcsan_check_access() (LLM) ===")

    files_to_patch = {}
    for loc in locations:
        src_file = loc.get('source_file', '')
        if not src_file:
            continue

        rel = normalize_source_path(src_file, kernel_src)
        actual_path = find_file_in_kernel(kernel_src, rel)

        if actual_path is None:
            print(f"[patch] WARNING: Cannot find {rel} in kernel source", file=sys.stderr)
            continue

        if actual_path not in files_to_patch:
            files_to_patch[actual_path] = []
        files_to_patch[actual_path].append(loc)

    all_patches = []
    patched_files = []

    for filepath, file_locs in files_to_patch.items():
        rel = os.path.relpath(filepath, kernel_src)
        print(f"\n[patch] === File: {rel} ({len(file_locs)} location(s)) ===")

        patches = patch_source_file(
            filepath, file_locs, kernel_src,
            api_key=api_key,
            record_dir=record_dir,
            context_lines=args.context_lines,
            dry_run=args.dry_run,
        )
        if patches:
            all_patches.extend(patches)
            patched_files.append(filepath)

    # Summary
    print()
    print("[patch] === Summary ===")
    print(f"[patch] Files patched: {len(patched_files)}")
    print(f"[patch] Check_access calls inserted: {len(all_patches)}")
    for p in all_patches:
        print(f"  {p}")

    # Write manifest
    manifest = {
        'kernel_src': kernel_src,
        'patched_files': [os.path.relpath(f, kernel_src) for f in patched_files],
        'patches': all_patches,
        'cflags_kcsan_disabled': True,
        'llm_assisted': True,
    }

    manifest_path = os.path.join(
        os.path.dirname(os.path.abspath(args.source_locations)),
        'kcsan_patch_manifest.json'
    )
    if not args.dry_run:
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        print(f"\n[patch] Manifest: {manifest_path}")

    if args.output_log:
        with open(args.output_log, 'w') as f:
            f.write(f"Kernel: {kernel_src}\n")
            f.write(f"Files: {len(patched_files)}\n")
            f.write(f"Checks: {len(all_patches)}\n\n")
            for p in all_patches:
                f.write(f"{p}\n")

    print()
    if not args.dry_run:
        print("[patch] Done! Now rebuild kernel:")
        print(f"  cd {kernel_src} && make -j$(nproc) bzImage")
    else:
        print("[patch] Dry run complete. Remove --dry-run to apply patches.")


if __name__ == "__main__":
    main()
