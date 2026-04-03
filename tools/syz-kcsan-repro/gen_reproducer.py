#!/usr/bin/env python3
"""
gen_reproducer.py - Generate barrier-style C reproducer from two syzkaller programs.

Usage:
    python3 gen_reproducer.py <record_dir> [options]

Options:
    --syz-prog2c <path>    Path to syz-prog2c binary
    --output-dir <path>    Output directory (default: <record_dir>)
    --gcc <path>           Compiler for static build (default: gcc)
    --compile              Also compile the reproducer

Strategy:
  syz-prog2c generates complex self-contained C programs with their own main(),
  sandbox setup, NONFAILING macros, signal handlers, etc. Merging two such programs
  into one is fragile. Instead, we use a fork+exec barrier approach:

  1. Convert each .syz program to standalone C via syz-prog2c
  2. Compile each as a separate binary (prog0_bin, prog1_bin)
  3. Provide a barrier_runner binary that fork+exec's both with futex sync
  4. Also generate a shell-based runner as backup

Output files:
  - prog0.c / prog0_bin         : Standalone program 0
  - prog1.c / prog1_bin         : Standalone program 1
  - barrier_runner / barrier_runner.c : C barrier synchronizer
  - run_barrier.sh              : Shell-based backup runner
  - reproducer                  : Symlink to barrier_runner (for pipeline)
"""

import os
import re
import shutil
import subprocess
import stat
import sys


def read_file(path):
    with open(path) as f:
        return f.read()


def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)


def prog2c(syz_prog2c_bin, prog_path):
    """Convert a syzkaller program (.syz) to C code using syz-prog2c."""
    result = subprocess.run(
        [syz_prog2c_bin, "-prog", prog_path, "-threaded=false", "-procs=1",
         "-repeat=1", "-sandbox=none", "-segv"],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"[gen_reproducer] syz-prog2c failed for {prog_path}: {result.stderr}", file=sys.stderr)
        return None
    return result.stdout


def compile_c(gcc, src_path, bin_path):
    """Compile a C file to binary, try static first then dynamic."""
    # Try static compilation first
    result = subprocess.run(
        [gcc, "-static", "-o", bin_path, src_path,
         "-lpthread", "-Wall", "-Wno-unused-result", "-Wno-unused-variable"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        os.chmod(bin_path, os.stat(bin_path).st_mode | stat.S_IEXEC)
        return True, "static"
    
    # Fallback to dynamic
    result2 = subprocess.run(
        [gcc, "-o", bin_path, src_path,
         "-lpthread", "-Wall", "-Wno-unused-result", "-Wno-unused-variable"],
        capture_output=True, text=True
    )
    if result2.returncode == 0:
        os.chmod(bin_path, os.stat(bin_path).st_mode | stat.S_IEXEC)
        return True, "dynamic"
    
    print(f"[gen_reproducer] Compilation failed for {src_path}:", file=sys.stderr)
    print(result2.stderr, file=sys.stderr)
    return False, result2.stderr


def generate_barrier_runner_wrapper(output_dir, prog0_bin_name, prog1_bin_name):
    """Generate a wrapper script that calls barrier_runner with the correct paths."""
    wrapper = f"""#!/bin/bash
# Auto-generated KCSAN barrier reproducer wrapper
# Usage: ./reproducer [repeat] [delay_us]
#
# This script calls barrier_runner with the two program binaries.

DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
REPEAT="${{1:-100}}"
DELAY_US="${{2:-0}}"

# Tune KCSAN parameters (best-effort)
# skip_watch=500: check 1 in 500 accesses (0 = every access, kills performance!)
echo 500 > /sys/module/kcsan/parameters/skip_watch 2>/dev/null
echo 200 > /sys/module/kcsan/parameters/udelay_task 2>/dev/null
echo 0 > /sys/module/kcsan/parameters/report_once_in_ms 2>/dev/null

if [[ -x "$DIR/barrier_runner" ]]; then
    exec "$DIR/barrier_runner" "$DIR/{prog0_bin_name}" "$DIR/{prog1_bin_name}" "$REPEAT" "$DELAY_US"
else
    # Fallback: run both concurrently without barrier
    echo "[reproducer] barrier_runner not found, running concurrently..."
    for ((i=1; i<=REPEAT; i++)); do
        "$DIR/{prog0_bin_name}" &
        P0=$!
        [[ "$DELAY_US" -gt 0 ]] && usleep "$DELAY_US" 2>/dev/null
        "$DIR/{prog1_bin_name}" &
        P1=$!
        wait $P0 $P1 2>/dev/null
    done
fi
"""
    wrapper_path = os.path.join(output_dir, "reproducer")
    write_file(wrapper_path, wrapper)
    os.chmod(wrapper_path, 0o755)
    return wrapper_path


def generate_shell_runner(output_dir, prog0_bin_name, prog1_bin_name):
    """Generate a shell-based runner as backup."""
    runner = f"""#!/bin/bash
# Shell-based barrier runner for KCSAN race detection
# Usage: ./run_barrier.sh [repeat] [delay_us]

REPEAT=${{1:-100}}
DELAY_US=${{2:-0}}
DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

echo "[barrier-runner] Tuning KCSAN parameters..."
echo 500 > /sys/module/kcsan/parameters/skip_watch 2>/dev/null
echo 200 > /sys/module/kcsan/parameters/udelay_task 2>/dev/null

for ((i=1; i<=REPEAT; i++)); do
    # Run both programs concurrently
    "$DIR/{prog0_bin_name}" &
    P0=$!

    if [[ "$DELAY_US" -gt 0 ]]; then
        usleep "$DELAY_US" 2>/dev/null || sleep 0
    fi

    "$DIR/{prog1_bin_name}" &
    P1=$!

    # Wait with timeout
    timeout 30 bash -c "wait $P0 $P1" 2>/dev/null
    kill $P0 $P1 2>/dev/null
    wait $P0 $P1 2>/dev/null

    if (( i % 10 == 0 )); then
        echo "[barrier-runner] Completed $i/$REPEAT"
    fi

    # Check for KCSAN reports
    if dmesg 2>/dev/null | tail -5 | grep -q "BUG: KCSAN"; then
        echo "[barrier-runner] KCSAN report detected at iteration $i!"
        dmesg | grep -A 30 "BUG: KCSAN" | tail -35
    fi
done

echo "[barrier-runner] Done. Check dmesg for KCSAN reports."
"""
    runner_path = os.path.join(output_dir, "run_barrier.sh")
    write_file(runner_path, runner)
    os.chmod(runner_path, 0o755)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate KCSAN barrier reproducer")
    parser.add_argument("record_dir", help="Path to parsed record directory")
    parser.add_argument("--syz-prog2c", help="Path to syz-prog2c binary")
    parser.add_argument("--output-dir", help="Output directory")
    parser.add_argument("--gcc", default="gcc", help="Compiler for static build")
    parser.add_argument("--compile", action="store_true", help="Compile the reproducer")
    args = parser.parse_args()

    record_dir = args.record_dir
    output_dir = args.output_dir or record_dir

    # Auto-detect syz-prog2c
    script_dir = os.path.dirname(os.path.abspath(__file__))
    syzkaller_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    syz_prog2c_bin = args.syz_prog2c or os.path.join(syzkaller_root, "bin", "syz-prog2c")

    if not os.path.isfile(syz_prog2c_bin):
        print(f"[gen_reproducer] ERROR: syz-prog2c not found: {syz_prog2c_bin}", file=sys.stderr)
        sys.exit(1)

    prog0_syz = os.path.join(record_dir, "prog0.syz")
    prog1_syz = os.path.join(record_dir, "prog1.syz")

    if not os.path.isfile(prog0_syz) or not os.path.isfile(prog1_syz):
        print(f"[gen_reproducer] ERROR: prog0.syz or prog1.syz not found in {record_dir}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    # ============================================================
    # Step 1: Convert both programs to C
    # ============================================================
    print("[gen_reproducer] Converting programs to C via syz-prog2c...")

    prog0_c = prog2c(syz_prog2c_bin, prog0_syz)
    prog1_c = prog2c(syz_prog2c_bin, prog1_syz)

    if not prog0_c:
        print("[gen_reproducer] ERROR: Failed to convert prog0.syz to C", file=sys.stderr)
        sys.exit(1)
    if not prog1_c:
        print("[gen_reproducer] ERROR: Failed to convert prog1.syz to C", file=sys.stderr)
        sys.exit(1)

    prog0_c_path = os.path.join(output_dir, "prog0.c")
    prog1_c_path = os.path.join(output_dir, "prog1.c")
    write_file(prog0_c_path, prog0_c)
    write_file(prog1_c_path, prog1_c)
    print(f"[gen_reproducer] Generated: prog0.c, prog1.c")

    # ============================================================
    # Step 2: Copy barrier_runner.c template
    # ============================================================
    runner_template = os.path.join(script_dir, "template", "barrier_runner.c")
    runner_c_path = os.path.join(output_dir, "barrier_runner.c")
    if os.path.isfile(runner_template):
        shutil.copy2(runner_template, runner_c_path)
    else:
        print(f"[gen_reproducer] WARNING: barrier_runner.c template not found", file=sys.stderr)

    # ============================================================
    # Step 3: Generate shell runner and wrapper
    # ============================================================
    generate_shell_runner(output_dir, "prog0_bin", "prog1_bin")
    generate_barrier_runner_wrapper(output_dir, "prog0_bin", "prog1_bin")
    print("[gen_reproducer] Generated: run_barrier.sh, reproducer (wrapper)")

    # ============================================================
    # Step 4: Compile everything (if --compile)
    # ============================================================
    if args.compile:
        print("[gen_reproducer] Compiling...")
        gcc = args.gcc

        # Compile prog0
        prog0_bin = os.path.join(output_dir, "prog0_bin")
        ok0, mode0 = compile_c(gcc, prog0_c_path, prog0_bin)
        if ok0:
            print(f"[gen_reproducer]   prog0_bin: OK ({mode0})")
        else:
            print(f"[gen_reproducer]   prog0_bin: FAILED")

        # Compile prog1
        prog1_bin = os.path.join(output_dir, "prog1_bin")
        ok1, mode1 = compile_c(gcc, prog1_c_path, prog1_bin)
        if ok1:
            print(f"[gen_reproducer]   prog1_bin: OK ({mode1})")
        else:
            print(f"[gen_reproducer]   prog1_bin: FAILED")

        # Compile barrier_runner
        if os.path.isfile(runner_c_path):
            runner_bin = os.path.join(output_dir, "barrier_runner")
            ok_r, mode_r = compile_c(gcc, runner_c_path, runner_bin)
            if ok_r:
                print(f"[gen_reproducer]   barrier_runner: OK ({mode_r})")
            else:
                print(f"[gen_reproducer]   barrier_runner: FAILED")

        if ok0 and ok1:
            print(f"[gen_reproducer] All binaries compiled successfully!")
            print(f"[gen_reproducer] Run: {os.path.join(output_dir, 'reproducer')} [repeat] [delay_us]")
        else:
            print(f"[gen_reproducer] WARNING: Some compilations failed, check errors above")
    else:
        print("[gen_reproducer] Skipping compilation (use --compile to build)")

    print(f"[gen_reproducer] Output directory: {output_dir}")
    print(f"[gen_reproducer] Files:")
    for f in sorted(os.listdir(output_dir)):
        fp = os.path.join(output_dir, f)
        if os.path.isfile(fp):
            size = os.path.getsize(fp)
            x = " (exec)" if os.access(fp, os.X_OK) else ""
            print(f"  {f}: {size} bytes{x}")


if __name__ == "__main__":
    main()
