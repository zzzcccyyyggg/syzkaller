#!/usr/bin/env python3
"""Prepare or launch the three-module, 12-arm, 24-hour formal experiment."""

from __future__ import annotations

import argparse
import shlex
import subprocess
from pathlib import Path

from run_three_module_72vm_capacity import ARMS


ROOT = Path(__file__).resolve().parents[4]
RUNNER = ROOT / "paper/artifacts/claims/added-threshold-control/run_threshold_12h_kimi.py"


def arm_command(args: argparse.Namespace, arm, run_id: str) -> list[str]:
    cpu = arm.index * 4
    cmd = [
        "python3", str(RUNNER),
        "--run-id", run_id,
        "--manager-bin", str(Path(args.manager_bin).resolve()),
        "--module", arm.module,
        "--variant", arm.variant,
        "--duration", "86400",
        "--allow-existing-experiments",
        "--dynamic-threshold-min-us", "50",
        "--dynamic-threshold-max-us", "10000",
        "--fuzz-vm-stall-timeout-seconds", "120",
        "--stall-timeout", "240",
        "--validation-repeat-count", "2",
        "--stable-min-occurrences", "1",
        "--verify-repeat-times", "1",
        "--validation-timeout-seconds", "300",
        "--max-batch-timeout-seconds", "1200",
        "--executor-program-timeout-seconds", "300",
        "--executor-syscall-timeout-ms", "40000",
        "--verify-access-delay-min-us", "1000",
        "--verify-access-delay-multiplier", "200",
        "--verify-access-delay-max-us", "1000000",
        "--verify-stack-access-delay-multiplier", "40",
        "--max-tasks-per-corpus", "3",
        "--max-stacks-per-varname", "4",
        "--max-concurrent-per-varname", "1",
        "--enable-threshold-aware-validation-priority",
        "--enable-collection-miss-backoff",
        "--collection-miss-free-attempts", "1",
        "--collection-miss-weight", "0.95",
        "--collection-miss-max-defer", "0.9",
        "--max-stable-pairs-per-entry", "0",
        "--max-stable-pairs-per-origin", "0",
        "--fuzz-cpuset", f"{cpu}-{cpu + 1}",
        "--validate-cpuset", f"{cpu + 2}-{cpu + 3}",
        "--kimi-cpuset", str(48 + arm.index % 4),
        "--http-base-port", str(62000 + arm.index * 100),
        "--fuzz-vm-count", "2",
        "--validate-vm-count", "4",
        "--fuzz-vm-mem-mib", "1024",
        "--validate-vm-mem-mib", "1024",
        "--vm-running-time-seconds", "3600",
        "--watch-interval", "30",
        "--kimi-entries-per-round", "2",
        "--kimi-parallel-calls", "1",
        "--llm-provider", "openai-responses",
        "--openai-base-url", args.openai_base_url,
        "--openai-model", "gpt-5.4",
        "--openai-auth-json", args.openai_auth_json,
        "--openai-reasoning-effort", "medium",
        "--min-start-memory-gib", "80",
        "--abort-memory-gib", "20",
        "--min-start-disk-gib", "200",
        "--abort-disk-gib", "100",
    ]
    if arm.fixed_us:
        cmd.extend(["--fixed-threshold-us", str(arm.fixed_us)])
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prepare", "launch"), required=True)
    parser.add_argument("--run-prefix", default="20260826-remote-formal24h-v1")
    parser.add_argument(
        "--manager-bin",
        default=str(ROOT / "bin/syz-manager-threshold-priority-initial"),
    )
    parser.add_argument("--openai-base-url", default="https://deepkey.top/v1")
    parser.add_argument("--openai-auth-json", default="/home/zzzccc/.codex-bass/auth.json")
    args = parser.parse_args()

    for arm in ARMS:
        arm_name = f"{arm.module}-{arm.label}"
        suffix = "-config-audit" if args.mode == "prepare" else ""
        run_id = f"{args.run_prefix}-{arm_name}{suffix}"
        cmd = arm_command(args, arm, run_id)
        if args.mode == "prepare":
            subprocess.run(cmd + ["--prepare-only"], cwd=ROOT, check=True)
            print(f"prepared {run_id}")
            continue
        session = f"formal24-{arm_name}"
        if subprocess.run(
            ["tmux", "has-session", "-t", session],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0:
            raise SystemExit(f"tmux session already exists: {session}")
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session, "-c", str(ROOT), shlex.join(cmd)],
            check=True,
        )
        print(f"launched {session}: {run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
