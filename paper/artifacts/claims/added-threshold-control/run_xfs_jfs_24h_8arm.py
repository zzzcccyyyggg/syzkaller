#!/usr/bin/env python3
"""Prepare or launch the isolated XFS/JFS eight-arm, 24-hour experiment."""

from __future__ import annotations

import argparse
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
RUNNER = ROOT / "paper/artifacts/claims/added-threshold-control/run_threshold_12h_kimi.py"


@dataclass(frozen=True)
class Arm:
    module: str
    label: str
    variant: str
    fixed_us: int
    index: int


ARMS = tuple(
    Arm(module, label, variant, fixed_us, module_index * 4 + policy_index)
    for module_index, module in enumerate(("xfs", "jfs"))
    for policy_index, (label, variant, fixed_us) in enumerate((
        ("dynamic", "dynamic", 0),
        ("random", "random", 0),
        ("fixed50", "fixed", 50),
        ("fixed10000", "fixed", 10000),
    ))
)


def arm_command(args: argparse.Namespace, arm: Arm, run_id: str) -> list[str]:
    cpu = arm.index * 4
    cmd = [
        "python3", str(RUNNER),
        "--run-id", run_id,
        "--manager-bin", str(Path(args.manager_bin).resolve()),
        "--module", arm.module,
        "--variant", arm.variant,
        "--duration", str(args.duration),
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
        "--kimi-cpuset", str(32 + arm.index),
        "--http-base-port", str(args.http_base_port + arm.index * 100),
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
        "--min-start-memory-gib", "35",
        "--abort-memory-gib", "20",
        "--min-start-disk-gib", "45",
        "--abort-disk-gib", "30",
    ]
    if arm.fixed_us:
        cmd.extend(["--fixed-threshold-us", str(arm.fixed_us)])
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prepare", "launch"), required=True)
    parser.add_argument("--run-prefix", default="20260826-remote2-xfs-jfs-formal24h-v4")
    parser.add_argument("--duration", type=int, default=86400)
    parser.add_argument(
        "--manager-bin",
        default=str(ROOT / "bin/syz-manager-stall-terminal-1c3300367"),
    )
    parser.add_argument("--http-base-port", type=int, default=61000)
    parser.add_argument(
        "--arm",
        choices=("all", *(f"{arm.module}-{arm.label}" for arm in ARMS)),
        default="all",
    )
    parser.add_argument("--openai-base-url", default="https://deepkey.top/v1")
    parser.add_argument("--openai-auth-json", default=str(Path.home() / ".codex-zzzccc/auth.json"))
    args = parser.parse_args()

    if args.duration <= 0:
        parser.error("--duration must be positive")

    for arm in ARMS:
        arm_name = f"{arm.module}-{arm.label}"
        if args.arm != "all" and args.arm != arm_name:
            continue
        suffix = "-config-audit" if args.mode == "prepare" else ""
        run_id = f"{args.run_prefix}-{arm.module}-{arm.label}{suffix}"
        cmd = arm_command(args, arm, run_id)
        if args.mode == "prepare":
            subprocess.run(cmd + ["--prepare-only"], cwd=ROOT, check=True)
            print(f"prepared {run_id}")
            continue

        session = f"remote2-{arm.module}-{arm.label}"
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
