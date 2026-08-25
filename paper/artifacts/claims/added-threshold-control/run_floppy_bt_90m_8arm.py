#!/usr/bin/env python3
"""Prepare or launch the remote Floppy/Bluetooth eight-arm 90-minute pilot."""

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
    fuzz_cpus: str
    validate_cpus: str
    llm_cpu: str
    port: int


ARMS = (
    Arm("floppy", "dynamic", "dynamic", 0, "0-1", "2-3", "4", 64000),
    Arm("floppy", "random", "random", 0, "5-6", "7-8", "9", 64100),
    Arm("floppy", "fixed50", "fixed", 50, "10-11", "12-13", "14", 64200),
    Arm("floppy", "fixed10000", "fixed", 10000, "15-16", "17-18", "19", 64300),
    Arm("bt-stack", "dynamic", "dynamic", 0, "20-21", "22-23", "24", 64400),
    Arm("bt-stack", "random", "random", 0, "25-26", "27-28", "29", 64500),
    Arm("bt-stack", "fixed50", "fixed", 50, "30-31", "32-33", "34", 64600),
    Arm("bt-stack", "fixed10000", "fixed", 10000, "35-36", "37-38", "39", 64700),
)


def arm_command(args: argparse.Namespace, arm: Arm, run_id: str) -> list[str]:
    cmd = [
        "python3", str(RUNNER),
        "--run-id", run_id,
        "--manager-bin", str(Path(args.manager_bin).resolve()),
        "--module", arm.module,
        "--variant", arm.variant,
        "--duration", "5400",
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
        "--fuzz-cpuset", arm.fuzz_cpus,
        "--validate-cpuset", arm.validate_cpus,
        "--kimi-cpuset", arm.llm_cpu,
        "--http-base-port", str(arm.port),
        "--fuzz-vm-count", "2",
        "--validate-vm-count", "4",
        "--fuzz-vm-mem-mib", "1024",
        "--validate-vm-mem-mib", "1024",
        "--vm-running-time-seconds", "3600",
        "--kimi-entries-per-round", "2",
        "--kimi-parallel-calls", "1",
        "--llm-provider", "openai-responses",
        "--openai-base-url", args.openai_base_url,
        "--openai-model", "gpt-5.4",
        "--openai-auth-json", args.openai_auth_json,
        "--openai-reasoning-effort", "medium",
        "--min-start-memory-gib", "80",
        "--abort-memory-gib", "30",
        "--min-start-disk-gib", "100",
        "--abort-disk-gib", "50",
    ]
    if arm.fixed_us:
        cmd.extend(["--fixed-threshold-us", str(arm.fixed_us)])
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prepare", "launch"), required=True)
    parser.add_argument("--module", choices=("all", "floppy", "bt-stack"), default="all")
    parser.add_argument("--run-prefix", default="20260825-remote-fbt90-pervm-v1")
    parser.add_argument("--manager-bin", default=str(ROOT / "bin/syz-manager-per-vm-watchdog"))
    parser.add_argument("--openai-base-url", default="https://deepkey.top/v1")
    parser.add_argument("--openai-auth-json", default="/home/zzzccc/.codex-bass/auth.json")
    args = parser.parse_args()

    for arm in ARMS:
        if args.module != "all" and arm.module != args.module:
            continue
        arm_name = f"{arm.module}-{arm.label}"
        suffix = "-config-audit" if args.mode == "prepare" else ""
        run_id = f"{args.run_prefix}-{arm_name}{suffix}"
        cmd = arm_command(args, arm, run_id)
        if args.mode == "prepare":
            subprocess.run(cmd + ["--prepare-only"], cwd=ROOT, check=True)
            print(f"prepared {run_id}")
            continue
        session = f"fbt90-{arm_name}"
        if subprocess.run(["tmux", "has-session", "-t", session], check=False).returncode == 0:
            raise SystemExit(f"tmux session already exists: {session}")
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session, "-c", str(ROOT), shlex.join(cmd)],
            check=True,
        )
        print(f"launched {session}: {run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
