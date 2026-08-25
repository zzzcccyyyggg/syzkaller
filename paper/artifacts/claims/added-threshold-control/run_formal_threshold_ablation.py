#!/usr/bin/env python3
"""Run all four threshold policies concurrently for one module."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[4]
CLAIM_ROOT = ROOT / "paper/artifacts/claims/added-threshold-control"
RUN_ROOT = CLAIM_ROOT / "runs"
MATRIX_ROOT = CLAIM_ROOT / "matrices"
RUNNER = CLAIM_ROOT / "run_threshold_12h_kimi.py"

POLICIES = (
    ("dynamic", "dynamic", None, 65100),
    ("fixed-min", "fixed", 100, 65110),
    ("random", "random", None, 65120),
    ("fixed-max", "fixed", 2000, 65130),
)

REMOTE_ALL_LAYOUT = (
    ("0-3", "4-7", "32"),
    ("8-11", "12-15", "33"),
    ("16-19", "20-23", "34"),
    ("24-27", "28-31", "35"),
)

LOCAL_WAVE_LAYOUT = (
    ("0-3", "4-7", "16"),
    ("8-11", "12-15", "17"),
)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
    tmp.replace(path)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def available_gib() -> tuple[float, float]:
    memory = 0.0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            memory = int(line.split()[1]) / (1024 * 1024)
            break
    stat = os.statvfs(ROOT)
    disk = stat.f_bavail * stat.f_frsize / (1024**3)
    return memory, disk


class FormalMatrix:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        selected = POLICIES if args.wave == "all" else POLICIES[:2] if args.wave == "1" else POLICIES[2:]
        if args.layout == "local-waves":
            if args.wave == "all":
                raise SystemExit("--layout=local-waves requires --wave=1 or --wave=2")
            layout = LOCAL_WAVE_LAYOUT
        else:
            indexes = range(4) if args.wave == "all" else range(2) if args.wave == "1" else range(2, 4)
            layout = tuple(REMOTE_ALL_LAYOUT[index] for index in indexes)
        self.arms = tuple((*policy, *cpus) for policy, cpus in zip(selected, layout))
        self.matrix_dir = MATRIX_ROOT / args.matrix_id
        self.state_path = self.matrix_dir / "state.json"
        self.children: dict[str, subprocess.Popen[bytes]] = {}
        self.handles: list[Any] = []

    def run_id(self, label: str) -> str:
        return f"{self.args.matrix_id}-{label}"

    def command(self, arm: tuple[str, str, int | None, int, str, str, str]) -> list[str]:
        label, variant, fixed, port, fuzz_cpus, validate_cpus, llm_cpu = arm
        cmd = [
            sys.executable,
            str(RUNNER),
            "--run-id", self.run_id(label),
            "--module", self.args.module,
            "--manager-bin", self.args.manager_bin,
            "--variant", variant,
            "--duration", str(self.args.duration),
            "--dynamic-threshold-min-us", "100",
            "--dynamic-threshold-max-us", "2000",
            "--validation-repeat-count", "2",
            "--stable-min-occurrences", "1",
            "--verify-repeat-times", "1",
            "--executor-syscall-timeout-ms", "5000",
            # Manager-level values. The kernel runtime applies a fixed x10 multiplier,
            # yielding strict/range 10ms-1s and stack-only 10ms effectively.
            "--verify-access-delay-min-us", "1000",
            "--verify-access-delay-normalize",
            "--verify-access-delay-target-us", "100000",
            "--verify-access-delay-max-us", "100000",
            "--verify-stack-access-delay-us", "1000",
            "--max-tasks-per-corpus", "3",
            "--max-stacks-per-varname", str(self.args.max_stacks_per_varname),
            "--max-concurrent-per-varname", str(self.args.max_concurrent_per_varname),
            "--max-stable-pairs-per-entry", "0",
            "--max-stable-pairs-per-origin", "0",
            "--fuzz-cpuset", fuzz_cpus,
            "--validate-cpuset", validate_cpus,
            "--kimi-cpuset", llm_cpu,
            "--http-base-port", str(port),
            "--fuzz-vm-count", "4",
            "--validate-vm-count", "4",
            "--fuzz-vm-mem-mib", "1024",
            "--validate-vm-mem-mib", "1024",
            "--vm-running-time-seconds", "3600",
            "--kimi-entries-per-round", "4",
            "--kimi-parallel-calls", "2",
            "--llm-provider", "openai-responses",
            "--openai-base-url", "https://deepkey.top/v1",
            "--openai-model", "gpt-5.4",
            "--openai-auth-json", "/home/zzzccc/.codex-bass/auth.json",
            "--openai-reasoning-effort", "medium",
            "--allow-existing-experiments",
            "--validate-start-delay", "30",
            "--kimi-start-delay", "30",
            "--watch-interval", "30",
            "--boot-grace", "300",
            "--stall-timeout", "240",
            "--min-start-memory-gib", "20",
            "--abort-memory-gib", "8",
            "--min-start-disk-gib", "100",
            "--abort-disk-gib", "50",
        ]
        if fixed is not None:
            cmd += ["--fixed-threshold-us", str(fixed)]
        if self.args.enable_collection_miss_backoff:
            cmd += ["--enable-collection-miss-backoff"]
        return cmd

    def snapshot(self, status: str, detail: str = "") -> None:
        memory, disk = available_gib()
        arms = {}
        for label, *_ in self.arms:
            proc = self.children.get(label)
            arms[label] = {
                "run_id": self.run_id(label),
                "pid": proc.pid if proc else None,
                "returncode": proc.poll() if proc else None,
                "state": read_json(RUN_ROOT / self.run_id(label) / "state.json"),
                "health": read_json(RUN_ROOT / self.run_id(label) / "HEALTH.json"),
            }
        write_json(
            self.state_path,
            {
                "matrix_id": self.args.matrix_id,
                "module": self.args.module,
                "status": status,
                "detail": detail,
                "duration_seconds_per_arm": self.args.duration,
                "selected_wave": self.args.wave,
                "resource_layout": self.args.layout,
                "queue_control": {
                    "manager_bin": self.args.manager_bin,
                    "max_stacks_per_varname": self.args.max_stacks_per_varname,
                    "max_concurrent_per_varname": self.args.max_concurrent_per_varname,
                    "collection_miss_backoff": self.args.enable_collection_miss_backoff,
                },
                "updated_at": now_iso(),
                "memory_available_gib": round(memory, 3),
                "disk_free_gib": round(disk, 3),
                "arms": arms,
            },
        )

    def stop_children(self) -> None:
        for proc in self.children.values():
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
        for proc in self.children.values():
            if proc.poll() is None:
                try:
                    proc.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        for handle in self.handles:
            try:
                handle.close()
            except OSError:
                pass

    def run(self) -> None:
        if self.matrix_dir.exists():
            raise SystemExit(f"matrix directory already exists: {self.matrix_dir}")
        memory, disk = available_gib()
        min_memory = 30 * len(self.arms)
        if memory < min_memory or disk < 200:
            raise SystemExit(
                f"insufficient start resources: memory={memory:.1f}GiB disk={disk:.1f}GiB"
            )
        self.matrix_dir.mkdir(parents=True)

        def handle_signal(signum: int, _frame: object) -> None:
            self.snapshot("interrupted", f"signal={signum}")
            self.stop_children()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        try:
            for arm in self.arms:
                label = arm[0]
                cmd = self.command(arm)
                write_json(self.matrix_dir / f"{label}.command.json", cmd)
                handle = (self.matrix_dir / f"{label}.runner.log").open("wb")
                self.handles.append(handle)
                proc = subprocess.Popen(
                    cmd,
                    cwd=ROOT,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                self.children[label] = proc
                time.sleep(3)
                if proc.poll() is not None:
                    raise RuntimeError(f"{label} exited immediately rc={proc.returncode}")

            while True:
                failures = []
                running = 0
                for label, proc in self.children.items():
                    rc = proc.poll()
                    if rc is None:
                        running += 1
                    elif rc != 0:
                        failures.append(f"{label} rc={rc}")
                if failures:
                    raise RuntimeError(", ".join(failures))
                self.snapshot("running")
                if running == 0:
                    break
                time.sleep(30)
            self.stop_children()
            self.snapshot("complete")
        except Exception as exc:
            self.snapshot("failed", str(exc))
            self.stop_children()
            raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-id", required=True)
    parser.add_argument("--module", choices=("ptmx", "dsp", "bt-stack"), required=True)
    parser.add_argument("--duration", type=int, default=12 * 60 * 60)
    parser.add_argument("--wave", choices=("all", "1", "2"), default="all")
    parser.add_argument("--layout", choices=("remote-all", "local-waves"), default="remote-all")
    parser.add_argument("--manager-bin", default=str(ROOT / "bin/syz-manager-canonical-family1"))
    parser.add_argument("--max-stacks-per-varname", type=int, default=10)
    parser.add_argument("--max-concurrent-per-varname", type=int, default=1)
    parser.add_argument("--enable-collection-miss-backoff", action="store_true")
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be positive")
    if args.max_stacks_per_varname <= 0 or args.max_concurrent_per_varname < 0:
        parser.error("invalid queue-control limits")
    return args


def main() -> int:
    FormalMatrix(parse_args()).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
