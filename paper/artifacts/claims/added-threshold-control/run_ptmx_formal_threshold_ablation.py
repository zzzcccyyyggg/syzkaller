#!/usr/bin/env python3
"""Run one or both waves of the four-arm formal PTMX threshold ablation."""

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
CLAIM_ROOT = ROOT / "paper" / "artifacts" / "claims" / "added-threshold-control"
RUNNER = CLAIM_ROOT / "run_threshold_12h_kimi.py"
PYTHON = Path(sys.executable)
MATRIX_ROOT = CLAIM_ROOT / "matrices"

WAVES = (
    (
        ("dynamic", "dynamic", None, "0-5", "6-11", "24", 65400),
        ("fixed-min", "fixed", 100, "12-17", "18-23", "25", 65410),
    ),
    (
        ("random", "random", None, "0-5", "6-11", "24", 65400),
        ("fixed-max", "fixed", 2000, "12-17", "18-23", "25", 65410),
    ),
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
        self.matrix_dir = MATRIX_ROOT / args.matrix_id
        self.state_path = self.matrix_dir / "state.json"
        self.children: dict[str, subprocess.Popen[bytes]] = {}
        self.handles: list[Any] = []
        self.wave = 0

    def run_id(self, label: str) -> str:
        return f"{self.args.matrix_id}-{label}"

    def command(self, arm: tuple[str, str, int | None, str, str, str, int]) -> list[str]:
        label, variant, fixed, fuzz_cpus, validate_cpus, llm_cpus, port = arm
        cmd = [
            str(PYTHON), str(RUNNER),
            "--run-id", self.run_id(label),
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
            "--max-stacks-per-varname", "20",
            "--max-concurrent-per-varname", "0",
            "--max-stable-pairs-per-entry", "0",
            "--max-stable-pairs-per-origin", "0",
            "--fuzz-cpuset", fuzz_cpus,
            "--validate-cpuset", validate_cpus,
            "--kimi-cpuset", llm_cpus,
            "--http-base-port", str(port),
            "--fuzz-vm-count", "6",
            "--validate-vm-count", "12",
            "--fuzz-vm-mem-mib", "1024",
            "--validate-vm-mem-mib", "1024",
            "--vm-running-time-seconds", "3600",
            "--kimi-entries-per-round", "6",
            "--kimi-parallel-calls", "3",
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
            "--abort-memory-gib", "2",
            "--min-start-disk-gib", "50",
            "--abort-disk-gib", "10",
        ]
        if fixed is not None:
            cmd += ["--fixed-threshold-us", str(fixed)]
        return cmd

    def snapshot(self, status: str, detail: str = "") -> None:
        memory, disk = available_gib()
        arms = {}
        for wave in WAVES:
            for label, *_ in wave:
                proc = self.children.get(label)
                arms[label] = {
                    "run_id": self.run_id(label),
                    "pid": proc.pid if proc else None,
                    "returncode": proc.poll() if proc else None,
                    "state": read_json(CLAIM_ROOT / "runs" / self.run_id(label) / "state.json"),
                }
        write_json(
            self.state_path,
            {
                "matrix_id": self.args.matrix_id,
                "status": status,
                "detail": detail,
                "wave": self.wave,
                "selected_wave": self.args.wave,
                "duration_seconds_per_arm": self.args.duration,
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
                    proc.wait(timeout=45)
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

    def run_wave(self, index: int) -> None:
        self.wave = index + 1
        self.children = {}
        self.handles = []
        for arm in WAVES[index]:
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
            time.sleep(2)
            if proc.poll() is not None:
                raise RuntimeError(f"{label} exited immediately rc={proc.returncode}")
        self.snapshot("running")
        while True:
            running = 0
            failures = []
            for label, proc in self.children.items():
                rc = proc.poll()
                if rc is None:
                    running += 1
                elif rc != 0:
                    failures.append(f"{label} rc={rc}")
            if failures:
                raise RuntimeError(", ".join(failures))
            if running == 0:
                break
            self.snapshot("running")
            time.sleep(30)
        self.stop_children()

    def run(self) -> None:
        if self.matrix_dir.exists():
            raise SystemExit(f"matrix directory already exists: {self.matrix_dir}")
        memory, disk = available_gib()
        if memory < 50 or disk < 80:
            raise SystemExit(f"insufficient start resources: memory={memory:.1f}GiB disk={disk:.1f}GiB")
        self.matrix_dir.mkdir(parents=True)

        def handle_signal(signum: int, _frame: object) -> None:
            self.snapshot("interrupted", f"signal={signum}")
            self.stop_children()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        try:
            indexes = range(len(WAVES)) if self.args.wave == "all" else (int(self.args.wave) - 1,)
            for index in indexes:
                self.run_wave(index)
            self.snapshot("complete")
        except Exception as exc:
            self.snapshot("failed", str(exc))
            self.stop_children()
            raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-id", required=True)
    parser.add_argument("--duration", type=int, default=8 * 60 * 60)
    parser.add_argument("--wave", choices=("all", "1", "2"), default="all")
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be positive")
    return args


def main() -> int:
    FormalMatrix(parse_args()).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
