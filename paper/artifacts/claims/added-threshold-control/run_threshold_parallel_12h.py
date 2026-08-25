#!/usr/bin/env python3
"""Run Random, Dynamic, and Fixed-1000 PTMX threshold variants in parallel."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path("/home/zzzccc/BASS/DDRD-syzkaller")
CLAIM_ROOT = ROOT / "paper/artifacts/claims/added-threshold-control"
RUNNER = CLAIM_ROOT / "run_threshold_12h_kimi.py"
MATRIX_ROOT = CLAIM_ROOT / "matrices"
PYTHON = ROOT / ".venv/bin/python3"
VARIANTS = (
    ("random", "0-3", "4-7", 64910),
    ("dynamic", "8-11", "12-15", 64920),
    ("fixed-1000", "16-19", "20-23", 64930),
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


def memory_available_gib() -> float:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) / (1024 * 1024)
    return 0.0


def disk_free_gib() -> float:
    stat = os.statvfs(ROOT)
    return stat.f_bavail * stat.f_frsize / (1024**3)


def conflicting_processes() -> list[str]:
    proc = subprocess.run(
        ["ps", "-eo", "pid=,ppid=,comm=,args="],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return [
        line.strip()
        for line in proc.stdout.splitlines()
        if ("syz-manager" in line or "qemu-system" in line) and "rg " not in line
    ]


class ParallelRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.matrix_dir = MATRIX_ROOT / args.matrix_id
        self.state_path = self.matrix_dir / "state.json"
        self.children: dict[str, subprocess.Popen[bytes]] = {}
        self.handles: list[Any] = []
        self.results: dict[str, dict[str, Any]] = {}

    def snapshot(self, status: str, detail: str = "") -> None:
        variants = {}
        for variant, _, _, _ in VARIANTS:
            run_id = f"{self.args.matrix_id}-{variant}"
            proc = self.children.get(variant)
            variants[variant] = {
                "pid": proc.pid if proc else None,
                "returncode": proc.poll() if proc else None,
                "run_id": run_id,
                "state": read_json(CLAIM_ROOT / "runs" / run_id / "state.json"),
            }
        write_json(
            self.state_path,
            {
                "matrix_id": self.args.matrix_id,
                "status": status,
                "detail": detail,
                "updated_at": now_iso(),
                "duration_seconds": self.args.duration,
                "memory_available_gib": round(memory_available_gib(), 3),
                "disk_free_gib": round(disk_free_gib(), 3),
                "variants": variants,
                "results": self.results,
            },
        )

    def command(self, variant: str, fuzz_cpus: str, validate_cpus: str, port: int) -> list[str]:
        return [
            str(PYTHON),
            str(RUNNER),
            "--run-id", f"{self.args.matrix_id}-{variant}",
            "--variant", variant,
            "--duration", str(self.args.duration),
            "--fuzz-cpuset", fuzz_cpus,
            "--validate-cpuset", validate_cpus,
            "--kimi-cpuset", self.args.kimi_cpuset,
            "--http-base-port", str(port),
            "--fuzz-vm-count", str(self.args.fuzz_vm_count),
            "--validate-vm-count", str(self.args.validate_vm_count),
            "--fuzz-vm-mem-mib", str(self.args.fuzz_vm_mem_mib),
            "--validate-vm-mem-mib", str(self.args.validate_vm_mem_mib),
            "--allow-existing-experiments",
            "--min-start-memory-gib", "8",
            "--abort-memory-gib", str(self.args.abort_memory_gib),
            "--min-start-disk-gib", "20",
            "--abort-disk-gib", str(self.args.abort_disk_gib),
            "--kimi-cli-bin", "/home/zzzccc/.kimi-code/bin/kimi",
            "--kimi-cli-model", "my-kimi-code/k3",
        ]

    def stop_all(self) -> None:
        for proc in self.children.values():
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 45
        for proc in self.children.values():
            if proc.poll() is not None:
                continue
            try:
                proc.wait(timeout=max(1, deadline - time.monotonic()))
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
        self.matrix_dir.mkdir(parents=True)
        active = conflicting_processes()
        if active:
            raise SystemExit("existing syz-manager/qemu-system processes:\n" + "\n".join(active))
        if memory_available_gib() < self.args.min_start_memory_gib:
            raise SystemExit("insufficient available memory for parallel launch")
        if disk_free_gib() < self.args.min_start_disk_gib:
            raise SystemExit("insufficient disk for parallel launch")

        def handle_signal(signum: int, _frame: object) -> None:
            self.snapshot("interrupted", f"signal={signum}")
            self.stop_all()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        try:
            for variant, fuzz_cpus, validate_cpus, port in VARIANTS:
                cmd = self.command(variant, fuzz_cpus, validate_cpus, port)
                write_json(self.matrix_dir / f"{variant}.command.json", cmd)
                handle = (self.matrix_dir / f"{variant}.runner.log").open("wb")
                self.handles.append(handle)
                proc = subprocess.Popen(
                    cmd,
                    cwd=ROOT,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                self.children[variant] = proc
                time.sleep(2)
                if proc.poll() is not None:
                    raise RuntimeError(f"{variant} runner exited immediately rc={proc.returncode}")
            self.snapshot("running")

            while True:
                running = 0
                failed = []
                for variant, proc in self.children.items():
                    rc = proc.poll()
                    if rc is None:
                        running += 1
                    elif rc != 0:
                        failed.append(f"{variant} rc={rc}")
                    elif variant not in self.results:
                        self.results[variant] = {"returncode": rc, "finished_at": now_iso()}
                if failed:
                    raise RuntimeError(", ".join(failed))
                if running == 0:
                    break
                self.snapshot("running")
                time.sleep(30)
            self.snapshot("complete")
        except Exception as exc:
            self.snapshot("failed", str(exc))
            self.stop_all()
            raise
        finally:
            self.stop_all()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-id", required=True)
    parser.add_argument("--duration", type=int, default=12 * 60 * 60)
    parser.add_argument("--kimi-cpuset", default="24-27")
    parser.add_argument("--fuzz-vm-count", type=int, default=4)
    parser.add_argument("--validate-vm-count", type=int, default=4)
    parser.add_argument("--fuzz-vm-mem-mib", type=int, default=2048)
    parser.add_argument("--validate-vm-mem-mib", type=int, default=1536)
    parser.add_argument("--min-start-memory-gib", type=float, default=45.0)
    parser.add_argument("--abort-memory-gib", type=float, default=8.0)
    parser.add_argument("--min-start-disk-gib", type=float, default=85.0)
    parser.add_argument("--abort-disk-gib", type=float, default=20.0)
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be positive")
    if args.fuzz_vm_count <= 0 or args.validate_vm_count <= 0:
        parser.error("VM counts must be positive")
    return args


def main() -> int:
    ParallelRunner(parse_args()).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
