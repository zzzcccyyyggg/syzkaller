#!/usr/bin/env python3
"""Run Random, Dynamic, and Fixed-1000 PTMX threshold variants sequentially."""

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
VARIANTS = ("random", "dynamic", "fixed-1000")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
    tmp.replace(path)


class MatrixRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.matrix_dir = MATRIX_ROOT / args.matrix_id
        self.state_path = self.matrix_dir / "state.json"
        self.current: subprocess.Popen[bytes] | None = None
        self.results: list[dict[str, Any]] = []

    def write_state(self, status: str, variant: str = "", detail: str = "") -> None:
        write_json(
            self.state_path,
            {
                "matrix_id": self.args.matrix_id,
                "status": status,
                "variant": variant,
                "detail": detail,
                "updated_at": now_iso(),
                "duration_seconds_per_variant": self.args.duration,
                "results": self.results,
            },
        )

    def stop_current(self) -> None:
        if self.current is None or self.current.poll() is not None:
            return
        try:
            os.killpg(self.current.pid, signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            self.current.wait(timeout=45)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.current.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.current.wait(timeout=10)

    def command(self, variant: str, index: int) -> tuple[str, list[str]]:
        run_id = f"{self.args.matrix_id}-{index:02d}-{variant}"
        cmd = [
            str(PYTHON),
            str(RUNNER),
            "--run-id",
            run_id,
            "--variant",
            variant,
            "--duration",
            str(self.args.duration),
            "--fuzz-cpuset",
            self.args.fuzz_cpuset,
            "--validate-cpuset",
            self.args.validate_cpuset,
            "--kimi-cpuset",
            self.args.kimi_cpuset,
            "--http-base-port",
            str(self.args.http_base_port + index * 10),
            "--fuzz-vm-count",
            "4",
            "--validate-vm-count",
            "8",
            "--fuzz-vm-mem-mib",
            "4096",
            "--validate-vm-mem-mib",
            "4096",
            "--min-start-memory-gib",
            str(self.args.min_start_memory_gib),
            "--abort-memory-gib",
            str(self.args.abort_memory_gib),
            "--min-start-disk-gib",
            str(self.args.min_start_disk_gib),
            "--abort-disk-gib",
            str(self.args.abort_disk_gib),
            "--kimi-cli-bin",
            self.args.kimi_cli_bin,
            "--kimi-cli-model",
            self.args.kimi_cli_model,
        ]
        return run_id, cmd

    def run(self) -> None:
        if self.matrix_dir.exists():
            raise SystemExit(f"matrix directory already exists: {self.matrix_dir}")
        self.matrix_dir.mkdir(parents=True)
        self.write_state("created")

        def handle_signal(signum: int, _frame: object) -> None:
            self.write_state("interrupted", detail=f"signal={signum}")
            self.stop_current()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        for index, variant in enumerate(VARIANTS, start=1):
            run_id, cmd = self.command(variant, index)
            log_path = self.matrix_dir / f"{index:02d}-{variant}.runner.log"
            self.write_state("starting", variant)
            started = time.time()
            with log_path.open("wb") as log:
                self.current = subprocess.Popen(
                    cmd,
                    cwd=ROOT,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                self.write_state("running", variant, f"pid={self.current.pid}")
                rc = self.current.wait()
            result = {
                "variant": variant,
                "run_id": run_id,
                "returncode": rc,
                "started_at_epoch": started,
                "finished_at_epoch": time.time(),
                "log": str(log_path),
                "run_dir": str(CLAIM_ROOT / "runs" / run_id),
            }
            self.results.append(result)
            self.current = None
            if rc != 0:
                self.write_state("failed", variant, f"returncode={rc}")
                raise SystemExit(rc)
            self.write_state("variant-complete", variant)

        self.write_state("complete")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-id", required=True)
    parser.add_argument("--duration", type=int, default=12 * 60 * 60)
    parser.add_argument("--fuzz-cpuset", default="0-3")
    parser.add_argument("--validate-cpuset", default="4-7")
    parser.add_argument("--kimi-cpuset", default="8-9")
    parser.add_argument("--http-base-port", type=int, default=64800)
    parser.add_argument("--min-start-memory-gib", type=float, default=45.0)
    parser.add_argument("--abort-memory-gib", type=float, default=8.0)
    parser.add_argument("--min-start-disk-gib", type=float, default=50.0)
    parser.add_argument("--abort-disk-gib", type=float, default=25.0)
    parser.add_argument("--kimi-cli-bin", default="/home/zzzccc/.kimi-code/bin/kimi")
    parser.add_argument("--kimi-cli-model", default="my-kimi-code/k3")
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be positive")
    return args


def main() -> int:
    MatrixRunner(parse_args()).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
