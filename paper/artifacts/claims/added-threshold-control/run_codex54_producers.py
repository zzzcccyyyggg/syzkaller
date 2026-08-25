#!/usr/bin/env python3
"""Run external GPT-5.4 producers while a threshold matrix remains active."""

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
PYTHON = ROOT / ".venv/bin/python3"
CODEX = Path("/home/zzzccc/.npm-global/bin/codex")
CODEX_HOME = Path("/home/zzzccc/.codex-bass")
VARIANTS = ("random", "dynamic", "fixed-1000")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def write_json(path: Path, value: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
    tmp.replace(path)


class Supervisor:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.matrix_dir = CLAIM_ROOT / "matrices" / args.matrix_id
        self.matrix_state = self.matrix_dir / "state.json"
        self.state_path = self.matrix_dir / "codex54-producers.json"
        self.children: dict[str, subprocess.Popen[bytes]] = {}
        self.handles: list[Any] = []

    def run_dir(self, variant: str) -> Path:
        return CLAIM_ROOT / "runs" / f"{self.args.matrix_id}-{variant}"

    def command(self, variant: str) -> list[str]:
        run = self.run_dir(variant)
        return [
            "taskset", "-c", self.args.cpuset,
            str(PYTHON), "tools/llm-mutate-pilot/continuous.py",
            "--provider", "codex",
            "--codex-bin", str(CODEX),
            "--codex-model", "gpt-5.4",
            "--codex-sandbox", "read-only",
            "--codex-reasoning-effort", "medium",
            "--config", str(run / "configs/fuzz.cfg"),
            "--module", "ptmx",
            "--out", str(run / "kimi"),
            "--entries-per-round", "4",
            "--variants-per-entry", "2",
            "--max-calls", "8",
            "--poll-sec", "30",
            "--parallel-calls", "1",
            "--timeout-sec", "600",
        ]

    def snapshot(self, status: str, detail: str = "") -> None:
        write_json(
            self.state_path,
            {
                "status": status,
                "detail": detail,
                "updated_at": now_iso(),
                "model": "gpt-5.4",
                "codex_home": str(CODEX_HOME),
                "parallel_calls_per_variant": 1,
                "variants": {
                    variant: {
                        "pid": proc.pid,
                        "returncode": proc.poll(),
                        "state_totals": read_json(self.run_dir(variant) / "kimi/state.json").get("totals", {}),
                    }
                    for variant, proc in self.children.items()
                },
            },
        )

    def stop(self) -> None:
        for proc in self.children.values():
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
        for proc in self.children.values():
            if proc.poll() is None:
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        for handle in self.handles:
            handle.close()

    def run(self) -> None:
        if read_json(self.matrix_state).get("status") != "running":
            raise SystemExit("threshold matrix is not running")
        env = os.environ.copy()
        env["CODEX_HOME"] = str(CODEX_HOME)

        def handle_signal(signum: int, _frame: object) -> None:
            self.snapshot("interrupted", f"signal={signum}")
            self.stop()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        for variant in VARIANTS:
            run = self.run_dir(variant)
            log = (run / "logs/codex54.log").open("ab")
            self.handles.append(log)
            proc = subprocess.Popen(
                self.command(variant),
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self.children[variant] = proc
        self.snapshot("running")
        try:
            while True:
                matrix_status = read_json(self.matrix_state).get("status")
                failures = [f"{v} rc={p.poll()}" for v, p in self.children.items() if p.poll() is not None]
                if matrix_status != "running":
                    self.snapshot("stopping", f"matrix_status={matrix_status}")
                    break
                if failures:
                    self.snapshot("failed", ", ".join(failures))
                    break
                self.snapshot("running")
                time.sleep(30)
        finally:
            self.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-id", required=True)
    parser.add_argument("--cpuset", default="24-27")
    return parser.parse_args()


def main() -> int:
    Supervisor(parse_args()).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
