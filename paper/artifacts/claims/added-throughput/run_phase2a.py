#!/usr/bin/env python3
"""Run the fixed-resource Phase 2A ptmx throughput matrix."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


DDRD_ROOT = Path("/home/zzzccc/BASS/DDRD-syzkaller")
SEGFUZZ_ROOT = Path("/home/zzzccc/BASS/segfuzz")
SEGFUZZ_GO_ROOT = SEGFUZZ_ROOT / "gotools/src/github.com/google/segfuzz"
ARTIFACT_ROOT = DDRD_ROOT / "paper/artifacts/claims/added-throughput"

MRPFUZZ_SRC_CONFIG = DDRD_ROOT / "exp/ptmx/fuzz-throughput-binary.cfg"
SEGFUZZ_SRC_CONFIG = SEGFUZZ_ROOT / "exp/segfuzz-comparison/ptmx/syzkaller.cfg"
PTMX_CORPUS = DDRD_ROOT / "corpus/ptmx-corpus.db"

FORBIDDEN_LOG_PATTERNS = [
    "revision mismatch",
    "SYZFAIL",
    "panic",
    "BUG:",
    "KASAN",
]

STAT_KEYS = [
    "exec total",
    "calls scheduled",
    "calls executed",
    "calls finished",
]


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.run_id = args.run_id or datetime.now().strftime("%Y%m%d-%H%M%S-phase2a-ptmx")
        self.run_dir = ARTIFACT_ROOT / "runs" / self.run_id
        self.config_dir = self.run_dir / "configs"
        self.log_dir = self.run_dir / "logs"
        self.bench_dir = self.run_dir / "bench"
        self.workdir_root = self.run_dir / "workdirs"
        self.samples_dir = self.run_dir / "samples"
        self.watcher_dir = self.run_dir / "watcher"
        self.build_dir = self.run_dir / "build"
        self.state_path = self.run_dir / "state.json"
        self.metrics_path = self.run_dir / "metrics.csv"
        self.current_proc: subprocess.Popen[bytes] | None = None
        self.current_case: dict[str, object] | None = None
        self.start_monotonic = 0.0
        self.last_tick = 0.0
        self.metrics_rows: list[dict[str, object]] = []

    def run(self) -> None:
        self.create_dirs()
        self.write_metadata("created")
        self.preflight()
        if not self.args.skip_build:
            self.build_binaries()
        self.prepare_cases()
        self.write_state(status="running", current_case=None)
        install_signal_handlers(self)
        for case in self.cases:
            self.run_case(case)
        self.write_metrics()
        self.write_state(status="complete", current_case=None)
        self.write_readme()

    def create_dirs(self) -> None:
        for path in [
            self.config_dir,
            self.log_dir,
            self.bench_dir,
            self.workdir_root,
            self.samples_dir,
            self.watcher_dir,
            self.build_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)
        latest = ARTIFACT_ROOT / "runs/latest-phase2a"
        try:
            latest.unlink()
        except FileNotFoundError:
            pass
        latest.symlink_to(self.run_dir)

    def write_metadata(self, phase: str) -> None:
        metadata = {
            "experiment": "added-throughput-phase2a-ptmx",
            "phase": phase,
            "run_id": self.run_id,
            "created_at": now_iso(),
            "duration_seconds": self.args.duration,
            "warmup_seconds": self.args.warmup,
            "cpuset": self.args.cpuset,
            "repos": {
                "mrpfuzz": repo_metadata(DDRD_ROOT),
                "segfuzz": repo_metadata(SEGFUZZ_ROOT),
            },
            "host": command_text(["bash", "-lc", "hostname; uname -a; lscpu | sed -n '1,40p'"]),
            "disk": command_text(["df", "-h", str(DDRD_ROOT), str(SEGFUZZ_ROOT)]),
            "spec": str(ARTIFACT_ROOT / "SPEC.md"),
        }
        write_json(self.run_dir / "metadata.json", metadata)

    def preflight(self) -> None:
        required = [
            MRPFUZZ_SRC_CONFIG,
            SEGFUZZ_SRC_CONFIG,
            PTMX_CORPUS,
            DDRD_ROOT / "images/bookworm.img",
            DDRD_ROOT / "images/bookworm.id_rsa",
            DDRD_ROOT / "bin/syz-manager",
            SEGFUZZ_GO_ROOT / "bin/syz-manager",
        ]
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise SystemExit("missing required files:\n" + "\n".join(missing))
        active = command_text(
            ["bash", "-lc", "ps -eo pid,ppid,stat,comm,args | rg 'syz-manager|qemu-system' | rg -v 'rg ' || true"]
        ).strip()
        if active:
            raise SystemExit("existing syz-manager/qemu-system process found:\n" + active)
        free_gb = shutil.disk_usage(DDRD_ROOT).free / (1024**3)
        if free_gb < self.args.min_free_gb:
            raise SystemExit(f"free disk too low: {free_gb:.1f} GiB < {self.args.min_free_gb} GiB")

    def build_binaries(self) -> None:
        commands = [
            (
                "mrpfuzz-build.log",
                DDRD_ROOT,
                ["make", "TARGETOS=linux", "TARGETARCH=amd64", "manager", "executor"],
            ),
            (
                "segfuzz-build.log",
                SEGFUZZ_GO_ROOT,
                ["make", "TARGETOS=linux", "TARGETARCH=amd64", "manager", "fuzzer", "executor"],
            ),
        ]
        for log_name, cwd, cmd in commands:
            log_path = self.build_dir / log_name
            with log_path.open("wb") as log:
                proc = subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=False)
            if proc.returncode != 0:
                raise SystemExit(f"build failed: {cmd} rc={proc.returncode}, log={log_path}")

    def prepare_cases(self) -> None:
        self.cases = [
            {
                "name": "mrpfuzz-ptmx-vm1",
                "tool": "mrpfuzz",
                "src_config": MRPFUZZ_SRC_CONFIG,
                "manager": DDRD_ROOT / "bin/syz-manager",
                "cwd": DDRD_ROOT,
                "vm_count": 1,
                "vm_cpu": 2,
                "procs": 2,
                "http_port": 64101,
            },
            {
                "name": "mrpfuzz-ptmx-vm2",
                "tool": "mrpfuzz",
                "src_config": MRPFUZZ_SRC_CONFIG,
                "manager": DDRD_ROOT / "bin/syz-manager",
                "cwd": DDRD_ROOT,
                "vm_count": 2,
                "vm_cpu": 2,
                "procs": 2,
                "http_port": 64102,
            },
            {
                "name": "mrpfuzz-ptmx-vm4",
                "tool": "mrpfuzz",
                "src_config": MRPFUZZ_SRC_CONFIG,
                "manager": DDRD_ROOT / "bin/syz-manager",
                "cwd": DDRD_ROOT,
                "vm_count": 4,
                "vm_cpu": 2,
                "procs": 2,
                "http_port": 64104,
            },
            {
                "name": "segfuzz-ptmx-vm1",
                "tool": "segfuzz",
                "src_config": SEGFUZZ_SRC_CONFIG,
                "manager": SEGFUZZ_GO_ROOT / "bin/syz-manager",
                "cwd": SEGFUZZ_GO_ROOT,
                "vm_count": 1,
                "vm_cpu": 4,
                "procs": 1,
                "http_port": 64201,
            },
        ]
        for case in self.cases:
            self.prepare_case(case)
        write_json(self.run_dir / "cases.json", self.cases, stringify=True)

    def prepare_case(self, case: dict[str, object]) -> None:
        name = str(case["name"])
        workdir = self.workdir_root / name
        config_path = self.config_dir / f"{name}.cfg"
        log_path = self.log_dir / f"{name}.log"
        bench_path = self.bench_dir / f"{name}.json"
        sample_path = self.samples_dir / f"{name}.jsonl"
        workdir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PTMX_CORPUS, workdir / "corpus.db")
        with Path(case["src_config"]).open() as f:
            cfg = json.load(f)
        cfg["workdir"] = str(workdir)
        cfg["http"] = f"127.0.0.1:{case['http_port']}"
        cfg["procs"] = case["procs"]
        cfg["reproduce"] = False
        cfg["vm"]["count"] = case["vm_count"]
        cfg["vm"]["cpu"] = case["vm_cpu"]
        if case["tool"] == "mrpfuzz":
            cfg["vm_running_time"] = 3600
        write_json(config_path, cfg)
        case["config"] = config_path
        case["workdir"] = workdir
        case["log"] = log_path
        case["bench"] = bench_path
        case["samples"] = sample_path

    def run_case(self, case: dict[str, object]) -> None:
        name = str(case["name"])
        self.current_case = case
        self.write_state(status="running", current_case=name)
        for path_key in ["log", "bench", "samples"]:
            path = Path(case[path_key])
            if path.exists():
                path.unlink()
        command = [
            "taskset",
            "-c",
            self.args.cpuset,
            "timeout",
            "--signal=INT",
            "--kill-after=30s",
            f"{self.args.duration}s",
            str(case["manager"]),
            "-config",
            str(case["config"]),
            "-bench",
            str(case["bench"]),
        ]
        case["command"] = command
        case["started_at"] = now_iso()
        self.start_monotonic = time.monotonic()
        self.last_tick = 0.0
        with Path(case["log"]).open("wb") as log:
            self.current_proc = subprocess.Popen(
                command,
                cwd=Path(case["cwd"]),
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            case["pid"] = self.current_proc.pid
            self.write_state(status="running", current_case=name)
            self.monitor_case(case)
        rc = self.current_proc.returncode if self.current_proc else None
        case["finished_at"] = now_iso()
        case["returncode"] = rc
        self.current_proc = None
        self.write_state(status="running", current_case=None)
        self.record_tick(case, final=True)
        self.metrics_rows.append(self.compute_case_metrics(case))
        self.write_metrics()

    def monitor_case(self, case: dict[str, object]) -> None:
        while self.current_proc and self.current_proc.poll() is None:
            elapsed = time.monotonic() - self.start_monotonic
            if should_tick(elapsed, self.last_tick):
                self.record_tick(case)
                self.last_tick = elapsed
            time.sleep(10)

    def record_tick(self, case: dict[str, object], final: bool = False) -> None:
        elapsed = time.monotonic() - self.start_monotonic
        latest = latest_bench(Path(case["bench"]))
        log_tail = tail_text(Path(case["log"]), 2_000_000)
        forbidden = [pat for pat in FORBIDDEN_LOG_PATTERNS if pat in log_tail]
        qemu_pids = pgrep_qemu(Path(case["workdir"]))
        alive = self.current_proc is not None and self.current_proc.poll() is None
        verdict = health_verdict(elapsed, latest, forbidden, alive, final)
        tick = {
            "timestamp": now_iso(),
            "run_id": self.run_id,
            "case": case["name"],
            "elapsed_seconds": round(elapsed, 3),
            "runner_alive": alive,
            "manager_pid": case.get("pid"),
            "qemu_pids": qemu_pids,
            "latest_stats": pick_stats(latest),
            "forbidden_patterns": forbidden,
            "disk_free_gb": round(shutil.disk_usage(DDRD_ROOT).free / (1024**3), 2),
            "verdict": verdict,
            "final": final,
        }
        with Path(case["samples"]).open("a") as f:
            f.write(json.dumps(tick, sort_keys=True) + "\n")
        with (self.watcher_dir / "ticks.jsonl").open("a") as f:
            f.write(json.dumps(tick, sort_keys=True) + "\n")

    def compute_case_metrics(self, case: dict[str, object]) -> dict[str, object]:
        samples = read_jsonl(Path(case["samples"]))
        usable = [
            s for s in samples
            if s.get("elapsed_seconds", 0) >= self.args.warmup
            and s.get("latest_stats", {}).get("calls executed") is not None
        ]
        row: dict[str, object] = {
            "case": case["name"],
            "tool": case["tool"],
            "vm_count": case["vm_count"],
            "vm_cpu": case["vm_cpu"],
            "procs": case["procs"],
            "returncode": case.get("returncode"),
            "valid": False,
        }
        if len(usable) < 2:
            row["reason"] = "not enough post-warmup samples"
            return row
        first, last = usable[0], usable[-1]
        seconds = float(last["elapsed_seconds"]) - float(first["elapsed_seconds"])
        row["measurement_seconds"] = round(seconds, 3)
        if seconds <= 0:
            row["reason"] = "non-positive measurement window"
            return row
        for key in STAT_KEYS:
            a = first["latest_stats"].get(key)
            b = last["latest_stats"].get(key)
            if a is None or b is None:
                continue
            delta = float(b) - float(a)
            row[f"delta_{key}"] = int(delta)
            row[f"rate_{key}_per_s"] = round(delta / seconds, 6)
        exec_total = row.get("delta_exec total")
        calls_executed = row.get("delta_calls executed")
        if isinstance(exec_total, int) and exec_total > 0 and isinstance(calls_executed, int):
            row["calls_executed_per_exec_total"] = round(calls_executed / exec_total, 6)
        row["valid"] = case.get("returncode") == 124 and not any(s.get("forbidden_patterns") for s in samples)
        if not row["valid"]:
            row["reason"] = "non-timeout rc or forbidden log pattern"
        return row

    def write_metrics(self) -> None:
        if not self.metrics_rows:
            return
        fieldnames: list[str] = []
        for row in self.metrics_rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        with self.metrics_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in self.metrics_rows:
                writer.writerow(row)

    def write_state(self, status: str, current_case: str | None) -> None:
        state = {
            "run_id": self.run_id,
            "status": status,
            "updated_at": now_iso(),
            "current_case": current_case,
            "duration_seconds": self.args.duration,
            "warmup_seconds": self.args.warmup,
            "cpuset": self.args.cpuset,
            "run_dir": str(self.run_dir),
            "metrics": str(self.metrics_path),
        }
        if self.current_proc is not None:
            state["current_pid"] = self.current_proc.pid
        write_json(self.state_path, state)

    def write_readme(self) -> None:
        lines = [
            "# Phase 2A ptmx Throughput Run",
            "",
            f"- run_id: `{self.run_id}`",
            f"- completed_at: `{now_iso()}`",
            f"- cpuset: `{self.args.cpuset}`",
            f"- duration_seconds: `{self.args.duration}`",
            f"- warmup_seconds: `{self.args.warmup}`",
            f"- metrics: `{self.metrics_path}`",
            "",
            "Primary metric is post-warmup `calls executed/s`.",
        ]
        (self.run_dir / "README.md").write_text("\n".join(lines) + "\n")

    def stop_current(self) -> None:
        if self.current_proc and self.current_proc.poll() is None:
            self.current_proc.send_signal(signal.SIGINT)
            try:
                self.current_proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.current_proc.kill()


def should_tick(elapsed: float, last_tick: float) -> bool:
    if elapsed < 60:
        return False
    if last_tick == 0:
        return True
    if elapsed < 300:
        return elapsed - last_tick >= 60
    return elapsed - last_tick >= 600


def health_verdict(
    elapsed: float,
    latest: dict[str, object] | None,
    forbidden: list[str],
    alive: bool,
    final: bool,
) -> str:
    if forbidden:
        return "unhealthy"
    if not alive and not final:
        return "unhealthy"
    if latest is None:
        return "uncertain" if elapsed < 600 else "unhealthy"
    stats = pick_stats(latest)
    if stats.get("calls executed") is None:
        return "uncertain" if elapsed < 600 else "unhealthy"
    return "healthy"


def install_signal_handlers(runner: Runner) -> None:
    def handler(signum: int, _frame: object) -> None:
        runner.write_state(status=f"interrupted-signal-{signum}", current_case=None)
        runner.stop_current()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def latest_bench(path: Path) -> dict[str, object] | None:
    objects = read_json_stream(path)
    return objects[-1] if objects else None


def read_json_stream(path: Path) -> list[dict[str, object]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    data = path.read_text(errors="replace")
    decoder = json.JSONDecoder()
    idx = 0
    objects: list[dict[str, object]] = []
    while idx < len(data):
        while idx < len(data) and data[idx].isspace():
            idx += 1
        if idx >= len(data):
            break
        try:
            obj, end = decoder.raw_decode(data, idx)
        except json.JSONDecodeError:
            break
        if isinstance(obj, dict):
            objects.append(obj)
        idx = end
    return objects


def read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def pick_stats(stats: dict[str, object] | None) -> dict[str, int | None]:
    if not stats:
        return {key: None for key in STAT_KEYS}
    picked: dict[str, int | None] = {}
    for key in STAT_KEYS:
        value = stats.get(key)
        picked[key] = int(value) if isinstance(value, (int, float)) else None
    return picked


def pgrep_qemu(workdir: Path) -> list[int]:
    pattern = f"qemu-system.*{workdir}"
    out = command_text(["pgrep", "-f", pattern]).strip()
    pids = []
    for item in out.splitlines():
        try:
            pids.append(int(item))
        except ValueError:
            pass
    return pids


def tail_text(path: Path, max_bytes: int) -> str:
    if not path.exists():
        return ""
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        return f.read().decode(errors="replace")


def repo_metadata(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "branch": command_text(["git", "branch", "--show-current"], cwd=path).strip(),
        "head": command_text(["git", "rev-parse", "HEAD"], cwd=path).strip(),
        "status_short": command_text(["git", "status", "--short", "--branch"], cwd=path),
        "diff_stat": command_text(["git", "diff", "--stat"], cwd=path),
    }


def command_text(cmd: list[str], cwd: Path | None = None) -> str:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return ""
    return proc.stdout + proc.stderr


def write_json(path: Path, obj: object, stringify: bool = False) -> None:
    if stringify:
        obj = stringify_paths(obj)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def stringify_paths(obj: object) -> object:
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, list):
        return [stringify_paths(item) for item in obj]
    if isinstance(obj, dict):
        return {str(key): stringify_paths(value) for key, value in obj.items()}
    return obj


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="")
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--warmup", type=int, default=600)
    parser.add_argument("--cpuset", default="0,1")
    parser.add_argument("--min-free-gb", type=float, default=20.0)
    parser.add_argument("--skip-build", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        Runner(parse_args()).run()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
