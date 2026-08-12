#!/usr/bin/env python3
"""Run a Phase 2B complete-MRPFuzz throughput diagnostic.

This diagnostic compares:
- MRPFuzz fuzz producer throughput on a pinned fuzz cpuset, while validate
  remains enabled on a separate background cpuset.
- SegFuzz baseline throughput on a comparable pinned cpuset.

It is intentionally a short diagnostic runner, not the final paper-grade repeat
matrix. It keeps all workdirs and copied configs under the run artifact dir.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


DDRD_ROOT = Path("/home/zzzccc/BASS/DDRD-syzkaller")
SEGFUZZ_ROOT = Path("/home/zzzccc/BASS/segfuzz")
SEGFUZZ_GO_ROOT = SEGFUZZ_ROOT / "gotools/src/github.com/google/segfuzz"
ARTIFACT_ROOT = DDRD_ROOT / "paper/artifacts/claims/added-throughput"

PTMX_CORPUS = DDRD_ROOT / "corpus/ptmx-corpus.db"
SEGFUZZ_SRC_CONFIG = SEGFUZZ_ROOT / "exp/segfuzz-comparison/ptmx/syzkaller.cfg"
MRPFUZZ_BINARY_OUTPUT = DDRD_ROOT / "kernels/output-binary-trace-20260630"
MRPFUZZ_BINARY_BUILDS = DDRD_ROOT / "kernels/builds-binary-trace-20260630"

STAT_KEYS = ["exec total", "calls scheduled", "calls executed", "calls finished"]
FUZZ_LOG_KEYS = [
    "ddrd pairs fuzz",
    "ddrd varnames fuzz",
    "uaf corpus",
    "uaf pairs fuzz",
    "dynamic threshold (μs)",
]
FORBIDDEN_LOG_PATTERNS = [
    "revision mismatch",
    "SYZFAIL",
    "panic",
    "BUG:",
    "KASAN",
    "KCSAN: data-race",
    "BUG: KCSAN",
    "crash:",
    "no output from test machine",
]


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.run_id = args.run_id or datetime.now().strftime("%Y%m%d-%H%M%S-phase2b-complete-ptmx")
        self.run_dir = ARTIFACT_ROOT / "runs" / self.run_id
        self.config_dir = self.run_dir / "configs"
        self.log_dir = self.run_dir / "logs"
        self.bench_dir = self.run_dir / "bench"
        self.workdir_root = self.run_dir / "workdirs"
        self.samples_dir = self.run_dir / "samples"
        self.watcher_dir = self.run_dir / "watcher"
        self.build_dir = self.run_dir / "build"
        self.metrics_path = self.run_dir / "metrics.csv"
        self.state_path = self.run_dir / "state.json"
        self.children: list[subprocess.Popen[bytes]] = []
        self.metrics_rows: list[dict[str, object]] = []

    def run(self) -> None:
        self.create_dirs()
        install_signal_handlers(self)
        self.write_metadata("created")
        self.preflight()
        if self.args.build:
            self.build_binaries()
        if self.want_mrpfuzz():
            self.prepare_mrpfuzz_complete()
        if self.want_segfuzz():
            self.prepare_segfuzz()
        if self.want_mrpfuzz():
            self.write_state("running", "mrpfuzz-complete")
            self.run_mrpfuzz_complete()
        if self.want_segfuzz():
            self.write_state("running", self.segfuzz["name"])
            self.run_segfuzz()
        self.write_metrics()
        self.write_summary()
        self.write_state("complete", None)

    def want_mrpfuzz(self) -> bool:
        return self.args.case in ("both", "mrpfuzz")

    def want_segfuzz(self) -> bool:
        return self.args.case in ("both", "segfuzz")

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
        latest = ARTIFACT_ROOT / "runs/latest-phase2b"
        try:
            latest.unlink()
        except FileNotFoundError:
            pass
        latest.symlink_to(self.run_dir)

    def write_metadata(self, phase: str) -> None:
        metadata = {
            "experiment": "added-throughput-phase2b-complete-ptmx",
            "phase": phase,
            "case": self.args.case,
            "run_id": self.run_id,
            "created_at": now_iso(),
            "duration_seconds": self.args.duration,
            "warmup_seconds": self.args.warmup,
            "resource_model": {
                "mrpfuzz_total_cpuset": self.args.mrpfuzz_cpuset,
                "mrpfuzz_fuzz_cpuset": self.args.mrpfuzz_fuzz_cpuset,
                "mrpfuzz_validate_cpuset": self.args.mrpfuzz_validate_cpuset,
                "segfuzz_cpuset": self.args.segfuzz_cpuset,
                "segfuzz_vm_cpu": segfuzz_vm_cpu(self.args),
                "segfuzz_procs": self.args.segfuzz_procs,
            },
            "mrpfuzz_seed_workdir": self.args.mrpfuzz_seed_workdir,
            "mrpfuzz_max_pairs_per_task": self.args.mrpfuzz_max_pairs_per_task,
            "stall_timeout_seconds": self.args.stall_timeout,
            "repos": {
                "mrpfuzz": repo_metadata(DDRD_ROOT),
                "segfuzz": repo_metadata(SEGFUZZ_ROOT),
            },
            "host": command_text(["bash", "-lc", "hostname; uname -a; lscpu | sed -n '1,40p'"]),
            "disk": command_text(["df", "-h", str(DDRD_ROOT), str(SEGFUZZ_ROOT)]),
        }
        write_json(self.run_dir / "metadata.json", metadata)

    def preflight(self) -> None:
        required = [
            PTMX_CORPUS,
            DDRD_ROOT / "images/bookworm.img",
            DDRD_ROOT / "images/bookworm.id_rsa",
        ]
        if self.want_mrpfuzz():
            required += [
                DDRD_ROOT / "bin/syz-manager",
                MRPFUZZ_BINARY_OUTPUT / "ptmx/bzImage",
                MRPFUZZ_BINARY_OUTPUT / "ptmx/vmlinux",
            ]
            if self.args.mrpfuzz_seed_workdir:
                seed = Path(self.args.mrpfuzz_seed_workdir)
                required += [
                    seed / "corpus.db",
                    seed / "uaf-corpus.db",
                    seed / "uaf-validate-queue.db",
                    seed / "race-pair-index.db",
                ]
        if self.want_segfuzz():
            required += [
                SEGFUZZ_SRC_CONFIG,
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
        ]
        if self.want_mrpfuzz():
            commands.append(
                ("mrpfuzz-build.log", DDRD_ROOT, ["make", "TARGETOS=linux", "TARGETARCH=amd64", "manager", "executor"])
            )
        if self.want_segfuzz():
            commands.append(
                (
                    "segfuzz-build.log",
                    SEGFUZZ_GO_ROOT,
                    ["make", "TARGETOS=linux", "TARGETARCH=amd64", "manager", "fuzzer", "executor"],
                )
            )
        for log_name, cwd, cmd in commands:
            log_path = self.build_dir / log_name
            with log_path.open("wb") as log:
                proc = subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=False)
            if proc.returncode != 0:
                raise SystemExit(f"build failed: {cmd} rc={proc.returncode}, log={log_path}")

    def prepare_mrpfuzz_complete(self) -> None:
        scripts_dir = DDRD_ROOT / "scripts"
        sys.path.insert(0, str(scripts_dir))
        import generate_config as cfggen  # type: ignore

        cfggen.KERNEL_OUTPUT = str(MRPFUZZ_BINARY_OUTPUT)
        cfggen.KERNEL_BUILDS = str(MRPFUZZ_BINARY_BUILDS)

        workdir = self.workdir_root / "mrpfuzz-complete"
        validate_workdir = workdir / "validate-run"
        workdir.mkdir(parents=True, exist_ok=True)
        validate_workdir.mkdir(parents=True, exist_ok=True)
        if self.args.mrpfuzz_seed_workdir:
            self.copy_mrpfuzz_seed_state(Path(self.args.mrpfuzz_seed_workdir), workdir)
        else:
            shutil.copy2(PTMX_CORPUS, workdir / "corpus.db")

        fuzz_cfg = cfggen.generate_config("ptmx", "fuzz", include_experimental=True)
        validate_cfg = cfggen.generate_config("ptmx", "validate", include_experimental=True)

        self.apply_mrpfuzz_common(fuzz_cfg, workdir, "127.0.0.1:64301", vm_count=1, vm_cpu=2, procs=2)
        fuzz_exp = fuzz_cfg.setdefault("experimental", {})
        fuzz_exp["race_mode"] = True
        fuzz_exp["barrier_mode"] = True
        fuzz_exp["disable_race_validate_queue"] = False
        fuzz_exp["disable_uaf_validate_queue"] = False
        fuzz_exp["disable_race_history"] = False
        fuzz_exp["skip_race_activation_restart"] = False
        fuzz_exp["enable_timing_exploration"] = False
        fuzz_exp["enable_solo_filter"] = False
        fuzz_exp["enable_coverage_triage"] = False
        fuzz_exp["enable_affinity_table"] = False
        fuzz_exp["enable_dynamic_threshold"] = True
        fuzz_exp["dynamic_threshold_eval_sec"] = 30
        fuzz_cfg["vm_running_time"] = 3600

        self.apply_mrpfuzz_common(validate_cfg, validate_workdir, "127.0.0.1:64302", vm_count=1, vm_cpu=2, procs=2)
        validate_exp = validate_cfg.setdefault("experimental", {})
        validate_exp["race_mode"] = True
        validate_exp["barrier_mode"] = True
        uaf_validate = validate_exp.setdefault("uaf_validate", {})
        uaf_validate["max_concurrent"] = 1
        uaf_validate["continuous_mode"] = True
        uaf_validate["streaming_load"] = True
        uaf_validate["continue_after_hb"] = True
        uaf_validate.setdefault("max_batch_timeout_seconds", 600)
        uaf_validate.setdefault("idle_reload_seconds", 10)
        uaf_validate["max_pairs_per_task"] = self.args.mrpfuzz_max_pairs_per_task
        validate_cfg["vm_running_time"] = 3600

        self.mrpfuzz = {
            "fuzz": {
                "name": "mrpfuzz-complete-fuzz",
                "config": self.config_dir / "mrpfuzz-complete-fuzz.cfg",
                "log": self.log_dir / "mrpfuzz-complete-fuzz.log",
                "bench": self.bench_dir / "mrpfuzz-complete-fuzz.json",
                "workdir": workdir,
                "cpuset": self.args.mrpfuzz_fuzz_cpuset,
            },
            "validate": {
                "name": "mrpfuzz-complete-validate",
                "config": self.config_dir / "mrpfuzz-complete-validate.cfg",
                "log": self.log_dir / "mrpfuzz-complete-validate.log",
                "bench": self.bench_dir / "mrpfuzz-complete-validate.json",
                "workdir": validate_workdir,
                "cpuset": self.args.mrpfuzz_validate_cpuset,
            },
        }
        write_json(self.mrpfuzz["fuzz"]["config"], fuzz_cfg)
        write_json(self.mrpfuzz["validate"]["config"], validate_cfg)

    def copy_mrpfuzz_seed_state(self, seed_workdir: Path, workdir: Path) -> None:
        copied = []
        for name in ["corpus.db", "uaf-corpus.db", "uaf-validate-queue.db", "race-pair-index.db", "threshold-state.json"]:
            src = seed_workdir / name
            if not src.exists():
                if name == "threshold-state.json":
                    continue
                raise SystemExit(f"missing MRPFuzz seed file: {src}")
            dst = workdir / name
            shutil.copy2(src, dst)
            copied.append(str(dst))
        write_json(
            self.run_dir / "mrpfuzz-seed-state.json",
            {
                "seed_workdir": str(seed_workdir),
                "copied_files": copied,
            },
        )

    def apply_mrpfuzz_common(
        self,
        cfg: dict[str, object],
        workdir: Path,
        http: str,
        vm_count: int,
        vm_cpu: int,
        procs: int,
    ) -> None:
        cfg["workdir"] = str(workdir)
        cfg["http"] = http
        cfg["syzkaller"] = str(DDRD_ROOT)
        cfg["image"] = str(DDRD_ROOT / "images/bookworm.img")
        cfg["sshkey"] = str(DDRD_ROOT / "images/bookworm.id_rsa")
        cfg["procs"] = procs
        cfg["reproduce"] = False
        cfg["fuzzing_vms"] = vm_count
        vm_cfg = cfg.setdefault("vm", {})
        vm_cfg["count"] = vm_count
        vm_cfg["cpu"] = vm_cpu
        vm_cfg["mem"] = 4096
        vm_cfg["kernel"] = str(MRPFUZZ_BINARY_OUTPUT / "ptmx/bzImage")
        vm_cfg["qemu_args"] = "-enable-kvm"
        cfg["kernel_obj"] = str(MRPFUZZ_BINARY_BUILDS / "x86")
        cfg["vmlinux"] = str(MRPFUZZ_BINARY_OUTPUT / "ptmx/vmlinux")

    def prepare_segfuzz(self) -> None:
        vm_cpu = segfuzz_vm_cpu(self.args)
        name = f"segfuzz-{vm_cpu}core"
        workdir = self.workdir_root / name
        workdir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PTMX_CORPUS, workdir / "corpus.db")
        with SEGFUZZ_SRC_CONFIG.open() as f:
            cfg = json.load(f)
        cfg["workdir"] = str(workdir)
        cfg["http"] = "127.0.0.1:64311"
        cfg["procs"] = self.args.segfuzz_procs
        cfg["reproduce"] = False
        cfg["vm"]["count"] = 1
        cfg["fuzzing_vms"] = 1
        cfg["vm"]["cpu"] = vm_cpu
        cfg["vm"]["mem"] = 4096
        self.segfuzz = {
            "name": name,
            "config": self.config_dir / f"{name}.cfg",
            "log": self.log_dir / f"{name}.log",
            "bench": self.bench_dir / f"{name}.json",
            "workdir": workdir,
            "cpuset": self.args.segfuzz_cpuset,
        }
        write_json(self.segfuzz["config"], cfg)

    def run_mrpfuzz_complete(self) -> None:
        fuzz = self.mrpfuzz["fuzz"]
        validate = self.mrpfuzz["validate"]
        fuzz_cmd = manager_cmd(DDRD_ROOT / "bin/syz-manager", fuzz["config"], fuzz["bench"], fuzz["cpuset"])
        validate_cmd = manager_cmd(
            DDRD_ROOT / "bin/syz-manager",
            validate["config"],
            validate["bench"],
            validate["cpuset"],
            mode="uaf-validate",
        )
        fuzz["command"] = fuzz_cmd
        validate["command"] = validate_cmd
        fuzz_proc = self.start_process(fuzz_cmd, DDRD_ROOT, fuzz["log"])
        fuzz["pid"] = fuzz_proc.pid
        time.sleep(self.args.validate_start_delay)
        validate_proc = self.start_process(validate_cmd, DDRD_ROOT, validate["log"])
        validate["pid"] = validate_proc.pid
        self.monitor_pair(
            "mrpfuzz-complete",
            fuzz_proc,
            validate_proc,
            duration=self.args.duration,
            sample_path=self.samples_dir / "mrpfuzz-complete.jsonl",
        )
        self.metrics_rows.append(self.compute_bench_metrics("mrpfuzz-complete-fuzz", "mrpfuzz", fuzz["bench"]))
        self.metrics_rows[-1].update(self.summarize_mrpfuzz_logs())
        self.write_metrics()

    def run_segfuzz(self) -> None:
        case = self.segfuzz
        cmd = manager_cmd(SEGFUZZ_GO_ROOT / "bin/syz-manager", case["config"], case["bench"], case["cpuset"])
        case["command"] = cmd
        proc = self.start_process(cmd, SEGFUZZ_GO_ROOT, case["log"])
        case["pid"] = proc.pid
        self.monitor_single(
            case["name"],
            proc,
            duration=self.args.duration,
            sample_path=self.samples_dir / f"{case['name']}.jsonl",
            log_path=case["log"],
            bench_path=case["bench"],
        )
        self.metrics_rows.append(self.compute_bench_metrics(case["name"], "segfuzz", case["bench"]))
        self.write_metrics()

    def start_process(self, cmd: list[str], cwd: Path, log_path: Path) -> subprocess.Popen[bytes]:
        for path in [log_path]:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        bench_index = cmd.index("-bench") + 1 if "-bench" in cmd else -1
        if bench_index > 0:
            try:
                Path(cmd[bench_index]).unlink()
            except FileNotFoundError:
                pass
        log = log_path.open("wb")
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        proc._phase2b_log_handle = log  # type: ignore[attr-defined]
        self.children.append(proc)
        time.sleep(2)
        if proc.poll() is not None:
            log.close()
            raise SystemExit(f"process failed to start rc={proc.returncode}: {' '.join(cmd)} log={log_path}")
        return proc

    def monitor_pair(
        self,
        label: str,
        fuzz_proc: subprocess.Popen[bytes],
        validate_proc: subprocess.Popen[bytes],
        duration: int,
        sample_path: Path,
    ) -> None:
        start = time.monotonic()
        last_tick = 0.0
        watchdog = ProgressWatchdog(self.args.stall_timeout, "calls executed")
        while True:
            elapsed = time.monotonic() - start
            if elapsed >= duration:
                break
            if should_tick(elapsed, last_tick):
                self.record_mrpfuzz_tick(label, elapsed, sample_path, final=False)
                last_tick = elapsed
            stall_reason = watchdog.check(self.mrpfuzz["fuzz"]["bench"])
            if stall_reason:
                self.write_state("failed-stalled", label)
                self.stop_process(fuzz_proc)
                self.stop_process(validate_proc)
                self.record_mrpfuzz_tick(label, time.monotonic() - start, sample_path, final=True)
                raise SystemExit(f"{label}: {stall_reason}")
            if fuzz_proc.poll() is not None or validate_proc.poll() is not None:
                break
            time.sleep(10)
        self.stop_process(fuzz_proc)
        self.stop_process(validate_proc)
        self.record_mrpfuzz_tick(label, time.monotonic() - start, sample_path, final=True)

    def monitor_single(
        self,
        label: str,
        proc: subprocess.Popen[bytes],
        duration: int,
        sample_path: Path,
        log_path: Path,
        bench_path: Path,
    ) -> None:
        start = time.monotonic()
        last_tick = 0.0
        watchdog = ProgressWatchdog(self.args.stall_timeout, "calls executed")
        while True:
            elapsed = time.monotonic() - start
            if elapsed >= duration:
                break
            if should_tick(elapsed, last_tick):
                self.record_single_tick(label, elapsed, sample_path, log_path, bench_path, proc, final=False)
                last_tick = elapsed
            stall_reason = watchdog.check(bench_path)
            if stall_reason:
                self.write_state("failed-stalled", label)
                self.stop_process(proc)
                self.record_single_tick(label, time.monotonic() - start, sample_path, log_path, bench_path, proc, final=True)
                raise SystemExit(f"{label}: {stall_reason}")
            if proc.poll() is not None:
                break
            time.sleep(10)
        self.stop_process(proc)
        self.record_single_tick(label, time.monotonic() - start, sample_path, log_path, bench_path, proc, final=True)

    def stop_process(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        handle = getattr(proc, "_phase2b_log_handle", None)
        if handle is not None:
            handle.close()

    def stop_all(self) -> None:
        for proc in list(self.children):
            self.stop_process(proc)

    def record_mrpfuzz_tick(self, label: str, elapsed: float, sample_path: Path, final: bool) -> None:
        fuzz = self.mrpfuzz["fuzz"]
        validate = self.mrpfuzz["validate"]
        tick = {
            "timestamp": now_iso(),
            "run_id": self.run_id,
            "case": label,
            "elapsed_seconds": round(elapsed, 3),
            "final": final,
            "fuzz": {
                "pid": fuzz.get("pid"),
                "bench": pick_stats(latest_bench(fuzz["bench"])),
                "log": latest_fuzz_stats(fuzz["log"]),
                "forbidden": forbidden_patterns(fuzz["log"]),
                "qemu_pids": qemu_child_pids(fuzz.get("pid")),
            },
            "validate": {
                "pid": validate.get("pid"),
                "bench": pick_stats(latest_bench(validate["bench"])),
                "queue": latest_validate_queue_stats(validate["log"]),
                "storage": latest_storage_stats(validate["log"]),
                "forbidden": forbidden_patterns(validate["log"]),
                "qemu_pids": qemu_child_pids(validate.get("pid")),
            },
            "disk_free_gb": round(shutil.disk_usage(DDRD_ROOT).free / (1024**3), 2),
        }
        append_jsonl(sample_path, tick)
        append_jsonl(self.watcher_dir / "ticks.jsonl", tick)

    def record_single_tick(
        self,
        label: str,
        elapsed: float,
        sample_path: Path,
        log_path: Path,
        bench_path: Path,
        proc: subprocess.Popen[bytes],
        final: bool,
    ) -> None:
        tick = {
            "timestamp": now_iso(),
            "run_id": self.run_id,
            "case": label,
            "elapsed_seconds": round(elapsed, 3),
            "final": final,
            "pid": proc.pid,
            "qemu_pids": qemu_child_pids(proc.pid),
            "bench": pick_stats(latest_bench(bench_path)),
            "forbidden": forbidden_patterns(log_path),
            "disk_free_gb": round(shutil.disk_usage(DDRD_ROOT).free / (1024**3), 2),
        }
        append_jsonl(sample_path, tick)
        append_jsonl(self.watcher_dir / "ticks.jsonl", tick)

    def compute_bench_metrics(self, case: str, tool: str, bench_path: Path) -> dict[str, object]:
        samples = read_json_stream(bench_path)
        usable = [s for s in samples if isinstance(s.get("uptime"), (int, float)) and s["uptime"] >= self.args.warmup]
        row: dict[str, object] = {"case": case, "tool": tool, "valid_preliminary": False, "samples": len(samples)}
        if len(samples) >= 2:
            row["full_valid"] = add_bench_window_metrics(row, "full_", samples[0], samples[-1])
        if len(usable) < 2:
            row["reason"] = "not enough post-warmup bench samples"
            return row
        if not add_bench_window_metrics(row, "", usable[0], usable[-1]):
            row["reason"] = "non-positive measurement window"
            return row
        row["valid_preliminary"] = row.get("rate_calls executed_per_s") is not None
        return row

    def summarize_mrpfuzz_logs(self) -> dict[str, object]:
        fuzz_stats = all_fuzz_stats(self.mrpfuzz["fuzz"]["log"])
        result: dict[str, object] = {}
        usable = [row for row in fuzz_stats if row["seconds_from_start"] >= self.args.warmup]
        if len(usable) >= 2:
            first, last = usable[0], usable[-1]
            seconds = last["seconds_from_start"] - first["seconds_from_start"]
            if seconds > 0:
                for key in FUZZ_LOG_KEYS:
                    if key in first and key in last:
                        delta = last[key] - first[key]
                        result[f"delta_{key}"] = delta
                        result[f"rate_{key}_per_s"] = round(delta / seconds, 6)
                result["last_ddrd_pairs_fuzz"] = last.get("ddrd pairs fuzz")
                result["last_uaf_corpus"] = last.get("uaf corpus")
        queue = latest_validate_queue_stats(self.mrpfuzz["validate"]["log"])
        for key, value in queue.items():
            result[f"validate_{key}"] = value
        storage = latest_storage_stats(self.mrpfuzz["validate"]["log"])
        for key, value in storage.items():
            result[f"storage_{key}"] = value
        return result

    def write_metrics(self) -> None:
        if not self.metrics_rows:
            return
        fieldnames: list[str] = []
        for row in self.metrics_rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        with self.metrics_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(self.metrics_rows)

    def write_summary(self) -> None:
        lines = [
            "# Phase 2B Complete MRPFuzz Diagnostic",
            "",
            f"- Run id: `{self.run_id}`",
            f"- Completed at: `{now_iso()}`",
            f"- Duration seconds: `{self.args.duration}`",
            f"- Warmup seconds: `{self.args.warmup}`",
            f"- Case: `{self.args.case}`",
            f"- MRPFuzz fuzz cpuset: `{self.args.mrpfuzz_fuzz_cpuset}`",
            f"- MRPFuzz validate cpuset: `{self.args.mrpfuzz_validate_cpuset}`",
            f"- SegFuzz cpuset: `{self.args.segfuzz_cpuset}`",
            f"- SegFuzz VM CPUs: `{segfuzz_vm_cpu(self.args)}`",
            f"- SegFuzz procs: `{self.args.segfuzz_procs}`",
            f"- Metrics: `{self.metrics_path}`",
            "",
            "This is a diagnostic run. Treat results as preliminary until repeated.",
        ]
        if self.metrics_rows:
            lines += [
                "",
                "| case | post-warmup calls executed/s | full calls executed/s | exec total/s | notes |",
                "| --- | ---: | ---: | ---: | --- |",
            ]
            for row in self.metrics_rows:
                lines.append(
                    "| {case} | {calls} | {full_calls} | {execs} | {notes} |".format(
                        case=row.get("case", ""),
                        calls=row.get("rate_calls executed_per_s", ""),
                        full_calls=row.get("full_rate_calls executed_per_s", ""),
                        execs=row.get("rate_exec total_per_s", ""),
                        notes=row.get("reason", ""),
                    )
                )
        (self.run_dir / "SUMMARY.md").write_text("\n".join(lines) + "\n")

    def write_state(self, status: str, current_case: str | None) -> None:
        write_json(
            self.state_path,
            {
                "run_id": self.run_id,
                "status": status,
                "updated_at": now_iso(),
                "current_case": current_case,
                "duration_seconds": self.args.duration,
                "warmup_seconds": self.args.warmup,
                "run_dir": str(self.run_dir),
                "metrics": str(self.metrics_path),
            },
        )


def manager_cmd(
    manager: Path,
    config: Path,
    bench: Path,
    cpuset: str,
    mode: str | None = None,
) -> list[str]:
    cmd = [
        "taskset",
        "-c",
        cpuset,
        str(manager),
    ]
    if mode:
        cmd += ["-mode", mode]
    cmd += ["-config", str(config), "-bench", str(bench)]
    return cmd


def cpuset_cpu_count(cpuset: str) -> int:
    count = 0
    for part in cpuset.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if end < start:
                raise ValueError(f"invalid cpuset range: {part}")
            count += end - start + 1
        else:
            int(part)
            count += 1
    return count


def segfuzz_vm_cpu(args: argparse.Namespace) -> int:
    if args.segfuzz_vm_cpu > 0:
        return args.segfuzz_vm_cpu
    count = cpuset_cpu_count(args.segfuzz_cpuset)
    return count if count > 0 else 1


class ProgressWatchdog:
    def __init__(self, timeout: int, stat: str) -> None:
        self.timeout = timeout
        self.stat = stat
        self.last_value: float | None = None
        self.last_progress = time.monotonic()
        self.started = False

    def check(self, bench_path: Path) -> str | None:
        if self.timeout <= 0:
            return None
        bench = latest_bench(bench_path)
        stats = pick_stats(bench)
        value = stats.get(self.stat)
        now = time.monotonic()
        if not isinstance(value, (int, float)):
            return None
        if self.last_value is None or value > self.last_value:
            self.last_value = float(value)
            self.last_progress = now
            self.started = True
            return None
        if self.started and now-self.last_progress >= self.timeout:
            return f"{self.stat} stalled at {value} for {self.timeout}s"
        return None


def should_tick(elapsed: float, last_tick: float) -> bool:
    if elapsed < 60:
        return False
    if last_tick == 0:
        return True
    return elapsed - last_tick >= 60


def install_signal_handlers(runner: Runner) -> None:
    def handler(signum: int, _frame: object) -> None:
        runner.write_state(f"interrupted-signal-{signum}", None)
        runner.stop_all()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def latest_bench(path: Path) -> dict[str, object] | None:
    rows = read_json_stream(path)
    return rows[-1] if rows else None


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


def pick_stats(stats: dict[str, object] | None) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    stats = stats or {}
    for key in STAT_KEYS:
        value = stats.get(key)
        result[key] = int(value) if isinstance(value, (int, float)) else None
    return result


def latest_fuzz_stats(path: Path) -> dict[str, int]:
    rows = all_fuzz_stats(path)
    return rows[-1] if rows else {}


def all_fuzz_stats(path: Path) -> list[dict[str, int]]:
    if not path.exists():
        return []
    ts_re = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) ")
    key_re = {key: re.compile(re.escape(key) + r"=(\d+)") for key in STAT_KEYS + FUZZ_LOG_KEYS}
    rows: list[dict[str, int]] = []
    first_ts: datetime | None = None
    for line in path.read_text(errors="replace").splitlines():
        if "calls executed=" not in line:
            continue
        ts_match = ts_re.match(line)
        if not ts_match:
            continue
        ts = datetime.strptime(ts_match.group(1), "%Y/%m/%d %H:%M:%S")
        if first_ts is None:
            first_ts = ts
        row: dict[str, int] = {"seconds_from_start": int((ts - first_ts).total_seconds())}
        for key, regex in key_re.items():
            match = regex.search(line)
            if match:
                row[key] = int(match.group(1))
        rows.append(row)
    return rows


def latest_validate_queue_stats(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    status_re = re.compile(
        r"uaf validation queue: status pending=(?P<pending>\d+) processed=(?P<processed>\d+) "
        r"success=(?P<success>\d+) rate_per_min=(?P<rate>[0-9.]+) idle=(?P<idle>true|false)"
    )
    poll_re = re.compile(
        r"uaf validation queue: (?:initial load|poll) accepted=(?P<accepted>\d+) acked=(?P<acked>\d+) "
        r"pending=(?P<pending>\d+) seq=(?P<seq>\d+)"
    )
    latest: dict[str, object] = {}
    for line in path.read_text(errors="replace").splitlines():
        match = status_re.search(line)
        if match:
            latest.update(
                {
                    "pending": int(match.group("pending")),
                    "processed": int(match.group("processed")),
                    "success": int(match.group("success")),
                    "rate_per_min": float(match.group("rate")),
                    "idle": match.group("idle") == "true",
                }
            )
        match = poll_re.search(line)
        if match:
            latest.update(
                {
                    "last_poll_accepted": int(match.group("accepted")),
                    "last_poll_acked": int(match.group("acked")),
                    "last_poll_pending": int(match.group("pending")),
                    "last_poll_seq": int(match.group("seq")),
                }
            )
    return latest


def latest_storage_stats(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    pair_re = re.compile(
        r"race storage\[[^\]]+\]: pair_index total=(?P<total>\d+) queueable=(?P<queueable>\d+) "
        r"discovered=(?P<discovered>\d+) queued=(?P<queued>\d+) processing=(?P<processing>\d+) "
        r"processed=(?P<processed>\d+) validated=(?P<validated>\d+) invalid=(?P<invalid>\d+) "
        r"unknown=(?P<unknown>\d+) with_corpus=(?P<with_corpus>\d+) with_history=(?P<with_history>\d+) "
        r"max_queue_seq=(?P<max_queue_seq>\d+)"
    )
    latest: dict[str, int] = {}
    for line in path.read_text(errors="replace").splitlines():
        match = pair_re.search(line)
        if match:
            latest = {key: int(value) for key, value in match.groupdict().items()}
    return latest


def forbidden_patterns(path: Path) -> list[str]:
    if not path.exists():
        return []
    text = tail_text(path, 2_000_000)
    return [pattern for pattern in FORBIDDEN_LOG_PATTERNS if pattern in text]


def add_bench_window_metrics(row: dict[str, object], prefix: str, first: dict[str, object], last: dict[str, object]) -> bool:
    start = first.get("uptime")
    end = last.get("uptime")
    if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
        return False
    seconds = float(end) - float(start)
    row[f"{prefix}measurement_seconds"] = round(seconds, 3)
    row[f"{prefix}first_uptime"] = start
    row[f"{prefix}last_uptime"] = end
    if seconds <= 0:
        return False
    for key in STAT_KEYS:
        a, b = first.get(key), last.get(key)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            delta = float(b) - float(a)
            row[f"{prefix}delta_{key}"] = int(delta)
            row[f"{prefix}rate_{key}_per_s"] = round(delta / seconds, 6)
    exec_total = row.get(f"{prefix}delta_exec total")
    calls_executed = row.get(f"{prefix}delta_calls executed")
    if isinstance(exec_total, int) and exec_total > 0 and isinstance(calls_executed, int):
        row[f"{prefix}calls_executed_per_exec_total"] = round(calls_executed / exec_total, 6)
    return row.get(f"{prefix}rate_calls executed_per_s") is not None


def qemu_child_pids(parent_pid: object) -> list[int]:
    if not isinstance(parent_pid, int):
        return []
    out = command_text(["ps", "-eo", "pid=,ppid=,comm="]).strip()
    pids: list[int] = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        try:
            pid, ppid, comm = int(parts[0]), int(parts[1]), parts[2]
        except ValueError:
            continue
        if ppid == parent_pid and comm.startswith("qemu-system"):
            pids.append(pid)
    return pids


def tail_text(path: Path, max_bytes: int) -> str:
    if not path.exists():
        return ""
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        return f.read().decode(errors="replace")


def append_jsonl(path: Path, value: dict[str, object]) -> None:
    with path.open("a") as f:
        f.write(json.dumps(value, sort_keys=True) + "\n")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(value, f, indent=2, sort_keys=True, default=str)
        f.write("\n")


def command_text(cmd: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    return proc.stdout


def repo_metadata(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "head": command_text(["git", "rev-parse", "HEAD"], cwd=path).strip(),
        "branch": command_text(["git", "branch", "--show-current"], cwd=path).strip(),
        "status_short": command_text(["git", "status", "--short", "--branch"], cwd=path),
    }


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--case", choices=["both", "mrpfuzz", "segfuzz"], default="both")
    parser.add_argument("--duration", type=int, default=1800)
    parser.add_argument("--warmup", type=int, default=300)
    parser.add_argument("--mrpfuzz-cpuset", default="8,9,10,11")
    parser.add_argument("--mrpfuzz-fuzz-cpuset", default="8,9")
    parser.add_argument("--mrpfuzz-validate-cpuset", default="10,11")
    parser.add_argument("--segfuzz-cpuset", default="8,9,10,11")
    parser.add_argument("--segfuzz-vm-cpu", type=int, default=0, help="SegFuzz VM CPUs; default is the cpuset CPU count.")
    parser.add_argument("--segfuzz-procs", type=int, default=1)
    parser.add_argument("--mrpfuzz-max-pairs-per-task", type=int, default=32)
    parser.add_argument(
        "--mrpfuzz-seed-workdir",
        default="",
        help="Optional previous MRPFuzz workdir whose corpus/race DBs seed a race-active diagnostic run.",
    )
    parser.add_argument("--validate-start-delay", type=int, default=30)
    parser.add_argument("--stall-timeout", type=int, default=180, help="Abort a case if calls executed does not increase for this many seconds; 0 disables.")
    parser.add_argument("--min-free-gb", type=float, default=10.0)
    parser.add_argument("--build", action="store_true", help="Rebuild manager/executor binaries before running")
    return parser.parse_args()


def main() -> None:
    Runner(parse_args()).run()


if __name__ == "__main__":
    main()
