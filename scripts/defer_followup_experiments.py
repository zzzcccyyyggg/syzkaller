#!/usr/bin/env python3
"""Defer module experiments until earlier experiment slots finish.

This helper is intentionally conservative:
- it waits for all timeout/manager pids under dependency run dirs to exit;
- it builds a fresh versioned kernel for the next module by default;
- it generates paired random/GPT5.4 fuzz+validate configs from known-good bases;
- it performs a boot-window health check after launch.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PRODUCER_BASE = ROOT / "paper/results/llm-mutate-continuous"


MODULES: dict[str, dict[str, Any]] = {
    "f2fs": {
        "slug": "f2fs",
        "base_random": ROOT / "exp/f2fs/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/f2fs/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/f2fs/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/f2fs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260528-225819/exp-validate-gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260528-225819.cfg",
        "seed_corpus": ROOT / "exp/f2fs/modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h/random/workdir/corpus.db",
    },
    "xfs": {
        "slug": "xfs",
        "base_random": ROOT / "exp/xfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/xfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/xfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/xfs/exp-validate-gpt54-uapi-fix-xfs-vm8-12h-20260525-231530.cfg",
        "seed_corpus": ROOT / "exp/xfs/modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h/random/workdir/corpus.db",
    },
    "jfs": {
        "slug": "jfs",
        "base_random": ROOT / "exp/jfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/jfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/jfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/jfs/exp-validate-gpt54-7mods-vm8-12h-20260525-193718.cfg",
        "seed_corpus": ROOT / "exp/jfs/modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h/random/workdir/corpus.db",
    },
    "bt-stack": {
        "slug": "bt-stack",
        "base_random": ROOT / "exp/bt-stack/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/bt-stack/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/bt-stack/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/bt-stack/exp-validate-gpt54-7mods-vm8-12h-20260525-193718.cfg",
        "seed_corpus": ROOT / "exp/bt-stack/modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h/random/workdir/corpus.db",
    },
    "dsp": {
        "slug": "dsp",
        "base_random": ROOT / "exp/dsp/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/dsp/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/dsp/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/dsp/exp-validate-gpt54-7mods-vm8-12h-20260525-193718.cfg",
        "seed_corpus": ROOT / "exp/dsp/modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h/random/workdir/corpus.db",
    },
    "floppy": {
        "slug": "floppy",
        "base_random": ROOT / "exp/floppy/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/floppy/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/floppy/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/floppy/exp-validate-gpt54-uapi-fix-btrfs-floppy-vm8-12h-20260525-230410.cfg",
        "seed_corpus": ROOT / "exp/floppy/modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h/random/workdir/corpus.db",
    },
    "ptmx": {
        "slug": "ptmx",
        "base_random": ROOT / "exp/ptmx/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/ptmx/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/ptmx/exp-fuzz-modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/ptmx/exp-validate-gpt54-7mods-vm8-12h-20260525-193718.cfg",
        "seed_corpus": ROOT / "exp/ptmx/modelcmp-20260525-rest4-fixedenv2-node24-dskey1-gpt54-deepseek-random-vm4-10h/random/workdir/corpus.db",
    },
    "btrfs": {
        "slug": "btrfs",
        "base_random": ROOT / "exp/btrfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-random.cfg",
        "base_gpt": ROOT / "exp/btrfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-codex54.cfg",
        "base_deepseek": ROOT / "exp/btrfs/exp-fuzz-modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h-deepseek-v4pro.cfg",
        "base_validate": ROOT / "exp/btrfs/exp-validate-gpt54-uapi-fix-btrfs-floppy-vm8-12h-20260525-230410.cfg",
        "seed_corpus": ROOT / "exp/btrfs/modelcmp-20260524-201021-gpt54-deepseek-v4pro-random-vm4-10h/random/workdir/corpus.db",
    },
}


DEFAULT_DEPS: dict[str, list[Path]] = {
    "f2fs": [],
    "jfs": [],
    "xfs": [
        ROOT / "exp/dsp/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-124426",
        ROOT / "exp/dsp/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-124426",
    ],
    "bt-stack": [
        ROOT / "exp/jfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-162215",
        ROOT / "exp/jfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260529-162215",
    ],
    "floppy": [
        ROOT / "exp/xfs/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-005042",
        ROOT / "exp/xfs/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-005042",
    ],
    "ptmx": [],
    "btrfs": [
        ROOT / "exp/floppy/random-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-135147",
        ROOT / "exp/floppy/gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260530-135147",
    ],
    "dsp": [],
}


def log(msg: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")


def is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_pid(path: Path) -> int | None:
    try:
        text = path.read_text().strip()
        return int(text) if text else None
    except (OSError, ValueError):
        return None


def dependency_pids(dep_roots: list[Path]) -> list[tuple[Path, int]]:
    pids: list[tuple[Path, int]] = []
    for dep in dep_roots:
        for pid_file in sorted((dep / "pids").glob("*.pid")):
            pid = read_pid(pid_file)
            if pid is not None:
                pids.append((pid_file, pid))
    return pids


def deps_alive(dep_roots: list[Path]) -> list[tuple[Path, int]]:
    return [(path, pid) for path, pid in dependency_pids(dep_roots) if is_pid_alive(pid)]


def wait_for_deps(dep_roots: list[Path], poll_sec: int) -> None:
    log("waiting for dependencies:")
    for dep in dep_roots:
        log(f"  dep={dep}")
    while True:
        alive = deps_alive(dep_roots)
        if not alive:
            log("all dependency pids have exited")
            return
        sample = ", ".join(f"{p.name}:{pid}" for p, pid in alive[:8])
        log(f"dependency pids still alive: {len(alive)} ({sample})")
        time.sleep(poll_sec)


def ensure_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing {label}: {path}")


def find_free_ports(count: int, start: int) -> list[int]:
    ports: list[int] = []
    port = start
    while len(ports) < count:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                port += 1
                continue
        ports.append(port)
        port += 1
    return ports


def update_fuzz_config(
    cfg: dict[str, Any],
    *,
    http_port: int,
    workdir: Path,
    kernel_dir: Path,
    mode: str,
    producer_dir: Path | None,
) -> dict[str, Any]:
    cfg = json.loads(json.dumps(cfg))
    cfg["http"] = f"127.0.0.1:{http_port}"
    cfg["workdir"] = str(workdir)
    cfg["kernel_obj"] = str(kernel_dir)
    cfg["vmlinux"] = str(kernel_dir / "vmlinux")
    cfg.setdefault("vm", {})["kernel"] = str(kernel_dir / "bzImage")
    cfg["vm"]["count"] = 4
    exp = cfg.setdefault("experimental", {})
    exp["race_mode"] = True
    exp["barrier_mode"] = True
    exp["barrier_procs"] = [0, 1]
    exp["history_buffer_size"] = 100
    exp["new_varname_pair_history"] = 100
    exp["new_stack_history"] = 10
    exp["max_stacks_per_varname_pair"] = 20
    exp["normal_threshold_micros"] = 10000
    exp["enable_timing_exploration"] = False
    exp["timing_exploration_ratio"] = 0
    exp["enable_dynamic_threshold"] = True
    exp["dynamic_threshold_initial_us"] = 2500
    exp["dynamic_threshold_min_us"] = 500
    exp["dynamic_threshold_max_us"] = 10000
    exp["dynamic_threshold_eval_sec"] = 30
    exp["static_input_exploration"] = True
    exp["static_input_seed"] = 1592594996
    exp["static_input_skip_builtin_seeds"] = True
    exp["enable_object_linking"] = False
    exp["object_link_attempt_ratio"] = 0
    exp["enable_coverage_triage"] = False
    exp["enable_affinity_table"] = False
    exp["no_object_kccwf_namespace"] = False
    exp["isolate_kccwf_partner_objects"] = False
    if mode in ("gpt54", "deepseek"):
        if producer_dir is None:
            raise ValueError(f"producer_dir is required for {mode}")
        exp["llm_input_seed_dir"] = str(producer_dir)
        exp["llm_input_seed_poll_sec"] = 10
        exp["llm_input_seed_max_per_poll"] = 32
    else:
        for key in ("llm_input_seed_dir", "llm_input_seed_poll_sec", "llm_input_seed_max_per_poll"):
            exp.pop(key, None)
    return cfg


def update_validate_config(
    cfg: dict[str, Any],
    *,
    http_port: int,
    workdir: Path,
    kernel_dir: Path,
) -> dict[str, Any]:
    cfg = json.loads(json.dumps(cfg))
    cfg["http"] = f"127.0.0.1:{http_port}"
    cfg["workdir"] = str(workdir)
    cfg["kernel_obj"] = str(kernel_dir)
    cfg["vmlinux"] = str(kernel_dir / "vmlinux")
    cfg.setdefault("vm", {})["kernel"] = str(kernel_dir / "bzImage")
    cfg["vm"]["count"] = 8
    exp = cfg.setdefault("experimental", {})
    exp["skip_duplicate_data_races"] = True
    exp["race_mode"] = True
    exp["barrier_mode"] = True
    exp["barrier_procs"] = [0, 1]
    exp["history_buffer_size"] = 100
    exp["new_varname_pair_history"] = 100
    exp["new_stack_history"] = 10
    exp["max_stacks_per_varname_pair"] = 20
    exp["ddrd_monitor"] = False
    uv = exp.setdefault("uaf_validate", {})
    uv["max_concurrent"] = 8
    uv["delay_retry_budget"] = 1
    uv["timeout_seconds"] = 120
    uv["max_batch_timeout_seconds"] = 600
    uv["repeat_count"] = 1
    uv["disable_async_split"] = True
    uv["enable_vm_snapshot"] = True
    uv["verify_repeat_times"] = 1
    uv["executor_syscall_timeout_millis"] = 100
    uv["continuous_mode"] = True
    uv["streaming_load"] = True
    uv["streaming_batch_size"] = 500
    uv["max_entries"] = 0
    uv["incremental_reload_minutes"] = 10
    uv["idle_reload_seconds"] = 10
    uv["enable_replay"] = True
    uv["enable_varname_scheduling"] = True
    uv["priority_low_history"] = True
    uv["target_match_mode"] = "sn-fallback"
    uv["sn_fallback_range"] = 2
    uv["disable_verify_delay"] = True
    uv["disable_access_delay"] = False
    uv["disable_collection_delay"] = True
    uv["require_origin_match"] = False
    uv["replay_collect_pairs"] = False
    uv["verify_collect_pairs"] = False
    uv["verify_delay_sweep"] = False
    uv["enable_history_minimization"] = False
    uv["max_stable_pairs_per_entry"] = 16
    uv["max_stable_pairs_per_origin"] = 1
    uv["origin_match_mode"] = "varname"
    uv["continue_after_hb"] = True
    return cfg


def prepare_run_dirs(module: str, ts: str, mode: str, seed_corpus: Path) -> tuple[Path, Path, Path]:
    run_name = f"{mode}-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-{ts}"
    run_dir = ROOT / "exp" / module / run_name
    workdir = run_dir / "workdir"
    validate_dir = workdir / "validate-run"
    for path in (workdir, validate_dir, run_dir / "logs", run_dir / "pids"):
        path.mkdir(parents=True, exist_ok=True)
    shutil.copy2(seed_corpus, workdir / "corpus.db")
    for name in ("uaf-corpus.db", "uaf-validate-queue.db", "race-pair-index.db", "threshold-state.json"):
        dst = validate_dir / name
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        dst.symlink_to(workdir / name)
    return run_dir, workdir, validate_dir


def build_kernel(
    module: str,
    ts: str,
    jobs: int,
    dry_run: bool,
    skip_build: bool,
    kernel_output_dir: Path | None,
) -> Path:
    if kernel_output_dir is not None:
        kernel_dir = kernel_output_dir / module
        ensure_file(kernel_dir / "bzImage", "prebuilt kernel bzImage")
        ensure_file(kernel_dir / "vmlinux", "prebuilt kernel vmlinux")
        log(f"using prebuilt kernel: {kernel_dir}")
        return kernel_dir
    out_dir = ROOT / "kernels/output-versions" / f"{module}-targetdelay-latest-{ts}"
    kernel_dir = out_dir / module
    if skip_build:
        existing = latest_existing_kernel(module)
        if existing is None:
            raise FileNotFoundError(f"no existing versioned kernel found for {module}")
        log(f"using latest existing kernel: {existing}")
        return existing
    cmd = [
        str(ROOT / "scripts/build_kernel.sh"),
        "--jobs",
        str(jobs),
        "--output-dir",
        str(out_dir),
        module,
    ]
    log("kernel build command: " + " ".join(cmd))
    if dry_run:
        return kernel_dir
    subprocess.run(cmd, cwd=ROOT, check=True)
    ensure_file(kernel_dir / "bzImage", "built kernel bzImage")
    ensure_file(kernel_dir / "vmlinux", "built kernel vmlinux")
    return kernel_dir


def parse_modes(raw: str) -> list[str]:
    modes = [mode.strip() for mode in raw.split(",") if mode.strip()]
    allowed = {"random", "gpt54", "deepseek"}
    bad = [mode for mode in modes if mode not in allowed]
    if bad:
        raise ValueError(f"unsupported mode(s): {', '.join(bad)}")
    if not modes:
        raise ValueError("at least one mode is required")
    if len(set(modes)) != len(modes):
        raise ValueError(f"duplicate modes are not allowed: {raw}")
    return modes


def producer_path(module: str, mode: str, ts: str, dry_run_dir: Path | None) -> Path:
    if mode == "gpt54":
        base = PRODUCER_BASE / f"gpt54-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-{ts}"
        leaf = f"{module}-codex54"
    elif mode == "deepseek":
        base = PRODUCER_BASE / f"deepseek-v4pro-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-{ts}"
        leaf = f"{module}-deepseek-v4pro"
    else:
        raise ValueError(f"mode has no producer: {mode}")
    if dry_run_dir is not None:
        return dry_run_dir / "producer" / leaf
    return base / leaf


def fuzz_base_for(spec: dict[str, Any], mode: str) -> Path:
    if mode == "random":
        return spec["base_random"]
    if mode == "gpt54":
        return spec["base_gpt"]
    if mode == "deepseek":
        return spec["base_deepseek"]
    raise ValueError(f"unsupported mode: {mode}")


def generate_configs(
    module: str,
    ts: str,
    kernel_dir: Path,
    modes: list[str],
    dry_run_dir: Path | None = None,
) -> list[dict[str, Any]]:
    spec = MODULES[module]
    for key in ("base_random", "base_gpt", "base_deepseek", "base_validate", "seed_corpus"):
        ensure_file(spec[key], f"{module} {key}")
    if dry_run_dir is None:
        base_exp = ROOT / "exp" / module
    else:
        base_exp = dry_run_dir / "exp" / module
    ports = find_free_ports(len(modes) * 2, 57400 if module == "xfs" else 57500)
    runs = []
    for idx, mode in enumerate(modes):
        if dry_run_dir is None:
            run_dir, workdir, validate_dir = prepare_run_dirs(module, ts, mode, spec["seed_corpus"])
        else:
            run_name = f"{mode}-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-{ts}"
            run_dir = base_exp / run_name
            workdir = run_dir / "workdir"
            validate_dir = workdir / "validate-run"
            for path in (workdir, validate_dir, run_dir / "logs", run_dir / "pids"):
                path.mkdir(parents=True, exist_ok=True)
            shutil.copy2(spec["seed_corpus"], workdir / "corpus.db")
        producer_dir = None
        if mode in ("gpt54", "deepseek"):
            producer_dir = producer_path(module, mode, ts, dry_run_dir)
            producer_dir.mkdir(parents=True, exist_ok=True)
        fuzz_base = load_json(fuzz_base_for(spec, mode))
        val_base = load_json(spec["base_validate"])
        fuzz_cfg = update_fuzz_config(
            fuzz_base,
            http_port=ports[idx * 2],
            workdir=workdir,
            kernel_dir=kernel_dir,
            mode=mode,
            producer_dir=producer_dir,
        )
        val_cfg = update_validate_config(
            val_base,
            http_port=ports[idx * 2 + 1],
            workdir=validate_dir,
            kernel_dir=kernel_dir,
        )
        fuzz_cfg_path = run_dir / f"exp-fuzz-{mode}-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-{ts}.cfg"
        val_cfg_path = run_dir / f"exp-validate-{mode}-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-{ts}.cfg"
        write_json(fuzz_cfg_path, fuzz_cfg)
        write_json(val_cfg_path, val_cfg)
        runs.append(
            {
                "mode": mode,
                "run_dir": run_dir,
                "workdir": workdir,
                "validate_dir": validate_dir,
                "fuzz_cfg": fuzz_cfg_path,
                "validate_cfg": val_cfg_path,
                "producer_dir": producer_dir,
            }
        )
    return runs


def launch_process(cmd: list[str], cwd: Path, log_path: Path, pid_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    out = log_path.open("ab")
    proc = subprocess.Popen(cmd, cwd=cwd, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    pid_path.write_text(f"{proc.pid}\n")
    return proc.pid


def launch_runs(module: str, runs: list[dict[str, Any]], dry_run: bool) -> None:
    for run in runs:
        mode = run["mode"]
        run_dir = run["run_dir"]
        fuzz_cmd = [
            "timeout",
            "--kill-after=180s",
            "12h",
            str(ROOT / "bin/syz-manager"),
            "-config",
            str(run["fuzz_cfg"]),
        ]
        val_cmd = [
            "timeout",
            "--kill-after=180s",
            "12h",
            str(ROOT / "bin/syz-manager"),
            "-mode=uaf-validate",
            "-config",
            str(run["validate_cfg"]),
        ]
        log(f"{module}/{mode} fuzz command: {' '.join(fuzz_cmd)}")
        log(f"{module}/{mode} validate command: {' '.join(val_cmd)}")
        if dry_run:
            continue
        fp = launch_process(fuzz_cmd, ROOT, run_dir / "logs/fuzz-manager.log", run_dir / "pids/fuzz-timeout.pid")
        log(f"started {module}/{mode} fuzz timeout pid={fp}")
        time.sleep(2)
        vp = launch_process(val_cmd, ROOT, run_dir / "logs/validate-manager.log", run_dir / "pids/validate-timeout.pid")
        log(f"started {module}/{mode} validate timeout pid={vp}")
        if mode == "gpt54":
            producer_dir = run["producer_dir"]
            prod_cmd = [
                "timeout",
                "--kill-after=180s",
                "12h",
                "python3",
                "tools/llm-mutate-pilot/continuous.py",
                "--provider",
                "codex",
                "--codex-model",
                "gpt-5.4",
                "--codex-reasoning-effort",
                "medium",
                "--codex-sandbox",
                "read-only",
                "--config",
                str(run["fuzz_cfg"]),
                "--module",
                module,
                "--out",
                str(producer_dir),
                "--entries-per-round",
                "4",
                "--variants-per-entry",
                "2",
                "--parallel-calls",
                "2",
                "--max-calls",
                "8",
                "--poll-sec",
                "30",
                "--source",
                "fuzz",
                "--timeout-sec",
                "600",
            ]
            log(f"{module}/gpt54 producer command: {' '.join(prod_cmd)}")
            pp = launch_process(prod_cmd, ROOT, producer_dir / "producer.outer.log", run_dir / "pids/producer-timeout.pid")
            log(f"started {module}/gpt54 producer timeout pid={pp}")
        elif mode == "deepseek":
            producer_dir = run["producer_dir"]
            api_key_file = Path(os.environ.get("INFERAICHAT_DEEPSEEK_KEY_FILE", "tmp/inferaichat-deepseek-helper.keys"))
            if not api_key_file.is_absolute():
                api_key_file = ROOT / api_key_file
            prod_cmd = [
                "timeout",
                "--kill-after=180s",
                "12h",
                "python3",
                "tools/llm-mutate-pilot/continuous.py",
                "--provider",
                "deepseek",
                "--base-url",
                os.environ.get("INFERAICHAT_DEEPSEEK_BASE_URL", "https://inferaichat.com/v1"),
                "--model",
                os.environ.get("INFERAICHAT_DEEPSEEK_MODEL", "deepseek-v4-pro"),
                "--thinking",
                os.environ.get("INFERAICHAT_DEEPSEEK_THINKING", "disabled"),
                "--max-tokens",
                os.environ.get("INFERAICHAT_DEEPSEEK_MAX_TOKENS", "32768"),
                "--api-key-file",
                str(api_key_file),
                "--api-key-alias",
                os.environ.get("INFERAICHAT_DEEPSEEK_KEY_ALIAS", "inferaichat-deepseek-v4pro"),
                "--config",
                str(run["fuzz_cfg"]),
                "--module",
                module,
                "--out",
                str(producer_dir),
                "--entries-per-round",
                "4",
                "--variants-per-entry",
                "2",
                "--parallel-calls",
                "2",
                "--max-calls",
                "8",
                "--poll-sec",
                "30",
                "--source",
                "fuzz",
                "--timeout-sec",
                "600",
            ]
            log(f"{module}/deepseek producer command: {' '.join(prod_cmd)}")
            pp = launch_process(prod_cmd, ROOT, producer_dir / "producer.outer.log", run_dir / "pids/producer-timeout.pid")
            log(f"started {module}/deepseek producer timeout pid={pp}")


def health_check(module: str, runs: list[dict[str, Any]], window_sec: int, dry_run: bool) -> None:
    if dry_run:
        log(f"dry-run health check skipped for {module}")
        return
    deadline = time.time() + window_sec
    while time.time() < deadline:
        all_basic = True
        for run in runs:
            run_dir = run["run_dir"]
            for name in ("fuzz-timeout.pid", "validate-timeout.pid"):
                pid = read_pid(run_dir / "pids" / name)
                if pid is None or not is_pid_alive(pid):
                    raise RuntimeError(f"{module}/{run['mode']} {name} is not alive")
            fuzz_log = (run_dir / "logs/fuzz-manager.log").read_text(errors="ignore") if (run_dir / "logs/fuzz-manager.log").exists() else ""
            val_log = (run_dir / "logs/validate-manager.log").read_text(errors="ignore") if (run_dir / "logs/validate-manager.log").exists() else ""
            if "failed to load config" in fuzz_log or "failed to load config" in val_log:
                raise RuntimeError(f"{module}/{run['mode']} config load failure")
            if "unknown field" in fuzz_log or "unknown field" in val_log:
                raise RuntimeError(f"{module}/{run['mode']} unknown config field")
            if "KCCWF_UAF_TARGET_INSTALL ret=-1" in val_log:
                raise RuntimeError(f"{module}/{run['mode']} target install ret=-1")
            has_fuzz = "machine check:" in fuzz_log and "frozen input pool loaded" in fuzz_log and "exec total=" in fuzz_log
            has_validate = "uaf validation queue: continuous mode started" in val_log
            all_basic = all_basic and has_fuzz and has_validate
        if all_basic:
            log(f"{module} startup health check passed")
            return
        time.sleep(30)
    raise TimeoutError(f"{module} did not pass startup health check within {window_sec}s")


def preflight(module: str, dep_roots: list[Path], dry_run_dir: Path | None) -> None:
    spec = MODULES[module]
    for key in ("base_random", "base_gpt", "base_validate", "seed_corpus"):
        ensure_file(spec[key], f"{module} {key}")
    ensure_file(ROOT / "bin/syz-manager", "syz-manager")
    ensure_file(ROOT / "tools/llm-mutate-pilot/continuous.py", "LLM producer")
    ensure_file(ROOT / "scripts/build_kernel.sh", "kernel build script")
    for dep in dep_roots:
        ensure_file(dep / "pids", f"dependency pid dir {dep}")
    log(f"{module} preflight ok")


def run_module(module: str, dep_roots: list[Path], args: argparse.Namespace) -> None:
    preflight(module, dep_roots, args.dry_run_dir)
    if not args.no_wait:
        wait_for_deps(dep_roots, args.poll_sec)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    kernel_dir = build_kernel(module, ts, args.jobs, args.dry_run, args.skip_build, args.kernel_output_dir)
    if args.dry_run and not args.skip_build:
        # Dry-runs do not build, so point generated configs to an existing kernel when available.
        existing = latest_existing_kernel(module)
        if existing is not None:
            kernel_dir = existing
            log(f"dry-run using existing kernel for config validation: {kernel_dir}")
    runs = generate_configs(module, ts, kernel_dir, parse_modes(args.modes), args.dry_run_dir if args.dry_run else None)
    launch_runs(module, runs, args.dry_run)
    health_check(module, runs, args.health_window_sec, args.dry_run)
    log(f"{module} handoff complete")


def latest_existing_kernel(module: str) -> Path | None:
    candidates = []
    for base in (ROOT / "kernels/output-versions", ROOT / "kernels/output"):
        if not base.exists():
            continue
        for path in base.glob(f"**/{module}/bzImage"):
            vmlinux = path.parent / "vmlinux"
            if vmlinux.exists():
                candidates.append(path.parent)
    if not candidates:
        return None
    return max(candidates, key=lambda p: (p / "bzImage").stat().st_mtime)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--module", choices=sorted(MODULES), action="append", required=True)
    p.add_argument("--dry-run", action="store_true", help="validate and print commands without launching")
    p.add_argument("--dry-run-dir", type=Path, default=ROOT / "tmp/deferred-followup-dryrun")
    p.add_argument("--no-wait", action="store_true", help="do not wait for dependency pids")
    p.add_argument("--skip-build", action="store_true", help="use kernels/output-versions/<module>-targetdelay-latest-<ts>")
    p.add_argument("--kernel-output-dir", type=Path, help="prebuilt output dir containing <module>/bzImage and <module>/vmlinux")
    p.add_argument("--modes", default="random,gpt54", help="comma-separated subset of random,gpt54,deepseek")
    p.add_argument("--jobs", type=int, default=12)
    p.add_argument("--poll-sec", type=int, default=300)
    p.add_argument("--health-window-sec", type=int, default=900)
    p.add_argument("--dep", type=Path, action="append", default=[], help="extra dependency run dir to wait for")
    p.add_argument("--replace-deps", action="store_true", help="wait only for --dep run dirs, ignoring module defaults")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.dry_run:
        args.dry_run_dir.mkdir(parents=True, exist_ok=True)
    extra_deps = [dep if dep.is_absolute() else ROOT / dep for dep in args.dep]
    for module in args.module:
        dep_roots = ([] if args.replace_deps else list(DEFAULT_DEPS[module])) + extra_deps
        run_module(module, dep_roots, args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        log(f"ERROR: {e}")
        raise
