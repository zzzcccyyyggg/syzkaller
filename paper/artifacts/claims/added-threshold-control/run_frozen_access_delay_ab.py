#!/usr/bin/env python3
"""Run frozen-corpus validation A/B for the kernel access-delay floor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path("/home/zzzccc/BASS/DDRD-syzkaller")
RUN_ROOT = ROOT / "paper/artifacts/claims/added-threshold-control/runs"
DEFAULT_SOURCE_RUN = (
    RUN_ROOT
    / "20260822-ptmx-admission-threshold-dynamic-min500-cap3-allstable-12c12c-kimi-live-v1"
)


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def process_matches() -> str:
    proc = subprocess.run(
        ["ps", "-eo", "pid=,comm=,args="],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return "\n".join(
        line.strip()
        for line in proc.stdout.splitlines()
        if "syz-manager" in line or "qemu-system" in line
    )


def prepare_arm(
    source_cfg: dict[str, Any], source_corpus: Path, root: Path,
    name: str, cpuset: str, port: int, vm_count: int, floor_us: int,
    stack_floor_us: int, stack_delay_us: int, normalize_to_threshold: bool,
    target_us: int, max_us: int, syscall_timeout_ms: int, repeat_count: int,
    stable_min_occurrences: int, verify_repeat_times: int,
) -> dict[str, Any]:
    arm = root / name
    workdir = arm / "workdir"
    validate_workdir = workdir / "validate-run"
    logdir = arm / "logs"
    for path in (validate_workdir, logdir):
        path.mkdir(parents=True, exist_ok=True)

    corpus_copy = workdir / "uaf-corpus.db"
    shutil.copy2(source_corpus, corpus_copy)

    cfg = json.loads(json.dumps(source_cfg))
    cfg["workdir"] = str(validate_workdir)
    cfg["http"] = f"127.0.0.1:{port}"
    cfg["fuzzing_vms"] = vm_count
    cfg["procs"] = 2
    cfg["vm"]["count"] = vm_count
    cfg["vm"]["cpu"] = 2
    cfg["vm"]["mem"] = 2048
    uv = cfg["experimental"]["uaf_validate"]
    uv["continuous_mode"] = False
    uv["streaming_load"] = True
    uv["max_concurrent"] = vm_count
    uv["verify_access_delay_min_us"] = floor_us
    uv["verify_access_delay_normalize_to_threshold"] = normalize_to_threshold
    uv["verify_access_delay_target_us"] = target_us
    uv["verify_access_delay_max_us"] = max_us
    uv["verify_stack_access_delay_us"] = stack_delay_us
    uv["verify_stack_access_delay_min_us"] = stack_floor_us
    uv["executor_syscall_timeout_millis"] = syscall_timeout_ms
    uv["repeat_count"] = repeat_count
    uv["stable_pair_min_occurrences"] = stable_min_occurrences
    uv["verify_repeat_times"] = verify_repeat_times

    cfg_path = arm / "validate.cfg"
    log_path = logdir / "validate.log"
    bench_path = arm / "bench.json"
    write_json(cfg_path, cfg)
    cmd = [
        "taskset", "-c", cpuset,
        str(ROOT / "bin/syz-manager"),
        "-mode", "uaf-validate",
        "-config", str(cfg_path),
        "-bench", str(bench_path),
    ]
    if normalize_to_threshold:
        effective_delay = f"10*clamp(delta_t/threshold*{target_us}us,{floor_us}us,{max_us}us)"
    else:
        effective_delay = "10*delta_t" if floor_us == 0 else f"10*max(delta_t,{floor_us}us)"
        if max_us > 0:
            effective_delay = f"10*clamp(delta_t,{floor_us}us,{max_us}us)"
    if stack_delay_us > 0:
        effective_delay = f"strict/range={effective_delay}; stack-only=10*{stack_delay_us}us"
    elif stack_floor_us > 0:
        effective_delay = (
            f"strict/range={effective_delay}; "
            f"stack-only=10*max(delta_t,{stack_floor_us}us)"
        )
    return {
        "name": name,
        "cpuset": cpuset,
        "port": port,
        "vm_count": vm_count,
        "verify_access_delay_min_us": floor_us,
        "verify_access_delay_normalize_to_threshold": normalize_to_threshold,
        "verify_access_delay_target_us": target_us,
        "verify_access_delay_max_us": max_us,
        "verify_stack_access_delay_us": stack_delay_us,
        "verify_stack_access_delay_min_us": stack_floor_us,
        "executor_syscall_timeout_millis": syscall_timeout_ms,
        "repeat_count": repeat_count,
        "stable_pair_min_occurrences": stable_min_occurrences,
        "verify_repeat_times": verify_repeat_times,
        "effective_kernel_delay": effective_delay,
        "corpus": str(corpus_copy),
        "corpus_sha256": sha256(corpus_copy),
        "config": str(cfg_path),
        "log": str(log_path),
        "bench": str(bench_path),
        "command": cmd,
    }


def stop_children(children: list[subprocess.Popen[bytes]], sig: int) -> None:
    for child in children:
        if child.poll() is not None:
            continue
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-run", type=Path, default=DEFAULT_SOURCE_RUN)
    parser.add_argument("--duration", type=int, default=0, help="seconds; 0 runs until interrupted")
    parser.add_argument("--vm-count", type=int, default=8)
    parser.add_argument("--adaptive-cpuset", default="0-7")
    parser.add_argument("--floor-cpuset", default="8-15")
    parser.add_argument("--port-base", type=int, default=65510)
    parser.add_argument("--baseline-floor-us", type=int, default=0)
    parser.add_argument("--floor-us", type=int, default=1000)
    parser.add_argument("--stack-floor-us", type=int, default=0)
    parser.add_argument("--stack-delay-us", type=int, default=0)
    parser.add_argument("--normalize-baseline", action="store_true")
    parser.add_argument("--normalize-floor", action="store_true")
    parser.add_argument("--precise-target-us", type=int, default=0)
    parser.add_argument("--precise-max-us", type=int, default=0)
    parser.add_argument("--executor-syscall-timeout-ms", type=int, default=100)
    parser.add_argument("--repeat-count", type=int, default=1)
    parser.add_argument("--stable-min-occurrences", type=int, default=0)
    parser.add_argument("--verify-repeat-times", type=int, default=1)
    args = parser.parse_args()

    if (args.duration < 0 or args.vm_count <= 0 or args.baseline_floor_us < 0 or
            args.stack_floor_us < 0 or args.stack_delay_us < 0 or args.precise_target_us < 0 or
            args.precise_max_us < 0 or args.floor_us <= 0 or args.executor_syscall_timeout_ms <= 0 or
            args.repeat_count <= 0 or args.stable_min_occurrences < 0 or
            args.stable_min_occurrences > args.repeat_count or args.verify_repeat_times <= 0):
        parser.error("invalid duration, VM count, delay floor, or syscall timeout")
    if args.baseline_floor_us == args.floor_us:
        parser.error("baseline-floor-us and floor-us must differ")
    if (args.normalize_baseline or args.normalize_floor) and args.precise_target_us == 0:
        parser.error("precise-target-us must be positive when threshold normalization is enabled")
    if args.precise_max_us > 0 and max(args.baseline_floor_us, args.floor_us) > args.precise_max_us:
        parser.error("precise-max-us must not be smaller than either precise delay floor")
    run_dir = RUN_ROOT / args.run_id
    if run_dir.exists():
        raise SystemExit(f"run directory already exists: {run_dir}")
    source_cfg_path = args.source_run / "configs/validate.cfg"
    source_corpus = args.source_run / "workdir/uaf-corpus.db"
    for path in (source_cfg_path, source_corpus, ROOT / "bin/syz-manager"):
        if not path.is_file():
            raise SystemExit(f"missing required file: {path}")
    active = process_matches()
    if active:
        raise SystemExit("existing syz-manager/qemu process found:\n" + active)
    for port in (args.port_base, args.port_base + 1):
        if not port_free(port):
            raise SystemExit(f"port already in use: {port}")

    run_dir.mkdir(parents=True)
    source_cfg = json.loads(source_cfg_path.read_text())
    baseline_name = "adaptive" if args.baseline_floor_us == 0 else f"floor-{args.baseline_floor_us}us"
    floor_name = f"floor-{args.floor_us}us"
    arms = [
        prepare_arm(source_cfg, source_corpus, run_dir, baseline_name, args.adaptive_cpuset,
                    args.port_base, args.vm_count, args.baseline_floor_us,
                    args.stack_floor_us, args.stack_delay_us, args.normalize_baseline,
                    args.precise_target_us, args.precise_max_us, args.executor_syscall_timeout_ms,
                    args.repeat_count, args.stable_min_occurrences, args.verify_repeat_times),
        prepare_arm(source_cfg, source_corpus, run_dir, floor_name, args.floor_cpuset,
                    args.port_base + 1, args.vm_count, args.floor_us,
                    args.stack_floor_us, args.stack_delay_us, args.normalize_floor,
                    args.precise_target_us, args.precise_max_us, args.executor_syscall_timeout_ms,
                    args.repeat_count, args.stable_min_occurrences, args.verify_repeat_times),
    ]
    manifest = {
        "run_id": args.run_id,
        "created_at": now(),
        "source_run": str(args.source_run),
        "source_config": str(source_cfg_path),
        "source_corpus": str(source_corpus),
        "source_corpus_sha256": sha256(source_corpus),
        "duration_seconds": args.duration,
        "kernel_multiplier": 10,
        "repeat_count": args.repeat_count,
        "required_stable_count": (
            args.stable_min_occurrences if args.stable_min_occurrences > 0
            else args.repeat_count // 2 + 1 if args.repeat_count > 1 else 1
        ),
        "verify_repeat_times": args.verify_repeat_times,
        "comparison": (
            f"strict/range floors {args.baseline_floor_us}us vs {args.floor_us}us; "
            f"normalized={args.normalize_baseline}/{args.normalize_floor}; "
            f"target/max={args.precise_target_us}/{args.precise_max_us}us; "
            f"stack-only fixed/floor={args.stack_delay_us}/{args.stack_floor_us}us"
        ),
        "arms": arms,
    }
    write_json(run_dir / "manifest.json", manifest)
    write_json(run_dir / "state.json", {"status": "starting", "updated_at": now()})

    children: list[subprocess.Popen[bytes]] = []
    logs = []
    interrupted = False

    def handle_signal(signum: int, _frame: Any) -> None:
        nonlocal interrupted
        interrupted = True
        stop_children(children, signal.SIGINT)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    try:
        for arm in arms:
            log_file = Path(arm["log"]).open("ab")
            logs.append(log_file)
            children.append(subprocess.Popen(
                arm["command"], cwd=ROOT, stdout=log_file, stderr=subprocess.STDOUT,
                start_new_session=True,
            ))
        write_json(run_dir / "state.json", {
            "status": "running", "updated_at": now(),
            "pids": {arm["name"]: child.pid for arm, child in zip(arms, children)},
        })
        deadline = time.monotonic() + args.duration if args.duration else None
        while not interrupted and any(child.poll() is None for child in children):
            if deadline is not None and time.monotonic() >= deadline:
                stop_children(children, signal.SIGINT)
                break
            time.sleep(2)
        end = time.monotonic() + 180
        while any(child.poll() is None for child in children) and time.monotonic() < end:
            time.sleep(1)
        stop_children(children, signal.SIGTERM)
        codes = {arm["name"]: child.wait(timeout=30) for arm, child in zip(arms, children)}
        write_json(run_dir / "state.json", {
            "status": "interrupted" if interrupted else "complete",
            "updated_at": now(), "exit_codes": codes,
        })
    finally:
        stop_children(children, signal.SIGTERM)
        for log_file in logs:
            log_file.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
