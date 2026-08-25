#!/usr/bin/env python3
"""Run frozen-corpus collection-threshold A/B validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[4]
RUN_ROOT = ROOT / "paper/artifacts/claims/added-threshold-control/runs"
DEFAULT_INPUT = (
    ROOT
    / "paper/artifacts/claims/added-threshold-control/frozen-inputs"
    / "dsp-fixed100-improved-8h"
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
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def replace_root(value: Any, old_root: str) -> Any:
    if isinstance(value, dict):
        return {key: replace_root(item, old_root) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_root(item, old_root) for item in value]
    if isinstance(value, str):
        return value.replace(old_root, str(ROOT))
    return value


def prepare_arm(
    source_cfg: dict[str, Any], source_corpus: Path, run_dir: Path,
    name: str, cpuset: str, port: int, vm_count: int, floor_us: int,
    manager: Path, collection_only: bool,
) -> dict[str, Any]:
    arm_dir = run_dir / name
    workdir = arm_dir / "workdir"
    validate_workdir = workdir / "validate-run"
    log_dir = arm_dir / "logs"
    validate_workdir.mkdir(parents=True)
    log_dir.mkdir(parents=True)

    corpus = workdir / "uaf-corpus.db"
    corpus.write_bytes(source_corpus.read_bytes())

    cfg = json.loads(json.dumps(source_cfg))
    cfg["workdir"] = str(validate_workdir)
    cfg["http"] = f"127.0.0.1:{port}"
    cfg["procs"] = 2
    cfg["fuzzing_vms"] = vm_count
    cfg["vm"]["count"] = vm_count
    cfg["vm"]["cpu"] = 2
    cfg["vm"]["mem"] = 1024
    validate = cfg["experimental"]["uaf_validate"]
    validate.update(
        {
            "continuous_mode": False,
            "streaming_load": True,
            "max_concurrent": vm_count,
            "max_concurrent_per_varname": 1,
            "enable_collection_miss_backoff": False,
            "collection_only": collection_only,
            "disable_backoff_skip": True,
            "continue_after_backoff": False,
            "continue_after_hb": False,
            "repeat_count": 2,
            "stable_pair_min_occurrences": 1,
            "require_origin_match": False,
        }
    )
    if floor_us > 0:
        validate["collection_threshold_floor_us"] = floor_us
    else:
        validate.pop("collection_threshold_floor_us", None)

    cfg_path = arm_dir / "validate.cfg"
    bench_path = arm_dir / "bench.json"
    log_path = log_dir / "validate.log"
    write_json(cfg_path, cfg)
    command = [
        "taskset", "-c", cpuset,
        str(manager), "-mode", "uaf-validate",
        "-config", str(cfg_path), "-bench", str(bench_path),
    ]
    return {
        "name": name,
        "cpuset": cpuset,
        "port": port,
        "vm_count": vm_count,
        "collection_threshold_floor_us": floor_us,
        "collection_only": collection_only,
        "corpus": str(corpus),
        "corpus_sha256": sha256(corpus),
        "config": str(cfg_path),
        "bench": str(bench_path),
        "log": str(log_path),
        "command": command,
    }


def stop(children: list[subprocess.Popen[bytes]], sig: int) -> None:
    for child in children:
        if child.poll() is None:
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manager", type=Path, default=ROOT / "bin/syz-manager-collection2ms")
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--vm-count", type=int, default=12)
    parser.add_argument("--baseline-cpuset", default="0-11")
    parser.add_argument("--treatment-cpuset", default="12-23")
    parser.add_argument("--port-base", type=int, default=65300)
    parser.add_argument("--treatment-floor-us", type=int, default=2000)
    parser.add_argument("--treatment-only", action="store_true")
    parser.add_argument("--full-verify", action="store_true")
    args = parser.parse_args()

    if args.duration <= 0 or args.vm_count <= 0 or args.treatment_floor_us <= 0:
        parser.error("duration, VM count, and treatment floor must be positive")
    run_dir = RUN_ROOT / args.run_id
    if run_dir.exists():
        raise SystemExit(f"run directory already exists: {run_dir}")

    source_cfg_path = args.input_dir / "validate-source.cfg"
    source_corpus = args.input_dir / "uaf-corpus.db"
    for path in (source_cfg_path, source_corpus, args.manager):
        if not path.is_file():
            raise SystemExit(f"missing required file: {path}")
    for port in (args.port_base, args.port_base + 10):
        if not port_free(port):
            raise SystemExit(f"port is busy: {port}")

    source_cfg = json.loads(source_cfg_path.read_text())
    old_root = str(source_cfg.get("syzkaller") or "").rstrip("/")
    if not old_root:
        raise SystemExit("source config does not identify its syzkaller root")
    source_cfg = replace_root(source_cfg, old_root)
    run_dir.mkdir(parents=True)
    collection_only = not args.full_verify
    treatment = prepare_arm(
        source_cfg, source_corpus, run_dir,
        "collection-floor-2000-full-verify" if args.full_verify else "collection-floor-2000",
        args.treatment_cpuset, args.port_base + 10, args.vm_count,
        args.treatment_floor_us, args.manager, collection_only,
    )
    if args.treatment_only:
        arms = [treatment]
    else:
        arms = [
            prepare_arm(source_cfg, source_corpus, run_dir, "admission-linked",
                        args.baseline_cpuset, args.port_base, args.vm_count, 0,
                        args.manager, collection_only),
            treatment,
        ]
    manifest = {
        "run_id": args.run_id,
        "created_at": now(),
        "duration_seconds": args.duration,
        "collection_only": collection_only,
        "source_config": str(source_cfg_path),
        "source_config_sha256": sha256(source_cfg_path),
        "source_corpus": str(source_corpus),
        "source_corpus_sha256": sha256(source_corpus),
        "manager": str(args.manager),
        "manager_sha256": sha256(args.manager),
        "arms": arms,
    }
    write_json(run_dir / "manifest.json", manifest)

    children: list[subprocess.Popen[bytes]] = []
    handles = []
    interrupted = False

    def handle_signal(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
        stop(children, signal.SIGINT)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    try:
        for arm in arms:
            handle = Path(arm["log"]).open("ab")
            handles.append(handle)
            children.append(subprocess.Popen(
                arm["command"], cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT,
                start_new_session=True,
            ))
        write_json(run_dir / "state.json", {
            "status": "running", "updated_at": now(),
            "pids": {arm["name"]: child.pid for arm, child in zip(arms, children)},
        })
        deadline = time.monotonic() + args.duration
        while not interrupted and time.monotonic() < deadline:
            failures = [
                f"{arm['name']} rc={child.returncode}"
                for arm, child in zip(arms, children)
                if child.poll() not in (None, 0)
            ]
            if failures:
                raise RuntimeError(", ".join(failures))
            write_json(run_dir / "state.json", {
                "status": "running", "updated_at": now(),
                "remaining_seconds": max(0, round(deadline - time.monotonic())),
                "return_codes": {
                    arm["name"]: child.poll()
                    for arm, child in zip(arms, children)
                },
            })
            time.sleep(30)
        stop(children, signal.SIGINT)
        end = time.monotonic() + 180
        while any(child.poll() is None for child in children) and time.monotonic() < end:
            time.sleep(1)
        stop(children, signal.SIGTERM)
        codes = {arm["name"]: child.wait(timeout=30) for arm, child in zip(arms, children)}
        write_json(run_dir / "state.json", {
            "status": "interrupted" if interrupted else "complete",
            "updated_at": now(), "return_codes": codes,
        })
    except Exception as exc:
        stop(children, signal.SIGTERM)
        write_json(run_dir / "state.json", {
            "status": "failed", "updated_at": now(), "detail": str(exc),
        })
        raise
    finally:
        for handle in handles:
            handle.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
