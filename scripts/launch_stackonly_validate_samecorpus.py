#!/usr/bin/env python3
"""Prepare and launch validation on the DeepSeek frozen corpus."""

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


ROOT = Path(__file__).resolve().parents[1]
SOURCE_RESULT_DIR = (
    ROOT
    / "paper/results/llm-model-comparison"
    / "20260603-8module-3way-dynthresh-12h-as24h"
)
SOURCE_MANIFEST = SOURCE_RESULT_DIR / "run_manifest.json"
DEFAULT_MODULES = ["f2fs", "jfs", "xfs", "btrfs", "floppy", "ptmx", "dsp", "bt-stack"]


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%F %T')}] {message}", flush=True)


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def deepseek_runs_by_module() -> dict[str, dict[str, Any]]:
    manifest = load_json(SOURCE_MANIFEST)
    out: dict[str, dict[str, Any]] = {}
    for run in manifest.get("runs", []):
        if run.get("variant") != "deepseek-v4pro":
            continue
        module = run["module"]
        copied = run.get("copied_files", {})
        validate_key = next(
            key for key in copied if key.startswith("config:exp-validate")
        )
        out[module] = {
            "module": module,
            "source_exp_dir": ROOT / run["exp_dir"],
            "source_validate_config": ROOT / copied[validate_key],
            "source_validate_log": ROOT / run["validate_manager_log"],
        }
    return out


def ensure_symlink(dst: Path, src: Path) -> None:
    if dst.is_symlink():
        if dst.resolve() == src.resolve():
            return
        dst.unlink()
    elif dst.exists():
        raise FileExistsError(f"refusing to replace existing non-symlink: {dst}")
    dst.symlink_to(src)


def prepare(args: argparse.Namespace) -> Path:
    modules = args.modules or DEFAULT_MODULES
    source_runs = deepseek_runs_by_module()
    missing = [module for module in modules if module not in source_runs]
    if missing:
        raise SystemExit(f"missing DeepSeek runs in source manifest: {', '.join(missing)}")

    stamp = args.stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    mode_label = args.target_match_mode.replace("-", "")
    run_name = f"deepseek-{mode_label}-validate-samecorpus-12h-{stamp}"
    manifest_path = args.manifest or SOURCE_RESULT_DIR / f"{run_name}.json"

    runs = []
    for idx, module in enumerate(modules):
        source = source_runs[module]
        source_exp_dir = source["source_exp_dir"]
        source_cfg_path = source["source_validate_config"]
        source_corpus = source_exp_dir / "workdir/uaf-corpus.db"
        if not source_corpus.is_file():
            raise FileNotFoundError(f"missing source corpus for {module}: {source_corpus}")
        if not source_cfg_path.is_file():
            raise FileNotFoundError(f"missing source validate config for {module}: {source_cfg_path}")

        run_dir = ROOT / "exp" / module / run_name
        workdir = run_dir / "workdir"
        validate_dir = workdir / "validate-run"
        log_dir = run_dir / "logs"
        pid_dir = run_dir / "pids"
        for path in (workdir, validate_dir, log_dir, pid_dir):
            path.mkdir(parents=True, exist_ok=True)

        ensure_symlink(workdir / "uaf-corpus.db", source_corpus)

        source_cfg = load_json(source_cfg_path)
        old_uv = source_cfg.setdefault("experimental", {}).setdefault("uaf_validate", {})
        old_mode = old_uv.get("target_match_mode")
        if old_mode != "sn-fallback":
            log(f"warning: {module} source target_match_mode is {old_mode!r}, expected 'sn-fallback'")

        cfg = json.loads(json.dumps(source_cfg))
        cfg["http"] = f"127.0.0.1:{args.port_base + idx}"
        cfg["workdir"] = str(validate_dir)
        uv = cfg.setdefault("experimental", {}).setdefault("uaf_validate", {})
        uv["target_match_mode"] = args.target_match_mode
        loader_overrides = {}
        if args.offline_corpus_loader:
            loader_overrides = {
                "continuous_mode": uv.get("continuous_mode"),
                "streaming_load": uv.get("streaming_load"),
            }
            uv["continuous_mode"] = False
            uv["streaming_load"] = True

        cfg_path = run_dir / f"exp-validate-{run_name}.cfg"
        write_json(cfg_path, cfg)

        source_note = {
            "module": module,
            "source_exp_dir": str(source_exp_dir),
            "source_validate_config": str(source_cfg_path),
            "source_validate_log": str(source["source_validate_log"]),
            "source_corpus": str(source_corpus),
            "source_corpus_bytes": source_corpus.stat().st_size,
            "new_corpus_symlink": str(workdir / "uaf-corpus.db"),
        }
        write_json(run_dir / "source-corpus.json", source_note)

        runs.append(
            {
                "module": module,
                "run_dir": str(run_dir),
                "workdir": str(workdir),
                "validate_dir": str(validate_dir),
                "validate_config": str(cfg_path),
                "validate_log": str(log_dir / "validate-manager.log"),
                "validate_pidfile": str(pid_dir / "validate-timeout.pid"),
                "validate_exitcode": str(pid_dir / "validate-exitcode.txt"),
                "source_exp_dir": str(source_exp_dir),
                "source_validate_config": str(source_cfg_path),
                "source_validate_log": str(source["source_validate_log"]),
                "source_corpus": str(source_corpus),
                "target_match_mode": args.target_match_mode,
                "source_target_match_mode": old_mode,
                "loader_overrides": loader_overrides,
                "http": cfg["http"],
                "duration": args.duration,
            }
        )

    manifest = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "source_result_dir": str(SOURCE_RESULT_DIR),
        "source_manifest": str(SOURCE_MANIFEST),
        "run_name": run_name,
        "duration": args.duration,
        "max_parallel": args.max_parallel,
        "offline_corpus_loader": args.offline_corpus_loader,
        "target_match_mode": args.target_match_mode,
        "note": f"DeepSeek validate rerun on the same frozen uaf-corpus.db; target_match_mode is changed to {args.target_match_mode}. If offline_corpus_loader=true, continuous_mode is disabled while streaming_load is kept enabled so validate scans the frozen corpus directly instead of waiting for the fuzz-populated queue.",
        "runs": runs,
    }
    write_json(manifest_path, manifest)
    log(f"prepared manifest: {manifest_path}")
    return manifest_path


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def launch_one(run: dict[str, Any], duration: str) -> subprocess.Popen[bytes]:
    log_path = Path(run["validate_log"])
    pid_path = Path(run["validate_pidfile"])
    exit_path = Path(run["validate_exitcode"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    if exit_path.exists():
        exit_path.unlink()

    cmd = [
        "timeout",
        "--kill-after=180s",
        duration,
        str(ROOT / "bin/syz-manager"),
        "-mode=uaf-validate",
        "-config",
        run["validate_config"],
    ]
    with (Path(run["run_dir"]) / "validate-command.txt").open("w") as f:
        f.write(" ".join(cmd) + "\n")
    log(f"launch {run['module']}: {' '.join(cmd)}")
    log_file = log_path.open("ab")
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    log_file.close()
    pid_path.write_text(f"{proc.pid}\n")
    return proc


def run_supervisor(args: argparse.Namespace, manifest_path: Path) -> None:
    manifest = load_json(manifest_path)
    pending = list(manifest["runs"])
    active: list[tuple[dict[str, Any], subprocess.Popen[bytes]]] = []

    log(f"supervisor manifest={manifest_path}")
    log(f"max_parallel={args.max_parallel} duration={args.duration}")
    while pending or active:
        while pending and len(active) < args.max_parallel:
            run = pending.pop(0)
            proc = launch_one(run, args.duration)
            active.append((run, proc))
            time.sleep(args.launch_gap_sec)

        still_active: list[tuple[dict[str, Any], subprocess.Popen[bytes]]] = []
        for run, proc in active:
            code = proc.poll()
            if code is None:
                still_active.append((run, proc))
                continue
            Path(run["validate_exitcode"]).write_text(f"{code}\n")
            log(f"finished {run['module']} exit={code}")
        active = still_active

        status = {
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "pending": [run["module"] for run in pending],
            "active": [
                {"module": run["module"], "pid": proc.pid}
                for run, proc in active
                if proc.poll() is None
            ],
            "finished": [
                run["module"]
                for run in manifest["runs"]
                if Path(run["validate_exitcode"]).exists()
            ],
        }
        write_json(Path(manifest_path).with_suffix(".status.json"), status)
        if pending or active:
            time.sleep(args.poll_sec)
    log(f"all {manifest.get('target_match_mode', 'configured')} validate runs finished")


def print_status(manifest_path: Path) -> None:
    manifest = load_json(manifest_path)
    for run in manifest["runs"]:
        pid_path = Path(run["validate_pidfile"])
        exit_path = Path(run["validate_exitcode"])
        pid = None
        if pid_path.exists():
            text = pid_path.read_text().strip()
            pid = int(text) if text else None
        state = "not-started"
        if exit_path.exists():
            state = f"exited({exit_path.read_text().strip()})"
        elif pid is not None and pid_alive(pid):
            state = f"running(pid={pid})"
        elif pid is not None:
            state = f"pid-not-alive(pid={pid})"
        print(f"{run['module']}\t{state}\t{run['validate_log']}")


def stop_runs(manifest_path: Path) -> None:
    manifest = load_json(manifest_path)
    for run in manifest["runs"]:
        pid_path = Path(run["validate_pidfile"])
        if not pid_path.exists():
            continue
        text = pid_path.read_text().strip()
        if not text:
            continue
        pid = int(text)
        if not pid_alive(pid):
            continue
        log(f"stopping {run['module']} timeout pid={pid}")
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules", nargs="*", default=None)
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--duration", default="12h")
    parser.add_argument(
        "--target-match-mode",
        default="stack-only",
        choices=("stack-only", "site-only"),
    )
    parser.add_argument("--max-parallel", type=int, default=3)
    parser.add_argument("--port-base", type=int, default=57601)
    parser.add_argument("--launch-gap-sec", type=int, default=20)
    parser.add_argument("--poll-sec", type=int, default=60)
    parser.add_argument("--offline-corpus-loader", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--stop", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.max_parallel <= 0:
        raise SystemExit("--max-parallel must be > 0")
    if args.status:
        if args.manifest is None:
            raise SystemExit("--status requires --manifest")
        print_status(args.manifest)
        return 0
    if args.stop:
        if args.manifest is None:
            raise SystemExit("--stop requires --manifest")
        stop_runs(args.manifest)
        return 0
    manifest_path = prepare(args)
    if args.prepare_only:
        return 0
    if args.start:
        run_supervisor(args, manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
