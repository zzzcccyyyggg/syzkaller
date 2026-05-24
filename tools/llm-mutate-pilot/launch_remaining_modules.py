#!/usr/bin/env python3
"""Launch the second half of an LLM-helper fuzzing batch.

This is intentionally conservative: it creates fresh workdirs, copies only the
prepared corpus.db, checks ports and duplicate processes, and refuses to
overwrite existing experiment artifacts unless --force is used.
"""

from __future__ import annotations

import argparse
import fcntl
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


DEFAULT_MODULES = ("ptmx", "floppy", "dsp", "bt-stack")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--template-manifest", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--provider", choices=("codex", "kimi"), required=True)
    parser.add_argument("--ports", required=True, help="Comma-separated HTTP ports, one per module.")
    parser.add_argument("--modules", default=",".join(DEFAULT_MODULES))
    parser.add_argument("--wait-until", help="Local timestamp: YYYY-mm-dd HH:MM:SS")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--prepare-only", action="store_true", help="Create configs/workdirs/manifest but do not launch processes.")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[{now_text()}] {msg}", flush=True)


def load_json(path: Path) -> Any:
    with path.open() as f:
        return json.load(f)


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")
    tmp.replace(path)


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def iter_processes() -> list[tuple[int, str]]:
    out = subprocess.check_output(["ps", "-eo", "pid=,args="], text=True)
    procs: list[tuple[int, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_s, _, args = line.partition(" ")
        try:
            procs.append((int(pid_s), args.strip()))
        except ValueError:
            continue
    return procs


def find_process_containing(*needles: str) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []
    this_pid = os.getpid()
    for pid, args in iter_processes():
        if pid == this_pid:
            continue
        if all(needle in args for needle in needles):
            matches.append((pid, args))
    return matches


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def wait_until_local(ts: str) -> None:
    target = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    while True:
        remaining = (target - datetime.now()).total_seconds()
        if remaining <= 0:
            log(f"target time reached: {ts}")
            return
        sleep_s = min(remaining, 300)
        log(f"waiting {remaining:.0f}s until {ts}")
        time.sleep(sleep_s)


def refuse_existing_path(path: Path, kind: str, force: bool) -> None:
    if not path.exists():
        return
    if force:
        return
    raise SystemExit(f"{kind} already exists, refusing to overwrite: {path}")


def prepare_config(
    repo: Path,
    module: str,
    label: str,
    port: int,
    module_template: dict[str, Any],
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    template_cfg_path = Path(module_template["config"])
    cfg = load_json(template_cfg_path)

    producer_out = repo / "paper/results/llm-mutate-continuous" / f"{module}-{label}"
    workdir = repo / "exp-static/paper-static-input" / module / label / "workdir"
    config_path = repo / "exp" / module / f"exp-fuzz-{label}.cfg"
    manager_log = repo / "exp" / module / "logs" / f"exp-fuzz-{label}.log"

    refuse_existing_path(config_path, "config", force)
    refuse_existing_path(workdir, "workdir", force)
    refuse_existing_path(producer_out, "producer output", force)
    refuse_existing_path(manager_log, "manager log", force)

    if not port_is_free(port):
        raise SystemExit(f"http port is not free: {port}")

    source_corpus = Path(module_template["source_corpus"])
    if not source_corpus.is_file():
        raise SystemExit(f"source corpus.db not found: {source_corpus}")

    cfg["http"] = f"127.0.0.1:{port}"
    cfg["workdir"] = str(workdir)
    cfg.setdefault("experimental", {})
    exp = cfg["experimental"]
    exp["random_baseline_mode"] = True
    exp["enable_timing_exploration"] = False
    exp["timing_exploration_ratio"] = 0
    exp["enable_object_linking"] = False
    exp["object_link_attempt_ratio"] = 1
    exp["static_input_exploration"] = True
    exp["static_input_skip_builtin_seeds"] = True
    exp["isolate_kccwf_partner_objects"] = True
    exp["enable_coverage_triage"] = False
    exp["enable_affinity_table"] = False
    exp["llm_input_seed_dir"] = str(producer_out)
    exp["llm_input_seed_poll_sec"] = 30
    exp["llm_input_seed_max_per_poll"] = 12

    if not dry_run:
        workdir.mkdir(parents=True, exist_ok=False)
        shutil.copy2(source_corpus, workdir / "corpus.db")
        producer_out.mkdir(parents=True, exist_ok=False)
        manager_log.parent.mkdir(parents=True, exist_ok=True)
        dump_json(config_path, cfg)
    return {
        "base_config": module_template.get("base_config"),
        "source_corpus": str(source_corpus),
        "source_corpus_bytes": source_corpus.stat().st_size,
        "template_config": str(template_cfg_path),
        "config": str(config_path),
        "workdir": str(workdir),
        "manager_log": str(manager_log),
        "producer_out": str(producer_out),
        "producer_log": str(producer_out / "producer.log"),
        "http": f"127.0.0.1:{port}",
    }


def launch_one(repo: Path, provider: str, module: str, info: dict[str, Any]) -> dict[str, Any]:
    config = info["config"]
    out_dir = info["producer_out"]

    existing_mgr = find_process_containing("./bin/syz-manager", "-config", config)
    existing_prod = find_process_containing("tools/llm-mutate-pilot/continuous.py", "--out", out_dir)
    if existing_mgr or existing_prod:
        raise SystemExit(
            f"duplicate process for {module}: manager={existing_mgr[:1]} producer={existing_prod[:1]}"
        )

    manager_cmd = ["./bin/syz-manager", "-config", config]
    producer_cmd = [
        "python3",
        "tools/llm-mutate-pilot/continuous.py",
    ]
    if provider == "codex":
        producer_cmd += [
            "--provider",
            "codex",
            "--codex-model",
            "gpt-5.4",
            "--codex-sandbox",
            "read-only",
            "--codex-reasoning-effort",
            "medium",
        ]
    else:
        producer_cmd += [
            "--provider",
            "kimi",
            "--base-url",
            "https://kimi.a7m.com.cn/v1",
            "--model",
            "kimi-k2.6",
            "--thinking",
            "disabled",
            "--reasoning-effort",
            "high",
            "--max-tokens",
            "65536",
            "--api-key-file",
            ".secrets/kimi_key",
            "--api-key-alias",
            "kimi-main",
        ]
    producer_cmd += [
        "--config",
        config,
        "--module",
        module,
        "--out",
        out_dir,
        "--entries-per-round",
        "4",
        "--variants-per-entry",
        "2",
        "--max-calls",
        "8",
        "--poll-sec",
        "30",
        "--parallel-calls",
        "2",
        "--timeout-sec",
        "600",
    ]

    with Path(info["manager_log"]).open("ab") as mgr_log:
        mgr = subprocess.Popen(
            manager_cmd,
            cwd=repo,
            stdout=mgr_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    with Path(info["producer_log"]).open("ab") as prod_log:
        prod = subprocess.Popen(
            producer_cmd,
            cwd=repo,
            stdout=prod_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    time.sleep(2)
    if not pid_alive(mgr.pid):
        raise SystemExit(f"manager exited immediately for {module}; see {info['manager_log']}")
    if not pid_alive(prod.pid):
        raise SystemExit(f"producer exited immediately for {module}; see {info['producer_log']}")

    info["manager_pid"] = mgr.pid
    info["producer_pid"] = prod.pid
    info["manager_cmd"] = manager_cmd
    info["producer_cmd"] = producer_cmd
    return info


def main() -> int:
    args = parse_args()
    repo = Path(args.repo_root).resolve()
    os.chdir(repo)

    if args.wait_until:
        wait_until_local(args.wait_until)

    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    if len(modules) != len(ports):
        raise SystemExit("--ports must contain exactly one port per module")

    lock_dir = repo / "paper/results/llm-mutate-continuous/schedulers"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{args.label}.lock"
    lock_f = lock_path.open("w")
    try:
        fcntl.flock(lock_f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit(f"another launcher holds lock {lock_path}") from exc

    template_manifest = load_json((repo / args.template_manifest).resolve())
    template_modules = template_manifest.get("modules", {})
    for module in modules:
        if module not in template_modules:
            raise SystemExit(f"module {module} missing from template manifest")

    manifest_path = repo / "paper/results/llm-mutate-continuous" / f"{args.label}-manifest.json"
    refuse_existing_path(manifest_path, "manifest", args.force)

    manifest: dict[str, Any] = {
        "label": args.label,
        "created_at": datetime.now().isoformat(),
        "provider": args.provider,
        "modules_requested": modules,
        "template_manifest": str((repo / args.template_manifest).resolve()),
        "corpus_policy": "fresh workdir; copy only corpus.db from the template manifest source corpus; do not copy uaf-corpus.db, race-pair-index.db, or validation state",
        "rewrite_policy": "KCCWF partner namespace rewrite uses random namespace bucket per partner rewrite attempt; buckets may collide.",
        "producer": {
            "provider": args.provider,
            "entries_per_round": 4,
            "variants_per_entry": 2,
            "parallel_calls": 2,
            "max_calls": 8,
            "poll_sec": 30,
            "timeout_sec": 600,
        },
        "modules": {},
    }
    if args.provider == "codex":
        manifest["producer"].update(
            {"codex_model": "gpt-5.4", "codex_sandbox": "read-only", "codex_reasoning_effort": "medium"}
        )
    else:
        manifest["producer"].update(
            {
                "base_url": "https://kimi.a7m.com.cn/v1",
                "model": "kimi-k2.6",
                "thinking": "disabled",
                "reasoning_effort": "high",
                "max_tokens": 65536,
            }
        )

    log(f"preparing {args.label}: modules={modules}, ports={ports}")
    for module, port in zip(modules, ports):
        info = prepare_config(repo, module, args.label, port, template_modules[module], args.force, args.dry_run)
        manifest["modules"][module] = info

    if args.dry_run:
        log("dry run succeeded; no processes launched")
        dump_json(manifest_path.with_suffix(".dry-run.json"), manifest)
        return 0

    if args.prepare_only:
        dump_json(manifest_path, manifest)
        log(f"prepare-only complete: {manifest_path}")
        return 0

    for module in modules:
        log(f"launching {module}")
        manifest["modules"][module] = launch_one(repo, args.provider, module, manifest["modules"][module])
        dump_json(manifest_path, manifest)

    log(f"launch complete: {manifest_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        raise
