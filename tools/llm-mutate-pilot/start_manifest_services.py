#!/usr/bin/env python3
"""Start managers/producers from an existing LLM-helper manifest via systemd."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--clean-vm-copies", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def unit_safe(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", text)
    text = text.strip("-")
    return text[:180]


def load_json(path: Path) -> Any:
    with path.open() as f:
        return json.load(f)


def dump_json(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    tmp.replace(path)


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


def systemctl_show_pid(unit: str) -> int:
    try:
        out = subprocess.check_output(
            ["systemctl", "--user", "show", unit, "-p", "MainPID", "--value"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return int(out or "0")
    except Exception:
        return 0


def start_unit(repo: Path, unit: str, cmd: list[str], log_path: Path, dry_run: bool) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    service_path = ":".join(
        [
            str(repo / ".codex/tmp/arg0/codex-arg0zcCX6s"),
            "/home/zzzccc/.local/bin",
            "/home/zzzccc/.npm-global/bin",
            "/home/zzzccc/.nvm/versions/node/v24.14.0/bin",
            "/home/zzzccc/Tools/go/bin",
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ]
    )
    shell = (
        f"export PATH={shlex.quote(service_path)}; "
        "export GOROOT=/home/zzzccc/Tools/go; "
        f"exec >> {shlex.quote(str(log_path))} 2>&1; "
        f"echo '[{datetime.now():%F %T}] systemd service start: {unit}'; "
        "echo \"PATH=$PATH\"; "
        "go version || true; "
        "command -v codex || true; "
        f"exec {shlex.join(cmd)}"
    )
    full_cmd = [
        "systemd-run",
        "--user",
        f"--unit={unit}",
        f"--working-directory={repo}",
        "--property=KillMode=process",
        "--property=Restart=no",
        "/usr/bin/bash",
        "-lc",
        shell,
    ]
    print(shlex.join(full_cmd), flush=True)
    if dry_run:
        return 0
    subprocess.check_call(full_cmd)
    time.sleep(2)
    return systemctl_show_pid(unit)


def build_producer_cmd(manifest: dict[str, Any], module: str, info: dict[str, Any]) -> list[str]:
    producer = manifest.get("producer") or {}
    provider = producer.get("provider")
    cmd = ["python3", "tools/llm-mutate-pilot/continuous.py"]
    if provider == "codex":
        cmd += [
            "--provider",
            "codex",
            "--codex-model",
            producer.get("codex_model") or "gpt-5.4",
            "--codex-sandbox",
            producer.get("codex_sandbox") or "read-only",
        ]
    elif provider == "kimi":
        cmd += [
            "--provider",
            "kimi",
            "--base-url",
            producer.get("base_url") or "https://kimi.a7m.com.cn/v1",
            "--model",
            producer.get("model") or "kimi-k2.6",
            "--thinking",
            producer.get("thinking") or "disabled",
            "--reasoning-effort",
            producer.get("reasoning_effort") or "high",
            "--max-tokens",
            str(producer.get("max_tokens") or 65536),
            "--api-key-file",
            ".secrets/kimi_key",
            "--api-key-alias",
            "kimi-main",
        ]
    else:
        raise SystemExit(f"unsupported provider in manifest: {provider}")
    cmd += [
        "--config",
        info["config"],
        "--module",
        module,
        "--out",
        info["producer_out"],
        "--entries-per-round",
        str(producer.get("entries_per_round") or 4),
        "--variants-per-entry",
        str(producer.get("variants_per_entry") or 2),
        "--max-calls",
        str(producer.get("max_calls") or 8),
        "--poll-sec",
        str(producer.get("poll_sec") or 30),
        "--parallel-calls",
        str(producer.get("parallel_calls") or 2),
        "--timeout-sec",
        str(producer.get("timeout_sec") or 600),
    ]
    return cmd


def clean_vm_copies(workdir: Path, dry_run: bool) -> None:
    for path in sorted(workdir.glob("vm-*.qcow2")):
        print(f"remove stale VM copy {path}", flush=True)
        if not dry_run:
            path.unlink()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo_root).resolve()
    manifest_path = (repo / args.manifest).resolve()
    manifest = load_json(manifest_path)
    label = manifest["label"]

    for module, info in manifest["modules"].items():
        config = info["config"]
        out_dir = info["producer_out"]
        if find_process_containing("./bin/syz-manager", "-config", config):
            raise SystemExit(f"manager already running for {module}: {config}")
        if find_process_containing("tools/llm-mutate-pilot/continuous.py", "--out", out_dir):
            raise SystemExit(f"producer already running for {module}: {out_dir}")

        if args.clean_vm_copies:
            clean_vm_copies(Path(info["workdir"]), args.dry_run)

        manager_cmd = info.get("manager_cmd") or ["./bin/syz-manager", "-config", config]
        producer_cmd = info.get("producer_cmd") or build_producer_cmd(manifest, module, info)

        prefix = unit_safe(f"mrpfuzz-{label}-{module}")
        manager_unit = f"{prefix}-manager.service"
        producer_unit = f"{prefix}-producer.service"

        manager_pid = start_unit(repo, manager_unit, manager_cmd, Path(info["manager_log"]), args.dry_run)
        producer_pid = start_unit(repo, producer_unit, producer_cmd, Path(info["producer_log"]), args.dry_run)

        if not args.dry_run:
            if manager_pid <= 0:
                raise SystemExit(f"manager service did not stay active for {module}: {manager_unit}")
            if producer_pid <= 0:
                raise SystemExit(f"producer service did not stay active for {module}: {producer_unit}")
            info["manager_pid"] = manager_pid
            info["producer_pid"] = producer_pid
            info["manager_unit"] = manager_unit
            info["producer_unit"] = producer_unit
            dump_json(manifest_path, manifest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
