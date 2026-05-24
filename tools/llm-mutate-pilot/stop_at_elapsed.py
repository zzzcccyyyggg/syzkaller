#!/usr/bin/env python3
"""Stop selected MRPFuzz module runs when their syz-managers reach a duration."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import signal
import subprocess
import time
from pathlib import Path


def parse_etime(value: str) -> int:
    days = 0
    rest = value.strip()
    if "-" in rest:
        day_s, rest = rest.split("-", 1)
        days = int(day_s)
    parts = [int(part) for part in rest.split(":")]
    if len(parts) == 2:
        hours = 0
        minutes, seconds = parts
    elif len(parts) == 3:
        hours, minutes, seconds = parts
    else:
        return 0
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def ps_rows() -> list[tuple[int, int, str, str]]:
    out = subprocess.check_output(["ps", "-eo", "pid=,etime=,args="], text=True)
    rows: list[tuple[int, int, str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid_s, etime, args = parts
        try:
            rows.append((int(pid_s), parse_etime(etime), etime, args))
        except ValueError:
            continue
    return rows


def manager_rows(module: str) -> list[tuple[int, int, str, str]]:
    needle_abs = f"/exp/{module}/"
    needle_rel = f" exp/{module}/"
    return [
        row
        for row in ps_rows()
        if "syz-manager -config" in row[3]
        and (needle_abs in row[3] or needle_rel in row[3])
    ]


def root_pids(module: str) -> list[int]:
    needle_abs = f"/exp/{module}/"
    needle_rel = f" exp/{module}/"
    roots: list[int] = []
    for pid, _, _, args in ps_rows():
        if "syz-manager -config" in args and (needle_abs in args or needle_rel in args):
            roots.append(pid)
        elif "tools/llm-mutate-pilot/continuous.py" in args and f"--module {module}" in args:
            roots.append(pid)
    return sorted(set(roots))


def child_pids(pid: int) -> list[int]:
    try:
        out = subprocess.check_output(["pgrep", "-P", str(pid)], text=True)
    except subprocess.CalledProcessError:
        return []
    children = [int(line) for line in out.splitlines() if line.strip()]
    all_children = children[:]
    for child in children:
        all_children.extend(child_pids(child))
    return all_children


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_module(module: str, log) -> None:
    pids: list[int] = []
    for root in root_pids(module):
        pids.append(root)
        pids.extend(child_pids(root))
    pids = sorted(set(pids), reverse=True)
    if not pids:
        log(f"{module}: no matching pids to stop")
        return
    log(f"{module}: stopping pids {' '.join(map(str, pids))}")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    time.sleep(8)
    remaining = [pid for pid in pids if alive(pid)]
    if remaining:
        log(f"{module}: force killing {' '.join(map(str, remaining))}")
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", nargs="+", required=True)
    parser.add_argument("--hours", type=float, default=10.0)
    parser.add_argument("--poll-sec", type=int, default=30)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    threshold = int(args.hours * 3600)
    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(message: str) -> None:
        line = f"[{dt.datetime.now().isoformat(timespec='seconds')}] {message}"
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        print(line, flush=True)

    pending = set(args.modules)
    log(f"watcher started threshold={threshold}s modules={' '.join(args.modules)}")
    while pending:
        for module in list(pending):
            managers = manager_rows(module)
            if not managers:
                log(f"{module}: no manager remains; marking done")
                pending.remove(module)
                continue
            summary = " ".join(f"{pid}:{etime}" for pid, _, etime, _ in managers)
            ready = all(seconds >= threshold for _, seconds, _, _ in managers)
            log(f"{module}: managers {summary} ready={int(ready)}")
            if ready:
                stop_module(module, log)
                pending.remove(module)
        if pending:
            time.sleep(max(args.poll_sec, 5))
    log("all target modules stopped; watcher exiting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
