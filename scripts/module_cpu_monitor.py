#!/usr/bin/env python3
"""Monitor per-module CPU usage based on current syz-manager CPU affinity."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def parse_duration(text: str) -> float:
    text = str(text).strip().lower()
    if text.endswith("ms"):
        return float(text[:-2]) / 1000.0
    if text.endswith("s"):
        return float(text[:-1])
    if text.endswith("m"):
        return float(text[:-1]) * 60.0
    if text.endswith("h"):
        return float(text[:-1]) * 3600.0
    return float(text)


def parse_cpu_list(spec: str) -> List[int]:
    cpus: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.extend(range(int(lo), int(hi) + 1))
        else:
            cpus.append(int(part))
    return sorted(set(cpus))


def compress_cpu_list(cpus: Iterable[int]) -> str:
    values = sorted(set(cpus))
    if not values:
        return "—"
    ranges: List[str] = []
    start = prev = values[0]
    for cpu in values[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = cpu
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges)


def dig(obj: Dict, *keys: str, default=""):
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def load_json(path: Path) -> Dict:
    if not path.exists():
        return {}
    with path.open() as f:
        return json.load(f)


def read_proc_stat() -> Dict[int, Tuple[int, int]]:
    stats: Dict[int, Tuple[int, int]] = {}
    with open("/proc/stat") as f:
        for line in f:
            if not line.startswith("cpu"):
                continue
            parts = line.split()
            name = parts[0]
            if name == "cpu" or not name[3:].isdigit():
                continue
            cpu = int(name[3:])
            vals = [int(x) for x in parts[1:]]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals)
            stats[cpu] = (idle, total)
    return stats


def sample_cpu_usage(cpus: Iterable[int], window: float) -> Dict[int, float]:
    cpus = sorted(set(cpus))
    if not cpus:
        return {}
    start = read_proc_stat()
    time.sleep(window)
    end = read_proc_stat()
    usage: Dict[int, float] = {}
    for cpu in cpus:
        idle1, total1 = start[cpu]
        idle2, total2 = end[cpu]
        didle = idle2 - idle1
        dtotal = total2 - total1
        usage[cpu] = 0.0 if dtotal <= 0 else (dtotal - didle) * 100.0 / dtotal
    return usage


def scan_syz_manager_processes() -> List[Tuple[int, str]]:
    procs: List[Tuple[int, str]] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        cmdline_path = Path("/proc") / entry / "cmdline"
        try:
            raw = cmdline_path.read_bytes()
        except OSError:
            continue
        if not raw:
            continue
        argv = [arg.decode(errors="ignore") for arg in raw.split(b"\0") if arg]
        if not argv:
            continue
        joined = " ".join(argv)
        if "syz-manager" not in joined:
            continue
        procs.append((int(entry), joined))
    return procs


def find_pid_by_fragments(processes: List[Tuple[int, str]], fragments: List[str]) -> Optional[int]:
    for pid, cmdline in processes:
        if all(fragment in cmdline for fragment in fragments):
            return pid
    return None


def pid_cpu_list(pid: Optional[int]) -> List[int]:
    if not pid:
        return []
    status_path = Path("/proc") / str(pid) / "status"
    if not status_path.exists():
        return []
    try:
        with status_path.open() as f:
            for line in f:
                if line.startswith("Cpus_allowed_list:"):
                    return parse_cpu_list(line.split(":", 1)[1].strip())
    except OSError:
        return []
    return []


@dataclass
class ModuleRuntime:
    module: str
    fuzz_pid: Optional[int]
    validate_pid: Optional[int]
    fuzz_cores: List[int]
    validate_cores: List[int]
    module_cores: List[int]
    layout: str
    fuzz_vm_count: str
    validate_vm_count: str
    validate_max_concurrent: str


def discover_runtime(project_home: Path, module: str, processes: List[Tuple[int, str]]) -> ModuleRuntime:
    exp_dir = project_home / "exp" / module

    fuzz_pid = find_pid_by_fragments(
        processes,
        [f"/exp/{module}/", "syz-manager", f"/exp/{module}/exp-fuzz"],
    )
    if fuzz_pid is None:
        fuzz_pid = find_pid_by_fragments(
            processes,
            [f"/exp/{module}/", "syz-manager", f"/exp/{module}/fuzz"],
        )

    validate_pid = find_pid_by_fragments(
        processes,
        [f"/exp/{module}/", "syz-manager", "-mode=uaf-validate", f"/exp/{module}/exp-validate"],
    )
    if validate_pid is None:
        validate_pid = find_pid_by_fragments(
            processes,
            [f"/exp/{module}/", "syz-manager", "-mode=uaf-validate", f"/exp/{module}/validate"],
        )

    fuzz_cores = pid_cpu_list(fuzz_pid)
    validate_cores = pid_cpu_list(validate_pid)

    if fuzz_cores and validate_cores:
        layout = "shared" if fuzz_cores == validate_cores else "split"
        module_cores = sorted(set(fuzz_cores) | set(validate_cores))
    elif fuzz_cores:
        layout = "fuzz-only"
        module_cores = fuzz_cores
    elif validate_cores:
        layout = "validate-only"
        module_cores = validate_cores
    else:
        layout = "stopped"
        module_cores = []

    fuzz_cfg = exp_dir / "exp-fuzz.cfg"
    validate_cfg = exp_dir / "exp-validate.cfg"
    if not fuzz_cfg.exists():
        fuzz_cfg = exp_dir / "fuzz.cfg"
    if not validate_cfg.exists():
        validate_cfg = exp_dir / "validate.cfg"

    fuzz = load_json(fuzz_cfg)
    validate = load_json(validate_cfg)

    return ModuleRuntime(
        module=module,
        fuzz_pid=fuzz_pid,
        validate_pid=validate_pid,
        fuzz_cores=fuzz_cores,
        validate_cores=validate_cores,
        module_cores=module_cores,
        layout=layout,
        fuzz_vm_count=str(dig(fuzz, "vm", "count", default="")),
        validate_vm_count=str(dig(validate, "vm", "count", default="")),
        validate_max_concurrent=str(dig(validate, "experimental", "uaf_validate", "max_concurrent", default="")),
    )


def configured_modules(project_home: Path) -> List[str]:
    exp_dir = project_home / "exp"
    modules = []
    for path in sorted(exp_dir.iterdir()):
        if not path.is_dir():
            continue
        if (path / "fuzz.cfg").exists() or (path / "validate.cfg").exists():
            modules.append(path.name)
    return modules


def resolve_modules(project_home: Path, requested: List[str]) -> List[str]:
    processes = scan_syz_manager_processes()
    all_modules = configured_modules(project_home)
    if requested:
        return requested
    running = []
    for module in all_modules:
        runtime = discover_runtime(project_home, module, processes)
        if runtime.fuzz_pid or runtime.validate_pid:
            running.append(module)
    return running


def take_snapshot(project_home: Path, modules: List[str], window: float) -> Tuple[List[ModuleRuntime], Dict[str, Dict]]:
    processes = scan_syz_manager_processes()
    runtimes = [discover_runtime(project_home, module, processes) for module in modules]
    cpus = sorted({cpu for runtime in runtimes for cpu in runtime.module_cores})
    per_cpu = sample_cpu_usage(cpus, window) if cpus else {}

    snapshot: Dict[str, Dict] = {}
    for runtime in runtimes:
        core_usage = {cpu: per_cpu.get(cpu, 0.0) for cpu in runtime.module_cores}
        values = list(core_usage.values())
        avg_usage = sum(values) / len(values) if values else 0.0
        peak_core = max(values) if values else 0.0
        snapshot[runtime.module] = {
            "avg_usage_pct": avg_usage,
            "peak_core_pct": peak_core,
            "core_usage_pct": core_usage,
        }
    return runtimes, snapshot


def render_snapshot(timestamp: str, window: float, runtimes: List[ModuleRuntime], snapshot: Dict[str, Dict]) -> str:
    lines = [
        f"CPU usage snapshot at {timestamp} (window={window:.1f}s)",
        "MODULE        STATE        VMs    VCONC  LAYOUT       AVG      PEAK     CORESET",
        "------        -----        ---    -----  ------       ---      ----     -------",
    ]
    for runtime in runtimes:
        data = snapshot[runtime.module]
        state = "running" if runtime.module_cores else "stopped"
        cores = compress_cpu_list(runtime.module_cores)
        lines.append(
            f"{runtime.module:12s} {state:12s} "
            f"{runtime.fuzz_vm_count or '?':>1s}/{runtime.validate_vm_count or '-':<3s} "
            f"{(runtime.validate_max_concurrent or '-'):>5s}  "
            f"{runtime.layout:11s} "
            f"{data['avg_usage_pct']:6.1f}%  {data['peak_core_pct']:6.1f}%  {cores}"
        )
        if runtime.module_cores:
            per_core = "  ".join(
                f"cpu{cpu}={data['core_usage_pct'][cpu]:5.1f}%"
                for cpu in runtime.module_cores
            )
            lines.append(f"  {per_core}")
    return "\n".join(lines)


def write_monitor_summary(
    output_dir: Path,
    started_at: str,
    finished_at: str,
    duration_seconds: float,
    interval_seconds: float,
    sample_window_seconds: float,
    runtimes: List[ModuleRuntime],
    aggregate: Dict[str, Dict],
):
    summary_txt = output_dir / "summary.txt"
    summary_json = output_dir / "summary.json"

    lines = [
        "CPU monitor summary",
        f"started_at: {started_at}",
        f"finished_at: {finished_at}",
        f"duration_seconds: {duration_seconds:.1f}",
        f"interval_seconds: {interval_seconds:.1f}",
        f"sample_window_seconds: {sample_window_seconds:.1f}",
        "",
        "MODULE        VMs    VCONC  LAYOUT       AVG      PEAK-AVG  PEAK-CORE  CORESET",
        "------        ---    -----  ------       ---      --------  ---------  -------",
    ]

    json_summary = {
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration_seconds,
        "interval_seconds": interval_seconds,
        "sample_window_seconds": sample_window_seconds,
        "modules": {},
    }

    runtime_by_module = {runtime.module: runtime for runtime in runtimes}
    for module, data in aggregate.items():
        runtime = runtime_by_module[module]
        cores = compress_cpu_list(runtime.module_cores)
        lines.append(
            f"{module:12s} "
            f"{runtime.fuzz_vm_count or '?':>1s}/{runtime.validate_vm_count or '-':<3s} "
            f"{(runtime.validate_max_concurrent or '-'):>5s}  "
            f"{runtime.layout:11s} "
            f"{data['avg_usage_pct']:6.1f}%  {data['peak_avg_usage_pct']:8.1f}%  "
            f"{data['peak_core_usage_pct']:9.1f}%  {cores}"
        )
        core_lines = []
        for cpu in sorted(data["per_core_avg_pct"]):
            core_lines.append(
                f"cpu{cpu}: avg={data['per_core_avg_pct'][cpu]:5.1f}% peak={data['per_core_peak_pct'][cpu]:5.1f}%"
            )
        if core_lines:
            lines.append("  " + "  ".join(core_lines))
        json_summary["modules"][module] = data

    summary_txt.write_text("\n".join(lines) + "\n")
    summary_json.write_text(json.dumps(json_summary, indent=2, sort_keys=True) + "\n")


def command_snapshot(args: argparse.Namespace) -> int:
    project_home = Path(args.project_home).resolve()
    modules = resolve_modules(project_home, args.modules)
    if not modules:
        print("No running modules found.", file=sys.stderr)
        return 1
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    runtimes, snapshot = take_snapshot(project_home, modules, args.window)
    print(render_snapshot(timestamp, args.window, runtimes, snapshot))
    return 0


def command_monitor(args: argparse.Namespace) -> int:
    project_home = Path(args.project_home).resolve()
    modules = resolve_modules(project_home, args.modules)
    if not modules:
        print("No running modules found.", file=sys.stderr)
        return 1

    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = project_home / ".experiment" / "runs" / f"cpu-monitor-{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    samples_path = output_dir / "samples.csv"
    meta_path = output_dir / "metadata.json"

    started_dt = datetime.now().astimezone()
    started_at = started_dt.isoformat()
    duration_seconds = args.duration
    interval_seconds = args.interval
    sample_window_seconds = args.window

    aggregate: Dict[str, Dict] = {}
    finished_runtimes: List[ModuleRuntime] = []

    with samples_path.open("w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                "timestamp",
                "module",
                "layout",
                "coreset",
                "avg_usage_pct",
                "peak_core_usage_pct",
                "core_usage_json",
            ]
        )

        next_time = time.time()
        deadline = next_time + duration_seconds
        sample_no = 0

        print(f"CPU monitor started: modules={','.join(modules)}")
        print(f"window={sample_window_seconds:.1f}s interval={interval_seconds:.1f}s duration={duration_seconds:.1f}s")
        print(f"output_dir={output_dir}")

        while next_time < deadline:
            now = time.time()
            if now < next_time:
                time.sleep(next_time - now)

            timestamp = datetime.now().astimezone()
            runtimes, snapshot = take_snapshot(project_home, modules, sample_window_seconds)
            finished_runtimes = runtimes
            sample_no += 1

            parts = []
            for runtime in runtimes:
                data = snapshot[runtime.module]
                writer.writerow(
                    [
                        timestamp.isoformat(),
                        runtime.module,
                        runtime.layout,
                        compress_cpu_list(runtime.module_cores),
                        f"{data['avg_usage_pct']:.4f}",
                        f"{data['peak_core_pct']:.4f}",
                        json.dumps(data["core_usage_pct"], sort_keys=True),
                    ]
                )
                bucket = aggregate.setdefault(
                    runtime.module,
                    {
                        "samples": 0,
                        "avg_usage_sum": 0.0,
                        "peak_avg_usage_pct": 0.0,
                        "peak_core_usage_pct": 0.0,
                        "per_core_sum_pct": {},
                        "per_core_peak_pct": {},
                    },
                )
                bucket["samples"] += 1
                bucket["avg_usage_sum"] += data["avg_usage_pct"]
                bucket["peak_avg_usage_pct"] = max(bucket["peak_avg_usage_pct"], data["avg_usage_pct"])
                bucket["peak_core_usage_pct"] = max(bucket["peak_core_usage_pct"], data["peak_core_pct"])

                for cpu, usage in data["core_usage_pct"].items():
                    bucket["per_core_sum_pct"][cpu] = bucket["per_core_sum_pct"].get(cpu, 0.0) + usage
                    bucket["per_core_peak_pct"][cpu] = max(bucket["per_core_peak_pct"].get(cpu, 0.0), usage)

                parts.append(f"{runtime.module}={data['avg_usage_pct']:.1f}%")

            csv_file.flush()
            print(f"[{timestamp.strftime('%H:%M:%S')}] sample={sample_no:03d} " + "  ".join(parts))
            next_time += interval_seconds

    finished_dt = datetime.now().astimezone()
    finished_at = finished_dt.isoformat()

    for module, bucket in aggregate.items():
        samples = max(bucket["samples"], 1)
        bucket["avg_usage_pct"] = bucket["avg_usage_sum"] / samples
        bucket["per_core_avg_pct"] = {
            cpu: total / samples for cpu, total in bucket["per_core_sum_pct"].items()
        }
        del bucket["avg_usage_sum"]
        del bucket["per_core_sum_pct"]

    meta = {
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration_seconds,
        "interval_seconds": interval_seconds,
        "sample_window_seconds": sample_window_seconds,
        "modules": modules,
        "output_dir": str(output_dir),
        "samples_csv": str(samples_path),
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    write_monitor_summary(
        output_dir=output_dir,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=duration_seconds,
        interval_seconds=interval_seconds,
        sample_window_seconds=sample_window_seconds,
        runtimes=finished_runtimes,
        aggregate=aggregate,
    )

    print(f"CPU monitor finished: summary={output_dir / 'summary.txt'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Per-module CPU usage monitor for DDRD experiments")
    parser.add_argument("--project-home", default=str(Path(__file__).resolve().parents[1]))

    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot", help="Show one CPU usage snapshot")
    snapshot.add_argument("--window", type=parse_duration, default=1.0)
    snapshot.add_argument("modules", nargs="*")
    snapshot.set_defaults(func=command_snapshot)

    monitor = subparsers.add_parser("monitor", help="Record CPU usage over time")
    monitor.add_argument("--window", type=parse_duration, default=1.0)
    monitor.add_argument("--interval", type=parse_duration, default=5.0)
    monitor.add_argument("--duration", type=parse_duration, default=20 * 60.0)
    monitor.add_argument("--output-dir")
    monitor.add_argument("modules", nargs="*")
    monitor.set_defaults(func=command_monitor)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
