#!/usr/bin/env python3
"""Run one module threshold-policy variant with its own live LLM producer."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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


ROOT = Path(__file__).resolve().parents[4]
CLAIM_ROOT = ROOT / "paper/artifacts/claims/added-threshold-control"
RUN_ROOT = CLAIM_ROOT / "runs"
BASE_RUNNER = ROOT / "paper/artifacts/claims/added-throughput/run_phase2b_complete.py"
KERNEL_OUTPUT = ROOT / "kernels/output-binary-trace-20260630"
KERNEL_BUILD = ROOT / "kernels/builds-binary-trace-20260630/x86"
QEMU_VERSION = "QEMU emulator version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.30)"
QEMU_SHA256 = "7d1e85a29e09c49f6a1c60a18713d80a72ef3b8932c4183cc100bce3a01fa64e"
KERNEL_ACCESS_DELAY_MULTIPLIER = 10
COMMON_FROZEN_ARTIFACT_SHA256 = {
    ROOT / "bin/syz-llm-candidate-check": "501f0ac48f2bb49095d577d02e049c9931adab7186d150354f521e334580a3c0",
    ROOT / "scripts/generate_config.py": "00e595ddd4cd5902cd68c809d191fe168125071542374b803f38c6c827f5be80",
    ROOT / "tools/llm-mutate-pilot/pilot.py": "9a9552460e0701ce48c11b1cfbbd703f52adc7e14958d82c074e26b045a3bf71",
    ROOT / "tools/llm-mutate-pilot/continuous.py": "7e746e9944bdbab18451130b02138eb5c3db34aa58cc61255ebe5424dd627763",
}
MODULE_SPECS: dict[str, dict[str, Any]] = {
    "ptmx": {
        "corpus": "exp/ptmx/workdir/tuned-prepared-corpus.db",
        "corpus_sha256": "9e7aefe1f39f6565fe35501268c6fdc3c2835ba53212289a7e7bfa2be60119c9",
        "syscalls": "exp/ptmx/syscalls.txt",
        "syscalls_sha256": "6133edd722886db88c1a0e9d6424abc78e0fbebb8b31fbe0e5930b7ff77aa170",
        "syscall_count": 131,
        "required_syscalls": ("openat$ptmx",),
        "overrides": "exp/ptmx/overrides.json",
        "overrides_sha256": "3328f61b59f76962083d578f48f2d21b8a76866e84967e4ab887c18bb521523d",
        "bzimage_sha256": "35b102dae9fd9645e0059cc3b91d4d877b1ce1bdf63a9579fdd85e5977e7c594",
        "vmlinux_sha256": "6fc4ae61e043b031de37549d085a88d750db2be559d9321daa3276dd6b0c648a",
    },
    "dsp": {
        "corpus": "exp/dsp/workdir/tuned-prepared-corpus.db",
        "corpus_sha256": "8cecb1d33ebe04876d5c4ec0d71bcf7de3fc3a76e44481417b0c80f7db669c34",
        "syscalls": "exp/dsp/syscalls.txt",
        "syscalls_sha256": "b71237409b7af7f2f864d961d37a4874a78bc579a2ea4752cbaa08b6caeb47a8",
        "syscall_count": 48,
        "required_syscalls": ("openat$dsp",),
        "overrides": "exp/dsp/overrides.json",
        "overrides_sha256": "1d185e94bb53b2a9c7007763aac7740dda538fd234a91e4f12cc3f9c85f5fc28",
        "bzimage_sha256": "5b9ce96cf6fdd423a513c6f44cc1a15140978c30d02413ae9669d8f8a748ff59",
        "vmlinux_sha256": "87168fbff4fb77e30387bea586b76253b4dcba03c06d4371429130dc14adb80b",
    },
    "bt-stack": {
        "corpus": "exp/bt-stack/workdir/tuned-prepared-corpus.db",
        "corpus_sha256": "5d8d1b033a3c3741b280924b445d5d7ca480dabe24502d94bdfdb6c091e48e57",
        "syscalls": "exp/bt-stack/syscalls.txt",
        "syscalls_sha256": "cc4e2d57120bb57318c9de2f504799b1722d5e20bd6172e0bded29934e8f8a76",
        "syscall_count": 67,
        "required_syscalls": ("syz_init_net_socket$bt_hci",),
        "overrides": "exp/bt-stack/overrides.json",
        "overrides_sha256": "738f86f71a154809debc97e49889258c65c6fff58a101338567b5efc9c815257",
        "bzimage_sha256": "f25b4cc9f57115798788e863a6ee25435440fdcf158b966ed320293f8acb69d4",
        "vmlinux_sha256": "203030871aba039fa32ffa0f8017aed043e4379dce2f93b9bdb8108bb47f97f6",
        "kernel_cmdline": "rcupdate.rcu_cpu_stall_timeout=120",
    },
    "f2fs": {
        "corpus": "exp/f2fs/workdir/tuned-prepared-corpus.db",
        "corpus_sha256": "6dd501a31fc66dcf0a95e8af26e5888340b4bdf2b5936f5cbfcb3c21160529a9",
        "syscalls": "exp/f2fs/syscalls.txt",
        "syscalls_sha256": "5bc8a32f4c0b65a4752b73a24c1e62f5572088427921f9f9af3d6ce102cbae9e",
        "syscall_count": 88,
        "required_syscalls": ("ioctl$F2FS_IOC_START_ATOMIC_WRITE",),
        "overrides": "exp/f2fs/overrides.json",
        "overrides_sha256": "59d23ff8709adb9ad81d9641e6c3ac7bea38fb5f13fbf9d18f4edb3ccbf37258",
        "bzimage_sha256": "f8fab7cc2c4a576c35342d1100d859040bbe69aeb991c535d8976f03cb21d177",
        "vmlinux_sha256": "8824c8b458c181f186f9dd6dc43c5e5cfa9ff11eea381df7f3d86a8f79a15b5f",
        "cover": False,
        "qemu_args": "-enable-kvm -hdb {root}/images/f2fs-2G.raw",
        "extra_artifacts": {
            "images/f2fs-2G.raw": "875f49787b33c9dec87ff4ef31cf53074ff47392b1141a293be15dc996977598",
        },
    },
}


def load_base_runner():
    spec = importlib.util.spec_from_file_location("threshold_base_runner", BASE_RUNNER)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load base runner: {BASE_RUNNER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base_runner()


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
    tmp.replace(path)


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as output:
        output.write(json.dumps(value, sort_keys=True, default=str) + "\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def memory_available_gib() -> float:
    values: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, rest = line.partition(":")
        if not rest:
            continue
        try:
            values[key] = int(rest.strip().split()[0])
        except (ValueError, IndexError):
            continue
    return values.get("MemAvailable", 0) / (1024 * 1024)


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def host_processes() -> str:
    proc = subprocess.run(
        ["ps", "-eo", "pid=,ppid=,comm=,args="],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    matches = []
    for line in proc.stdout.splitlines():
        if "syz-manager" in line or "qemu-system" in line:
            if "run_threshold_12h_kimi.py" not in line:
                matches.append(line.strip())
    return "\n".join(matches)


def repo_state() -> dict[str, str]:
    def command(*args: str) -> str:
        return subprocess.run(
            list(args), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False,
        ).stdout.strip()

    return {
        "head": command("git", "rev-parse", "HEAD"),
        "branch": command("git", "branch", "--show-current"),
        "status": command("git", "status", "--short"),
    }


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def frozen_module_syscalls(path: Path, spec: dict[str, Any], module: str) -> list[str]:
    syscalls = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    expected_count = int(spec["syscall_count"])
    if len(syscalls) != expected_count:
        raise SystemExit(
            f"{module} syscall count mismatch: {len(syscalls)} != {expected_count}"
        )
    if len(set(syscalls)) != len(syscalls):
        raise SystemExit(f"{module} syscall allowlist contains duplicates")
    for required in spec["required_syscalls"]:
        if required not in syscalls:
            raise SystemExit(f"{module} syscall allowlist does not contain {required}")
    return syscalls


def verify_generated_syscalls(
    cfg: dict[str, Any], expected: list[str], label: str, module: str,
) -> None:
    actual = cfg.get("enable_syscalls")
    if actual != expected:
        actual_count = len(actual) if isinstance(actual, list) else 0
        raise SystemExit(
            f"{label} enable_syscalls differs from frozen {module} allowlist "
            f"({actual_count} entries, expected {len(expected)})"
        )


class VariantRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.module = args.module
        self.module_spec = MODULE_SPECS[self.module]
        self.init_corpus = ROOT / self.module_spec["corpus"]
        self.module_syscalls = ROOT / self.module_spec["syscalls"]
        self.module_overrides = ROOT / self.module_spec["overrides"]
        self.kernel_dir = KERNEL_OUTPUT / self.module
        self.frozen_artifacts = dict(COMMON_FROZEN_ARTIFACT_SHA256)
        self.frozen_artifacts.update(
            {
                self.kernel_dir / "bzImage": self.module_spec["bzimage_sha256"],
                self.kernel_dir / "vmlinux": self.module_spec["vmlinux_sha256"],
            }
        )
        for relative, digest in self.module_spec.get("extra_artifacts", {}).items():
            self.frozen_artifacts[ROOT / relative] = digest
        self.run_dir = RUN_ROOT / args.run_id
        self.config_dir = self.run_dir / "configs"
        self.log_dir = self.run_dir / "logs"
        self.bench_dir = self.run_dir / "bench"
        self.workdir = self.run_dir / "workdir"
        self.validate_workdir = self.workdir / "validate-run"
        self.kimi_dir = self.run_dir / "kimi"
        self.watcher_dir = self.run_dir / "watcher"
        self.state_path = self.run_dir / "state.json"
        self.manifest_path = self.run_dir / "manifest.json"
        self.children: list[tuple[str, subprocess.Popen[bytes], Any]] = []
        self.max_fuzz_qemu = 0
        self.max_validate_qemu = 0
        self.min_memory_gib = float("inf")
        self.initial_calls: int | None = None
        self.last_calls: int | None = None
        self.last_calls_progress = time.monotonic()
        self.seen_pair_unit = False
        self.qemu_path = ""
        self.qemu_version = ""
        self.manager_path = ""
        self.manager_sha256 = ""
        self.executor_path = ""
        self.executor_sha256 = ""

    def create_dirs(self) -> None:
        if self.run_dir.exists():
            raise SystemExit(f"run directory already exists: {self.run_dir}")
        for path in (
            self.config_dir,
            self.log_dir,
            self.bench_dir,
            self.validate_workdir,
            self.kimi_dir,
            self.watcher_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def preflight(self) -> None:
        manager = Path(self.args.manager_bin).resolve()
        required = [
            self.init_corpus,
            self.module_syscalls,
            self.module_overrides,
            ROOT / "images/bookworm.img",
            ROOT / "images/bookworm.id_rsa",
            manager,
            ROOT / "bin/linux_amd64/syz-executor",
            self.kernel_dir / "bzImage",
            self.kernel_dir / "vmlinux",
            KERNEL_BUILD / ".config",
            ROOT / "tools/llm-mutate-pilot/continuous.py",
            ROOT / "bin/syz-llm-candidate-check",
        ]
        if not self.args.skip_kimi and self.args.llm_provider == "kimi-cli":
            required.append(Path(self.args.kimi_cli_bin))
        elif not self.args.skip_kimi and self.args.llm_provider == "codex":
            required.append(Path(self.args.codex_bin))
        elif not self.args.skip_kimi and self.args.llm_provider == "grok-cli":
            required.append(Path(self.args.grok_cli_bin))
        elif not self.args.skip_kimi and self.args.llm_provider == "openai-responses":
            required.append(Path(self.args.openai_auth_json))
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise SystemExit("missing required files:\n" + "\n".join(missing))
        actual_hash = sha256(self.init_corpus)
        if actual_hash != self.module_spec["corpus_sha256"]:
            raise SystemExit(
                "initial corpus hash mismatch: "
                f"{actual_hash} != {self.module_spec['corpus_sha256']}"
            )
        metadata_hashes = (
            (self.module_syscalls, self.module_spec["syscalls_sha256"]),
            (self.module_overrides, self.module_spec["overrides_sha256"]),
        )
        for path, expected_hash in metadata_hashes:
            actual_hash = sha256(path)
            if actual_hash != expected_hash:
                raise SystemExit(
                    f"frozen {self.module} metadata hash mismatch for {path}: "
                    f"{actual_hash} != {expected_hash}"
                )
        for path, expected_hash in self.frozen_artifacts.items():
            actual_hash = sha256(path)
            if actual_hash != expected_hash:
                raise SystemExit(
                    f"frozen experiment artifact hash mismatch for {path}: "
                    f"{actual_hash} != {expected_hash}"
                )
        if not manager.is_file():
            raise SystemExit(f"manager binary does not exist: {manager}")
        self.manager_path = str(manager)
        self.manager_sha256 = sha256(manager)
        executor = (ROOT / "bin/linux_amd64/syz-executor").resolve()
        self.executor_path = str(executor)
        self.executor_sha256 = sha256(executor)
        qemu = shutil.which("qemu-system-x86_64")
        if not qemu:
            raise SystemExit("qemu-system-x86_64 is not available in PATH")
        self.qemu_path = str(Path(qemu).resolve())
        qemu_hash = sha256(Path(self.qemu_path))
        if qemu_hash != QEMU_SHA256:
            raise SystemExit(f"QEMU hash mismatch: {qemu_hash} != {QEMU_SHA256}")
        qemu_version = subprocess.run(
            [self.qemu_path, "--version"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, check=False,
        ).stdout.splitlines()
        self.qemu_version = qemu_version[0] if qemu_version else ""
        if self.qemu_version != QEMU_VERSION:
            raise SystemExit(
                f"QEMU version mismatch: {self.qemu_version!r} != {QEMU_VERSION!r}"
            )
        frozen_module_syscalls(self.module_syscalls, self.module_spec, self.module)
        active = host_processes()
        if active and not self.args.allow_existing_experiments:
            raise SystemExit("existing syz-manager/qemu-system process found:\n" + active)
        for port in (self.args.http_base_port + 1, self.args.http_base_port + 2):
            if not port_is_free(port):
                raise SystemExit(f"HTTP port is busy: {port}")
        free_disk = shutil.disk_usage(ROOT).free / (1024**3)
        if free_disk < self.args.min_start_disk_gib:
            raise SystemExit(
                f"free disk too low: {free_disk:.1f} GiB < {self.args.min_start_disk_gib:.1f} GiB"
            )
        available = memory_available_gib()
        if available < self.args.min_start_memory_gib:
            raise SystemExit(
                f"available memory too low: {available:.1f} GiB < {self.args.min_start_memory_gib:.1f} GiB"
            )

    def apply_common(
        self,
        cfg: dict[str, Any],
        workdir: Path,
        http_port: int,
        vm_count: int,
        vm_mem_mib: int,
    ) -> None:
        cfg["workdir"] = str(workdir)
        cfg["http"] = f"127.0.0.1:{http_port}"
        cfg["syzkaller"] = str(ROOT)
        cfg["image"] = str(ROOT / "images/bookworm.img")
        cfg["sshkey"] = str(ROOT / "images/bookworm.id_rsa")
        cfg["kernel_obj"] = str(KERNEL_BUILD)
        cfg["vmlinux"] = str(self.kernel_dir / "vmlinux")
        cfg["procs"] = 2
        cfg["reproduce"] = False
        if "cover" in self.module_spec:
            cfg["cover"] = bool(self.module_spec["cover"])
        cfg["vm_running_time"] = self.args.vm_running_time_seconds
        cfg["fuzzing_vms"] = vm_count
        vm = cfg.setdefault("vm", {})
        vm["count"] = vm_count
        vm["cpu"] = 2
        vm["mem"] = vm_mem_mib
        vm["kernel"] = str(self.kernel_dir / "bzImage")
        vm["qemu_args"] = str(self.module_spec.get("qemu_args", "-enable-kvm")).format(root=ROOT)
        extra_cmdline = str(self.module_spec.get("kernel_cmdline", "")).strip()
        if extra_cmdline:
            cmdline = str(vm.get("cmdline", "")).strip()
            parts = cmdline.split()
            for option in extra_cmdline.split():
                if option not in parts:
                    parts.append(option)
            vm["cmdline"] = " ".join(parts)

    def prepare(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import generate_config as cfggen  # type: ignore

        cfggen.KERNEL_OUTPUT = str(KERNEL_OUTPUT)
        cfggen.KERNEL_BUILDS = str(KERNEL_BUILD.parent)
        fuzz_cfg = cfggen.generate_config(self.module, "fuzz", include_experimental=True)
        validate_cfg = cfggen.generate_config(self.module, "validate", include_experimental=True)
        expected_syscalls = frozen_module_syscalls(
            self.module_syscalls, self.module_spec, self.module,
        )
        verify_generated_syscalls(fuzz_cfg, expected_syscalls, "fuzz", self.module)
        verify_generated_syscalls(validate_cfg, expected_syscalls, "validate", self.module)

        shutil.copy2(self.init_corpus, self.workdir / "corpus.db")
        copied_hash = sha256(self.workdir / "corpus.db")
        if copied_hash != self.module_spec["corpus_sha256"]:
            raise SystemExit(f"copied corpus hash mismatch: {copied_hash}")

        self.apply_common(
            fuzz_cfg,
            self.workdir,
            self.args.http_base_port + 1,
            self.args.fuzz_vm_count,
            self.args.fuzz_vm_mem_mib,
        )
        exp = fuzz_cfg.setdefault("experimental", {})
        exp.update(
            {
                "race_mode": True,
                "barrier_mode": True,
                "barrier_procs": [0, 1],
                "disable_race_validate_queue": False,
                "disable_uaf_validate_queue": False,
                "disable_race_history": False,
                "history_buffer_size": 100,
                "new_varname_pair_history": 100,
                "new_stack_history": 10,
                "max_stacks_per_varname_pair": self.args.max_stacks_per_varname,
                "normal_threshold_micros": 1000,
                "enable_timing_exploration": False,
                "timing_exploration_ratio": 0,
                "enable_solo_filter": False,
                "enable_object_linking": False,
                "object_link_attempt_ratio": 0,
                "enable_coverage_triage": False,
                "enable_affinity_table": False,
                "race_disable_normal_triage": False,
                "static_input_exploration": True,
                "static_input_seed": 1592594996,
                "static_input_skip_builtin_seeds": True,
                "llm_input_seed_dir": str(self.kimi_dir),
                "llm_input_seed_poll_sec": 10,
                "llm_input_seed_max_per_poll": 32,
                "dynamic_threshold_counter_unit": self.args.dynamic_threshold_counter_unit,
            }
        )
        if self.args.variant in ("fixed", "fixed-1000"):
            fixed_threshold_us = 1000 if self.args.variant == "fixed-1000" else self.args.fixed_threshold_us
            exp.update(
                {
                    "enable_dynamic_threshold": True,
                    "dynamic_threshold_policy": "fixed",
                    "dynamic_threshold_initial_us": fixed_threshold_us,
                    "dynamic_threshold_min_us": fixed_threshold_us,
                    "dynamic_threshold_max_us": fixed_threshold_us,
                    "dynamic_threshold_eval_sec": 30,
                }
            )
        else:
            exp.update(
                {
                    "enable_dynamic_threshold": True,
                    "dynamic_threshold_policy": (
                        "random" if self.args.variant == "random" else "backpressure"
                    ),
                    "dynamic_threshold_random_seed": 1592594996,
                    "dynamic_threshold_initial_us": 1000,
                    "dynamic_threshold_min_us": self.args.dynamic_threshold_min_us,
                    "dynamic_threshold_max_us": self.args.dynamic_threshold_max_us,
                    "dynamic_threshold_eval_sec": 30,
                }
            )

        self.apply_common(
            validate_cfg,
            self.validate_workdir,
            self.args.http_base_port + 2,
            self.args.validate_vm_count,
            self.args.validate_vm_mem_mib,
        )
        validate_exp = validate_cfg.setdefault("experimental", {})
        validate_exp.update(
            {
                "race_mode": True,
                "barrier_mode": True,
                "barrier_procs": [0, 1],
                "history_buffer_size": 100,
                "new_varname_pair_history": 100,
                "new_stack_history": 10,
                "max_stacks_per_varname_pair": self.args.max_stacks_per_varname,
                "skip_duplicate_data_races": True,
                "dynamic_threshold_counter_unit": self.args.dynamic_threshold_counter_unit,
            }
        )
        uaf = validate_exp.setdefault("uaf_validate", {})
        uaf.update(
            {
                "max_concurrent": self.args.validate_vm_count,
                "delay_retry_budget": 1,
                "timeout_seconds": self.args.validation_timeout_seconds,
                "max_batch_timeout_seconds": self.args.max_batch_timeout_seconds,
                "repeat_count": self.args.validation_repeat_count,
                "stable_pair_min_occurrences": self.args.stable_min_occurrences,
                "disable_async_split": True,
                "enable_vm_snapshot": True,
                "verify_repeat_times": self.args.verify_repeat_times,
                "executor_program_timeout_seconds": self.args.executor_program_timeout_seconds,
                "executor_syscall_timeout_millis": self.args.executor_syscall_timeout_ms,
                "continuous_mode": True,
                "streaming_load": True,
                "streaming_batch_size": 500,
                "max_entries": 0,
                "incremental_reload_minutes": 10,
                "idle_reload_seconds": 10,
                "enable_replay": True,
                "enable_varname_scheduling": True,
                "priority_low_history": True,
                "target_match_mode": "sn-fallback",
                "sn_fallback_range": 2,
                "disable_verify_delay": True,
                "disable_access_delay": False,
                "verify_access_delay_min_us": self.args.verify_access_delay_min_us,
                "verify_access_delay_multiplier": self.args.verify_access_delay_multiplier,
                "verify_access_delay_normalize_to_threshold": self.args.verify_access_delay_normalize,
                "verify_access_delay_target_us": self.args.verify_access_delay_target_us,
                "verify_access_delay_max_us": self.args.verify_access_delay_max_us,
                "verify_stack_access_delay_us": self.args.verify_stack_access_delay_us,
                "verify_stack_access_delay_multiplier": self.args.verify_stack_access_delay_multiplier,
                "disable_collection_delay": True,
                "require_origin_match": self.args.require_origin_match,
                "replay_collect_pairs": False,
                "verify_collect_pairs": False,
                "verify_delay_sweep": False,
                "collection_only": self.args.collection_only,
                "enable_history_minimization": False,
                "max_pairs_per_task": 8,
                "max_tasks_per_corpus": self.args.max_tasks_per_corpus,
                "max_stable_pairs_per_entry": self.args.max_stable_pairs_per_entry,
                "max_stable_pairs_per_origin": self.args.max_stable_pairs_per_origin,
                "origin_match_mode": self.args.origin_match_mode,
                "continue_after_hb": True,
            }
        )
        if self.args.max_concurrent_per_varname > 0:
            uaf["max_concurrent_per_varname"] = self.args.max_concurrent_per_varname
        if self.args.enable_threshold_aware_validation_priority:
            uaf["enable_threshold_aware_validation_priority"] = True
        if self.args.collection_threshold_floor_us > 0:
            uaf["collection_threshold_floor_us"] = self.args.collection_threshold_floor_us
        if self.args.enable_collection_miss_backoff:
            uaf["enable_collection_miss_backoff"] = True
            uaf["collection_miss_free_attempts"] = self.args.collection_miss_free_attempts
            uaf["collection_miss_weight"] = self.args.collection_miss_weight
            uaf["collection_miss_max_defer"] = self.args.collection_miss_max_defer

        self.fuzz_cfg = self.config_dir / "fuzz.cfg"
        self.validate_cfg = self.config_dir / "validate.cfg"
        write_json(self.fuzz_cfg, fuzz_cfg)
        write_json(self.validate_cfg, validate_cfg)
        self.write_manifest("prepared")

    def threshold_manifest(self) -> dict[str, object]:
        if self.args.variant in ("fixed", "fixed-1000"):
            fixed = 1000 if self.args.variant == "fixed-1000" else self.args.fixed_threshold_us
            return {
                "policy": "fixed",
                "counter_unit": self.args.dynamic_threshold_counter_unit,
                "initial_us": fixed,
                "min_us": fixed,
                "max_us": fixed,
                "eval_seconds": 30,
            }
        manifest = {
            "policy": "random" if self.args.variant == "random" else "backpressure",
            "counter_unit": self.args.dynamic_threshold_counter_unit,
            "initial_us": 1000,
            "min_us": self.args.dynamic_threshold_min_us,
            "max_us": self.args.dynamic_threshold_max_us,
            "eval_seconds": 30,
        }
        if self.args.variant == "random":
            manifest.update(
                {
                    "sampling": "discrete-uniform-inclusive",
                    "random_seed": 1592594996,
                    "resample_scope": "control-interval",
                }
            )
        return manifest

    def write_manifest(self, phase: str) -> None:
        manifest = {
            "run_id": self.args.run_id,
            "module": self.module,
            "phase": phase,
            "updated_at": now_iso(),
            "variant": self.args.variant,
            "duration_seconds": self.args.duration,
            "smoke": self.args.smoke,
            "resource": {
                "fuzz_cpuset": self.args.fuzz_cpuset,
                "validate_cpuset": self.args.validate_cpuset,
                "kimi_cpuset": self.args.kimi_cpuset,
                "fuzz_vm_count": self.args.fuzz_vm_count,
                "validate_vm_count": self.args.validate_vm_count,
                "vm_cpu": 2,
                "fuzz_vm_mem_mib": self.args.fuzz_vm_mem_mib,
                "validate_vm_mem_mib": self.args.validate_vm_mem_mib,
                "vm_running_time_seconds": self.args.vm_running_time_seconds,
                "qemu": {
                    "path": self.qemu_path,
                    "version": self.qemu_version,
                    "sha256": QEMU_SHA256,
                },
                "manager": {
                    "path": self.manager_path,
                    "sha256": self.manager_sha256,
                },
                "executor": {
                    "path": self.executor_path,
                    "sha256": self.executor_sha256,
                },
            },
            "initial_corpus": {
                "source": str(self.init_corpus),
                "copied": str(self.workdir / "corpus.db"),
                "sha256": self.module_spec["corpus_sha256"],
                "bytes": self.init_corpus.stat().st_size,
            },
            "module_metadata": {
                "syscalls": str(self.module_syscalls),
                "syscalls_sha256": self.module_spec["syscalls_sha256"],
                "syscall_count": self.module_spec["syscall_count"],
                "overrides": str(self.module_overrides),
                "overrides_sha256": self.module_spec["overrides_sha256"],
            },
            "frozen_artifacts": {
                str(path.relative_to(ROOT)): digest
                for path, digest in self.frozen_artifacts.items()
            },
            "configs": {
                "fuzz": str(getattr(self, "fuzz_cfg", "")),
                "validate": str(getattr(self, "validate_cfg", "")),
            },
            "threshold": self.threshold_manifest(),
            "validation": {
                "max_stacks_per_varname": self.args.max_stacks_per_varname,
                "max_concurrent_per_varname": self.args.max_concurrent_per_varname,
                "enable_threshold_aware_validation_priority": (
                    self.args.enable_threshold_aware_validation_priority
                ),
                "collection_threshold_floor_us": self.args.collection_threshold_floor_us,
                "enable_collection_miss_backoff": self.args.enable_collection_miss_backoff,
                "collection_miss_free_attempts": self.args.collection_miss_free_attempts,
                "collection_miss_weight": self.args.collection_miss_weight,
                "collection_miss_max_defer": self.args.collection_miss_max_defer,
                "max_pairs_per_task": 8,
                "max_tasks_per_corpus": self.args.max_tasks_per_corpus,
                "max_stable_pairs_per_entry": self.args.max_stable_pairs_per_entry,
                "max_stable_pairs_per_origin": self.args.max_stable_pairs_per_origin,
                "paper_strict_pg": self.args.paper_strict_pg,
                "collection_only": self.args.collection_only,
                "require_origin_match": self.args.require_origin_match,
                "origin_match_mode": self.args.origin_match_mode,
                "repeat_count": self.args.validation_repeat_count,
                "stable_pair_min_occurrences": self.args.stable_min_occurrences,
                "verify_repeat_times": self.args.verify_repeat_times,
                "validation_timeout_seconds": self.args.validation_timeout_seconds,
                "max_batch_timeout_seconds": self.args.max_batch_timeout_seconds,
                "executor_program_timeout_seconds": self.args.executor_program_timeout_seconds,
                "executor_syscall_timeout_millis": self.args.executor_syscall_timeout_ms,
                "verify_access_delay_min_us": self.args.verify_access_delay_min_us,
                "verify_access_delay_multiplier": self.args.verify_access_delay_multiplier,
                "verify_access_delay_normalize_to_threshold": self.args.verify_access_delay_normalize,
                "verify_access_delay_target_us": self.args.verify_access_delay_target_us,
                "verify_access_delay_max_us": self.args.verify_access_delay_max_us,
                "verify_stack_access_delay_us": self.args.verify_stack_access_delay_us,
                "verify_stack_access_delay_multiplier": self.args.verify_stack_access_delay_multiplier,
                "kernel_access_delay_multiplier": KERNEL_ACCESS_DELAY_MULTIPLIER,
                "effective_verify_access_delay_multiplier": (
                    self.args.verify_access_delay_multiplier * KERNEL_ACCESS_DELAY_MULTIPLIER
                ),
                "effective_verify_stack_access_delay_multiplier": (
                    self.args.verify_stack_access_delay_multiplier * KERNEL_ACCESS_DELAY_MULTIPLIER
                ),
                "effective_verify_access_delay_min_us": (
                    self.args.verify_access_delay_min_us * KERNEL_ACCESS_DELAY_MULTIPLIER
                ),
                "effective_verify_access_delay_target_us": (
                    self.args.verify_access_delay_target_us * KERNEL_ACCESS_DELAY_MULTIPLIER
                ),
                "effective_verify_access_delay_max_us": (
                    self.args.verify_access_delay_max_us * KERNEL_ACCESS_DELAY_MULTIPLIER
                ),
                "effective_verify_stack_access_delay_us": (
                    self.args.verify_stack_access_delay_us * KERNEL_ACCESS_DELAY_MULTIPLIER
                ),
            },
            "kimi": {
                "enabled": not self.args.skip_kimi,
                "provider": self.args.llm_provider,
                "model": self.llm_model(),
                "binary": self.llm_binary(),
                "codex_home": os.environ.get("CODEX_HOME", "") if self.args.llm_provider == "codex" else "",
                "codex_profile": self.args.codex_profile if self.args.llm_provider == "codex" else "",
                "codex_reasoning_effort": (
                    self.args.codex_reasoning_effort if self.args.llm_provider == "codex" else ""
                ),
                "grok_reasoning_effort": (
                    self.args.grok_reasoning_effort if self.args.llm_provider == "grok-cli" else ""
                ),
                "openai_base_url": self.args.openai_base_url if self.args.llm_provider == "openai-responses" else "",
                "openai_reasoning_effort": (
                    self.args.openai_reasoning_effort if self.args.llm_provider == "openai-responses" else ""
                ),
                "out": str(self.kimi_dir),
                "max_rounds": self.args.kimi_max_rounds,
                "entries_per_round": self.args.kimi_entries_per_round,
                "parallel_calls": self.args.kimi_parallel_calls,
            },
            "repo": repo_state(),
        }
        write_json(self.manifest_path, manifest)

    def write_state(self, status: str, detail: str = "") -> None:
        write_json(
            self.state_path,
            {
                "run_id": self.args.run_id,
                "module": self.module,
                "variant": self.args.variant,
                "status": status,
                "detail": detail,
                "updated_at": now_iso(),
                "run_dir": str(self.run_dir),
            },
        )

    def start_process(self, name: str, cmd: list[str], log_path: Path) -> subprocess.Popen[bytes]:
        handle = log_path.open("wb")
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.children.append((name, proc, handle))
        time.sleep(2)
        if proc.poll() is not None:
            handle.close()
            raise RuntimeError(f"{name} exited immediately rc={proc.returncode}; log={log_path}")
        return proc

    def stop_process(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=10)

    def stop_all(self) -> None:
        for _, proc, _ in reversed(self.children):
            self.stop_process(proc)
        for _, _, handle in self.children:
            try:
                handle.close()
            except OSError:
                pass

    def cleanup_disposable_vm_images(self) -> None:
        images = sorted(self.validate_workdir.glob("validate-vm-*.qcow2"))
        removed_bytes = 0
        removed = []
        for path in images:
            try:
                removed_bytes += path.stat().st_size
                removed.append(path.name)
                path.unlink()
            except FileNotFoundError:
                continue
        write_json(
            self.run_dir / "cleanup.json",
            {
                "timestamp": now_iso(),
                "removed_disposable_images": removed,
                "removed_bytes": removed_bytes,
            },
        )

    def guarded_wait(self, seconds: int, proc: subprocess.Popen[bytes], name: str) -> None:
        deadline = time.monotonic() + max(seconds, 0)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"{name} exited during startup rc={proc.returncode}")
            available = memory_available_gib()
            if available < self.args.abort_memory_gib:
                raise RuntimeError(
                    f"available memory {available:.2f} GiB below abort floor during {name} startup"
                )
            time.sleep(min(2, max(deadline - time.monotonic(), 0)))

    def process_cmds(self) -> tuple[list[str], list[str], list[str]]:
        fuzz_cmd = [
            "taskset", "-c", self.args.fuzz_cpuset,
            self.manager_path,
            "-config", str(self.fuzz_cfg),
            "-bench", str(self.bench_dir / "fuzz.json"),
        ]
        validate_cmd = [
            "taskset", "-c", self.args.validate_cpuset,
            self.manager_path,
            "-mode", "uaf-validate",
            "-config", str(self.validate_cfg),
            "-bench", str(self.bench_dir / "validate.json"),
        ]
        kimi_cmd = [
            "taskset", "-c", self.args.kimi_cpuset,
            sys.executable, "tools/llm-mutate-pilot/continuous.py",
            "--provider", self.args.llm_provider,
            "--api-key-alias", f"{self.args.llm_provider}-{self.module}-{self.args.variant}",
            "--config", str(self.fuzz_cfg),
            "--module", self.module,
            "--out", str(self.kimi_dir),
            "--entries-per-round", str(self.args.kimi_entries_per_round),
            "--variants-per-entry", "2",
            "--max-calls", "8",
            "--poll-sec", "30",
            "--parallel-calls", str(self.args.kimi_parallel_calls),
            "--timeout-sec", "600",
        ]
        if self.args.llm_provider == "codex":
            kimi_cmd += [
                "--codex-bin", self.args.codex_bin,
                "--codex-model", self.args.codex_model,
                "--codex-sandbox", "read-only",
                "--codex-reasoning-effort", self.args.codex_reasoning_effort,
            ]
            if self.args.codex_profile:
                kimi_cmd += ["--codex-profile", self.args.codex_profile]
        elif self.args.llm_provider == "grok-cli":
            kimi_cmd += [
                "--grok-cli-bin", self.args.grok_cli_bin,
                "--grok-cli-model", self.args.grok_cli_model,
                "--grok-reasoning-effort", self.args.grok_reasoning_effort,
            ]
        elif self.args.llm_provider == "openai-responses":
            kimi_cmd += [
                "--base-url", self.args.openai_base_url,
                "--model", self.args.openai_model,
                "--openai-auth-json", self.args.openai_auth_json,
                "--openai-reasoning-effort", self.args.openai_reasoning_effort,
            ]
        else:
            kimi_cmd += [
                "--kimi-cli-bin", self.args.kimi_cli_bin,
                "--kimi-cli-model", self.args.kimi_cli_model,
            ]
        if self.args.kimi_max_rounds > 0:
            kimi_cmd += ["--max-rounds", str(self.args.kimi_max_rounds)]
        return fuzz_cmd, validate_cmd, kimi_cmd

    def llm_model(self) -> str:
        if self.args.llm_provider == "codex":
            return self.args.codex_model
        if self.args.llm_provider == "grok-cli":
            return self.args.grok_cli_model
        if self.args.llm_provider == "openai-responses":
            return self.args.openai_model
        return self.args.kimi_cli_model

    def llm_binary(self) -> str:
        if self.args.llm_provider == "codex":
            return self.args.codex_bin
        if self.args.llm_provider == "grok-cli":
            return self.args.grok_cli_bin
        if self.args.llm_provider == "openai-responses":
            return "direct-http"
        return self.args.kimi_cli_bin

    def qemu_count(self, manager_pid: int) -> int:
        proc = subprocess.run(
            ["ps", "-eo", "ppid=,comm="],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        count = 0
        for line in proc.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            try:
                ppid = int(parts[0])
            except ValueError:
                continue
            if ppid == manager_pid and parts[1].startswith("qemu-system"):
                count += 1
        return count

    def threshold_state(self) -> dict[str, Any]:
        return read_json(self.workdir / "threshold-state.json")

    def kimi_state(self) -> dict[str, Any]:
        return read_json(self.kimi_dir / "state.json")

    def record_tick(
        self,
        elapsed: float,
        fuzz: subprocess.Popen[bytes],
        validate: subprocess.Popen[bytes],
        kimi: subprocess.Popen[bytes] | None,
    ) -> dict[str, Any]:
        fuzz_bench = base.pick_stats(base.latest_bench(self.bench_dir / "fuzz.json"))
        calls = fuzz_bench.get("calls executed")
        if isinstance(calls, int):
            if self.initial_calls is None:
                self.initial_calls = calls
            if self.last_calls is None or calls > self.last_calls:
                self.last_calls = calls
                self.last_calls_progress = time.monotonic()
        fuzz_qemu = self.qemu_count(fuzz.pid)
        validate_qemu = self.qemu_count(validate.pid)
        self.max_fuzz_qemu = max(self.max_fuzz_qemu, fuzz_qemu)
        self.max_validate_qemu = max(self.max_validate_qemu, validate_qemu)
        available = memory_available_gib()
        self.min_memory_gib = min(self.min_memory_gib, available)
        threshold = self.threshold_state()
        fuzzer_state = threshold.get("fuzzer") if isinstance(threshold.get("fuzzer"), dict) else {}
        validator_state = threshold.get("validator") if isinstance(threshold.get("validator"), dict) else {}
        units = {fuzzer_state.get("counter_unit"), validator_state.get("counter_unit")}
        if self.args.dynamic_threshold_counter_unit in units:
            self.seen_pair_unit = True
        tick = {
            "timestamp": now_iso(),
            "elapsed_seconds": round(elapsed, 3),
            "variant": self.args.variant,
            "processes": {
                "fuzz": {"pid": fuzz.pid, "rc": fuzz.poll(), "qemu": fuzz_qemu},
                "validate": {"pid": validate.pid, "rc": validate.poll(), "qemu": validate_qemu},
                "kimi": {"pid": kimi.pid if kimi else None, "rc": kimi.poll() if kimi else None},
            },
            "fuzz_bench": fuzz_bench,
            "threshold_state": threshold,
            "kimi_state": self.kimi_state(),
            "memory_available_gib": round(available, 3),
            "disk_free_gib": round(shutil.disk_usage(ROOT).free / (1024**3), 3),
        }
        append_jsonl(self.watcher_dir / "ticks.jsonl", tick)
        return tick

    def run(self) -> None:
        self.create_dirs()
        self.write_state("preflight")
        self.preflight()
        self.prepare()
        if self.args.prepare_only:
            self.write_state("prepared")
            return

        def handle_signal(signum: int, _frame: object) -> None:
            self.write_state("interrupted", f"signal={signum}")
            self.stop_all()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        fuzz_cmd, validate_cmd, kimi_cmd = self.process_cmds()
        write_json(
            self.run_dir / "commands.json",
            {"fuzz": fuzz_cmd, "validate": validate_cmd, "kimi": kimi_cmd},
        )
        fuzz = validate = None
        kimi: subprocess.Popen[bytes] | None = None
        started = time.monotonic()
        try:
            self.write_state("starting-fuzz")
            fuzz = self.start_process("fuzz", fuzz_cmd, self.log_dir / "fuzz.log")
            self.guarded_wait(self.args.validate_start_delay, fuzz, "fuzz")
            self.write_state("starting-validate")
            validate = self.start_process("validate", validate_cmd, self.log_dir / "validate.log")
            if not self.args.skip_kimi:
                self.guarded_wait(self.args.kimi_start_delay, validate, "validate")
                self.write_state("starting-kimi")
                kimi = self.start_process("kimi", kimi_cmd, self.log_dir / "kimi.log")
            self.write_manifest("running")
            self.write_state("running")

            next_tick = 0.0
            failure = ""
            while True:
                elapsed = time.monotonic() - started
                if self.args.duration > 0 and elapsed >= self.args.duration:
                    break
                if fuzz.poll() is not None:
                    failure = f"fuzz exited rc={fuzz.returncode}"
                    break
                if validate.poll() is not None:
                    failure = f"validate exited rc={validate.returncode}"
                    break
                if kimi is not None and kimi.poll() is not None and self.args.kimi_max_rounds == 0:
                    failure = f"kimi exited rc={kimi.returncode}"
                    break
                if elapsed >= next_tick:
                    tick = self.record_tick(elapsed, fuzz, validate, kimi)
                    next_tick = elapsed + self.args.watch_interval
                    available = float(tick["memory_available_gib"])
                    disk_free = float(tick["disk_free_gib"])
                    if available < self.args.abort_memory_gib:
                        failure = f"available memory {available:.2f} GiB below abort floor"
                        break
                    if disk_free < self.args.abort_disk_gib:
                        failure = f"disk free {disk_free:.2f} GiB below abort floor"
                        break
                    if (
                        elapsed > self.args.boot_grace
                        and self.last_calls is not None
                        and time.monotonic() - self.last_calls_progress > self.args.stall_timeout
                    ):
                        failure = f"calls executed stalled at {self.last_calls}"
                        break
                time.sleep(5)

            self.record_tick(time.monotonic() - started, fuzz, validate, kimi)
            if failure:
                self.write_state("failed", failure)
                raise RuntimeError(failure)
            self.write_state("stopping")
        finally:
            self.stop_all()

        final_calls = self.last_calls or 0
        initial_calls = self.initial_calls or 0
        health = {
            "status": "complete",
            "module": self.module,
            "variant": self.args.variant,
            "duration_seconds": round(time.monotonic() - started, 3),
            "calls_delta": final_calls - initial_calls,
            "max_fuzz_qemu": self.max_fuzz_qemu,
            "max_validate_qemu": self.max_validate_qemu,
            "min_memory_available_gib": round(self.min_memory_gib, 3),
            "counter_unit_observed": self.seen_pair_unit,
            "kimi_totals": self.kimi_state().get("totals", {}),
        }
        if self.args.smoke:
            failures = []
            if health["calls_delta"] <= 0:
                failures.append("calls did not increase")
            if self.max_fuzz_qemu < self.args.fuzz_vm_count:
                failures.append(f"fuzz QEMU peak {self.max_fuzz_qemu} < {self.args.fuzz_vm_count}")
            if self.max_validate_qemu < self.args.validate_vm_count:
                failures.append(
                    f"validate QEMU peak {self.max_validate_qemu} < {self.args.validate_vm_count}"
                )
            if self.args.variant != "fixed-1000" and not self.seen_pair_unit:
                failures.append("queue-pair-record counter unit not observed")
            health["smoke_failures"] = failures
            health["status"] = "pass" if not failures else "inconclusive"
        write_json(self.run_dir / "HEALTH.json", health)
        self.cleanup_disposable_vm_images()
        self.write_manifest("complete")
        self.write_state(str(health["status"]))
        if self.args.smoke and health["status"] != "pass":
            raise SystemExit("smoke inconclusive: " + "; ".join(health["smoke_failures"]))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--manager-bin", default=str(ROOT / "bin/syz-manager-canonical-family1"))
    parser.add_argument("--module", choices=tuple(MODULE_SPECS), default="ptmx")
    parser.add_argument("--variant", choices=("random", "dynamic", "fixed", "fixed-1000"), required=True)
    parser.add_argument("--duration", type=int, default=12 * 60 * 60,
                        help="run duration in seconds; 0 runs until interrupted")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--skip-kimi", action="store_true")
    parser.add_argument("--kimi-max-rounds", type=int, default=0)
    parser.add_argument("--kimi-entries-per-round", type=int, default=4)
    parser.add_argument("--kimi-parallel-calls", type=int, default=2)
    parser.add_argument("--dynamic-threshold-min-us", type=int, default=50)
    parser.add_argument("--dynamic-threshold-max-us", type=int, default=10000)
    parser.add_argument(
        "--dynamic-threshold-counter-unit",
        choices=("queue-pair-record", "queue-varname-family"),
        default="queue-pair-record",
    )
    parser.add_argument("--fixed-threshold-us", type=int, default=1000)
    parser.add_argument("--validation-repeat-count", type=int, default=1)
    parser.add_argument("--stable-min-occurrences", type=int, default=0)
    parser.add_argument("--verify-repeat-times", type=int, default=1)
    parser.add_argument("--validation-timeout-seconds", type=int, default=120)
    parser.add_argument("--max-batch-timeout-seconds", type=int, default=600)
    parser.add_argument("--executor-program-timeout-seconds", type=int, default=0)
    parser.add_argument("--executor-syscall-timeout-ms", type=int, default=100)
    parser.add_argument("--verify-access-delay-min-us", type=int, default=0)
    parser.add_argument("--verify-access-delay-multiplier", type=int, default=0)
    parser.add_argument("--verify-access-delay-normalize", action="store_true")
    parser.add_argument("--verify-access-delay-target-us", type=int, default=0)
    parser.add_argument("--verify-access-delay-max-us", type=int, default=0)
    parser.add_argument("--verify-stack-access-delay-us", type=int, default=0)
    parser.add_argument("--verify-stack-access-delay-multiplier", type=int, default=0)
    parser.add_argument("--max-tasks-per-corpus", type=int, default=0)
    parser.add_argument("--max-stacks-per-varname", type=int, default=10)
    parser.add_argument("--max-concurrent-per-varname", type=int, default=1)
    parser.add_argument("--enable-threshold-aware-validation-priority", action="store_true")
    parser.add_argument("--collection-threshold-floor-us", type=int, default=0)
    parser.add_argument("--enable-collection-miss-backoff", action="store_true")
    parser.add_argument("--collection-miss-free-attempts", type=int, default=2)
    parser.add_argument("--collection-miss-weight", type=float, default=0.25)
    parser.add_argument("--collection-miss-max-defer", type=float, default=0.75)
    parser.add_argument("--max-stable-pairs-per-entry", type=int, default=16)
    parser.add_argument("--max-stable-pairs-per-origin", type=int, default=1)
    parser.add_argument("--paper-strict-pg", action="store_true")
    parser.add_argument("--collection-only", action="store_true")
    parser.add_argument("--require-origin-match", action="store_true")
    parser.add_argument(
        "--origin-match-mode",
        choices=("exact", "varname", "primary-varname"),
        default="varname",
    )
    parser.add_argument("--fuzz-cpuset", default="0-3")
    parser.add_argument("--validate-cpuset", default="4-7")
    parser.add_argument("--kimi-cpuset", default="8-9")
    parser.add_argument("--http-base-port", type=int, default=64700)
    parser.add_argument("--fuzz-vm-count", type=int, default=4)
    parser.add_argument("--validate-vm-count", type=int, default=4)
    parser.add_argument("--fuzz-vm-mem-mib", type=int, default=1024)
    parser.add_argument("--validate-vm-mem-mib", type=int, default=1024)
    parser.add_argument("--vm-running-time-seconds", type=int, default=3600)
    parser.add_argument("--allow-existing-experiments", action="store_true")
    parser.add_argument("--validate-start-delay", type=int, default=30)
    parser.add_argument("--kimi-start-delay", type=int, default=30)
    parser.add_argument("--watch-interval", type=int, default=30)
    parser.add_argument("--boot-grace", type=int, default=300)
    parser.add_argument("--stall-timeout", type=int, default=240)
    parser.add_argument("--min-start-memory-gib", type=float, default=45.0)
    parser.add_argument("--abort-memory-gib", type=float, default=8.0)
    parser.add_argument("--min-start-disk-gib", type=float, default=50.0)
    parser.add_argument("--abort-disk-gib", type=float, default=25.0)
    parser.add_argument("--llm-provider", choices=("kimi-cli", "codex", "grok-cli", "openai-responses"), default="kimi-cli")
    parser.add_argument("--kimi-cli-bin", default="/home/zzzccc/.kimi-code/bin/kimi")
    parser.add_argument("--kimi-cli-model", default="my-kimi-code/k3")
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("--codex-model", default="gpt-5.4")
    parser.add_argument("--codex-profile", default="")
    parser.add_argument(
        "--codex-reasoning-effort",
        choices=("low", "medium", "high", "xhigh"),
        default="low",
    )
    parser.add_argument("--grok-cli-bin", default="/home/zzzccc/.grok/bin/grok")
    parser.add_argument("--grok-cli-model", default="grok-4.5")
    parser.add_argument(
        "--grok-reasoning-effort",
        choices=("low", "medium", "high"),
        default="low",
    )
    parser.add_argument("--openai-base-url", default="https://api.openai.com/v1")
    parser.add_argument("--openai-model", default="gpt-5.4")
    parser.add_argument("--openai-auth-json", default="")
    parser.add_argument(
        "--openai-reasoning-effort",
        choices=("none", "low", "medium", "high", "xhigh"),
        default="medium",
    )
    args = parser.parse_args()
    if args.duration < 0:
        parser.error("--duration must be non-negative")
    if args.kimi_entries_per_round <= 0:
        parser.error("--kimi-entries-per-round must be positive")
    if args.kimi_parallel_calls <= 0:
        parser.error("--kimi-parallel-calls must be positive")
    if args.dynamic_threshold_min_us <= 0 or args.dynamic_threshold_min_us > 10000:
        parser.error("--dynamic-threshold-min-us must be in [1, 10000]")
    if args.dynamic_threshold_max_us < args.dynamic_threshold_min_us:
        parser.error("--dynamic-threshold-max-us must be >= --dynamic-threshold-min-us")
    if args.paper_strict_pg:
        if args.collection_threshold_floor_us not in (0, args.dynamic_threshold_max_us):
            parser.error("--paper-strict-pg requires collection threshold tau_max")
        args.collection_threshold_floor_us = args.dynamic_threshold_max_us
        args.require_origin_match = True
        args.origin_match_mode = "exact"
        args.max_stable_pairs_per_origin = 1
    if args.fixed_threshold_us <= 0:
        parser.error("--fixed-threshold-us must be positive")
    if args.validation_repeat_count <= 0:
        parser.error("--validation-repeat-count must be positive")
    if args.stable_min_occurrences < 0 or args.stable_min_occurrences > args.validation_repeat_count:
        parser.error("--stable-min-occurrences must be in [0, validation-repeat-count]")
    if args.verify_repeat_times <= 0 or args.executor_syscall_timeout_ms <= 0:
        parser.error("verify repeat and syscall timeout must be positive")
    if args.validation_timeout_seconds <= 0 or args.max_batch_timeout_seconds <= 0:
        parser.error("validation and batch timeouts must be positive")
    if args.executor_program_timeout_seconds < 0:
        parser.error("--executor-program-timeout-seconds must be non-negative")
    if args.max_stacks_per_varname <= 0:
        parser.error("--max-stacks-per-varname must be positive")
    if args.max_concurrent_per_varname < 0:
        parser.error("--max-concurrent-per-varname must be non-negative")
    if args.collection_miss_free_attempts <= 0:
        parser.error("--collection-miss-free-attempts must be positive")
    if args.collection_miss_weight <= 0:
        parser.error("--collection-miss-weight must be positive")
    if not 0 < args.collection_miss_max_defer < 1:
        parser.error("--collection-miss-max-defer must be in (0, 1)")
    if args.collection_threshold_floor_us < 0:
        parser.error("--collection-threshold-floor-us must be non-negative")
    for value in (
        args.verify_access_delay_min_us,
        args.verify_access_delay_multiplier,
        args.verify_access_delay_target_us,
        args.verify_access_delay_max_us,
        args.verify_stack_access_delay_us,
        args.verify_stack_access_delay_multiplier,
    ):
        if value < 0:
            parser.error("verification delay values must be non-negative")
    if args.verify_access_delay_normalize and args.verify_access_delay_target_us == 0:
        parser.error("--verify-access-delay-target-us must be positive with normalization")
    if args.verify_access_delay_normalize and args.verify_access_delay_multiplier > 0:
        parser.error("threshold normalization and fixed access-delay multiplier are mutually exclusive")
    if args.verify_stack_access_delay_us > 0 and args.verify_stack_access_delay_multiplier > 0:
        parser.error("fixed stack delay and stack access-delay multiplier are mutually exclusive")
    if args.max_tasks_per_corpus < 0:
        parser.error("--max-tasks-per-corpus must be non-negative")
    if args.max_stable_pairs_per_entry < 0:
        parser.error("--max-stable-pairs-per-entry must be non-negative")
    if args.max_stable_pairs_per_origin < 0:
        parser.error("--max-stable-pairs-per-origin must be non-negative")
    if args.fuzz_vm_count <= 0 or args.validate_vm_count <= 0:
        parser.error("VM counts must be positive")
    if args.vm_running_time_seconds <= 0:
        parser.error("--vm-running-time-seconds must be positive")
    if args.fuzz_vm_mem_mib <= 0 or args.validate_vm_mem_mib <= 0:
        parser.error("VM memory values must be positive")
    return args


def main() -> int:
    runner = VariantRunner(parse_args())
    try:
        runner.run()
    except Exception as exc:
        runner.write_state("failed", str(exc))
        runner.stop_all()
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
