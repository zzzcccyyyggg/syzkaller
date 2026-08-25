#!/usr/bin/env python3
"""Run one complete MRPFuzz PTMX threshold-policy pilot variant."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
from pathlib import Path


ROOT = Path("/home/zzzccc/BASS/DDRD-syzkaller")
CLAIM_ROOT = ROOT / "paper/artifacts/claims/added-threshold-control"
BASE_RUNNER = ROOT / "paper/artifacts/claims/added-throughput/run_phase2b_complete.py"
KIMI_SEEDS = (
    ROOT
    / "paper/results/llm-mutate-continuous"
    / "ptmx-llm-helper-kimi26-thinking-randrewrite-dev4-fixenv-20260521-1032"
)


def load_base_runner():
    spec = importlib.util.spec_from_file_location("throughput_runner", BASE_RUNNER)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load base runner: {BASE_RUNNER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ARTIFACT_ROOT = CLAIM_ROOT
    return module


base = load_base_runner()


class ThresholdVariantRunner(base.Runner):
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

    def preflight(self) -> None:
        required = [
            base.PTMX_CORPUS,
            ROOT / "images/bookworm.img",
            ROOT / "images/bookworm.id_rsa",
            ROOT / "bin/syz-manager",
            base.MRPFUZZ_BINARY_OUTPUT / "ptmx/bzImage",
            base.MRPFUZZ_BINARY_OUTPUT / "ptmx/vmlinux",
            KIMI_SEEDS / "accepted",
        ]
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise SystemExit("missing required files:\n" + "\n".join(missing))
        free_gb = shutil.disk_usage(ROOT).free / (1024**3)
        if free_gb < self.args.min_free_gb:
            raise SystemExit(
                f"free disk too low: {free_gb:.1f} GiB < {self.args.min_free_gb} GiB"
            )

    def write_metadata(self, phase: str) -> None:
        super().write_metadata(phase)
        path = self.run_dir / "metadata.json"
        metadata = json.loads(path.read_text())
        metadata.update(
            {
                "experiment": "added-threshold-control-ptmx-pilot",
                "threshold_variant": self.args.threshold_variant,
                "fixed_threshold_us": self.args.fixed_threshold_us,
                "llm_seed_source": str(KIMI_SEEDS),
                "llm_seed_poll_sec": self.args.llm_seed_poll_sec,
                "llm_seed_max_per_poll": self.args.llm_seed_max_per_poll,
                "max_stable_pairs_per_entry": self.args.max_stable_pairs_per_entry,
                "max_stable_pairs_per_origin": self.args.max_stable_pairs_per_origin,
                "http_base_port": self.args.http_base_port,
                "evidence_class": "pilot-not-paper-grade",
            }
        )
        base.write_json(path, metadata)

    def prepare_mrpfuzz_complete(self) -> None:
        super().prepare_mrpfuzz_complete()
        fuzz = self.mrpfuzz["fuzz"]
        validate = self.mrpfuzz["validate"]

        fuzz_cfg = json.loads(fuzz["config"].read_text())
        validate_cfg = json.loads(validate["config"].read_text())
        fuzz_cfg["http"] = f"127.0.0.1:{self.args.http_base_port + 1}"
        validate_cfg["http"] = f"127.0.0.1:{self.args.http_base_port + 2}"

        exp = fuzz_cfg.setdefault("experimental", {})
        exp["llm_input_seed_dir"] = str(KIMI_SEEDS)
        exp["llm_input_seed_poll_sec"] = self.args.llm_seed_poll_sec
        exp["llm_input_seed_max_per_poll"] = self.args.llm_seed_max_per_poll
        exp["static_input_exploration"] = True
        exp["static_input_seed"] = 1592594996
        exp["static_input_skip_builtin_seeds"] = True
        exp["enable_timing_exploration"] = False
        exp["enable_solo_filter"] = False

        if self.args.threshold_variant in ("dynamic", "random"):
            exp["enable_dynamic_threshold"] = True
            exp["dynamic_threshold_policy"] = (
                "backpressure" if self.args.threshold_variant == "dynamic" else "random"
            )
            exp["dynamic_threshold_random_seed"] = self.args.random_threshold_seed
            exp["normal_threshold_micros"] = 1000
            exp["dynamic_threshold_initial_us"] = 1000
            exp["dynamic_threshold_min_us"] = 50
            exp["dynamic_threshold_max_us"] = 10000
            exp["dynamic_threshold_eval_sec"] = 30
        else:
            threshold = self.args.fixed_threshold_us
            exp["enable_dynamic_threshold"] = False
            exp["normal_threshold_micros"] = threshold
            exp["dynamic_threshold_initial_us"] = threshold
            exp["dynamic_threshold_min_us"] = threshold
            exp["dynamic_threshold_max_us"] = threshold

        validate_settings = validate_cfg.setdefault("experimental", {}).setdefault(
            "uaf_validate", {}
        )
        validate_settings["max_stable_pairs_per_entry"] = self.args.max_stable_pairs_per_entry
        validate_settings["max_stable_pairs_per_origin"] = self.args.max_stable_pairs_per_origin

        base.write_json(fuzz["config"], fuzz_cfg)
        base.write_json(validate["config"], validate_cfg)
        base.write_json(
            self.run_dir / "threshold-policy.json",
            {
                "variant": self.args.threshold_variant,
                "fixed_threshold_us": self.args.fixed_threshold_us,
                "threshold_policy": (
                    "fixed"
                    if self.args.threshold_variant == "fixed"
                    else ("backpressure" if self.args.threshold_variant == "dynamic" else "random")
                ),
                "random_distribution": "log-uniform",
                "random_seed": self.args.random_threshold_seed,
                "dynamic_initial_us": 1000,
                "dynamic_min_us": 50,
                "dynamic_max_us": 10000,
                "dynamic_eval_sec": 30,
                "llm_seed_source": str(KIMI_SEEDS),
                "llm_seed_poll_sec": self.args.llm_seed_poll_sec,
                "llm_seed_max_per_poll": self.args.llm_seed_max_per_poll,
                "max_stable_pairs_per_entry": self.args.max_stable_pairs_per_entry,
                "max_stable_pairs_per_origin": self.args.max_stable_pairs_per_origin,
            },
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--threshold-variant",
        choices=["dynamic", "random", "fixed"],
        required=True,
    )
    parser.add_argument("--fixed-threshold-us", type=int, default=0)
    parser.add_argument("--random-threshold-seed", type=int, default=1592594996)
    parser.add_argument("--duration", type=int, default=1800)
    parser.add_argument("--fuzz-cpuset", required=True)
    parser.add_argument("--validate-cpuset", required=True)
    parser.add_argument("--http-base-port", type=int, required=True)
    parser.add_argument("--validate-start-delay", type=int, default=30)
    parser.add_argument("--llm-seed-poll-sec", type=int, default=10)
    parser.add_argument("--llm-seed-max-per-poll", type=int, default=12)
    parser.add_argument("--max-stable-pairs-per-entry", type=int, default=0)
    parser.add_argument("--max-stable-pairs-per-origin", type=int, default=0)
    args = parser.parse_args()
    if args.threshold_variant == "fixed" and args.fixed_threshold_us <= 0:
        parser.error("--fixed-threshold-us must be positive for fixed variants")
    if args.llm_seed_poll_sec <= 0 or args.llm_seed_max_per_poll <= 0:
        parser.error("LLM seed poll interval and batch size must be positive")
    if args.max_stable_pairs_per_entry < 0 or args.max_stable_pairs_per_origin < 0:
        parser.error("stable-pair caps must be non-negative")

    args.case = "mrpfuzz"
    args.warmup = 120
    args.mrpfuzz_cpuset = f"{args.fuzz_cpuset},{args.validate_cpuset}"
    args.mrpfuzz_fuzz_cpuset = args.fuzz_cpuset
    args.mrpfuzz_validate_cpuset = args.validate_cpuset
    args.mrpfuzz_fuzz_vm_count = 1
    args.mrpfuzz_fuzz_vm_cpu = 2
    args.mrpfuzz_fuzz_procs = 2
    args.mrpfuzz_max_pairs_per_task = 8
    args.mrpfuzz_race_normal_triage_interval = 8
    args.mrpfuzz_race_normal_triage_max_jobs = 8
    args.mrpfuzz_race_candidate_triage_max_jobs = 64
    args.mrpfuzz_disable_normal_triage = True
    args.mrpfuzz_seed_workdir = ""
    args.stall_timeout = 240
    args.min_free_gb = 20.0
    args.build = False
    args.segfuzz_cpuset = ""
    args.segfuzz_vm_cpu = 1
    args.segfuzz_procs = 1
    return args


def main() -> None:
    ThresholdVariantRunner(parse_args()).run()


if __name__ == "__main__":
    main()
