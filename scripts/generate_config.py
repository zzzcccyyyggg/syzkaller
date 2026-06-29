#!/usr/bin/env python3
"""
generate_config.py — 为指定模块生成 fuzz.cfg 和 validate.cfg

用法:
    python3 scripts/generate_config.py [选项] [module1 module2 ...]
    python3 scripts/generate_config.py xfs btrfs
    python3 scripts/generate_config.py --all
    python3 scripts/generate_config.py --list
    python3 scripts/generate_config.py --validate-only xfs
    python3 scripts/generate_config.py --vanilla-only xfs

Ablation 变体 (直接生成可用于敏感度实验的配置):
    python3 scripts/generate_config.py --ablation fuzz-no-timing xfs btrfs ptmx dsp
    python3 scripts/generate_config.py --ablation fuzz-no-objlink xfs btrfs ptmx dsp
    python3 scripts/generate_config.py --throughput-only xfs btrfs ptmx dsp
    python3 scripts/generate_config.py --ablation validate-no-delay xfs btrfs ptmx dsp
    python3 scripts/generate_config.py --ablation validate-no-replay xfs btrfs ptmx dsp
    python3 scripts/generate_config.py --ablation validate-no-backoff xfs btrfs ptmx dsp

配置生成到:
    默认:      exp/<slug>/fuzz.cfg / validate.cfg
    纯净版:    exp/<slug>/fuzz-vanilla.cfg / validate-vanilla.cfg
    Ablation:  exp/<slug>/fuzz-<variant>.cfg / validate-<variant>.cfg
"""
import argparse
import json
import os
import sys


def deep_merge_dict(base: dict, override: dict) -> dict:
    """Recursively merge override into base and return a new dict."""
    merged = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_HOME = os.path.dirname(SCRIPT_DIR)
EXP_DIR = os.path.join(PROJECT_HOME, "exp")
KERNEL_OUTPUT = os.path.join(PROJECT_HOME, "kernels", "output")
KERNEL_IMAGES = os.path.join(PROJECT_HOME, "images")

# ---------------------------------------------------------------------------
# 默认值 (可被 overrides.json 覆盖)
# ---------------------------------------------------------------------------
DEFAULTS = {
    "target": "linux/amd64",
    "syzkaller": PROJECT_HOME,
    "procs": 2,
    "type": "qemu",
    "reproduce": False,
    "vm_running_time": 6000,
    "ignore_warning_crashes": True,
    "vm_count": 2,
    "vm_cpu": 2,
    "vm_mem": 4096,
    "cmdline": "net.ifnames=0",
}

# HTTP 端口分配 (每个模块固定端口, 避免冲突)
PORT_MAP = {
    "xfs": 62001,
    "btrfs": 62002,
    "f2fs": 62003,
    "jfs": 62004,
    "floppy": 62005,
    "ptmx": 62006,
    "video": 62007,
    "wifi": 62008,
    "dsp": 62009,
    "usb-driver": 62010,
    "bt-stack": 62011,
    "ext4": 62012,
    "overlayfs": 62013,
    "ocfs2": 62014,
}

# Validate 端口 = fuzz 端口 + 100
VALIDATE_PORT_OFFSET = 100

# ---------------------------------------------------------------------------
# Fuzz 模式的 experimental 默认配置
# ---------------------------------------------------------------------------
FUZZ_EXPERIMENTAL = {
    "uaf_mode": True,
    "disable_uaf_validate_queue": False,
    "barrier_mode": True,
    "barrier_procs": [0, 1],
    "history_buffer_size": 100,
    "new_varname_pair_history": 100,
    "new_stack_history": 10,
    "max_stacks_per_varname_pair": 100,
    "normal_threshold_micros": 10000,
    "enable_timing_exploration": False,
    "enable_solo_filter": False,
    "enable_coverage_triage": False,
    "enable_affinity_table": False,
    "timing_exploration_queue_size": 500,
    "timing_exploration_ratio": 0.1,
    "delay_min_micros": 10,
    "delay_max_micros": 200000,
    "max_delays_per_program": 5,
    "timing_mutation_strategy": "timediff",
    "widened_threshold_micros": 20000,
    "max_attempts_per_pair": 20,
    "success_threshold": 0.1,
    "executions_per_attempt": 5,
    "enable_dynamic_threshold": True,
    "dynamic_threshold_initial_us": 2500,
    "dynamic_threshold_min_us": 500,
    "dynamic_threshold_max_us": 10000,
    "dynamic_threshold_eval_sec": 30,
}

# ---------------------------------------------------------------------------
# Validate 模式的 experimental 默认配置
# ---------------------------------------------------------------------------
VALIDATE_EXPERIMENTAL = {
    "skip_duplicate_data_races": True,
    "barrier_mode": True,
    "barrier_procs": [0, 1],
    "uaf_mode": True,
    "history_buffer_size": 100,
    "new_varname_pair_history": 100,
    "new_stack_history": 10,
    "max_stacks_per_varname_pair": 10000,
    "cooldown_threshold": 20,
    "new_stack_penalty": 1,
    "no_discovery_penalty": 2,
    "uaf_validate": {
        "max_concurrent": 6,
        "delay_retry_budget": 1,
        "timeout_seconds": 120,
        "max_batch_timeout_seconds": 600,
        "repeat_count": 1,
        "disable_async_split": True,
        "enable_vm_snapshot": True,
        "verify_repeat_times": 1,
        "executor_syscall_timeout_millis": 100,
        "continuous_mode": False,
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
        "disable_collection_delay": True,
        "require_origin_match": False,
        "replay_collect_pairs": False,
        "verify_delay_sweep": False,
        "verify_delay_steps": 10,
        "verify_delay_max_us": 250,
        "verify_delay_power": 2.0,
        "enable_history_minimization": True,
        "minimization_max_attempts": 3,
        "minimization_strategy": "binary",
    },
    "ddrd_monitor": False,
}


def load_module_data(slug: str):
    """加载模块的 syscalls 和 overrides"""
    mod_dir = os.path.join(EXP_DIR, slug)
    if not os.path.isdir(mod_dir):
        print(f"ERROR: 模块目录不存在: {mod_dir}", file=sys.stderr)
        print(f"       请先运行: python3 scripts/extract_module_data.py", file=sys.stderr)
        sys.exit(1)

    # syscalls
    sc_path = os.path.join(mod_dir, "syscalls.txt")
    syscalls = []
    if os.path.exists(sc_path):
        with open(sc_path) as f:
            syscalls = [line.strip() for line in f if line.strip()]

    # overrides
    ov_path = os.path.join(mod_dir, "overrides.json")
    overrides = {}
    if os.path.exists(ov_path):
        with open(ov_path) as f:
            overrides = json.load(f)

    return syscalls, overrides


def build_image_path():
    """查找主磁盘镜像"""
    for name in ["bookworm.img", "bullseye.img"]:
        p = os.path.join(KERNEL_IMAGES, name)
        if os.path.exists(p):
            return p
    # fallback to old location
    old = os.path.join(PROJECT_HOME, "test", "fs", "bookworm.img")
    if os.path.exists(old):
        return old
    return os.path.join(KERNEL_IMAGES, "bookworm.img")


def build_sshkey_path():
    """查找 SSH key"""
    for name in ["bookworm.id_rsa", "bullseye.id_rsa"]:
        p = os.path.join(KERNEL_IMAGES, name)
        if os.path.exists(p):
            return p
    old = os.path.join(PROJECT_HOME, "test", "fs", "bookworm.id_rsa")
    if os.path.exists(old):
        return old
    return os.path.join(KERNEL_IMAGES, "bookworm.id_rsa")


def generate_config(slug: str, mode: str = "fuzz", include_experimental: bool = True) -> dict:
    """
    生成配置字典
    mode: "fuzz" | "validate"
    """
    syscalls, overrides = load_module_data(slug)
    mode_overrides = overrides.get(mode, {})
    base_overrides = {k: v for k, v in overrides.items() if k not in ("fuzz", "validate")}
    effective_overrides = deep_merge_dict(base_overrides, mode_overrides)

    artifact_name = effective_overrides.get("artifact_name", slug)

    is_validate = (mode == "validate")
    port_base = PORT_MAP.get(slug, 62099)
    port = port_base + VALIDATE_PORT_OFFSET if is_validate else port_base

    workdir = os.path.join(EXP_DIR, slug, "workdir")

    # 内核路径: 优先从 kernels/output/<slug>/ 取, 否则回退到 DDRD_KERNEL_SRC
    output_dir = os.path.join(KERNEL_OUTPUT, artifact_name)
    vmlinux = os.path.join(output_dir, "vmlinux")
    bzimage = os.path.join(output_dir, "bzImage")

    # 如果 output 目录不存在, 回退到旧路径
    if not os.path.exists(vmlinux):
        kernel_src = os.environ.get("DDRD_KERNEL_SRC", "/home/zzzccc/Linux-Kernel/DDRD-Kernel")
        alt_vmlinux = os.path.join(kernel_src, f"vmlinux-{artifact_name}")
        alt_bzimage = os.path.join(kernel_src, f"arch/x86/boot/bzImage-{artifact_name}")
        if os.path.exists(alt_vmlinux):
            vmlinux = alt_vmlinux
            bzimage = alt_bzimage
            output_dir = kernel_src

    kernel_obj = output_dir

    # kernel_obj 优先使用 builds/ 中的完整构建目录 (含 .o 文件, 符号解析更准确)
    # isolated 模式: builds/<slug>/, shared 模式: builds/x86/
    kernel_builds = os.path.join(PROJECT_HOME, "kernels", "builds")
    isolated_build = os.path.join(kernel_builds, artifact_name)
    shared_build = os.path.join(kernel_builds, "x86")
    if os.path.isdir(isolated_build) and os.path.exists(os.path.join(isolated_build, "vmlinux")):
        kernel_obj = isolated_build
    elif os.path.isdir(shared_build):
        kernel_obj = shared_build

    # QEMU extra args
    qemu_args = effective_overrides.get("qemu_args", "")
    if not qemu_args:
        qemu_args = "-enable-kvm"
    elif "-enable-kvm" not in qemu_args:
        qemu_args = f"-enable-kvm {qemu_args}"

    # 将旧的 test/fs/ 路径替换为新的 images/ 路径
    old_fs_dir = os.path.join(PROJECT_HOME, "test", "fs")
    if old_fs_dir in qemu_args:
        qemu_args = qemu_args.replace(old_fs_dir, KERNEL_IMAGES)

    # VM 资源 (validate 模式可以用更多资源)
    vm_count = effective_overrides.get("vm_count", DEFAULTS["vm_count"])
    vm_cpu = effective_overrides.get("vm_cpu", DEFAULTS["vm_cpu"])
    vm_mem = effective_overrides.get("vm_mem", DEFAULTS["vm_mem"])
    procs = effective_overrides.get("procs", DEFAULTS["procs"])
    vm_running_time = effective_overrides.get("vm_running_time", DEFAULTS["vm_running_time"])

    if is_validate:
        vm_running_time = 600  # validate 通常短一些

    config = {
        "target": DEFAULTS["target"],
        "http": f"127.0.0.1:{port}",
        "workdir": workdir,
        "kernel_obj": kernel_obj,
        "image": build_image_path(),
        "sshkey": build_sshkey_path(),
        "syzkaller": DEFAULTS["syzkaller"],
        "procs": procs,
        "type": DEFAULTS["type"],
        "reproduce": DEFAULTS["reproduce"],
        "vm_running_time": vm_running_time,
        "vmlinux": vmlinux,
        "ignore_warning_crashes": DEFAULTS["ignore_warning_crashes"],
        "vm": {
            "count": vm_count,
            "kernel": bzimage,
            "cpu": vm_cpu,
            "mem": vm_mem,
            "cmdline": DEFAULTS["cmdline"],
            "qemu_args": qemu_args,
        },
        "enable_syscalls": syscalls,
    }

    # 纯净配置: 去掉 fork 扩展字段, 保留上游 syzkaller 可识别项
    if not include_experimental:
        config.pop("vm_running_time", None)
        config.pop("ignore_warning_crashes", None)

    # experimental section
    if include_experimental:
        common_exp = base_overrides.get("experimental", {})
        mode_exp = mode_overrides.get("experimental", {})
        if is_validate:
            config["experimental"] = deep_merge_dict(VALIDATE_EXPERIMENTAL, mode_exp)
        else:
            # 使用默认 fuzz experimental，并允许模块 overrides 做增量覆盖。
            mod_exp = deep_merge_dict(common_exp, mode_exp)
            config["experimental"] = deep_merge_dict(FUZZ_EXPERIMENTAL, mod_exp)

    return config


# ---------------------------------------------------------------------------
# Ablation variant definitions
# ---------------------------------------------------------------------------
# Each variant specifies: (suffix, mode, experimental_overrides)
ABLATION_VARIANTS = {
    # --- Fuzz-side ablations ---
    "fuzz-no-timing": {
        "description": "Disable timing exploration (pair-guided delay mutation)",
        "mode": "fuzz",
        "suffix": "-no-timing",
        "overrides": {
            "enable_timing_exploration": False,
        },
    },
    "fuzz-no-objlink": {
        "description": "Disable resource-aware object linking (ObjectLinker V2)",
        "mode": "fuzz",
        "suffix": "-no-objlink",
        "overrides": {
            "enable_object_linking": False,
        },
    },
    "fuzz-random": {
        "description": "Baseline run with timing exploration disabled",
        "mode": "fuzz",
        "suffix": "-random",
        "overrides": {
            "random_baseline_mode": True,
            "enable_timing_exploration": False,
        },
    },
    "fuzz-throughput": {
        "description": "Fuzzing throughput comparison with validation and legacy exploration queues disabled",
        "mode": "fuzz",
        "suffix": "-throughput",
        "overrides": {
            "disable_uaf_validate_queue": True,
            "enable_timing_exploration": False,
            "enable_solo_filter": False,
            "enable_coverage_triage": False,
            "enable_affinity_table": False,
        },
    },
    # --- Validate-side ablations ---
    "validate-site-only": {
        "description": "Use site-only target matching without SN/TID constraints",
        "mode": "validate",
        "suffix": "-site-only",
        "overrides": {
            "uaf_validate": {
                "target_match_mode": "site-only",
            },
        },
    },
    "validate-strict-sn": {
        "description": "Require strict SN/TID target matching without site-only fallback",
        "mode": "validate",
        "suffix": "-strict-sn",
        "overrides": {
            "uaf_validate": {
                "target_match_mode": "strict-sn",
            },
        },
    },
    "validate-no-delay": {
        "description": "Disable directed delay scheduling",
        "mode": "validate",
        "suffix": "-no-delay",
        "overrides": {
            "uaf_validate": {
                "disable_verify_delay": True,
                "disable_access_delay": True,
            },
        },
    },
    "validate-no-replay": {
        "description": "Disable state replay/restoration",
        "mode": "validate",
        "suffix": "-no-replay",
        "overrides": {
            "uaf_validate": {
                "enable_replay": False,
            },
        },
    },
    "validate-no-backoff": {
        "description": "Disable adaptive validation backoff",
        "mode": "validate",
        "suffix": "-no-backoff",
        "overrides": {
            "uaf_validate": {
                "continue_after_backoff": False,
                "enable_varname_scheduling": False,
            },
        },
    },
}


def apply_ablation_overrides(config: dict, variant_name: str) -> dict:
    """Apply ablation overrides to a generated config."""
    variant = ABLATION_VARIANTS[variant_name]
    overrides = variant["overrides"]

    if "experimental" not in config:
        return config

    exp = config["experimental"]

    for key, value in overrides.items():
        if key == "uaf_validate" and isinstance(value, dict):
            # Merge into uaf_validate sub-dict
            if "uaf_validate" not in exp:
                exp["uaf_validate"] = {}
            for vk, vv in value.items():
                exp["uaf_validate"][vk] = vv
        else:
            exp[key] = value

    return config


def list_available_modules():
    """列出 exp/ 下有 syscalls.txt 的模块"""
    modules = []
    if os.path.isdir(EXP_DIR):
        for d in sorted(os.listdir(EXP_DIR)):
            if os.path.exists(os.path.join(EXP_DIR, d, "syscalls.txt")):
                modules.append(d)
    return modules


def main():
    parser = argparse.ArgumentParser(description="DDRD 配置文件生成器")
    parser.add_argument("modules", nargs="*", help="要生成配置的模块 slug")
    parser.add_argument("--all", action="store_true", help="生成所有模块")
    parser.add_argument("--list", action="store_true", help="列出可用模块")
    parser.add_argument("--fuzz-only", action="store_true", help="仅生成 fuzz 配置")
    parser.add_argument("--validate-only", action="store_true", help="仅生成 validate 配置")
    parser.add_argument("--throughput-only", action="store_true",
                        help="生成 throughput 对比用 fuzz-throughput.cfg")
    parser.add_argument("--vanilla", action="store_true", help="额外生成纯净配置(不含 experimental), 文件名为 *-vanilla.cfg")
    parser.add_argument("--vanilla-only", action="store_true", help="仅生成纯净配置(不含 experimental)")
    parser.add_argument("--ablation", type=str, metavar="VARIANT",
                        help=f"生成 ablation 变体配置. 可选: {', '.join(sorted(ABLATION_VARIANTS.keys()))}")
    parser.add_argument("--list-ablations", action="store_true", help="列出所有 ablation 变体")
    parser.add_argument("--force", "-f", action="store_true", help="覆盖已存在的配置")
    parser.add_argument("--dry-run", action="store_true", help="仅打印, 不写入文件")
    args = parser.parse_args()

    if args.vanilla and args.vanilla_only:
        print("ERROR: --vanilla 和 --vanilla-only 不能同时使用", file=sys.stderr)
        sys.exit(1)

    if args.list_ablations:
        print("可用 ablation 变体:")
        for name, info in sorted(ABLATION_VARIANTS.items()):
            print(f"  {name:25s}  [{info['mode']:8s}]  {info['description']}")
        return

    if args.list:
        print("可用模块:")
        for m in list_available_modules():
            print(f"  {m}")
        return

    if args.throughput_only:
        if args.ablation:
            print("ERROR: --throughput-only 不能和 --ablation 同时使用", file=sys.stderr)
            sys.exit(1)
        if args.validate_only or args.vanilla or args.vanilla_only:
            print("ERROR: --throughput-only 不能和 validate/vanilla 生成模式同时使用", file=sys.stderr)
            sys.exit(1)
        args.ablation = "fuzz-throughput"

    targets = args.modules
    if args.all:
        targets = list_available_modules()

    if not targets:
        parser.print_help()
        sys.exit(1)

    # --- Ablation mode: generate single variant per module ---
    if args.ablation:
        variant_name = args.ablation
        if variant_name not in ABLATION_VARIANTS:
            print(f"ERROR: 未知 ablation 变体: {variant_name}", file=sys.stderr)
            print(f"       可选: {', '.join(sorted(ABLATION_VARIANTS.keys()))}", file=sys.stderr)
            sys.exit(1)

        variant = ABLATION_VARIANTS[variant_name]
        mode = variant["mode"]
        suffix = variant["suffix"]

        ok = 0
        for slug in targets:
            cfg = generate_config(slug, mode, include_experimental=True)
            cfg = apply_ablation_overrides(cfg, variant_name)
            out_path = os.path.join(EXP_DIR, slug, f"{mode}{suffix}.cfg")

            if os.path.exists(out_path) and not args.force:
                print(f"SKIP {out_path} (已存在, 使用 --force 覆盖)")
                continue

            if args.dry_run:
                print(f"--- {out_path} ---")
                print(json.dumps(cfg, indent=4))
                continue

            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                json.dump(cfg, f, indent=4)
            print(f"OK {out_path}  [{variant['description']}]")
            ok += 1

        if not args.dry_run:
            print(f"\n生成完成: {ok} 个 {variant_name} 配置文件")
        return

    modes = []
    if args.validate_only:
        modes = ["validate"]
    elif args.fuzz_only:
        modes = ["fuzz"]
    else:
        modes = ["fuzz", "validate"]

    profiles = []
    if args.vanilla_only:
        profiles = [("-vanilla", False)]
    elif args.vanilla:
        profiles = [("", True), ("-vanilla", False)]
    else:
        profiles = [("", True)]

    ok = 0
    for slug in targets:
        for mode in modes:
            for suffix, include_exp in profiles:
                cfg = generate_config(slug, mode, include_exp)
                out_path = os.path.join(EXP_DIR, slug, f"{mode}{suffix}.cfg")

                if os.path.exists(out_path) and not args.force:
                    print(f"SKIP {out_path} (已存在, 使用 --force 覆盖)")
                    continue

                if args.dry_run:
                    print(f"--- {out_path} ---")
                    print(json.dumps(cfg, indent=4))
                    continue

                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "w") as f:
                    json.dump(cfg, f, indent=4)
                print(f"OK {out_path}")
                ok += 1

    if not args.dry_run:
        print(f"\n生成完成: {ok} 个配置文件")


if __name__ == "__main__":
    main()
