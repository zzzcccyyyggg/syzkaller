#!/usr/bin/env python3
"""从现有 test 配置中提取每个模块的 syscalls 和 overrides 到 exp/ 目录"""
import json, os, sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DIR = os.path.join(PROJECT, "test/DDRD-PairCollector/test")
EXP_DIR = os.path.join(PROJECT, "exp")

MODULES = {
    "xfs":        ("xfs.cfg",        "xfs"),
    "btrfs":      ("btrfs.cfg",      "btrfs"),
    "f2fs":       ("f2fs.cfg",       "f2fs"),
    "jfs":        ("jfs.cfg",        "jfs"),
    "floppy":     ("floppy.cfg",     "floppy"),
    "ptmx":       ("ptmx.cfg",       "tty"),
    "video":      ("video.cfg",      "v4l2"),
    "wifi":       ("wifi.cfg",       "wifi-stack"),
    "dsp":        ("dsp.cfg",        "intel-hda"),
    "usb-driver": ("usb-driver.cfg", "usb"),
    "bt-stack":   ("bt-stack.cfg",   "bt-stack"),
}

for slug, (cfg_file, artifact_name) in MODULES.items():
    cfg_path = os.path.join(TEST_DIR, cfg_file)
    if not os.path.exists(cfg_path):
        print(f"SKIP {slug}: {cfg_path} not found")
        continue

    d = json.load(open(cfg_path))

    mod_dir = os.path.join(EXP_DIR, slug)
    os.makedirs(mod_dir, exist_ok=True)

    # syscalls
    syscalls = d.get("enable_syscalls", [])
    with open(os.path.join(mod_dir, "syscalls.txt"), "w") as f:
        for sc in syscalls:
            f.write(sc + "\n")

    # overrides
    vm = d.get("vm", {})
    overrides = {
        "artifact_name": artifact_name,
        "qemu_args": vm.get("qemu_args", "").strip(),
        "procs": d.get("procs", 2),
        "vm_count": vm.get("count", 3),
        "vm_cpu": vm.get("cpu", 2),
        "vm_mem": vm.get("mem", 4096),
        "vm_running_time": d.get("vm_running_time", 600),
    }
    exp = d.get("experimental", {})
    if exp:
        overrides["experimental"] = exp

    with open(os.path.join(mod_dir, "overrides.json"), "w") as f:
        json.dump(overrides, f, indent=4)

    print(f"OK {slug}: {len(syscalls)} syscalls, artifact={artifact_name}")

print("Done.")
