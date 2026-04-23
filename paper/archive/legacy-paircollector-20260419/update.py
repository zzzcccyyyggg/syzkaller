#!/usr/bin/env python3
import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict

NEW_IMAGE = "/home/zzzccc/BASS/DDRD-syzkaller/test/fs/bookworm.img"
NEW_SSHKEY = "/home/zzzccc/BASS/DDRD-syzkaller/test/fs/bookworm.id_rsa"
NEW_PROCS = 2
NEW_CPU = 2
NEW_MEM = 4096
NEW_VM_RUNNING_TIME = 6000

# workdir 统一迁移到这个基目录下（保留原 workdir 的最后一级目录名）
NEW_WORKDIR_BASE = "/home/zzzccc/BASS/DDRD-syzkaller/test/DDRD-Fuzz"

# experimental 里强制设置的字段
EXP_FORCED = {
    "skip_duplicate_data_races": True,
    "ddrd_monitor": false,
    "uaf_mode": true,
    "barrier_mode": true,
}


def relax_json(text: str) -> str:
    """
    Best-effort parser for slightly non-strict JSON:
    - strip //... and /*...*/ comments
    - remove trailing commas before } or ]
    """
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


def load_cfg(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return json.loads(relax_json(raw))


def dump_cfg(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=4, ensure_ascii=False) + "\n"


def update_workdir(old_workdir: Any, new_base: str) -> str:
    """
    将 workdir 迁移到 new_base 下：
    - 保留原 workdir 最后一级目录名
    - 若原 workdir 不存在/不是字符串，则默认给 "workdir"
    """
    base = Path(new_base)
    if isinstance(old_workdir, str) and old_workdir.strip():
        leaf = Path(old_workdir).name
    else:
        leaf = "workdir"
    return str(base / leaf)


def update_cfg(data: Dict[str, Any], new_workdir_base: str) -> Dict[str, Any]:
    # 基本字段
    data["image"] = NEW_IMAGE
    data["sshkey"] = NEW_SSHKEY
    data["procs"] = NEW_PROCS
    data["vm_running_time"] = NEW_VM_RUNNING_TIME

    # workdir 迁移到 DDRD-Fuzz 下的子目录
    data["workdir"] = update_workdir(data.get("workdir"), new_workdir_base)

    # vm.cpu / vm.mem
    vm = data.get("vm")
    if not isinstance(vm, dict):
        vm = {}
        data["vm"] = vm
    vm["cpu"] = NEW_CPU
    vm["mem"] = NEW_MEM

    # experimental 强制字段
    exp = data.get("experimental")
    if not isinstance(exp, dict):
        exp = {}
        data["experimental"] = exp
    exp.update(EXP_FORCED)

    return data


def process_file(path: Path, new_workdir_base: str, dry_run: bool = False) -> None:
    data = load_cfg(path)
    data2 = update_cfg(data, new_workdir_base)

    if dry_run:
        print(f"[DRY] would update: {path}")
        return

    bak = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, bak)
    path.write_text(dump_cfg(data2), encoding="utf-8")
    print(f"[OK] updated: {path} (backup: {bak})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "root",
        nargs="?",
        default=NEW_WORKDIR_BASE,
        help="root directory to scan recursively for *.cfg (default: DDRD-Fuzz base)",
    )
    ap.add_argument(
        "--workdir-base",
        default=NEW_WORKDIR_BASE,
        help="new base dir for cfg['workdir'] (default: DDRD-Fuzz base)",
    )
    ap.add_argument("--dry-run", action="store_true", help="only print what would change")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"[ERR] not a directory: {root}")

    cfgs = sorted(root.rglob("*.cfg"))
    if not cfgs:
        print(f"[WARN] no *.cfg found under: {root}")
        return

    for p in cfgs:
        try:
            process_file(p, args.workdir_base, dry_run=args.dry_run)
        except Exception as e:
            print(f"[ERR] failed: {p} -> {e}")

    print("Done.")


if __name__ == "__main__":
    main()
