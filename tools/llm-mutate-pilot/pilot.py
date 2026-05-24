#!/usr/bin/env python3
"""Offline LLM mutation pilot for MRPFuzz UAF program groups."""

import argparse
import collections
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap
import time
from typing import Any

import requests


DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-pro"
DEFAULT_KIMI_BASE_URL = "https://kimi.a7m.com.cn/v1"
DEFAULT_KIMI_MODEL = "kimi-k2.6"
DEFAULT_CODEX_MODEL = "gpt-5.4"
DEFAULT_MOUNT = "/mnt/kccwf"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="syzkaller manager config used for target/syscall allowlist")
    parser.add_argument("--module", default="jfs", help="module name for prompt/reporting")
    parser.add_argument("--out", default="", help="output directory; default under paper/results/llm-mutate-pilot")
    parser.add_argument("--entries", type=int, default=20, help="number of UAF entries to sample")
    parser.add_argument("--variants-per-entry", type=int, default=3, help="LLM variants requested per entry")
    parser.add_argument("--max-varname-count", type=int, default=10, help="prefer entries with at least one VarName pair below this count")
    parser.add_argument("--max-calls", type=int, default=8, help="max syscalls per generated single program")
    parser.add_argument("--mount-prefix", default=DEFAULT_MOUNT)
    parser.add_argument("--source", default="fuzz", choices=["fuzz", "timing", "all"], help="UAF corpus source filter")
    parser.add_argument("--provider", choices=["deepseek", "kimi", "codex"], default=os.environ.get("LLM_PROVIDER", "deepseek"))
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", os.environ.get("DEEPSEEK_BASE_URL", "")))
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", os.environ.get("DEEPSEEK_MODEL", "")))
    parser.add_argument("--temperature", type=float, default=0.25)
    parser.add_argument("--max-tokens", type=int, default=int(os.environ.get("LLM_MAX_TOKENS", "0") or "0"))
    parser.add_argument("--thinking", choices=["enabled", "disabled"], default=os.environ.get("DEEPSEEK_THINKING", "disabled"))
    parser.add_argument("--reasoning-effort", choices=["high", "max"], default=os.environ.get("DEEPSEEK_REASONING_EFFORT", "high"))
    parser.add_argument("--timeout-sec", type=int, default=180)
    parser.add_argument("--codex-bin", default=os.environ.get("CODEX_BIN", "codex"))
    parser.add_argument("--codex-model", default=os.environ.get("CODEX_MODEL", DEFAULT_CODEX_MODEL))
    parser.add_argument("--codex-profile", default=os.environ.get("CODEX_PROFILE", ""))
    parser.add_argument("--codex-sandbox", choices=["read-only", "workspace-write", "danger-full-access"], default=os.environ.get("CODEX_SANDBOX", "read-only"))
    parser.add_argument("--codex-reasoning-effort", choices=["low", "medium", "high", "xhigh"], default=os.environ.get("CODEX_REASONING_EFFORT", "medium"))
    parser.add_argument("--dry-run", action="store_true", help="only sample entries and write prompts")
    parser.add_argument("--api-key-stdin", action="store_true", help="read API key from stdin instead of environment")
    parser.add_argument("--checker", default="./tools/syz-llm-candidate-check", help="go package/path for the local checker")
    return parser.parse_args()


def effective_model(args: argparse.Namespace) -> str:
    provider = getattr(args, "provider", "deepseek")
    if provider == "codex":
        return getattr(args, "codex_model", "") or DEFAULT_CODEX_MODEL
    model = getattr(args, "model", "")
    if model:
        return model
    if provider == "kimi":
        return os.environ.get("KIMI_MODEL", DEFAULT_KIMI_MODEL)
    return DEFAULT_MODEL


def effective_base_url(args: argparse.Namespace) -> str:
    base_url = getattr(args, "base_url", "")
    if base_url:
        return base_url
    if getattr(args, "provider", "deepseek") == "kimi":
        return os.environ.get("KIMI_BASE_URL", DEFAULT_KIMI_BASE_URL)
    return DEFAULT_BASE_URL


def effective_max_tokens(args: argparse.Namespace) -> int:
    explicit = int(getattr(args, "max_tokens", 0) or 0)
    if explicit > 0:
        return explicit
    if getattr(args, "provider", "deepseek") == "kimi":
        return int(os.environ.get("KIMI_MAX_TOKENS", "65536") or "65536")
    return 0


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_kccwf_pools(path: str = "sys/linux/kccwf_fs.txt") -> dict[str, list[str]]:
    pools: dict[str, list[str]] = {}
    if not os.path.exists(path):
        return pools
    pattern = re.compile(r"^(kccwf_[a-z_]+)\s*=\s*(.*)$")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = pattern.match(line.strip())
            if not match:
                continue
            pools[match.group(1)] = re.findall(r'"([^"]+)"', match.group(2))
    return pools


def format_kccwf_pools(pools: dict[str, list[str]]) -> str:
    if not pools:
        return "- current pool unavailable; keep paths under /mnt/kccwf and prefer existing names from the original group"
    lines = []
    for name in sorted(pools):
        values = ", ".join(pools[name])
        lines.append(f"- {name}: {values}")
    return "\n".join(lines)


def default_out_dir(module: str) -> pathlib.Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return pathlib.Path("paper/results/llm-mutate-pilot") / f"{module}-{stamp}"


def run_uaf_corpus(config_path: str, workdir: str, source: str) -> list[dict[str, Any]]:
    if workdir:
        cmd = ["./bin/syz-uaf-corpus", "-workdir", workdir, "-json", "-sort-time"]
    else:
        cmd = ["./bin/syz-uaf-corpus", "-config", config_path, "-json", "-sort-time"]
    if source != "all":
        cmd += ["-source", source]
    proc = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return json.loads(proc.stdout)


def pair_key(pair: dict[str, Any]) -> str:
    return f"{pair.get('FreeAccessName', 0):016x}:{pair.get('UseAccessName', 0):016x}"


def entry_pairs(entry: dict[str, Any]) -> list[dict[str, Any]]:
    pairs = list(entry.get("pairs") or [])
    pair = entry.get("pair")
    if pair and (pair.get("FreeAccessName") or pair.get("UseAccessName")):
        key = pair_key(pair)
        if all(pair_key(p) != key for p in pairs):
            pairs.insert(0, pair)
    return pairs


def count_calls(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))


def compact_program_for_prompt(text: str, max_lines: int = 24, max_line_chars: int = 420, max_total_chars: int = 7000) -> tuple[str, bool]:
    """Return a prompt-friendly view of a syzkaller program.

    Some FS corpora, especially btrfs, contain enormous inline raw buffers.
    Sending those verbatim slows LLM calls and tempts the model to copy invalid
    byte strings. Keep the syscall shape while shrinking long hex payloads.
    """
    changed = False
    out: list[str] = []
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        if idx >= max_lines:
            out.append(f"<ELIDED_{len(lines) - idx}_CALLS>")
            changed = True
            break
        shrunk = re.sub(r'"[0-9a-fA-F]{96,}"', '"00"', line)
        if shrunk != line:
            changed = True
        if len(shrunk) > max_line_chars:
            shrunk = shrunk[:max_line_chars].rstrip() + " <ELIDED_LONG_ARGUMENTS>"
            changed = True
        out.append(shrunk)
    compact = "\n".join(out)
    if len(compact) > max_total_chars:
        compact = compact[:max_total_chars].rstrip() + "\n<ELIDED_PROGRAM_TAIL>"
        changed = True
    return compact, changed


def select_entries(
    entries: list[dict[str, Any]],
    want: int,
    max_varname_count: int,
    exclude_keys: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    exclude_keys = exclude_keys or set()
    counts: collections.Counter[str] = collections.Counter()
    for entry in entries:
        for pair in entry_pairs(entry):
            counts[pair_key(pair)] += 1

    scored: list[tuple[int, int, int, dict[str, Any]]] = []
    for idx, entry in enumerate(entries):
        if str(entry.get("key") or "") in exclude_keys:
            continue
        programs = entry.get("programs") or []
        pairs = entry_pairs(entry)
        if len(programs) < 2 or not pairs:
            continue
        min_count = min(counts[pair_key(pair)] for pair in pairs)
        total_calls = count_calls(programs[0]) + count_calls(programs[1])
        recent_rank = idx
        scored.append((min_count, -total_calls, recent_rank, entry))

    preferred = [item for item in scored if item[0] <= max_varname_count]
    pool = preferred if len(preferred) >= want else scored
    pool.sort(key=lambda item: (item[0], item[1], item[2]))

    selected: list[dict[str, Any]] = []
    seen_shapes: set[tuple[str, str]] = set()
    for _, _, _, entry in pool:
        programs = entry.get("programs") or []
        shape = (first_call(programs[0]), first_call(programs[1]))
        if shape in seen_shapes and len(pool) - len(selected) > want:
            continue
        seen_shapes.add(shape)
        selected.append(entry)
        if len(selected) >= want:
            break
    return selected, dict(counts)


def first_call(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line.split("(", 1)[0].split("=", 1)[-1].strip()
    return ""


def uses_kccwf(enabled_syscalls: list[str]) -> bool:
    return any("kccwf" in name for name in enabled_syscalls)


def uses_device_paths(enabled_syscalls: list[str]) -> bool:
    return any(
        name.startswith("syz_open_dev$")
        or name in {
            "openat$ptmx",
            "openat$tty",
            "openat$ttyS3",
            "openat$ttynull",
            "openat$ttyprintk",
            "syz_open_pts",
        }
        for name in enabled_syscalls
    )


def build_object_rules(module: str, enabled_syscalls: list[str], object_pools: dict[str, list[str]], mount_prefix: str) -> str:
    rules: list[str] = []
    if uses_kccwf(enabled_syscalls):
        rules.append(
            "Filesystem/kccwf calls may use only the current local kccwf string pools. "
            f"Absolute kccwf paths must stay under {mount_prefix}; relative kccwf names "
            "must come from kccwf_rel_files."
        )
        rules.append("Current kccwf pools:\n" + format_kccwf_pools(object_pools))
    if uses_device_paths(enabled_syscalls):
        rules.append(
            "Device calls may keep the concrete device path or encoded device selector "
            "already used by the original program. For ptmx/tty use the existing "
            "/dev/ptmx, /dev/tty*, or syz_open_dev$tty* opener families; for floppy use "
            "syz_open_dev$floppy with the literal /dev/fd# syzkaller device pattern. "
            "Do not invent unrelated devices."
        )
    if module == "ptmx" or "syz_open_pts" in enabled_syscalls:
        rules.append(
            "For ptmx, preserve master/slave semantics: openat$ptmx returns the master fd; "
            "syz_open_pts and ioctl$TIOCGPTPEER must consume a previously returned ptmx/tty fd."
        )
    if module == "floppy" or any(name.startswith("ioctl$FLOPPY_") for name in enabled_syscalls):
        rules.append(
            "For floppy, ioctl$FLOPPY_* calls must consume an fd returned earlier by "
            "syz_open_dev$floppy. kccwf file operations are auxiliary state perturbations, "
            "not replacements for the floppy opener."
        )
    if module == "btrfs" or any(name.startswith("ioctl$BTRFS_IOC_") for name in enabled_syscalls):
        rules.append(
            "For btrfs, avoid inventing large nested ioctl structs. Prefer compact, parser-safe "
            "BTRFS ioctl forms already present in the corpus, or simple fd-local ioctls paired "
            "with kccwf file operations and sync/fsync. For BTRFS *_V2 structs, do not write "
            "@name=\"subvol\" or @name='subvol\\x00': syzkaller raw data fields require "
            "double-quoted hex bytes only, and many accepted corpus forms use union arms like "
            "@devid/@treeid instead of a hand-written name. If unsure, keep the ioctl argument "
            "simple or use 0x0/simple output pointers rather than fabricating a struct."
        )
    if module in {"bt-stack", "bluetooth"} or any("$bt_" in name or name == "syz_emit_vhci" for name in enabled_syscalls):
        rules.append(
            "For bluetooth, keep generation conservative because the test VM only has the "
            "virtual Bluetooth stack, not arbitrary external Bluetooth/IP peers. Even if "
            "listed above, do not use openat$6lowpan_enable, openat$6lowpan_control, "
            "write$6lowpan_enable, write$6lowpan_control, HIDP, CMTP, or BNEP calls in "
            "generated variants. Prefer HCI/L2CAP/SCO/"
            "RFCOMM socket operations plus syz_emit_vhci. Keep each operation inside one "
            "compatible socket family: a syz_init_net_socket$bt_* call returns the fd for "
            "later bind/connect/ioctl/setsockopt/getsockopt/write calls in the same program; "
            "do not pass an HCI fd to L2CAP/SCO/RFCOMM-specific consumers. Do not invent HCI/"
            "HIDP/CMTP/BNEP packet structs. Use 0x0 or simple uninitialized pointers for "
            "output buffers; use only tiny hex raw buffers like \"00000000\" for input data."
        )
    if module == "dsp" or any(name.startswith("ioctl$SNDCTL_DSP_") or name.startswith("ioctl$SOUND_") for name in enabled_syscalls):
        rules.append(
            "For dsp/OSS audio, keep to devices that are likely present in the test VM: "
            "prefer openat$dsp with /dev/dsp and openat$mixer with /dev/mixer. Do not "
            "use /dev/dsp1, /dev/adsp1, /dev/audio, /dev/audio1, or proc_mixer in "
            "generated variants. DSP ioctls "
            "(SNDCTL_DSP_* and SOUND_PCM_*) must consume an fd from openat$dsp; "
            "mixer ioctls (SOUND_MIXER_* and mixer_OSS_*) must consume an fd from "
            "openat$mixer. Do not mix these fd families. Avoid mmap$dsp. For read$dsp "
            "output buffers, use 0x0 or a simple uninitialized pointer, never a quoted "
            "buffer. For write$dsp input data, use tiny hex buffers like \"4142\"."
        )
    if not rules:
        rules.append(
            "Preserve the resource families already present in the original group and keep "
            "each consuming syscall tied to a resource created earlier in the same program."
        )
    return "\n\n".join(f"- {rule}" for rule in rules)


def example_programs(module: str, enabled_syscalls: list[str], mount_prefix: str) -> tuple[str, str]:
    enabled = set(enabled_syscalls)
    if module == "btrfs" and "ioctl$BTRFS_IOC_SUBVOL_CREATE_V2" in enabled:
        return (
            f"r0 = open$kccwf(&(0x7f0000000000)='{mount_prefix}/testfile3\\\\x00', 0x42, 0x1ff)\\n"
            "write$kccwf(r0, &(0x7f0000000100)=\\\"4142\\\", 0x2)\\n"
            "ioctl$BTRFS_IOC_SUBVOL_CREATE_V2(r0, 0x50009418, &(0x7f0000000200)={{}, 0x0, 0x6, @inherit={0x58, &(0x7f0000000300)=ANY=[@ANYRES32]}, @devid})\\n"
            "fsync$kccwf(r0)",
            f"r0 = open$kccwf(&(0x7f0000000400)='{mount_prefix}/testfile4\\\\x00', 0x42, 0x1ff)\\n"
            "ioctl$BTRFS_IOC_SYNC(r0, 0x0)\\n"
            "sync$kccwf()",
        )
    if "openat$ptmx" in enabled and "ioctl$TIOCSPTLCK" in enabled and "syz_open_pts" in enabled:
        return (
            "r0 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000000)='/dev/ptmx\\\\x00', 0x2, 0x0)\\n"
            "ioctl$TIOCSPTLCK(r0, 0x40045431, &(0x7f0000000040)=0x0)\\n"
            "r1 = syz_open_pts(r0, 0x2)\\n"
            "ioctl$TCGETS(r1, 0x5401, &(0x7f0000000080))",
            "r0 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000100)='/dev/ptmx\\\\x00', 0x2, 0x0)\\n"
            "r1 = ioctl$TIOCGPTPEER(r0, 0x5441, 0x9)\\n"
            "ioctl$TIOCVHANGUP(r1, 0x5437, 0x0)",
        )
    if "syz_open_dev$floppy" in enabled and "ioctl$FLOPPY_FDGETPRM" in enabled:
        return (
            "r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\\\x00', 0x0, 0x2)\\n"
            "ioctl$FLOPPY_FDGETPRM(r0, 0x80200204, &(0x7f0000000040))",
            "r0 = syz_open_dev$floppy(&(0x7f0000000100)='/dev/fd#\\\\x00', 0x0, 0x2)\\n"
            "ioctl$FLOPPY_FDFLUSH(r0, 0x24b)",
        )
    if "syz_init_net_socket$bt_hci" in enabled and "ioctl$sock_bt_hci" in enabled:
        return (
            "r0 = syz_init_net_socket$bt_hci(0x1f, 0x3, 0x1)\\n"
            "bind$bt_hci(r0, &(0x7f0000000000)={0x1f, 0xffffffffffffffff, 0x3}, 0x6)\\n"
            "ioctl$sock_bt_hci(r0, 0x400448e6, &(0x7f0000000040)='\\\\x00\\\\x00\\\\x00\\\\x00')",
            "syz_emit_vhci(0x0, 0x0)\\n"
            "r0 = syz_init_net_socket$bt_l2cap(0x1f, 0x5, 0x0)\\n"
            "getsockopt$bt_l2cap_L2CAP_OPTIONS(r0, 0x6, 0x1, &(0x7f0000000100), 0x0)",
        )
    if uses_kccwf(enabled_syscalls):
        return (
            f"r0 = open$kccwf(&(0x7f0000000000)='{mount_prefix}/testfile3\\\\x00', 0x42, 0x1ff)\\n"
            "write$kccwf(r0, &(0x7f0000000100)=\\\"4142\\\", 0x2)\\n"
            "fsync$kccwf(r0)",
            f"stat$kccwf(&(0x7f0000000200)='{mount_prefix}/testfile3\\\\x00', 0x0)\\n"
            "sync$kccwf()",
        )
    first = enabled_syscalls[0] if enabled_syscalls else "syz_emit_ethernet"
    return (f"{first}()", f"{first}()")


def summarize_pairs(entry: dict[str, Any], counts: dict[str, int], limit: int = 8) -> str:
    lines = []
    for pair in entry_pairs(entry)[:limit]:
        key = pair_key(pair)
        lines.append(
            "- VarNamePair {key} corpus_count={count} "
            "free_stack=0x{free_stack:016x} use_stack=0x{use_stack:016x} "
            "free_prog={free_prog} free_call={free_call} use_prog={use_prog} use_call={use_call} "
            "time_diff_us={time_diff}".format(
                key=key,
                count=counts.get(key, 0),
                free_stack=pair.get("FreeCallStack", 0),
                use_stack=pair.get("UseCallStack", 0),
                free_prog=pair.get("FreeProgIdx", -1),
                free_call=pair.get("FreeCallIdx", -1),
                use_prog=pair.get("UseProgIdx", -1),
                use_call=pair.get("UseCallIdx", -1),
                time_diff=pair.get("TimeDiff", 0),
            )
        )
    return "\n".join(lines)


def build_prompt(
    module: str,
    target: str,
    enabled_syscalls: list[str],
    object_pools: dict[str, list[str]],
    entry: dict[str, Any],
    counts: dict[str, int],
    variants_per_entry: int,
    mount_prefix: str,
    max_calls: int,
) -> tuple[str, str]:
    programs = entry.get("programs") or ["", ""]
    if module == "btrfs":
        prompt_prog_a, compact_a = compact_program_for_prompt(programs[0], max_lines=14, max_line_chars=280, max_total_chars=3500)
        prompt_prog_b, compact_b = compact_program_for_prompt(programs[1], max_lines=14, max_line_chars=280, max_total_chars=3500)
    else:
        prompt_prog_a, compact_a = compact_program_for_prompt(programs[0])
        prompt_prog_b, compact_b = compact_program_for_prompt(programs[1])
    compact_note = ""
    if compact_a or compact_b:
        compact_note = (
            "The original program view below is compacted for prompting: very long raw byte "
            "buffers are replaced with \"00\" and <ELIDED_...> markers may appear. These markers "
            "are not valid syzkaller and must not be copied into generated programs."
        )
    enabled = "\n".join(f"- {name}" for name in enabled_syscalls)
    pair_summary = summarize_pairs(entry, counts)
    object_rules = build_object_rules(module, enabled_syscalls, object_pools, mount_prefix)
    example_a, example_b = example_programs(module, enabled_syscalls, mount_prefix)
    system = textwrap.dedent(
        f"""
        You generate syzkaller programs for an offline MRPFuzz input-construction pilot.
        Your output must be one strict JSON object and nothing else.

        Goal: construct a better concurrent input, not merely repair two independent
        single-program tests. Treat prog_a and prog_b as one program group and make their
        operations more likely to perturb overlapping kernel state in {module}, while
        preserving path/object diversity and valid resource dependencies.
        """
    ).strip()
    user = textwrap.dedent(
        f"""
        Target: {target}
        Mounted test root: {mount_prefix}
        Module under test: {module}

        Allowed syscall names. Use exact names only; do not invent suffixes:
        {enabled}

        State/resource rules for this module:
        {object_rules}

        Original concurrent program group from random UAF corpus:
        {compact_note}
        <prog_a>
        {prompt_prog_a.rstrip()}
        </prog_a>
        <prog_b>
        {prompt_prog_b.rstrip()}
        </prog_b>

        Observed race metadata. Prefer preserving or expanding the semantics around these
        program/call positions, especially rare VarName pairs:
        {pair_summary}

        Generate exactly {variants_per_entry} variants. Each variant is still a two-program
        group, with fields "id", "intent", "prog_a", and "prog_b".

        Interaction design:
        - The primary objective is concurrent interaction completeness. Each side should
          contain at least one operation that can affect the state observed or modified by
          the other side.
        - Do not collapse every variant to the exact same path. Same-object interaction is
          useful, but it is only one interaction scope. Across variants, diversify among:
          (1) same concrete object with complementary operations,
          (2) related objects such as directory/file, old/new rename names, link/target,
              symlink/target, parent/child, or same directory with different children,
          (3) same container/subsystem interaction, where one side performs local object
              work and the other performs sync/fsync/syncfs/ioctl/metadata activity.
        - Keep path randomization meaningful but legal: absolute kccwf paths stay under
          {mount_prefix}; prefer existing pool names such as testfile1..9, testdir/testdiN,
          hardlinkN, symlinkN, and targetN relations when available. If a path must exist,
          create it in the same program when feasible.
        - The "intent" field must name the chosen interaction scope, for example
          "same-object-write-fsync", "dir-child-rename-stat", or
          "local-object-global-sync".

        Hard constraints:
        1. Output valid JSON only. In syzkaller strings, write null terminators as "\\\\x00".
        2. Use only the allowed syscall names listed above.
        3. Each prog_a/prog_b must have 1 to {max_calls} syscalls. Count the
           non-empty syzkaller call lines before writing the final JSON. If a
           side would exceed {max_calls} calls, delete lower-value calls rather
           than exceeding the limit. Prefer compact 3-6 call programs unless
           the original semantic dependency truly needs more.
        4. Transform only by adding, deleting, reordering, or adjusting arguments of the
           original group. Keep at least one original syscall family in each side.
        5. Follow the State/resource rules above. Keep paths, device selectors, object
           names, and relation structure compatible with the original module and config.
        6. Use syzkaller string syntax correctly: path/string arguments use single quotes,
           e.g. &(0x7f0000000000)='{mount_prefix}/testfile3\\\\x00' and
           &(0x7f0000000100)='user.test\\\\x00'. Use double-quoted hex only for raw byte buffers.
           Do not use C-style double-quoted paths.
           Do not copy executor annotations such as "(async)" into generated programs.
           For raw byte input buffers, use only double-quoted hex bytes such as
           &(0x7f0000000100)="4142". Never write natural-language buffers like
           "data", "val", "GH", "some data", escaped byte strings like "\\x00\\x01",
           or empty data literals like "". For read/stat/ioctl output buffers, prefer
           0x0 or a simple uninitialized pointer such as &(0x7f0000000200), not a
           hand-written quoted buffer.
        7. openat$kccwf, mknodat*$kccwf, faccessat$kccwf, futimesat$kccwf,
           utimensat$kccwf, statx$kccwf, fchmodat$kccwf, and name_to_handle_at$kccwf
           require relative file names from kccwf_rel_files, not absolute paths.
        8. For stat$kccwf/statx$kccwf output buffers, prefer 0x0 or a simple output pointer;
           do not invent nested struct literals.
        9. fd/resource-consuming syscalls must use an rN returned by an earlier syscall in
           the same program. Do not use -1, 0xffffffffffffffff, or a bare constant as an fd.
           Example: r0 = open$kccwf(...); write$kccwf(r0, ...); fsync$kccwf(r0).
        10. open/openat that create or open files should use coherent flags such as 0x42
           (O_RDWR|O_CREAT) or 0x2 (O_RDWR), with mode 0x1ff when creation is possible.
        11. Preserve concurrency value: do not make both programs identical. Do not turn
           both sides into two unrelated valid single-program tests; make the group-level
           state interaction explicit through same-object, related-object, or
           container/global interaction.
        12. Keep generated programs self-contained enough to replay in the current {module}
           test environment. If a file/directory/path is required, create it first in the
           same program when feasible.

        JSON schema:
        {{
          "variants": [
            {{
              "id": "v1",
              "intent": "short reason such as fd-repair-local-sync or dir-relation",
              "prog_a": "{example_a}",
              "prog_b": "{example_b}"
            }}
          ]
        }}
        """
    ).strip()
    return system, user


def read_api_key(args: argparse.Namespace) -> str:
    if args.dry_run:
        return ""
    if getattr(args, "provider", "deepseek") == "codex":
        return ""
    if args.api_key_stdin:
        key = sys.stdin.readline().strip()
    else:
        if getattr(args, "provider", "deepseek") == "kimi":
            key = os.environ.get("KIMI_API_KEY", os.environ.get("LLM_API_KEY", "")).strip()
        else:
            key = os.environ.get("DEEPSEEK_API_KEY", os.environ.get("LLM_API_KEY", "")).strip()
    if not key:
        provider = getattr(args, "provider", "deepseek")
        raise SystemExit(f"missing API key for {provider}: set the provider API key env or use --api-key-stdin")
    return key


def call_llm(args: argparse.Namespace, api_key: str, system: str, user: str) -> str:
    provider = getattr(args, "provider", "deepseek")
    if provider == "codex":
        return call_codex(args, system, user)
    if provider == "deepseek":
        return call_deepseek(args, api_key, system, user)
    if provider == "kimi":
        return call_openai_compatible(args, api_key, system, user, "Kimi")
    raise RuntimeError(f"unknown LLM provider: {provider}")


def call_deepseek(args: argparse.Namespace, api_key: str, system: str, user: str) -> str:
    url = effective_base_url(args).rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": effective_model(args),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": args.temperature,
        "response_format": {"type": "json_object"},
    }
    max_tokens = effective_max_tokens(args)
    if max_tokens > 0:
        payload["max_tokens"] = max_tokens
    thinking = getattr(args, "thinking", "disabled")
    if thinking:
        payload["thinking"] = {"type": thinking}
        if thinking == "enabled":
            payload["reasoning_effort"] = getattr(args, "reasoning_effort", "high")
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=args.timeout_sec)
        if resp.status_code >= 400 and "response_format" in payload:
            payload.pop("response_format", None)
            resp = requests.post(url, headers=headers, json=payload, timeout=args.timeout_sec)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"DeepSeek request failed: {exc}") from exc
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def call_openai_compatible(args: argparse.Namespace, api_key: str, system: str, user: str, provider_name: str) -> str:
    url = effective_base_url(args).rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": effective_model(args),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": args.temperature,
        "response_format": {"type": "json_object"},
    }
    max_tokens = effective_max_tokens(args)
    if max_tokens > 0:
        payload["max_tokens"] = max_tokens
    thinking = getattr(args, "thinking", "")
    if thinking:
        payload["thinking"] = {"type": thinking}
        if thinking == "enabled":
            payload["reasoning_effort"] = getattr(args, "reasoning_effort", "high")
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=args.timeout_sec)
        if resp.status_code >= 400 and "response_format" in payload:
            payload.pop("response_format", None)
            resp = requests.post(url, headers=headers, json=payload, timeout=args.timeout_sec)
        resp.raise_for_status()
    except requests.RequestException as exc:
        body = ""
        if getattr(exc, "response", None) is not None:
            body = exc.response.text[:500]
        raise RuntimeError(f"{provider_name} request failed: {exc}; body={body}") from exc
    data = resp.json()
    choice = data["choices"][0]
    message = choice.get("message") or {}
    content = message.get("content")
    if not content:
        reasoning = message.get("reasoning_content") or ""
        raise RuntimeError(
            f"{provider_name} returned empty content finish_reason={choice.get('finish_reason')} "
            f"reasoning_len={len(reasoning)}"
        )
    return content


def codex_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "variants": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "id": {"type": "string"},
                        "intent": {"type": "string"},
                        "prog_a": {"type": "string"},
                        "prog_b": {"type": "string"},
                    },
                    "required": ["id", "intent", "prog_a", "prog_b"],
                },
            }
        },
        "required": ["variants"],
    }


def codex_prompt(system: str, user: str) -> str:
    return textwrap.dedent(
        f"""
        You are a constrained backend for MRPFuzz LLM-helper seed generation.

        Do not inspect files, run commands, modify the repository, or explain your answer.
        Return only one JSON object that follows the requested schema. The JSON object
        must contain a "variants" array, and each element must contain "id", "intent",
        "prog_a", and "prog_b". Do not wrap the JSON in Markdown fences.

        <system_prompt>
        {system}
        </system_prompt>

        <user_prompt>
        {user}
        </user_prompt>
        """
    ).strip()


def call_codex(args: argparse.Namespace, system: str, user: str) -> str:
    with tempfile.TemporaryDirectory(prefix="mrpfuzz-codex-") as tmpdir:
        tmp = pathlib.Path(tmpdir)
        schema_path = tmp / "schema.json"
        output_path = tmp / "last-message.json"
        schema_path.write_text(json.dumps(codex_schema(), indent=2) + "\n", encoding="utf-8")
        cmd = [
            getattr(args, "codex_bin", "codex"),
            "-a",
            "never",
            "exec",
            "--ephemeral",
            "-C",
            os.getcwd(),
            "-s",
            getattr(args, "codex_sandbox", "read-only"),
            "--output-schema",
            str(schema_path),
            "-o",
            str(output_path),
            "-m",
            effective_model(args),
            "-c",
            'model_reasoning_effort="%s"' % getattr(args, "codex_reasoning_effort", "medium"),
        ]
        profile = getattr(args, "codex_profile", "")
        if profile:
            cmd += ["-p", profile]
        cmd.append("-")
        proc = subprocess.run(
            cmd,
            input=codex_prompt(system, user),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=getattr(args, "timeout_sec", 180),
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "Codex request failed with exit code {code}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}".format(
                    code=proc.returncode,
                    stdout=proc.stdout[-4000:],
                    stderr=proc.stderr[-4000:],
                )
            )
        if output_path.exists():
            content = output_path.read_text(encoding="utf-8").strip()
            if content:
                return content
        return proc.stdout.strip()


def extract_json_object(text: str) -> dict[str, Any] | list[Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(text[start : end + 1])


def normalize_variants(raw: dict[str, Any] | list[Any], entry_key: str) -> list[dict[str, str]]:
    variants = raw if isinstance(raw, list) else raw.get("variants")
    if not isinstance(variants, list):
        return []
    out = []
    for idx, variant in enumerate(variants):
        if not isinstance(variant, dict):
            continue
        prog_a = variant.get("prog_a")
        prog_b = variant.get("prog_b")
        if not isinstance(prog_a, str) or not isinstance(prog_b, str):
            continue
        vid = str(variant.get("id") or f"v{idx + 1}")
        out.append(
            {
                "id": f"{entry_key[:10]}-{vid}",
                "entry_key": entry_key,
                "intent": str(variant.get("intent") or ""),
                "prog_a": prog_a.strip() + "\n",
                "prog_b": prog_b.strip() + "\n",
            }
        )
    return out


def run_checker(args: argparse.Namespace, cfg: dict[str, Any], variants: list[dict[str, str]]) -> dict[str, Any]:
    payload = {
        "target": cfg.get("target", "linux/amd64"),
        "enabled_syscalls": cfg.get("enable_syscalls", []),
        "mount_prefix": args.mount_prefix,
        "max_calls": args.max_calls,
        "variants": variants,
    }
    cmd = ["go", "run", args.checker]
    proc = subprocess.run(cmd, text=True, input=json.dumps(payload), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(f"checker failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return apply_module_policy(args.module, json.loads(proc.stdout))


def _item_text(item: dict[str, Any]) -> str:
    parts = [str(item.get("prog_a") or ""), str(item.get("prog_b") or "")]
    parts.extend(str(call) for call in item.get("calls_a") or [])
    parts.extend(str(call) for call in item.get("calls_b") or [])
    return "\n".join(parts)


def _dsp_read_has_literal_output(text: str) -> bool:
    for line in text.splitlines():
        if line.lstrip().startswith("read$dsp(") and ")=\"" in line:
            return True
    return False


def module_policy_reasons(module: str, item: dict[str, Any]) -> list[str]:
    text = _item_text(item)
    reasons: list[str] = []
    if module in {"bt-stack", "bluetooth"}:
        forbidden = [
            "6lowpan",
            "bt_bnep",
            "BNEP",
            "bt_cmtp",
            "CMTP",
            "bt_hidp",
            "HIDP",
        ]
        hits = sorted({token for token in forbidden if token in text})
        if hits:
            reasons.append(
                "module policy: bluetooth VM-conservative mode rejects unsupported families: "
                + ", ".join(hits)
            )
    if module == "dsp":
        forbidden = [
            "openat$dsp1",
            "openat$adsp1",
            "openat$audio",
            "openat$audio1",
            "openat$proc_mixer",
            "read$proc_mixer",
            "write$proc_mixer",
            "mmap$dsp",
            "/dev/dsp1",
            "/dev/adsp1",
            "/dev/audio",
            "/dev/audio1",
            "proc_mixer",
        ]
        hits = sorted({token for token in forbidden if token in text})
        if hits:
            reasons.append(
                "module policy: dsp VM-conservative mode rejects unsupported/fragile OSS paths: "
                + ", ".join(hits)
            )
        if _dsp_read_has_literal_output(text):
            reasons.append("module policy: read$dsp output buffer must not be a quoted literal")
    return reasons


def apply_module_policy(module: str, checker_out: dict[str, Any]) -> dict[str, Any]:
    accepted = checker_out.get("accepted") or []
    rejected = list(checker_out.get("rejected") or [])
    kept: list[dict[str, Any]] = []
    policy_rejected = 0
    for item in accepted:
        reasons = module_policy_reasons(module, item)
        if not reasons:
            kept.append(item)
            continue
        moved = dict(item)
        moved["reasons"] = list(moved.get("reasons") or []) + reasons
        rejected.append(moved)
        policy_rejected += 1

    checker_out["accepted"] = kept
    checker_out["rejected"] = rejected
    summary = dict(checker_out.get("summary") or {})
    summary["accepted"] = len(kept)
    summary["rejected"] = len(rejected)
    if policy_rejected:
        summary["module_policy_rejected"] = policy_rejected
    checker_out["summary"] = summary
    return checker_out


def write_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    object_pools = load_kccwf_pools()
    out_dir = pathlib.Path(args.out) if args.out else default_out_dir(args.module)
    for sub in ["prompts", "raw", "accepted", "rejected"]:
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    entries = run_uaf_corpus(args.config, cfg.get("workdir", ""), args.source)
    selected, counts = select_entries(entries, args.entries, args.max_varname_count)
    if not selected:
        raise SystemExit("no eligible UAF entries selected")

    manifest = {
        "created_at": dt.datetime.now().isoformat(),
        "module": args.module,
        "config": args.config,
        "workdir": cfg.get("workdir"),
        "target": cfg.get("target"),
        "provider": args.provider,
        "model": effective_model(args),
        "base_url": args.base_url if args.provider == "deepseek" else "",
        "codex_bin": args.codex_bin if args.provider == "codex" else "",
        "codex_profile": args.codex_profile if args.provider == "codex" else "",
        "codex_sandbox": args.codex_sandbox if args.provider == "codex" else "",
        "entries_requested": args.entries,
        "entries_selected": len(selected),
        "variants_per_entry": args.variants_per_entry,
        "max_varname_count": args.max_varname_count,
        "max_calls": args.max_calls,
        "selected_keys": [e.get("key") for e in selected],
    }
    write_text(out_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")

    api_key = read_api_key(args)
    all_variants: list[dict[str, str]] = []
    request_count = 0
    parse_failures: list[dict[str, str]] = []

    for idx, entry in enumerate(selected, start=1):
        key = entry.get("key", f"entry{idx}")
        system, user = build_prompt(
            args.module,
            cfg.get("target", "linux/amd64"),
            cfg.get("enable_syscalls", []),
            object_pools,
            entry,
            counts,
            args.variants_per_entry,
            args.mount_prefix,
            args.max_calls,
        )
        write_text(out_dir / "prompts" / f"{idx:02d}-{key[:10]}.system.txt", system + "\n")
        write_text(out_dir / "prompts" / f"{idx:02d}-{key[:10]}.user.txt", user + "\n")
        request_count += args.variants_per_entry
        if args.dry_run:
            continue
        print(f"[{idx}/{len(selected)}] requesting {args.variants_per_entry} variants for {key[:10]}", flush=True)
        try:
            content = call_llm(args, api_key, system, user)
            write_text(out_dir / "raw" / f"{idx:02d}-{key[:10]}.txt", content + "\n")
            raw_json = extract_json_object(content)
            write_text(out_dir / "raw" / f"{idx:02d}-{key[:10]}.json", json.dumps(raw_json, indent=2) + "\n")
            variants = normalize_variants(raw_json, key)
            all_variants.extend(variants)
            time.sleep(0.5)
        except Exception as exc:
            parse_failures.append({"entry_key": key, "error": str(exc)})
            write_text(out_dir / "raw" / f"{idx:02d}-{key[:10]}.error.txt", str(exc) + "\n")

    if args.dry_run:
        print(f"dry run complete: wrote {len(selected)} prompts under {out_dir}")
        return 0

    checker_out = run_checker(args, cfg, all_variants) if all_variants else {"accepted": [], "rejected": [], "summary": {}}
    write_text(out_dir / "checker.json", json.dumps(checker_out, indent=2) + "\n")

    for item in checker_out.get("accepted", []):
        base = out_dir / "accepted" / item["id"]
        write_text(base.with_suffix(".json"), json.dumps(item, indent=2) + "\n")
        write_text(out_dir / "accepted" / f"{item['id']}.a.syz", item.get("prog_a", ""))
        write_text(out_dir / "accepted" / f"{item['id']}.b.syz", item.get("prog_b", ""))
    for item in checker_out.get("rejected", []):
        write_text(out_dir / "rejected" / f"{item['id']}.json", json.dumps(item, indent=2) + "\n")

    accepted = len(checker_out.get("accepted", []))
    rejected = len(checker_out.get("rejected", []))
    returned = len(all_variants)
    summary = {
        **manifest,
        "variants_requested": request_count,
        "variants_returned": returned,
        "valid_json_variant_rate": returned / request_count if request_count else 0,
        "accepted_after_local_filter": accepted,
        "rejected_after_local_filter": rejected,
        "local_accept_rate": accepted / returned if returned else 0,
        "parse_failures": parse_failures,
        "pending_runtime_metrics": [
            "executable_rate",
            "new_pairs_per_generated_group",
            "new_varname_pairs",
            "new_stacks_per_existing_varname",
            "validation_yield",
        ],
    }
    write_text(out_dir / "summary.json", json.dumps(summary, indent=2) + "\n")
    write_text(
        out_dir / "summary.txt",
        textwrap.dedent(
            f"""
            module: {args.module}
            entries selected: {len(selected)}
            variants requested: {request_count}
            variants returned: {returned}
            accepted after local filter: {accepted}
            rejected after local filter: {rejected}
            valid JSON variant rate: {summary['valid_json_variant_rate']:.3f}
            local accept rate: {summary['local_accept_rate']:.3f}
            output: {out_dir}
            """
        ).strip()
        + "\n",
    )
    print((out_dir / "summary.txt").read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
