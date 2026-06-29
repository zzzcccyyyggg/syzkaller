#!/usr/bin/env python3
"""Summarize DeepSeek validate program-group/corpus accounting."""

from __future__ import annotations

import argparse
import csv
import json
import re
import struct
import zlib
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = (
    PROJECT_ROOT
    / "paper/results/llm-model-comparison/20260603-8module-3way-dynthresh-12h-as24h"
)
MODULE_ORDER = ["f2fs", "jfs", "xfs", "btrfs", "floppy", "ptmx", "dsp", "bt-stack"]
RUN_DIRS = {
    "f2fs": PROJECT_ROOT / "exp/f2fs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260603-100500",
    "jfs": PROJECT_ROOT / "exp/jfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260601-151816",
    "xfs": PROJECT_ROOT / "exp/xfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260601-151744",
    "btrfs": PROJECT_ROOT / "exp/btrfs/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260603-100425",
    "floppy": PROJECT_ROOT / "exp/floppy/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-031956",
    "ptmx": PROJECT_ROOT / "exp/ptmx/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-032028",
    "dsp": PROJECT_ROOT / "exp/dsp/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-152136",
    "bt-stack": PROJECT_ROOT / "exp/bt-stack/deepseek-dynthresh-maxstack20-vm4fuzz-vm8validate-12h-latestbz-20260602-152104",
}

DB_MAGIC = 0xBADDB
REC_MAGIC = 0xFEE1BAD
SEQ_DELETED = (1 << 64) - 1
TS_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
POLL_RE = re.compile(
    r"uaf validation queue: (?:initial load|poll) accepted=(\d+) acked=(\d+) pending=(\d+) seq=(\d+)"
)
ENTRY_SKIP_RE = re.compile(r"uafvalidate: skipping (?:entry|ref) \(all pairs high backoff score\): all (\d+) pairs")
SUMMARY_KEY_RE = re.compile(r"uafvalidate: verification phase summary key=(\S+)")
NO_STABLE_KEY_RE = re.compile(r"uafvalidate: no stable pairs key=(\S+)")


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def read_u32(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def read_u64(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from("<Q", data, offset)[0], offset + 8


def iter_db_records(path: Path, keep_values: bool = False) -> dict[str, tuple[int, bytes]]:
    data = path.read_bytes()
    offset = 0
    magic, offset = read_u32(data, offset)
    if magic != DB_MAGIC:
        raise ValueError(f"bad db magic in {path}: {magic:#x}")
    version, offset = read_u32(data, offset)
    if version >= 2:
        _, offset = read_u64(data, offset)

    records: dict[str, tuple[int, bytes]] = {}
    while offset < len(data):
        magic, offset = read_u32(data, offset)
        if magic != REC_MAGIC:
            raise ValueError(f"bad record magic in {path} at {offset - 4}: {magic:#x}")
        key_len, offset = read_u32(data, offset)
        key = data[offset : offset + key_len].decode("utf-8", errors="replace")
        offset += key_len
        seq, offset = read_u64(data, offset)
        if seq == SEQ_DELETED:
            records.pop(key, None)
            continue
        val_len, offset = read_u32(data, offset)
        raw = data[offset : offset + val_len]
        offset += val_len
        value = zlib.decompress(raw, -zlib.MAX_WBITS) if keep_values and val_len else b""
        records[key] = (seq, value)
    return records


def count_corpus_records(workdir: Path) -> int:
    return len(iter_db_records(workdir / "uaf-corpus.db", keep_values=False))


def queue_stats(workdir: Path) -> dict[str, int]:
    records = iter_db_records(workdir / "uaf-validate-queue.db", keep_values=True)
    groups: dict[str, int] = defaultdict(int)
    malformed = 0
    with_history = 0
    for _key, (_seq, value) in records.items():
        if not value:
            malformed += 1
            continue
        try:
            item = json.loads(value)
        except json.JSONDecodeError:
            malformed += 1
            continue
        corpus_id = item.get("corpus_record_id") or ""
        if corpus_id:
            groups[corpus_id] += 1
        else:
            malformed += 1
        if int(item.get("history_count") or 0) > 0:
            with_history += 1
    return {
        "queue_pending_pair_items_final": len(records),
        "queue_pending_program_groups_final": len(groups),
        "queue_pending_with_history_final": with_history,
        "queue_pending_malformed_final": malformed,
    }


def parse_log(log: Path) -> dict[str, int | str]:
    counts: dict[str, int | str] = {
        "verify_phase_program_groups": 0,
        "no_stable_program_groups": 0,
        "entry_backoff_skipped_groups": 0,
        "entry_backoff_skipped_pairs": 0,
        "task_errors": 0,
        "task_crashes": 0,
        "queue_poll_snapshots": 0,
        "queue_pending0_snapshots": 0,
        "queue_pending_min": "",
        "queue_pending_max": "",
        "queue_pending_last": "",
        "queue_pending0_first_ts": "",
        "queue_pending0_last_ts": "",
    }
    pending_values: list[int] = []
    verify_keys: set[str] = set()
    no_stable_keys: set[str] = set()
    with log.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            ts_match = TS_RE.match(line)
            ts = ts_match.group(1) if ts_match else ""
            summary_key = SUMMARY_KEY_RE.search(line)
            if summary_key:
                counts["verify_phase_program_groups"] = int(counts["verify_phase_program_groups"]) + 1
                verify_keys.add(summary_key.group(1))
            no_stable_key = NO_STABLE_KEY_RE.search(line)
            if no_stable_key:
                counts["no_stable_program_groups"] = int(counts["no_stable_program_groups"]) + 1
                no_stable_keys.add(no_stable_key.group(1))
            skip = ENTRY_SKIP_RE.search(line)
            if skip:
                counts["entry_backoff_skipped_groups"] = int(counts["entry_backoff_skipped_groups"]) + 1
                counts["entry_backoff_skipped_pairs"] = int(counts["entry_backoff_skipped_pairs"]) + int(skip.group(1))
            if "uafvalidate: task error " in line:
                counts["task_errors"] = int(counts["task_errors"]) + 1
            if "uafvalidate: task crash " in line:
                counts["task_crashes"] = int(counts["task_crashes"]) + 1
            poll = POLL_RE.search(line)
            if poll:
                pending = int(poll.group(3))
                pending_values.append(pending)
                counts["queue_poll_snapshots"] = int(counts["queue_poll_snapshots"]) + 1
                if pending == 0:
                    counts["queue_pending0_snapshots"] = int(counts["queue_pending0_snapshots"]) + 1
                    if not counts["queue_pending0_first_ts"]:
                        counts["queue_pending0_first_ts"] = ts
                    counts["queue_pending0_last_ts"] = ts
    if pending_values:
        counts["queue_pending_min"] = min(pending_values)
        counts["queue_pending_max"] = max(pending_values)
        counts["queue_pending_last"] = pending_values[-1]
    counts["collection_processed_program_groups"] = (
        int(counts["verify_phase_program_groups"]) + int(counts["no_stable_program_groups"])
    )
    counts["unique_verify_phase_program_groups"] = len(verify_keys)
    counts["unique_no_stable_program_groups"] = len(no_stable_keys)
    counts["unique_collection_processed_program_groups"] = len(verify_keys | no_stable_keys)
    counts["total_seen_by_validate_or_skipped_groups"] = (
        int(counts["collection_processed_program_groups"]) + int(counts["entry_backoff_skipped_groups"])
    )
    return counts


def threshold_stats(workdir: Path) -> dict[str, int | str | bool]:
    path = workdir / "threshold-state.json"
    if not path.exists():
        return {
            "threshold_processed_count": "",
            "threshold_pending_count": "",
            "threshold_idle": "",
        }
    validator = json.loads(path.read_text())["validator"]
    return {
        "threshold_processed_count": validator.get("processed_count", ""),
        "threshold_pending_count": validator.get("pending_count", ""),
        "threshold_idle": validator.get("idle", ""),
        "threshold_last_update": validator.get("last_update", ""),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=RESULTS_DIR / "deepseek_validate_program_groups.csv")
    args = parser.parse_args()

    rows: list[dict[str, int | str | bool]] = []
    for module in MODULE_ORDER:
        run_dir = RUN_DIRS[module]
        workdir = run_dir / "workdir"
        log = RESULTS_DIR / "source_data" / module / "deepseek-v4pro/logs/validate-manager.log"
        row: dict[str, int | str | bool] = {
            "module": module,
            "run_dir": rel(run_dir),
            "validate_log": rel(log),
            "corpus_program_groups_final": count_corpus_records(workdir),
            **queue_stats(workdir),
            **parse_log(log),
            **threshold_stats(workdir),
        }
        rows.append(row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(args.output)
    cols = [
        "module",
        "corpus_program_groups_final",
        "unique_collection_processed_program_groups",
        "collection_processed_program_groups",
        "verify_phase_program_groups",
        "no_stable_program_groups",
        "entry_backoff_skipped_groups",
        "queue_pending_program_groups_final",
        "queue_pending0_snapshots",
        "threshold_idle",
    ]
    print(",".join(cols))
    for row in rows:
        print(",".join(str(row[col]) for col in cols))


if __name__ == "__main__":
    main()
