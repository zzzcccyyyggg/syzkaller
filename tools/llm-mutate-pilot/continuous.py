#!/usr/bin/env python3
"""Continuous LLM seed producer for MRPFuzz input exploration.

This tool intentionally runs outside syz-manager: it reads newly discovered UAF
corpus entries, asks an LLM for bounded semantic variants, runs the local
parser/filter, and writes accepted two-program groups to a seed directory that
syz-manager can poll.
"""

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import pathlib
import time
from typing import Any

from pilot import (
    DEFAULT_BASE_URL,
    DEFAULT_CODEX_MODEL,
    DEFAULT_KIMI_BASE_URL,
    DEFAULT_KIMI_MODEL,
    DEFAULT_MODEL,
    DEFAULT_MOUNT,
    build_prompt,
    call_llm,
    effective_model,
    extract_json_object,
    load_config,
    load_kccwf_pools,
    normalize_variants,
    run_checker,
    run_uaf_corpus,
    select_entries,
    write_text,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--module", default="jfs")
    parser.add_argument("--out", default="")
    parser.add_argument("--entries-per-round", type=int, default=4)
    parser.add_argument("--variants-per-entry", type=int, default=2)
    parser.add_argument("--max-varname-count", type=int, default=10)
    parser.add_argument("--max-calls", type=int, default=8)
    parser.add_argument("--mount-prefix", default=DEFAULT_MOUNT)
    parser.add_argument("--source", default="fuzz", choices=["fuzz", "timing", "all"])
    parser.add_argument("--poll-sec", type=int, default=30)
    parser.add_argument("--parallel-calls", type=int, default=2, help="number of concurrent LLM calls per round")
    parser.add_argument("--max-rounds", type=int, default=0, help="0 means run until killed")
    parser.add_argument("--max-total-accepted", type=int, default=0, help="0 means no cap")
    parser.add_argument("--provider", choices=["deepseek", "kimi", "codex"], default=os.environ.get("LLM_PROVIDER", "deepseek"))
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", os.environ.get("DEEPSEEK_BASE_URL", "")))
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", os.environ.get("DEEPSEEK_MODEL", "")))
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-tokens", type=int, default=int(os.environ.get("LLM_MAX_TOKENS", "0") or "0"))
    parser.add_argument("--thinking", choices=["enabled", "disabled"], default=os.environ.get("DEEPSEEK_THINKING", "disabled"))
    parser.add_argument("--reasoning-effort", choices=["high", "max"], default=os.environ.get("DEEPSEEK_REASONING_EFFORT", "high"))
    parser.add_argument("--timeout-sec", type=int, default=600)
    parser.add_argument("--codex-bin", default=os.environ.get("CODEX_BIN", "codex"))
    parser.add_argument("--codex-model", default=os.environ.get("CODEX_MODEL", DEFAULT_CODEX_MODEL))
    parser.add_argument("--codex-profile", default=os.environ.get("CODEX_PROFILE", ""))
    parser.add_argument("--codex-sandbox", choices=["read-only", "workspace-write", "danger-full-access"], default=os.environ.get("CODEX_SANDBOX", "read-only"))
    parser.add_argument("--codex-reasoning-effort", choices=["low", "medium", "high", "xhigh"], default=os.environ.get("CODEX_REASONING_EFFORT", "medium"))
    parser.add_argument("--api-key-file", default=os.environ.get("LLM_API_KEY_FILE", os.environ.get("DEEPSEEK_API_KEY_FILE", "")))
    parser.add_argument("--api-key-index", type=int, default=int(os.environ.get("DEEPSEEK_API_KEY_INDEX", "-1")))
    parser.add_argument("--api-key-alias", default=os.environ.get("DEEPSEEK_API_KEY_ALIAS", ""))
    parser.add_argument("--checker", default="./tools/syz-llm-candidate-check")
    return parser.parse_args()


def default_out_dir(module: str) -> pathlib.Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return pathlib.Path("paper/results/llm-mutate-continuous") / f"{module}-{stamp}"


def load_state(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "created_at": dt.datetime.now().isoformat(),
            "processed_entry_keys": [],
            "rounds": [],
            "totals": {
                "entries_processed": 0,
                "variants_requested": 0,
                "variants_returned": 0,
                "accepted": 0,
                "rejected": 0,
                "api_failures": 0,
                "json_failures": 0,
            },
        }
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path: pathlib.Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def api_key_from_args(args: argparse.Namespace) -> tuple[str, str, int, int]:
    if args.provider == "codex":
        return "", f"codex:{effective_model(args)}", -1, 0
    key_file = args.api_key_file
    if not key_file and args.provider == "kimi":
        key_file = os.environ.get("KIMI_API_KEY_FILE", "")
    if key_file:
        key_path = pathlib.Path(key_file).expanduser()
        keys = [
            line.strip()
            for line in key_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not keys:
            raise SystemExit(f"no API keys found in {key_path}")
        idx = args.api_key_index if args.api_key_index >= 0 else 0
        idx %= len(keys)
        alias = args.api_key_alias or f"key-{idx + 1}"
        return keys[idx], alias, idx, len(keys)

    if args.provider == "kimi":
        key = os.environ.get("KIMI_API_KEY", os.environ.get("LLM_API_KEY", "")).strip()
    else:
        key = os.environ.get("DEEPSEEK_API_KEY", os.environ.get("LLM_API_KEY", "")).strip()
    if not key:
        raise SystemExit(f"API key is not set for provider {args.provider}")
    alias = args.api_key_alias or os.environ.get("LLM_API_KEY_ALIAS", os.environ.get("DEEPSEEK_API_KEY_ALIAS", "env-key"))
    return key, alias, -1, 1


def processed_set(state: dict[str, Any]) -> set[str]:
    return {str(key) for key in state.get("processed_entry_keys", [])}


def append_processed(state: dict[str, Any], keys: list[str]) -> None:
    done = processed_set(state)
    ordered = list(state.get("processed_entry_keys", []))
    for key in keys:
        if key and key not in done:
            done.add(key)
            ordered.append(key)
    state["processed_entry_keys"] = ordered


def write_checked_outputs(out_dir: pathlib.Path, checker_out: dict[str, Any]) -> None:
    for item in checker_out.get("accepted") or []:
        base = out_dir / "accepted" / item["id"]
        write_text(base.with_suffix(".json"), json.dumps(item, indent=2) + "\n")
        write_text(out_dir / "accepted" / f"{item['id']}.a.syz", item.get("prog_a", ""))
        write_text(out_dir / "accepted" / f"{item['id']}.b.syz", item.get("prog_b", ""))
    for item in checker_out.get("rejected") or []:
        write_text(out_dir / "rejected" / f"{item['id']}.json", json.dumps(item, indent=2) + "\n")


def generate_entry_variants(
    args: argparse.Namespace,
    cfg: dict[str, Any],
    object_pools: dict[str, list[str]],
    out_dir: pathlib.Path,
    counts: dict[str, int],
    api_key: str,
    round_idx: int,
    idx: int,
    entry: dict[str, Any],
) -> dict[str, Any]:
    key = str(entry.get("key") or f"round{round_idx}-entry{idx}")
    started = time.time()
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
    prefix = f"r{round_idx:04d}-{idx:02d}-{key[:10]}"
    write_text(out_dir / "prompts" / f"{prefix}.system.txt", system + "\n")
    write_text(out_dir / "prompts" / f"{prefix}.user.txt", user + "\n")
    try:
        content = call_llm(args, api_key, system, user)
    except Exception as exc:
        error = str(exc)
        return {
            "entry_key": key,
            "api_failure": error,
            "api_elapsed_sec": round(time.time() - started, 3),
            "rate_limited": "429" in error or "rate limit" in error.lower(),
            "variants": [],
        }
    write_text(out_dir / "raw" / f"{prefix}.txt", content + "\n")
    elapsed = round(time.time() - started, 3)
    try:
        raw_json = extract_json_object(content)
    except Exception as exc:
        return {"entry_key": key, "json_failure": str(exc), "api_elapsed_sec": elapsed, "variants": []}
    write_text(out_dir / "raw" / f"{prefix}.json", json.dumps(raw_json, indent=2) + "\n")
    return {
        "entry_key": key,
        "api_elapsed_sec": elapsed,
        "variants": normalize_variants(raw_json, key),
    }


def run_round(
    args: argparse.Namespace,
    cfg: dict[str, Any],
    object_pools: dict[str, list[str]],
    out_dir: pathlib.Path,
    state: dict[str, Any],
    api_key: str,
    round_idx: int,
) -> dict[str, Any]:
    round_started = time.time()
    round_info: dict[str, Any] = {
        "round": round_idx,
        "started_at": dt.datetime.now().isoformat(),
        "provider": args.provider,
        "model": effective_model(args),
        "thinking": args.thinking,
        "reasoning_effort": args.reasoning_effort if args.thinking == "enabled" else "",
        "max_tokens": args.max_tokens,
        "eligible_entries": 0,
        "selected": [],
        "variants_requested": 0,
        "variants_returned": 0,
        "accepted": 0,
        "rejected": 0,
        "api_failures": [],
        "api_calls": [],
        "rate_limited": 0,
        "json_failures": [],
    }
    try:
        entries = run_uaf_corpus(args.config, cfg.get("workdir", ""), args.source) or []
    except Exception as exc:
        round_info["uaf_corpus_error"] = str(exc)
        round_info["finished_at"] = dt.datetime.now().isoformat()
        return round_info
    selected, counts = select_entries(
        entries,
        args.entries_per_round,
        args.max_varname_count,
        exclude_keys=processed_set(state),
    )
    round_info.update(
        {
            "eligible_entries": len(entries),
            "selected": [entry.get("key") for entry in selected],
            "variants_requested": len(selected) * args.variants_per_entry,
        }
    )
    if not selected:
        round_info["finished_at"] = dt.datetime.now().isoformat()
        return round_info

    variants: list[dict[str, str]] = []
    processed_keys: list[str] = []
    max_workers = max(1, min(args.parallel_calls, len(selected)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                generate_entry_variants,
                args,
                cfg,
                object_pools,
                out_dir,
                counts,
                api_key,
                round_idx,
                idx,
                entry,
            )
            for idx, entry in enumerate(selected, start=1)
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            key = result.get("entry_key", "")
            call_info = {
                "entry_key": key,
                "elapsed_sec": result.get("api_elapsed_sec"),
                "variants": len(result.get("variants") or []),
                "status": "ok",
            }
            if result.get("api_failure"):
                call_info["status"] = "api_failure"
                if result.get("rate_limited"):
                    call_info["status"] = "rate_limited"
                    round_info["rate_limited"] += 1
                round_info["api_calls"].append(call_info)
                round_info["api_failures"].append({"entry_key": key, "error": result["api_failure"]})
                continue
            if result.get("json_failure"):
                call_info["status"] = "json_failure"
                round_info["api_calls"].append(call_info)
                round_info["json_failures"].append({"entry_key": key, "error": result["json_failure"]})
                processed_keys.append(key)
                continue
            round_info["api_calls"].append(call_info)
            variants.extend(result.get("variants") or [])
            processed_keys.append(key)

    round_info["variants_returned"] = len(variants)
    if variants:
        checker_out = run_checker(args, cfg, variants)
        write_text(out_dir / "checks" / f"round-{round_idx:04d}.json", json.dumps(checker_out, indent=2) + "\n")
        write_checked_outputs(out_dir, checker_out)
        round_info["accepted"] = len(checker_out.get("accepted") or [])
        round_info["rejected"] = len(checker_out.get("rejected") or [])
    append_processed(state, processed_keys)
    round_info["round_elapsed_sec"] = round(time.time() - round_started, 3)
    round_info["finished_at"] = dt.datetime.now().isoformat()
    return round_info


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    out_dir = pathlib.Path(args.out) if args.out else default_out_dir(args.module)
    for sub in ["prompts", "raw", "checks", "accepted", "rejected"]:
        (out_dir / sub).mkdir(parents=True, exist_ok=True)
    state_path = out_dir / "state.json"
    state = load_state(state_path)
    object_pools = load_kccwf_pools()
    api_key, api_key_alias, api_key_index, api_key_pool_size = api_key_from_args(args)

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
        "codex_reasoning_effort": args.codex_reasoning_effort if args.provider == "codex" else "",
        "temperature": args.temperature,
        "thinking": args.thinking,
        "reasoning_effort": args.reasoning_effort if args.thinking == "enabled" else "",
        "timeout_sec": args.timeout_sec,
        "entries_per_round": args.entries_per_round,
        "variants_per_entry": args.variants_per_entry,
        "poll_sec": args.poll_sec,
        "parallel_calls": args.parallel_calls,
        "max_calls": args.max_calls,
        "api_key_alias": api_key_alias,
        "api_key_index": api_key_index,
        "api_key_pool_size": api_key_pool_size,
    }
    write_text(out_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")

    round_idx = len(state.get("rounds", []))
    while True:
        round_idx += 1
        if args.max_rounds > 0 and round_idx > args.max_rounds:
            break
        totals = state.setdefault("totals", {})
        if args.max_total_accepted > 0 and int(totals.get("accepted", 0)) >= args.max_total_accepted:
            break

        info = run_round(args, cfg, object_pools, out_dir, state, api_key, round_idx)
        state.setdefault("rounds", []).append(info)
        totals["entries_processed"] = int(totals.get("entries_processed", 0)) + len(info.get("selected", []))
        totals["variants_requested"] = int(totals.get("variants_requested", 0)) + int(info.get("variants_requested", 0))
        totals["variants_returned"] = int(totals.get("variants_returned", 0)) + int(info.get("variants_returned", 0))
        totals["accepted"] = int(totals.get("accepted", 0)) + int(info.get("accepted", 0))
        totals["rejected"] = int(totals.get("rejected", 0)) + int(info.get("rejected", 0))
        totals["api_failures"] = int(totals.get("api_failures", 0)) + len(info.get("api_failures", []))
        totals["rate_limited"] = int(totals.get("rate_limited", 0)) + int(info.get("rate_limited", 0))
        totals["json_failures"] = int(totals.get("json_failures", 0)) + len(info.get("json_failures", []))
        save_state(state_path, state)

        api_elapsed = [
            float(call.get("elapsed_sec"))
            for call in info.get("api_calls", [])
            if isinstance(call.get("elapsed_sec"), (int, float))
        ]
        avg_api = sum(api_elapsed) / len(api_elapsed) if api_elapsed else 0.0
        max_api = max(api_elapsed) if api_elapsed else 0.0
        print(
            "round={round} selected={sel} returned={ret} accepted={acc} rejected={rej} "
            "rate_limited={rl} key={key} round_sec={round_sec:.1f} api_avg={api_avg:.1f} api_max={api_max:.1f} out={out}".format(
                round=info["round"],
                sel=len(info.get("selected", [])),
                ret=info.get("variants_returned", 0),
                acc=info.get("accepted", 0),
                rej=info.get("rejected", 0),
                rl=info.get("rate_limited", 0),
                key=api_key_alias,
                round_sec=float(info.get("round_elapsed_sec") or 0),
                api_avg=avg_api,
                api_max=max_api,
                out=out_dir,
            ),
            flush=True,
        )
        if args.max_rounds > 0 and round_idx >= args.max_rounds:
            break
        time.sleep(max(args.poll_sec, 5))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
