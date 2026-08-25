#!/usr/bin/env python3
"""Recover exact CLI token usage for completed MRPFuzz runs."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools" / "llm-mutate-pilot"))

from pilot import add_token_usage, grok_cli_prompt, normalize_token_usage  # noqa: E402


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def digest_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return digest_text(encoded)


def parse_timestamp(value: str, fallback: float) -> float:
    if not value:
        return fallback
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return fallback


def load_expected_calls(run_dir: Path) -> list[dict[str, Any]]:
    prompt_dir = run_dir / "kimi" / "prompts"
    raw_dir = run_dir / "kimi" / "raw"
    calls = []
    for system_path in sorted(prompt_dir.glob("*.system.txt")):
        prefix = system_path.name.removesuffix(".system.txt")
        user_path = prompt_dir / f"{prefix}.user.txt"
        raw_path = raw_dir / f"{prefix}.json"
        if not user_path.exists() or not raw_path.exists():
            continue
        system = system_path.read_text(encoding="utf-8").rstrip("\n")
        user = user_path.read_text(encoding="utf-8").rstrip("\n")
        try:
            output = json.loads(raw_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        calls.append(
            {
                "run_dir": run_dir,
                "prefix": prefix,
                "timestamp": system_path.stat().st_mtime,
                "fingerprint": (digest_text(grok_cli_prompt(system, user)), digest_json(output)),
            }
        )
    return calls


def load_session_output(session_dir: Path) -> Any | None:
    path = session_dir / "chat_history.jsonl"
    if not path.exists():
        return None
    output = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("type") != "assistant" or not isinstance(item.get("content"), str):
            continue
        try:
            output = json.loads(item["content"])
        except json.JSONDecodeError:
            continue
    return output


def load_session_usage(session_dir: Path) -> dict[str, Any]:
    path = session_dir / "updates.jsonl"
    if not path.exists():
        return {}
    usage: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        update = ((item.get("params") or {}).get("update") or {})
        if update.get("sessionUpdate") != "turn_completed":
            continue
        usage = normalize_token_usage(update.get("usage") or {})
        ticks = (update.get("usage") or {}).get("costUsdTicks")
        if isinstance(ticks, (int, float)) and not isinstance(ticks, bool):
            usage["cost_usd"] = float(ticks) / 10_000_000_000
    return usage


def load_grok_sessions(grok_home: Path, wanted_prompts: set[str]) -> list[dict[str, Any]]:
    sessions = []
    pattern = "%2Ftmp%2Fmrpfuzz-grok-cli-*/prompt_history.jsonl"
    for history_path in (grok_home / "sessions").glob(pattern):
        for line in history_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            prompt = item.get("prompt")
            session_id = item.get("session_id")
            if not isinstance(prompt, str) or not session_id:
                continue
            prompt_digest = digest_text(prompt)
            if prompt_digest not in wanted_prompts:
                continue
            session_dir = history_path.parent / str(session_id)
            output = load_session_output(session_dir)
            if output is None:
                continue
            usage = load_session_usage(session_dir)
            if not usage:
                continue
            sessions.append(
                {
                    "session_id": str(session_id),
                    "timestamp": parse_timestamp(str(item.get("timestamp") or ""), history_path.stat().st_mtime),
                    "fingerprint": (prompt_digest, digest_json(output)),
                    "usage": usage,
                }
            )
    return sessions


def summarize_recovery(
    run_dirs: list[Path],
    expected: list[dict[str, Any]],
    recovered: dict[Path, list[dict[str, Any]]],
    provider: str,
) -> list[dict[str, Any]]:
    summaries = []
    for run_dir in run_dirs:
        expected_calls = sum(1 for item in expected if item["run_dir"] == run_dir)
        matched = recovered.get(run_dir, [])
        usage: dict[str, Any] = {}
        for item in matched:
            add_token_usage(usage, item["usage"])
        summary = {
            "run_id": run_dir.name,
            "provider": provider,
            "usage_quality": "exact-cli-session-recovery",
            "expected_successful_calls": expected_calls,
            "recovered_calls": len(matched),
            "missing_calls": expected_calls - len(matched),
            "usage": usage,
        }
        output_path = run_dir / "kimi" / "usage-summary.json"
        output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        summaries.append(summary)
    return summaries


def recover_grok(run_dirs: list[Path], grok_home: Path) -> list[dict[str, Any]]:
    expected = []
    for run_dir in run_dirs:
        expected.extend(load_expected_calls(run_dir))

    by_fingerprint: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for call in expected:
        by_fingerprint[call["fingerprint"]].append(call)
    wanted_prompts = {fingerprint[0] for fingerprint in by_fingerprint}

    sessions_by_fingerprint: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for session in load_grok_sessions(grok_home, wanted_prompts):
        sessions_by_fingerprint[session["fingerprint"]].append(session)

    recovered: dict[Path, list[dict[str, Any]]] = collections.defaultdict(list)
    for fingerprint, calls in by_fingerprint.items():
        calls.sort(key=lambda item: item["timestamp"])
        sessions = sorted(sessions_by_fingerprint.get(fingerprint, []), key=lambda item: item["timestamp"])
        for call, session in zip(calls, sessions):
            recovered[call["run_dir"]].append({**call, **session})

    return summarize_recovery(run_dirs, expected, recovered, "grok-cli")


def load_expected_prompt_calls(run_dir: Path) -> list[dict[str, Any]]:
    prompt_dir = run_dir / "kimi" / "prompts"
    raw_dir = run_dir / "kimi" / "raw"
    calls = []
    for system_path in sorted(prompt_dir.glob("*.system.txt")):
        prefix = system_path.name.removesuffix(".system.txt")
        user_path = prompt_dir / f"{prefix}.user.txt"
        raw_path = raw_dir / f"{prefix}.txt"
        if not user_path.exists() or not raw_path.exists():
            continue
        system = system_path.read_text(encoding="utf-8").rstrip("\n")
        user = user_path.read_text(encoding="utf-8").rstrip("\n")
        calls.append(
            {
                "run_dir": run_dir,
                "prefix": prefix,
                "timestamp": system_path.stat().st_mtime,
                "fingerprint": digest_text(grok_cli_prompt(system, user)),
            }
        )
    return calls


def load_kimi_sessions(kimi_home: Path, wanted_prompts: set[str]) -> list[dict[str, Any]]:
    sessions = []
    pattern = "wd_mrpfuzz-kimi-cli-*/session_*"
    for session_dir in (kimi_home / "sessions").glob(pattern):
        wire_path = session_dir / "agents" / "main" / "wire.jsonl"
        if not wire_path.exists():
            continue
        prompt = ""
        usage: dict[str, Any] = {}
        model = ""
        for line in wire_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("type") == "turn.prompt":
                prompt = "".join(
                    part.get("text", "")
                    for part in item.get("input", [])
                    if isinstance(part, dict) and part.get("type") == "text"
                )
            elif item.get("type") == "usage.record":
                add_token_usage(usage, normalize_token_usage(item.get("usage") or {}))
                model = str(item.get("model") or model)
        prompt_digest = digest_text(prompt) if prompt else ""
        if prompt_digest not in wanted_prompts or not usage:
            continue
        state_path = session_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        sessions.append(
            {
                "session_id": session_dir.name,
                "timestamp": float(state.get("createdAt", 0)) / 1000 or wire_path.stat().st_mtime,
                "fingerprint": prompt_digest,
                "model": model,
                "usage": usage,
            }
        )
    return sessions


def recover_kimi(run_dirs: list[Path], kimi_home: Path) -> list[dict[str, Any]]:
    expected = []
    for run_dir in run_dirs:
        expected.extend(load_expected_prompt_calls(run_dir))
    by_fingerprint: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for call in expected:
        by_fingerprint[call["fingerprint"]].append(call)
    sessions_by_fingerprint: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for session in load_kimi_sessions(kimi_home, set(by_fingerprint)):
        sessions_by_fingerprint[session["fingerprint"]].append(session)
    recovered: dict[Path, list[dict[str, Any]]] = collections.defaultdict(list)
    for fingerprint, calls in by_fingerprint.items():
        calls.sort(key=lambda item: item["timestamp"])
        sessions = sorted(sessions_by_fingerprint.get(fingerprint, []), key=lambda item: item["timestamp"])
        for call, session in zip(calls, sessions):
            recovered[call["run_dir"]].append({**call, **session})
    return summarize_recovery(run_dirs, expected, recovered, "kimi-cli")


def run_provider(run_dir: Path) -> str:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        return ""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return str((manifest.get("kimi") or {}).get("provider") or "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dirs", nargs="+", type=Path)
    parser.add_argument("--grok-home", type=Path, default=Path.home() / ".grok")
    parser.add_argument("--kimi-home", type=Path, default=Path.home() / ".kimi-code")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    run_dirs = [path.resolve() for path in args.run_dirs]
    grouped: dict[str, list[Path]] = collections.defaultdict(list)
    for run_dir in run_dirs:
        grouped[run_provider(run_dir)].append(run_dir)
    summaries = []
    if grouped.get("grok-cli"):
        summaries.extend(recover_grok(grouped["grok-cli"], args.grok_home.expanduser()))
    if grouped.get("kimi-cli"):
        summaries.extend(recover_kimi(grouped["kimi-cli"], args.kimi_home.expanduser()))
    unsupported = sorted(provider for provider in grouped if provider not in ("grok-cli", "kimi-cli"))
    result = {
        "generated_at": dt.datetime.now().astimezone().isoformat(),
        "runs": summaries,
        "unsupported_providers": unsupported,
    }
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
