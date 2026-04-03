#!/usr/bin/env bash
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# ============================================================
# collect_pairs.sh - 统一的并发对数收集包装脚本
#
# 用于在 Conzzer / SegFuzz 实验运行期间 or 完成后，
# 提取并发对数时间序列数据并生成对比图。
#
# 用法:
#   ./collect_pairs.sh collect-conzzer <module> [options]
#   ./collect_pairs.sh collect-segfuzz <module> [options]
#   ./collect_pairs.sh collect-all <module> [options]
#   ./collect_pairs.sh plot <module> [options]
#   ./collect_pairs.sh live-conzzer <module>
#   ./collect_pairs.sh live-segfuzz <module>
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASS_DIR="${BASS_DIR:-/home/zzzccc/BASS}"

# 项目根目录
CONZZER_DIR="${BASS_DIR}/Conzzer"
SEGFUZZ_DIR="${BASS_DIR}/segfuzz"
DDRD_DIR="${BASS_DIR}/DDRD-syzkaller"

# 默认输出目录
OUTPUT_BASE="${OUTPUT_BASE:-${SCRIPT_DIR}/results}"

# Python 脚本路径
COLLECT_CONZZER="${SCRIPT_DIR}/collect_conzzer_pairs.py"
COLLECT_SEGFUZZ="${SCRIPT_DIR}/collect_segfuzz_pairs.py"
PLOT_COMPARISON="${SCRIPT_DIR}/plot_comparison.py"

# 支持的模块
MODULES=(xfs btrfs f2fs jfs floppy usb-driver video wifi-stack bt-stack ptmx dsp)

# ============================================================
# Helper functions
# ============================================================

log() { echo "[$(date '+%H:%M:%S')] $*"; }
err() { echo "[ERROR] $*" >&2; }
die() { err "$*"; exit 1; }

check_module() {
    local mod="$1"
    local found=0
    for m in "${MODULES[@]}"; do
        if [[ "$m" == "$mod" ]]; then found=1; break; fi
    done
    if [[ $found -eq 0 ]]; then
        die "Unknown module: $mod. Supported: ${MODULES[*]}"
    fi
}

ensure_output_dir() {
    local mod="$1"
    local dir="${OUTPUT_BASE}/${mod}"
    mkdir -p "$dir"
    echo "$dir"
}

# ============================================================
# Conzzer 数据源路径查找
# ============================================================

find_conzzer_plot_curve() {
    local mod="$1"
    local candidates=(
        "${CONZZER_DIR}/exp/${mod}/fuzz/output/plot-curve"
        "${CONZZER_DIR}/exp/${mod}/fuzz/output/plot_curve"
        "${CONZZER_DIR}/exp/${mod}/output/plot-curve"
    )
    for f in "${candidates[@]}"; do
        if [[ -f "$f" ]]; then
            echo "$f"
            return 0
        fi
    done
    # 动态搜索
    local found
    found="$(find "${CONZZER_DIR}/exp/${mod}" -name 'plot-curve' -o -name 'plot_curve' 2>/dev/null | head -1)"
    if [[ -n "$found" ]]; then
        echo "$found"
        return 0
    fi
    return 1
}

# ============================================================
# SegFuzz 数据源路径查找
# ============================================================

find_segfuzz_log() {
    local mod="$1"
    local candidates=(
        "${SEGFUZZ_DIR}/exp/segfuzz-comparison/${mod}/workdir/log"
        "${SEGFUZZ_DIR}/exp/${mod}/workdir/log"
        "${SEGFUZZ_DIR}/exp/x86_64/workdir/log"
    )
    for f in "${candidates[@]}"; do
        if [[ -f "$f" ]]; then
            echo "$f"
            return 0
        fi
    done
    return 1
}

find_segfuzz_bench() {
    local mod="$1"
    local dir="${SEGFUZZ_DIR}/exp/segfuzz-comparison/${mod}/workdir"
    if [[ -d "$dir" ]]; then
        local latest
        latest="$(ls -t "${dir}"/bench-*.txt 2>/dev/null | head -1)"
        if [[ -n "$latest" ]]; then
            echo "$latest"
            return 0
        fi
    fi
    # 尝试 x86_64 目录
    dir="${SEGFUZZ_DIR}/exp/x86_64/workdir"
    if [[ -d "$dir" ]]; then
        local latest
        latest="$(ls -t "${dir}"/bench-*.txt 2>/dev/null | head -1)"
        if [[ -n "$latest" ]]; then
            echo "$latest"
            return 0
        fi
    fi
    return 1
}

# ============================================================
# DDRD 数据源路径查找
# ============================================================

find_ddrd_timeseries() {
    local mod="$1"
    # 搜索 DDRD 的 race_timeseries.csv (由 run-with-collector.sh 生成)
    local candidates=(
        "${DDRD_DIR}/exp/${mod}/race_timeseries.csv"
        "${DDRD_DIR}/test/DDRD/workdir-${mod}/race_timeseries.csv"
    )
    # 也搜索批量实验目录
    for d in "${DDRD_DIR}"/batch_detect_results*/; do
        if [[ -d "${d}${mod}" ]]; then
            for f in "${d}${mod}"/*timeseries*.csv; do
                [[ -f "$f" ]] && candidates+=("$f")
            done
        fi
    done
    for f in "${candidates[@]}"; do
        if [[ -f "$f" ]]; then
            echo "$f"
            return 0
        fi
    done
    return 1
}

# ============================================================
# 收集命令
# ============================================================

cmd_collect_conzzer() {
    local mod="$1"; shift
    check_module "$mod"
    local outdir; outdir="$(ensure_output_dir "$mod")"
    local output="${outdir}/conzzer_${mod}.csv"

    local plot_curve
    if ! plot_curve="$(find_conzzer_plot_curve "$mod")"; then
        die "Cannot find Conzzer plot-curve for module '$mod'"
    fi

    log "Collecting Conzzer data for module: $mod"
    log "  Source: $plot_curve"
    log "  Output: $output"

    python3 "$COLLECT_CONZZER" "$plot_curve" -o "$output" "$@"
}

cmd_collect_segfuzz() {
    local mod="$1"; shift
    check_module "$mod"
    local outdir; outdir="$(ensure_output_dir "$mod")"
    local output="${outdir}/segfuzz_${mod}.csv"

    # 优先使用 log, 回退到 bench
    local source_type="log"
    local source_file
    if source_file="$(find_segfuzz_log "$mod")"; then
        source_type="log"
    elif source_file="$(find_segfuzz_bench "$mod")"; then
        source_type="bench"
    else
        die "Cannot find SegFuzz log or bench file for module '$mod'"
    fi

    log "Collecting SegFuzz data for module: $mod"
    log "  Source ($source_type): $source_file"
    log "  Output: $output"

    python3 "$COLLECT_SEGFUZZ" "$source_type" "$source_file" -o "$output" "$@"
}

cmd_collect_all() {
    local mod="$1"; shift
    check_module "$mod"

    log "Collecting all available data for module: $mod"

    # Conzzer
    if find_conzzer_plot_curve "$mod" >/dev/null 2>&1; then
        cmd_collect_conzzer "$mod" "$@" || log "Warning: Conzzer collection failed for $mod"
    else
        log "  Conzzer: No data found for $mod"
    fi

    # SegFuzz
    if find_segfuzz_log "$mod" >/dev/null 2>&1 || find_segfuzz_bench "$mod" >/dev/null 2>&1; then
        cmd_collect_segfuzz "$mod" "$@" || log "Warning: SegFuzz collection failed for $mod"
    else
        log "  SegFuzz: No data found for $mod"
    fi

    log "Collection complete for $mod"
}

# ============================================================
# 实时监控命令
# ============================================================

cmd_live_conzzer() {
    local mod="$1"
    check_module "$mod"
    local outdir; outdir="$(ensure_output_dir "$mod")"
    local output="${outdir}/conzzer_${mod}_live.csv"

    local plot_curve
    plot_curve="${CONZZER_DIR}/exp/${mod}/fuzz/output/plot-curve"

    log "Starting live Conzzer pair collection for: $mod"
    log "  Watching: $plot_curve"
    log "  Output:   $output"

    python3 "$COLLECT_CONZZER" "$plot_curve" -o "$output" --live
}

cmd_live_segfuzz() {
    local mod="$1"
    check_module "$mod"
    local outdir; outdir="$(ensure_output_dir "$mod")"
    local output="${outdir}/segfuzz_${mod}_live.csv"

    local log_file
    log_file="${SEGFUZZ_DIR}/exp/segfuzz-comparison/${mod}/workdir/log"

    log "Starting live SegFuzz pair collection for: $mod"
    log "  Watching: $log_file"
    log "  Output:   $output"

    python3 "$COLLECT_SEGFUZZ" log "$log_file" -o "$output" --live
}

# ============================================================
# 绘图命令
# ============================================================

cmd_plot() {
    local mod="$1"; shift
    check_module "$mod"
    local outdir; outdir="$(ensure_output_dir "$mod")"

    local plot_args=()
    plot_args+=(--target "$mod")

    # 自动查找各工具的 CSV 数据
    local ddrd_csv="${outdir}/ddrd_${mod}.csv"
    local conzzer_csv="${outdir}/conzzer_${mod}.csv"
    local segfuzz_csv="${outdir}/segfuzz_${mod}.csv"

    # 也查找 DDRD 原始数据
    local ddrd_src
    if [[ -f "$ddrd_csv" ]]; then
        plot_args+=(--ddrd "$ddrd_csv")
    elif ddrd_src="$(find_ddrd_timeseries "$mod" 2>/dev/null)"; then
        plot_args+=(--ddrd "$ddrd_src")
    fi

    if [[ -f "$conzzer_csv" ]]; then
        plot_args+=(--conzzer "$conzzer_csv")
    fi

    if [[ -f "$segfuzz_csv" ]]; then
        plot_args+=(--segfuzz "$segfuzz_csv")
    fi

    local output="${outdir}/comparison_${mod}.png"
    plot_args+=(-o "$output")
    plot_args+=("$@")

    if [[ ${#plot_args[@]} -le 3 ]]; then
        die "No data found for module '$mod'. Run collect commands first."
    fi

    log "Generating comparison plot for: $mod"
    python3 "$PLOT_COMPARISON" "${plot_args[@]}"
}

# ============================================================
# 批量操作
# ============================================================

cmd_collect_batch() {
    local tool="$1"; shift
    local failed=()

    for mod in "${MODULES[@]}"; do
        log "Processing module: $mod"
        case "$tool" in
            conzzer)
                cmd_collect_conzzer "$mod" "$@" 2>/dev/null || {
                    log "  Skipped: No Conzzer data for $mod"
                    failed+=("$mod")
                }
                ;;
            segfuzz)
                cmd_collect_segfuzz "$mod" "$@" 2>/dev/null || {
                    log "  Skipped: No SegFuzz data for $mod"
                    failed+=("$mod")
                }
                ;;
            all)
                cmd_collect_all "$mod" "$@" 2>/dev/null || {
                    failed+=("$mod")
                }
                ;;
        esac
    done

    log "Batch complete. Skipped modules: ${failed[*]:-none}"
}

cmd_plot_batch() {
    local failed=()
    for mod in "${MODULES[@]}"; do
        cmd_plot "$mod" "$@" 2>/dev/null || {
            log "  Skipped: No data for $mod"
            failed+=("$mod")
        }
    done
    log "Batch plot complete. Skipped: ${failed[*]:-none}"
}

# ============================================================
# 状态查看
# ============================================================

cmd_status() {
    local mod="${1:-}"

    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║            Pair Collection Data Status                       ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    printf "║ %-12s │ %-10s │ %-10s │ %-10s ║\n" "Module" "DDRD" "Conzzer" "SegFuzz"
    echo "╠════════════════════════════════════════════════════════════════╣"

    local modules_to_check=("${MODULES[@]}")
    if [[ -n "$mod" ]]; then
        modules_to_check=("$mod")
    fi

    for m in "${modules_to_check[@]}"; do
        local ddrd_status="—"
        local conzzer_status="—"
        local segfuzz_status="—"

        # Check DDRD
        if find_ddrd_timeseries "$m" >/dev/null 2>&1; then
            ddrd_status="✓ found"
        fi

        # Check Conzzer
        if find_conzzer_plot_curve "$m" >/dev/null 2>&1; then
            conzzer_status="✓ found"
        fi
        if [[ -f "${OUTPUT_BASE}/${m}/conzzer_${m}.csv" ]]; then
            conzzer_status="✓ collected"
        fi

        # Check SegFuzz
        if find_segfuzz_log "$m" >/dev/null 2>&1; then
            segfuzz_status="✓ found"
        fi
        if [[ -f "${OUTPUT_BASE}/${m}/segfuzz_${m}.csv" ]]; then
            segfuzz_status="✓ collected"
        fi

        printf "║ %-12s │ %-10s │ %-10s │ %-10s ║\n" "$m" "$ddrd_status" "$conzzer_status" "$segfuzz_status"
    done

    echo "╚════════════════════════════════════════════════════════════════╝"
}

# ============================================================
# Usage
# ============================================================

print_usage() {
    cat <<'EOF'
╔═══════════════════════════════════════════════════════════════════╗
║  collect_pairs.sh - Unified Pair Count Collection & Comparison  ║
╚═══════════════════════════════════════════════════════════════════╝

Usage:
  collect_pairs.sh <command> [module] [options]

Commands:
  collect-conzzer <module>   Extract pairs from Conzzer plot-curve
  collect-segfuzz <module>   Extract pairs from SegFuzz log/bench
  collect-all <module>       Collect from all available sources
  collect-batch <tool>       Batch collect for all modules (tool: conzzer|segfuzz|all)

  live-conzzer <module>      Live monitor Conzzer experiment
  live-segfuzz <module>      Live monitor SegFuzz experiment

  plot <module>              Generate comparison plot for a module
  plot-batch                 Generate plots for all modules

  status [module]            Show data availability status

Modules:
  xfs btrfs f2fs jfs floppy usb-driver video wifi-stack bt-stack ptmx dsp

Environment:
  BASS_DIR       Base directory (default: /home/zzzccc/BASS)
  OUTPUT_BASE    Output directory (default: tools/pair-collector/results)

Examples:
  # Collect Conzzer data for btrfs
  ./collect_pairs.sh collect-conzzer btrfs

  # Collect SegFuzz data for dsp
  ./collect_pairs.sh collect-segfuzz dsp

  # Collect everything for btrfs and plot
  ./collect_pairs.sh collect-all btrfs
  ./collect_pairs.sh plot btrfs

  # Live monitoring during Conzzer experiment
  ./collect_pairs.sh live-conzzer btrfs

  # Batch collect + plot all modules
  ./collect_pairs.sh collect-batch all
  ./collect_pairs.sh plot-batch

  # Check data availability
  ./collect_pairs.sh status
EOF
}

# ============================================================
# Main dispatch
# ============================================================

main() {
    if [[ $# -lt 1 ]]; then
        print_usage
        exit 1
    fi

    local cmd="$1"; shift

    case "$cmd" in
        collect-conzzer)
            [[ $# -lt 1 ]] && die "Usage: collect-conzzer <module>"
            cmd_collect_conzzer "$@"
            ;;
        collect-segfuzz)
            [[ $# -lt 1 ]] && die "Usage: collect-segfuzz <module>"
            cmd_collect_segfuzz "$@"
            ;;
        collect-all)
            [[ $# -lt 1 ]] && die "Usage: collect-all <module>"
            cmd_collect_all "$@"
            ;;
        collect-batch)
            [[ $# -lt 1 ]] && die "Usage: collect-batch <tool> (conzzer|segfuzz|all)"
            cmd_collect_batch "$@"
            ;;
        live-conzzer)
            [[ $# -lt 1 ]] && die "Usage: live-conzzer <module>"
            cmd_live_conzzer "$1"
            ;;
        live-segfuzz)
            [[ $# -lt 1 ]] && die "Usage: live-segfuzz <module>"
            cmd_live_segfuzz "$1"
            ;;
        plot)
            [[ $# -lt 1 ]] && die "Usage: plot <module>"
            cmd_plot "$@"
            ;;
        plot-batch)
            cmd_plot_batch "$@"
            ;;
        status)
            cmd_status "${1:-}"
            ;;
        -h|--help|help)
            print_usage
            ;;
        *)
            die "Unknown command: $cmd. Use --help for usage."
            ;;
    esac
}

main "$@"
