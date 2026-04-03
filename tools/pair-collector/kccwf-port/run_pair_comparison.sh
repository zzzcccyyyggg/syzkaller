#!/usr/bin/env bash
# ============================================================================
# run_pair_comparison.sh — DDRD vs Conzzer vs SegFuzz 对比实验自动化
#
# 此脚本编排完整的 Pair Count 对比实验:
#   1. 确保所有工具的内核已带 KCCWF 插桩
#   2. 启动各工具的 fuzzing
#   3. 部署 syz-race-collector 到各工具的 VM
#   4. 定时采集 pair 数据
#   5. 汇总、去重、生成对比图
#
# 使用方法:
#   ./run_pair_comparison.sh --config experiment.conf
#   ./run_pair_comparison.sh --ddrd-config ddrd.cfg --conzzer-port 10022 --segfuzz-port 10023
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAIR_COLLECTOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ts() { date +"%Y-%m-%d %H:%M:%S"; }
log_info()  { echo -e "$(ts) ${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "$(ts) ${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "$(ts) ${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "$(ts) ${BLUE}[STEP]${NC}  $*"; }

# ============================================================================
# 配置
# ============================================================================
# DDRD
DDRD_SYZKALLER_DIR="${DDRD_SYZKALLER_DIR:-/home/zzzccc/BASS/DDRD-syzkaller}"
DDRD_CONFIG=""
DDRD_ENABLED=false

# Conzzer
CONZZER_DIR="${CONZZER_DIR:-/home/zzzccc/BASS/Conzzer}"
CONZZER_VM_PORT=""
CONZZER_SSH_KEY=""
CONZZER_ENABLED=false

# SegFuzz
SEGFUZZ_DIR="${SEGFUZZ_DIR:-/home/zzzccc/BASS/segfuzz}"
SEGFUZZ_VM_PORT=""
SEGFUZZ_SSH_KEY=""
SEGFUZZ_ENABLED=false

# 通用
EXPERIMENT_NAME=""
OUTPUT_DIR=""
DURATION=3600          # 默认 1 小时
COLLECT_INTERVAL=60    # 采集间隔（秒）
SAMPLE_MS=1000         # collector 采样间隔
RACE_THRESHOLD=4270000
MODULE="btrfs"         # 目标模块

# 子进程 PID
declare -a CHILD_PIDS=()

# ============================================================================
# 帮助
# ============================================================================
print_usage() {
    cat <<'EOF'
Usage: run_pair_comparison.sh [options]

DDRD Options:
  --ddrd-config <file>     syz-manager config for DDRD (enables DDRD collection)

Conzzer Options:
  --conzzer-port <port>    Conzzer VM SSH port (enables Conzzer collection)
  --conzzer-key <path>     SSH key for Conzzer VM

SegFuzz Options:
  --segfuzz-port <port>    SegFuzz VM SSH port (enables SegFuzz collection)
  --segfuzz-key <path>     SSH key for SegFuzz VM

Common Options:
  --name <name>            Experiment name (default: auto-generated)
  --output-dir <dir>       Output directory (default: auto)
  --duration <sec>         Experiment duration (default: 3600)
  --interval <sec>         Collection interval (default: 60)
  --module <name>          Target module: btrfs, xfs, f2fs, etc. (default: btrfs)
  --race-threshold <ns>    Race threshold (default: 4270000)
  -h, --help               Show help

Examples:
  # Full 3-way comparison on btrfs for 2 hours
  ./run_pair_comparison.sh \
      --ddrd-config /path/to/ddrd.cfg \
      --conzzer-port 10022 --conzzer-key ~/.ssh/id_rsa \
      --segfuzz-port 10023 --segfuzz-key ~/.ssh/id_rsa \
      --module btrfs --duration 7200

  # DDRD only (baseline)
  ./run_pair_comparison.sh --ddrd-config /path/to/ddrd.cfg --duration 3600

  # Conzzer vs SegFuzz only
  ./run_pair_comparison.sh \
      --conzzer-port 10022 --conzzer-key ~/.ssh/id_rsa \
      --segfuzz-port 10023 --segfuzz-key ~/.ssh/id_rsa
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ddrd-config)    DDRD_CONFIG="$2"; DDRD_ENABLED=true; shift 2 ;;
            --conzzer-port)   CONZZER_VM_PORT="$2"; CONZZER_ENABLED=true; shift 2 ;;
            --conzzer-key)    CONZZER_SSH_KEY="$2"; shift 2 ;;
            --segfuzz-port)   SEGFUZZ_VM_PORT="$2"; SEGFUZZ_ENABLED=true; shift 2 ;;
            --segfuzz-key)    SEGFUZZ_SSH_KEY="$2"; shift 2 ;;
            --name)           EXPERIMENT_NAME="$2"; shift 2 ;;
            --output-dir)     OUTPUT_DIR="$2"; shift 2 ;;
            --duration)       DURATION="$2"; shift 2 ;;
            --interval)       COLLECT_INTERVAL="$2"; shift 2 ;;
            --module)         MODULE="$2"; shift 2 ;;
            --race-threshold) RACE_THRESHOLD="$2"; shift 2 ;;
            -h|--help)        print_usage; exit 0 ;;
            *) log_error "Unknown: $1"; exit 1 ;;
        esac
    done

    if ! $DDRD_ENABLED && ! $CONZZER_ENABLED && ! $SEGFUZZ_ENABLED; then
        log_error "At least one tool must be enabled"
        print_usage
        exit 1
    fi

    if [[ -z "$EXPERIMENT_NAME" ]]; then
        EXPERIMENT_NAME="pair-cmp-${MODULE}-$(date +%Y%m%d-%H%M%S)"
    fi

    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$PAIR_COLLECTOR_DIR/experiments/$EXPERIMENT_NAME"
    fi
}

# ============================================================================
# 清理子进程
# ============================================================================
cleanup() {
    echo ""
    log_info "Cleaning up..."

    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    log_info "All collection processes stopped."
}

trap cleanup INT TERM EXIT

# ============================================================================
# 启动 DDRD 采集
# ============================================================================
start_ddrd_collection() {
    if ! $DDRD_ENABLED; then return 0; fi

    log_step "Starting DDRD pair collection..."

    local ddrd_output="$OUTPUT_DIR/ddrd"
    mkdir -p "$ddrd_output"

    # DDRD 使用自己的 run-with-collector.sh
    local collector_script="$DDRD_SYZKALLER_DIR/tools/syz-race-collector/run-with-collector.sh"

    if [[ ! -f "$collector_script" ]]; then
        log_error "DDRD collector script not found: $collector_script"
        return 1
    fi

    bash "$collector_script" \
        --config "$DDRD_CONFIG" \
        --output-dir "$ddrd_output" \
        --interval "$COLLECT_INTERVAL" \
        --sample-ms "$SAMPLE_MS" \
        --race-threshold "$RACE_THRESHOLD" \
        --duration "$DURATION" \
        > "$ddrd_output/collector.log" 2>&1 &

    local pid=$!
    CHILD_PIDS+=("$pid")
    log_info "DDRD collection started (PID: $pid)"
}

# ============================================================================
# 启动 Conzzer 采集
# ============================================================================
start_conzzer_collection() {
    if ! $CONZZER_ENABLED; then return 0; fi

    log_step "Starting Conzzer pair collection..."

    local conzzer_output="$OUTPUT_DIR/conzzer"
    mkdir -p "$conzzer_output"

    local key_opt=""
    if [[ -n "$CONZZER_SSH_KEY" ]]; then
        key_opt="$CONZZER_SSH_KEY"
    else
        # 尝试默认位置
        local default_keys=(
            "$CONZZER_DIR/exp/$MODULE/fuzz/ssh_key"
            "$HOME/.ssh/id_rsa"
        )
        for k in "${default_keys[@]}"; do
            if [[ -f "$k" ]]; then
                key_opt="$k"
                break
            fi
        done
    fi

    if [[ -z "$key_opt" ]]; then
        log_error "SSH key for Conzzer not found"
        return 1
    fi

    bash "$SCRIPT_DIR/deploy_collector.sh" \
        --tool conzzer \
        --vm-port "$CONZZER_VM_PORT" \
        --ssh-key "$key_opt" \
        --output-dir "$conzzer_output" \
        --interval "$COLLECT_INTERVAL" \
        --sample-ms "$SAMPLE_MS" \
        --race-threshold "$RACE_THRESHOLD" \
        --duration "$DURATION" \
        > "$conzzer_output/collector.log" 2>&1 &

    local pid=$!
    CHILD_PIDS+=("$pid")
    log_info "Conzzer collection started (PID: $pid)"
}

# ============================================================================
# 启动 SegFuzz 采集
# ============================================================================
start_segfuzz_collection() {
    if ! $SEGFUZZ_ENABLED; then return 0; fi

    log_step "Starting SegFuzz pair collection..."

    local segfuzz_output="$OUTPUT_DIR/segfuzz"
    mkdir -p "$segfuzz_output"

    local key_opt=""
    if [[ -n "$SEGFUZZ_SSH_KEY" ]]; then
        key_opt="$SEGFUZZ_SSH_KEY"
    else
        local default_keys=(
            "$SEGFUZZ_DIR/images/bullseye.id_rsa"
            "$HOME/.ssh/id_rsa"
        )
        for k in "${default_keys[@]}"; do
            if [[ -f "$k" ]]; then
                key_opt="$k"
                break
            fi
        done
    fi

    if [[ -z "$key_opt" ]]; then
        log_error "SSH key for SegFuzz not found"
        return 1
    fi

    bash "$SCRIPT_DIR/deploy_collector.sh" \
        --tool segfuzz \
        --vm-port "$SEGFUZZ_VM_PORT" \
        --ssh-key "$key_opt" \
        --output-dir "$segfuzz_output" \
        --interval "$COLLECT_INTERVAL" \
        --sample-ms "$SAMPLE_MS" \
        --race-threshold "$RACE_THRESHOLD" \
        --duration "$DURATION" \
        > "$segfuzz_output/collector.log" 2>&1 &

    local pid=$!
    CHILD_PIDS+=("$pid")
    log_info "SegFuzz collection started (PID: $pid)"
}

# ============================================================================
# 等待所有采集完成
# ============================================================================
wait_for_completion() {
    log_step "Waiting for collection to complete ($DURATION seconds)..."

    local start=$SECONDS
    while true; do
        local elapsed=$((SECONDS - start))
        if [[ $elapsed -ge $DURATION ]]; then
            break
        fi

        # 检查是否所有子进程都已完成
        local all_done=true
        for pid in "${CHILD_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                all_done=false
                break
            fi
        done

        if $all_done; then
            log_info "All collection processes finished."
            break
        fi

        local remaining=$((DURATION - elapsed))
        local hours=$((remaining / 3600))
        local mins=$(((remaining % 3600) / 60))
        local secs=$((remaining % 60))
        printf "\r$(ts) [INFO] Remaining: %02d:%02d:%02d" $hours $mins $secs
        sleep 10
    done
    echo ""
}

# ============================================================================
# 生成对比图
# ============================================================================
generate_comparison_plot() {
    log_step "Generating comparison plot..."

    local plot_script="$PAIR_COLLECTOR_DIR/plot_comparison.py"

    # 收集各工具的 race_timeseries.csv
    local plot_args=()

    if $DDRD_ENABLED && [[ -f "$OUTPUT_DIR/ddrd/race_timeseries.csv" ]]; then
        plot_args+=("--ddrd" "$OUTPUT_DIR/ddrd/race_timeseries.csv")
    fi

    if $CONZZER_ENABLED && [[ -f "$OUTPUT_DIR/conzzer/race_timeseries.csv" ]]; then
        plot_args+=("--conzzer" "$OUTPUT_DIR/conzzer/race_timeseries.csv")
    fi

    if $SEGFUZZ_ENABLED && [[ -f "$OUTPUT_DIR/segfuzz/race_timeseries.csv" ]]; then
        plot_args+=("--segfuzz" "$OUTPUT_DIR/segfuzz/race_timeseries.csv")
    fi

    if [[ ${#plot_args[@]} -eq 0 ]]; then
        log_warn "No timeseries data available for plotting"
        return 0
    fi

    # 使用内联 Python 生成图
    python3 - "${plot_args[@]}" "$OUTPUT_DIR" <<'PYEOF'
import sys
import os
import csv

def parse_timeseries(filepath):
    """Parse race_timeseries.csv → list of (elapsed_sec, pair_count)"""
    data = []
    first_ts = None
    with open(filepath, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith('#') or row[0] == 'timestamp':
                continue
            try:
                ts = float(row[0])
                count = int(row[1])
                if first_ts is None:
                    first_ts = ts
                elapsed = ts - first_ts
                data.append((elapsed, count))
            except (ValueError, IndexError):
                continue
    return data

def main():
    args = sys.argv[1:]
    output_dir = args[-1]
    
    datasets = {}
    i = 0
    while i < len(args) - 1:
        if args[i] == '--ddrd':
            datasets['DDRD'] = parse_timeseries(args[i+1])
            i += 2
        elif args[i] == '--conzzer':
            datasets['Conzzer'] = parse_timeseries(args[i+1])
            i += 2
        elif args[i] == '--segfuzz':
            datasets['SegFuzz'] = parse_timeseries(args[i+1])
            i += 2
        else:
            i += 1
    
    if not datasets:
        print("No data to plot")
        return
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        
        fig, ax = plt.subplots(figsize=(12, 7))
        
        colors = {'DDRD': '#e74c3c', 'Conzzer': '#3498db', 'SegFuzz': '#2ecc71'}
        markers = {'DDRD': 'o', 'Conzzer': 's', 'SegFuzz': '^'}
        
        for name, data in datasets.items():
            if not data:
                continue
            xs = [d[0] / 3600 for d in data]  # hours
            ys = [d[1] for d in data]
            ax.plot(xs, ys, 
                    label=name, 
                    color=colors.get(name, '#333'),
                    marker=markers.get(name, 'o'),
                    markersize=3, linewidth=2, alpha=0.8)
        
        ax.set_xlabel('Time (hours)', fontsize=14)
        ax.set_ylabel('Unique Race Pairs', fontsize=14)
        ax.set_title('Race Pair Count Comparison', fontsize=16)
        ax.legend(fontsize=12)
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        outpath = os.path.join(output_dir, 'pair_comparison.png')
        plt.savefig(outpath, dpi=150)
        plt.savefig(outpath.replace('.png', '.pdf'))
        print(f"Plot saved: {outpath}")
        
    except ImportError:
        print("matplotlib not available, generating text summary instead")
        summary_path = os.path.join(output_dir, 'pair_comparison_summary.txt')
        with open(summary_path, 'w') as f:
            f.write("Race Pair Comparison Summary\n")
            f.write("=" * 50 + "\n\n")
            for name, data in datasets.items():
                if data:
                    final_count = data[-1][1]
                    duration_h = data[-1][0] / 3600
                    f.write(f"{name}: {final_count} pairs in {duration_h:.2f} hours\n")
        print(f"Summary saved: {summary_path}")

if __name__ == '__main__':
    main()
PYEOF
}

# ============================================================================
# 生成最终摘要
# ============================================================================
generate_final_summary() {
    log_step "Generating final summary..."

    local summary="$OUTPUT_DIR/experiment_summary.txt"

    {
        echo "═══════════════════════════════════════════════════════════"
        echo " Pair Count Comparison Experiment"
        echo "═══════════════════════════════════════════════════════════"
        echo " Name:     $EXPERIMENT_NAME"
        echo " Module:   $MODULE"
        echo " Duration: ${DURATION}s"
        echo " Date:     $(date)"
        echo "═══════════════════════════════════════════════════════════"
        echo ""

        for tool in ddrd conzzer segfuzz; do
            local ts_file="$OUTPUT_DIR/$tool/race_timeseries.csv"
            if [[ -f "$ts_file" ]]; then
                local pairs
                pairs=$(tail -1 "$ts_file" 2>/dev/null | cut -d',' -f2) || pairs="N/A"
                printf " %-10s: %s unique pairs\n" "$tool" "$pairs"
            fi
        done

        echo ""
        echo " Output:   $OUTPUT_DIR"
        echo "═══════════════════════════════════════════════════════════"
    } | tee "$summary"
}

# ============================================================================
# Main
# ============================================================================
main() {
    parse_args "$@"

    mkdir -p "$OUTPUT_DIR"

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Pair Count Comparison Experiment"
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Name:          $EXPERIMENT_NAME"
    log_info " Module:        $MODULE"
    log_info " Duration:      ${DURATION}s"
    log_info " DDRD:          $( $DDRD_ENABLED && echo "ENABLED" || echo "disabled")"
    log_info " Conzzer:       $( $CONZZER_ENABLED && echo "ENABLED (port: $CONZZER_VM_PORT)" || echo "disabled")"
    log_info " SegFuzz:       $( $SEGFUZZ_ENABLED && echo "ENABLED (port: $SEGFUZZ_VM_PORT)" || echo "disabled")"
    log_info " Output:        $OUTPUT_DIR"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # 保存实验配置
    cat > "$OUTPUT_DIR/experiment.conf" <<EOF
EXPERIMENT_NAME=$EXPERIMENT_NAME
MODULE=$MODULE
DURATION=$DURATION
COLLECT_INTERVAL=$COLLECT_INTERVAL
RACE_THRESHOLD=$RACE_THRESHOLD
DDRD_ENABLED=$DDRD_ENABLED
CONZZER_ENABLED=$CONZZER_ENABLED
SEGFUZZ_ENABLED=$SEGFUZZ_ENABLED
CONZZER_VM_PORT=$CONZZER_VM_PORT
SEGFUZZ_VM_PORT=$SEGFUZZ_VM_PORT
EOF

    # 启动各工具的采集
    start_ddrd_collection
    start_conzzer_collection
    start_segfuzz_collection

    # 等待完成
    wait_for_completion

    # 生成对比结果
    generate_comparison_plot
    generate_final_summary

    log_info "Experiment complete! Results in: $OUTPUT_DIR"
}

main "$@"
