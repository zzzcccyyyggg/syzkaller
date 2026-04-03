#!/usr/bin/env bash
# ============================================================================
# deploy_collector.sh — 部署 syz-race-collector 到外部工具的 VM
#
# 此脚本用于将 syz-race-collector 部署到 Conzzer/SegFuzz 的 QEMU VM 中，
# 以便在它们运行 fuzzing 时被动收集 KCCWF 的 race pair 数据。
#
# 与 DDRD-syzkaller 的 run-with-collector.sh 不同之处:
#   - run-with-collector.sh 是为 syzkaller 集成设计的（解析 syzkaller.log 获取端口）
#   - deploy_collector.sh 是通用的: 手动指定 VM SSH 端口，支持任何工具
#
# 使用方法:
#   # 部署到单个 VM
#   ./deploy_collector.sh --vm-port 10022 --ssh-key ~/.ssh/id_rsa --output-dir ./results
#
#   # 部署到多个 VM
#   ./deploy_collector.sh --vm-ports 10022,10023,10024 --ssh-key ~/.ssh/id_rsa
#
#   # 持续运行直到 Ctrl+C
#   ./deploy_collector.sh --vm-port 10022 --duration 3600 --interval 30
#
#   # 配合 Conzzer 使用
#   ./deploy_collector.sh --vm-port 10022 --ssh-key /path/to/conzzer/ssh_key
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/syz-race-collector"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ts() { date +"%Y-%m-%d %H:%M:%S"; }
log_info()  { echo -e "$(ts) ${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "$(ts) ${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "$(ts) ${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "$(ts) ${BLUE}[STEP]${NC}  $*"; }

# ============================================================================
# 配置
# ============================================================================
COLLECTOR_BIN="$COLLECTOR_DIR/syz-race-collector"
DEDUP_SCRIPT="$COLLECTOR_DIR/dedup_races.py"

VM_HOST="localhost"
VM_PORTS=()
SSH_KEY=""
SSH_USER="root"
SSH_TIMEOUT=10
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

COLLECT_INTERVAL=60                # 采集间隔（秒）
COLLECTOR_SAMPLE_MS=1000           # collector 采样间隔（毫秒）
RACE_THRESHOLD=4270000             # race pair 时间阈值（纳秒）
UAF_THRESHOLD=10000000000          # UAF 时间阈值（纳秒）

OUTPUT_DIR=""
DURATION=0                         # 0 = 无限
TOOL_NAME="unknown"                # conzzer / segfuzz / ddrd
VERBOSE=false

# 内部状态
declare -A VM_DEPLOYED=()
declare -A VM_SIGNALS_LINES=()

# ============================================================================
# 帮助
# ============================================================================
print_usage() {
    cat <<'EOF'
Usage: deploy_collector.sh [options]

Required (at least one):
  --vm-port <port>      Single VM SSH port
  --vm-ports <p1,p2>    Multiple VM SSH ports (comma-separated)
  --ssh-key <path>      SSH private key for VM access

Options:
  --tool <name>         Tool name for labeling: conzzer, segfuzz, ddrd (default: unknown)
  --vm-host <host>      VM SSH host (default: localhost)
  --ssh-user <user>     SSH user (default: root)
  --output-dir <dir>    Output directory (default: ./pair-data-<tool>-<timestamp>)
  --interval <sec>      Collection interval in seconds (default: 60)
  --sample-ms <ms>      Collector sample interval in ms (default: 1000)
  --race-threshold <ns> Race pair time threshold (default: 4270000)
  --uaf-threshold <ns>  UAF time threshold (default: 10000000000)
  --duration <sec>      Run duration, 0 = until Ctrl+C (default: 0)
  --verbose             Verbose output
  -h, --help            Show this help

Examples:
  # Collect from Conzzer VM
  ./deploy_collector.sh --tool conzzer --vm-port 10022 \
      --ssh-key /path/to/key --duration 3600

  # Collect from multiple SegFuzz VMs
  ./deploy_collector.sh --tool segfuzz --vm-ports 10022,10023 \
      --ssh-key /path/to/key --output-dir ./segfuzz-pairs
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --vm-port)      VM_PORTS+=("$2"); shift 2 ;;
            --vm-ports)     IFS=',' read -ra _ports <<< "$2"; VM_PORTS+=("${_ports[@]}"); shift 2 ;;
            --vm-host)      VM_HOST="$2"; shift 2 ;;
            --ssh-key)      SSH_KEY="$2"; shift 2 ;;
            --ssh-user)     SSH_USER="$2"; shift 2 ;;
            --tool)         TOOL_NAME="$2"; shift 2 ;;
            --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
            --interval)     COLLECT_INTERVAL="$2"; shift 2 ;;
            --sample-ms)    COLLECTOR_SAMPLE_MS="$2"; shift 2 ;;
            --race-threshold) RACE_THRESHOLD="$2"; shift 2 ;;
            --uaf-threshold)  UAF_THRESHOLD="$2"; shift 2 ;;
            --duration)     DURATION="$2"; shift 2 ;;
            --verbose)      VERBOSE=true; shift ;;
            -h|--help)      print_usage; exit 0 ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done

    if [[ ${#VM_PORTS[@]} -eq 0 ]]; then
        log_error "At least one --vm-port is required"
        exit 1
    fi

    if [[ -z "$SSH_KEY" ]]; then
        log_error "--ssh-key is required"
        exit 1
    fi

    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="./pair-data-${TOOL_NAME}-$(date +%Y%m%d-%H%M%S)"
    fi
}

# ============================================================================
# SSH 辅助函数
# ============================================================================
vm_ssh() {
    local port="$1"; shift
    ssh $SSH_OPTS -i "$SSH_KEY" -p "$port" \
        -o ConnectTimeout="$SSH_TIMEOUT" \
        "${SSH_USER}@${VM_HOST}" "$@" 2>/dev/null
}

vm_scp_to() {
    local port="$1"
    local local_file="$2"
    local remote_path="$3"
    scp $SSH_OPTS -i "$SSH_KEY" -P "$port" \
        -o ConnectTimeout="$SSH_TIMEOUT" \
        "$local_file" "${SSH_USER}@${VM_HOST}:${remote_path}" 2>/dev/null
}

vm_scp_from() {
    local port="$1"
    local remote_path="$2"
    local local_file="$3"
    scp $SSH_OPTS -i "$SSH_KEY" -P "$port" \
        -o ConnectTimeout="$SSH_TIMEOUT" \
        "${SSH_USER}@${VM_HOST}:${remote_path}" "$local_file" 2>/dev/null
}

# ============================================================================
# 检查 VM 是否可达
# ============================================================================
check_vm() {
    local port="$1"
    vm_ssh "$port" "echo ok" >/dev/null 2>&1
}

# ============================================================================
# 部署 collector 到 VM
# ============================================================================
deploy_to_vm() {
    local port="$1"
    local vm_id="vm_${port}"

    if [[ "${VM_DEPLOYED[$vm_id]:-}" == "true" ]]; then
        # 检查 collector 是否还在运行
        if vm_ssh "$port" "pgrep -x syz-race-collector" >/dev/null 2>&1; then
            $VERBOSE && log_info "[$vm_id] Collector still running"
            return 0
        fi
        log_warn "[$vm_id] Collector died, re-deploying..."
    fi

    log_info "[$vm_id] Deploying collector..."

    # 上传 collector 二进制
    if ! vm_scp_to "$port" "$COLLECTOR_BIN" "/tmp/syz-race-collector"; then
        log_error "[$vm_id] Failed to upload collector"
        return 1
    fi

    vm_ssh "$port" "chmod +x /tmp/syz-race-collector"

    # 启动 collector
    local collector_args="--interval=$COLLECTOR_SAMPLE_MS"
    collector_args+=" --race-threshold=$RACE_THRESHOLD"
    collector_args+=" --uaf-threshold=$UAF_THRESHOLD"
    collector_args+=" --format=csv"
    collector_args+=" -o /tmp/races.csv"
    collector_args+=" --signals /tmp/signals.csv"
    collector_args+=" --no-lru"  # 禁用 LRU，使用外部去重

    vm_ssh "$port" "nohup /tmp/syz-race-collector $collector_args > /tmp/collector.log 2>&1 &"

    sleep 1

    if vm_ssh "$port" "pgrep -x syz-race-collector" >/dev/null 2>&1; then
        log_info "[$vm_id] Collector started successfully"
        VM_DEPLOYED[$vm_id]="true"
        return 0
    else
        log_error "[$vm_id] Failed to start collector"
        vm_ssh "$port" "cat /tmp/collector.log" 2>/dev/null || true
        return 1
    fi
}

# ============================================================================
# 从 VM 收集数据
# ============================================================================
collect_from_vm() {
    local port="$1"
    local vm_id="vm_${port}"
    local vm_dir="$OUTPUT_DIR/$vm_id"
    mkdir -p "$vm_dir"

    # 收集 signals.csv（增量）
    local remote_signals="/tmp/signals.csv"
    local local_signals="$vm_dir/signals.csv"

    if vm_ssh "$port" "test -f $remote_signals" 2>/dev/null; then
        # 获取远程文件行数
        local remote_lines
        remote_lines=$(vm_ssh "$port" "wc -l < $remote_signals" 2>/dev/null) || remote_lines=0

        local prev_lines="${VM_SIGNALS_LINES[$vm_id]:-0}"

        if [[ "$remote_lines" -gt "$prev_lines" ]]; then
            local new_lines=$((remote_lines - prev_lines))
            # 增量下载新行
            local temp_file="$vm_dir/signals_new.csv"
            vm_ssh "$port" "tail -n +$((prev_lines + 1)) $remote_signals" > "$temp_file" 2>/dev/null

            if [[ -s "$temp_file" ]]; then
                cat "$temp_file" >> "$local_signals"
                VM_SIGNALS_LINES[$vm_id]="$remote_lines"
                $VERBOSE && log_info "[$vm_id] Collected $new_lines new signals (total: $remote_lines)"
            fi
            rm -f "$temp_file"
        else
            $VERBOSE && log_info "[$vm_id] No new signals"
        fi
    fi

    # 也收集 races.csv（summary）
    vm_scp_from "$port" "/tmp/races.csv" "$vm_dir/races.csv" 2>/dev/null || true
}

# ============================================================================
# 去重和生成时间序列
# ============================================================================
run_dedup() {
    log_step "Running deduplication..."

    # 合并所有 VM 的 signals
    local merged="$OUTPUT_DIR/all_signals.csv"
    > "$merged"

    for port in "${VM_PORTS[@]}"; do
        local vm_id="vm_${port}"
        local signals="$OUTPUT_DIR/$vm_id/signals.csv"
        if [[ -f "$signals" ]]; then
            cat "$signals" >> "$merged"
        fi
    done

    if [[ ! -s "$merged" ]]; then
        log_warn "No signals collected yet"
        return 0
    fi

    # 运行去重脚本
    if [[ -f "$DEDUP_SCRIPT" ]]; then
        local deduped="$OUTPUT_DIR/race_timeseries.csv"
        python3 "$DEDUP_SCRIPT" "$OUTPUT_DIR" --output "$deduped" 2>/dev/null || {
            # 如果专用的去重脚本失败，使用简单的去重
            log_warn "Dedup script failed, using simple dedup"
            simple_dedup "$merged" "$OUTPUT_DIR/race_timeseries.csv"
        }
    else
        simple_dedup "$merged" "$OUTPUT_DIR/race_timeseries.csv"
    fi
}

# ============================================================================
# 简单去重（如果专用脚本不可用）
# ============================================================================
simple_dedup() {
    local input="$1"
    local output="$2"

    python3 - "$input" "$output" <<'PYEOF'
import sys
import csv
from collections import OrderedDict

input_file = sys.argv[1]
output_file = sys.argv[2]

seen_pairs = OrderedDict()  # (addr1, addr2, is_write1, is_write2) -> first_seen_time
pair_count_over_time = []
current_count = 0

with open(input_file, 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        if not row or row[0].startswith('#') or row[0].startswith('timestamp'):
            continue
        try:
            # 期望格式: timestamp, addr1, addr2, is_write1, is_write2, ...
            ts = row[0].strip()
            key_parts = tuple(r.strip() for r in row[1:5]) if len(row) >= 5 else tuple(row[1:])
            if key_parts not in seen_pairs:
                seen_pairs[key_parts] = ts
                current_count += 1
                pair_count_over_time.append((ts, current_count))
        except (IndexError, ValueError):
            continue

with open(output_file, 'w') as f:
    f.write("timestamp,pair_count\n")
    for ts, count in pair_count_over_time:
        f.write(f"{ts},{count}\n")

print(f"Total unique pairs: {current_count}")
PYEOF

    local total
    total=$(tail -1 "$output" | cut -d',' -f2)
    log_info "Dedup complete: ${total:-0} unique pairs → $output"
}

# ============================================================================
# 生成最终报告
# ============================================================================
generate_final_report() {
    local report="$OUTPUT_DIR/collection_report.txt"

    {
        echo "═══════════════════════════════════════════════════════════"
        echo " Pair Collection Report"
        echo "═══════════════════════════════════════════════════════════"
        echo " Tool:       $TOOL_NAME"
        echo " Duration:   $(format_duration $SECONDS)"
        echo " VMs:        ${#VM_PORTS[@]} (ports: ${VM_PORTS[*]})"
        echo " Output:     $OUTPUT_DIR"
        echo "═══════════════════════════════════════════════════════════"
        echo ""

        for port in "${VM_PORTS[@]}"; do
            local vm_id="vm_${port}"
            local slines="${VM_SIGNALS_LINES[$vm_id]:-0}"
            echo " VM $vm_id: $slines signals collected"
        done

        echo ""
        if [[ -f "$OUTPUT_DIR/race_timeseries.csv" ]]; then
            local total
            total=$(tail -1 "$OUTPUT_DIR/race_timeseries.csv" | cut -d',' -f2)
            echo " Total unique race pairs: ${total:-0}"
        fi
        echo "═══════════════════════════════════════════════════════════"
    } | tee "$report"
}

format_duration() {
    local secs=$1
    printf '%02d:%02d:%02d' $((secs/3600)) $((secs%3600/60)) $((secs%60))
}

# ============================================================================
# 信号处理
# ============================================================================
RUNNING=true

cleanup() {
    RUNNING=false
    echo ""
    log_info "Stopping collection..."

    # 在 VM 上停止 collector
    for port in "${VM_PORTS[@]}"; do
        vm_ssh "$port" "pkill -x syz-race-collector" 2>/dev/null || true
    done

    # 最后一次收集
    for port in "${VM_PORTS[@]}"; do
        collect_from_vm "$port" 2>/dev/null || true
    done

    # 去重
    run_dedup

    # 报告
    generate_final_report
}

trap cleanup INT TERM

# ============================================================================
# Main Loop
# ============================================================================
main() {
    parse_args "$@"

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Race Pair Collector — External Deployment"
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Tool:       $TOOL_NAME"
    log_info " VMs:        ${VM_PORTS[*]}"
    log_info " Output:     $OUTPUT_DIR"
    log_info " Interval:   ${COLLECT_INTERVAL}s"
    log_info " Duration:   ${DURATION}s (0=unlimited)"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # 检查前置条件
    if [[ ! -x "$COLLECTOR_BIN" ]]; then
        log_error "Collector binary not found: $COLLECTOR_BIN"
        log_error "Build it: cd $COLLECTOR_DIR && make"
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"

    # 初始部署
    log_step "Deploying collector to VMs..."
    for port in "${VM_PORTS[@]}"; do
        local vm_id="vm_${port}"
        VM_SIGNALS_LINES[$vm_id]=0
        if check_vm "$port"; then
            deploy_to_vm "$port" || log_warn "Failed to deploy to port $port"
        else
            log_warn "VM on port $port is not reachable"
        fi
    done

    # 主循环
    local start_time=$SECONDS
    log_step "Starting collection loop (Ctrl+C to stop)..."

    while $RUNNING; do
        sleep "$COLLECT_INTERVAL"

        # 检查持续时间
        if [[ "$DURATION" -gt 0 ]]; then
            local elapsed=$((SECONDS - start_time))
            if [[ $elapsed -ge $DURATION ]]; then
                log_info "Duration reached ($DURATION seconds), stopping."
                break
            fi
        fi

        # 尝试重新部署（VM 可能重启）
        for port in "${VM_PORTS[@]}"; do
            if check_vm "$port"; then
                deploy_to_vm "$port" 2>/dev/null || true
            fi
        done

        # 收集数据
        for port in "${VM_PORTS[@]}"; do
            if check_vm "$port"; then
                collect_from_vm "$port" 2>/dev/null || true
            fi
        done

        # 周期性去重
        run_dedup 2>/dev/null || true

        # 状态输出
        local total_signals=0
        for port in "${VM_PORTS[@]}"; do
            local vm_id="vm_${port}"
            total_signals=$((total_signals + ${VM_SIGNALS_LINES[$vm_id]:-0}))
        done

        local pairs=0
        if [[ -f "$OUTPUT_DIR/race_timeseries.csv" ]]; then
            pairs=$(tail -1 "$OUTPUT_DIR/race_timeseries.csv" 2>/dev/null | cut -d',' -f2) || pairs=0
        fi

        log_info "[$(format_duration $((SECONDS - start_time)))] Signals: $total_signals | Unique pairs: ${pairs:-0}"
    done

    cleanup
}

main "$@"
