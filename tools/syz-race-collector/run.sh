#!/bin/bash
# 批量运行所有 cfg 配置的 race-collector 脚本
# 每个配置运行 24 小时，race pair 阈值 1ms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COLLECTOR_SCRIPT="$SYZKALLER_DIR/tools/syz-race-collector/run-with-collector.sh"

# 运行参数
DURATION=$((24 * 3600))  # 24小时 = 86400秒
INTERVAL=60              # 收集间隔 60 秒
RACE_THRESHOLD=1000000   # 1ms = 1000000ns
MAX_PARALLEL=0           # 最大并发数，0 表示不限制
DEBUG_MODE=false         # Debug 模式

# 日志目录
LOG_DIR="$SCRIPT_DIR/batch_logs"
mkdir -p "$LOG_DIR"

# 时间戳
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $1"; }
log_debug() { [[ "$DEBUG_MODE" == true ]] && echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[DEBUG]${NC} $1"; }

# 关闭之前运行的任务
kill_previous_tasks() {
    log_info "Checking for previous running tasks..."
    
    # 使用完整路径匹配，避免误杀其他项目的进程
    local syzkaller_pattern="$SYZKALLER_DIR"
    local script_pattern="$SCRIPT_DIR"
    
    # 查找并杀死之前的 syz-manager 进程（只匹配当前 syzkaller 目录下的）
    local manager_pids=$(pgrep -f "$syzkaller_pattern.*syz-manager" 2>/dev/null || true)
    if [[ -n "$manager_pids" ]]; then
        log_warn "Found running syz-manager processes: $manager_pids"
        for pid in $manager_pids; do
            log_info "Killing syz-manager (PID: $pid)..."
            kill -TERM "$pid" 2>/dev/null || true
        done
        sleep 2
        # 强制杀死残留进程
        for pid in $manager_pids; do
            if kill -0 "$pid" 2>/dev/null; then
                log_warn "Force killing syz-manager (PID: $pid)..."
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
    fi
    
    # 查找并杀死之前的 run-with-collector.sh 进程（只匹配当前 syzkaller 目录下的）
    local collector_pids=$(pgrep -f "$syzkaller_pattern.*run-with-collector.sh" 2>/dev/null || true)
    if [[ -n "$collector_pids" ]]; then
        log_warn "Found running collector processes: $collector_pids"
        for pid in $collector_pids; do
            log_info "Killing collector (PID: $pid)..."
            kill -TERM "$pid" 2>/dev/null || true
        done
        sleep 1
    fi
    
    # 查找并杀死与当前 workdir 相关的 QEMU 虚拟机进程
    # 通过匹配 workdir 路径来识别
    local qemu_pids=$(pgrep -f "qemu-system.*$script_pattern" 2>/dev/null || true)
    # 如果没找到，尝试匹配 syzkaller 目录
    if [[ -z "$qemu_pids" ]]; then
        qemu_pids=$(pgrep -f "qemu-system.*$syzkaller_pattern" 2>/dev/null || true)
    fi
    if [[ -n "$qemu_pids" ]]; then
        log_warn "Found running QEMU processes: $qemu_pids"
        for pid in $qemu_pids; do
            log_info "Killing QEMU (PID: $pid)..."
            kill -TERM "$pid" 2>/dev/null || true
        done
        sleep 2
        # 强制杀死残留进程
        for pid in $qemu_pids; do
            if kill -0 "$pid" 2>/dev/null; then
                log_warn "Force killing QEMU (PID: $pid)..."
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
    fi
    
    # 查找并杀死之前的 batch_run.sh 进程（只匹配当前目录下的，排除当前进程）
    local batch_pids=$(pgrep -f "$script_pattern/batch_run.sh" 2>/dev/null | grep -v "$$" || true)
    if [[ -n "$batch_pids" ]]; then
        log_warn "Found other batch_run.sh processes: $batch_pids"
        for pid in $batch_pids; do
            if [[ "$pid" != "$$" ]]; then
                log_info "Killing batch_run.sh (PID: $pid)..."
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
    fi
    
    log_info "Previous tasks cleanup completed"
}

# 获取所有 cfg 文件（排除 .bak 文件，支持 Collect- 前缀）
get_cfg_files() {
    find "$SCRIPT_DIR" -maxdepth 1 -name "*.cfg" ! -name "*.bak" -type f | sort
}

# 等待并发槽位
wait_for_slot() {
    if [[ $MAX_PARALLEL -le 0 ]]; then
        return 0
    fi
    
    while true; do
        local running=$(jobs -rp | wc -l)
        log_debug "Current running jobs: $running, max: $MAX_PARALLEL"
        if [[ $running -lt $MAX_PARALLEL ]]; then
            return 0
        fi
        log_debug "Waiting for a slot (running: $running, max: $MAX_PARALLEL)..."
        sleep 5
    done
}

# 运行单个配置
run_single() {
    local cfg_file="$1"
    local cfg_name=$(basename "$cfg_file" .cfg)
    local log_file="$LOG_DIR/${cfg_name}_${TIMESTAMP}.log"
    
    log_info "Starting: $cfg_name"
    log_debug "  Config: $cfg_file"
    log_debug "  Log: $log_file"
    log_info "  Duration: $((DURATION / 3600)) hours"
    log_info "  Race threshold: ${RACE_THRESHOLD}ns (1ms)"
    
    if [[ "$DEBUG_MODE" == true ]]; then
        log_debug "Command: sudo $COLLECTOR_SCRIPT -c $cfg_file -d $DURATION -i $INTERVAL --race-threshold=$RACE_THRESHOLD --clean -v"
    fi
    
    # 运行收集器
    sudo "$COLLECTOR_SCRIPT" \
        -c "$cfg_file" \
        -d "$DURATION" \
        -i "$INTERVAL" \
        --race-threshold="$RACE_THRESHOLD" \
        --clean \
        -v \
        > "$log_file" 2>&1
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_info "Completed: $cfg_name (exit code: $exit_code)"
    else
        log_warn "Finished with errors: $cfg_name (exit code: $exit_code)"
    fi
    
    return $exit_code
}

# 顺序运行所有配置
run_sequential() {
    local cfg_files=($(get_cfg_files))
    local total=${#cfg_files[@]}
    local completed=0
    local failed=0
    
    # 先关闭之前的任务
    kill_previous_tasks
    
    log_info "Found $total configuration files"
    log_info "Each will run for $((DURATION / 3600)) hours"
    log_info "Total estimated time: $((total * DURATION / 3600)) hours"
    log_info "Logs will be saved to: $LOG_DIR"
    echo ""
    
    for cfg in "${cfg_files[@]}"; do
        local cfg_name=$(basename "$cfg" .cfg)
        log_info "======================================"
        log_info "Running [$((completed + 1))/$total]: $cfg_name"
        log_info "======================================"
        
        if run_single "$cfg"; then
            ((completed++))
        else
            ((failed++))
            ((completed++))
        fi
        
        log_info "Progress: $completed/$total completed, $failed failed"
        echo ""
    done
    
    log_info "======================================"
    log_info "Batch run completed!"
    log_info "  Total: $total"
    log_info "  Successful: $((completed - failed))"
    log_info "  Failed: $failed"
    log_info "  Logs: $LOG_DIR"
    log_info "======================================"
}

# 并行运行指定配置（可选）
run_parallel() {
    local cfg_file="$1"
    local cfg_name=$(basename "$cfg_file" .cfg)
    local log_file="$LOG_DIR/${cfg_name}_${TIMESTAMP}.log"
    
    # 等待并发槽位
    wait_for_slot
    
    log_info "Starting in background: $cfg_name -> $log_file"
    log_debug "Command: nohup sudo $COLLECTOR_SCRIPT -c $cfg_file ..."
    
    nohup sudo "$COLLECTOR_SCRIPT" \
        -c "$cfg_file" \
        -d "$DURATION" \
        -i "$INTERVAL" \
        --race-threshold="$RACE_THRESHOLD" \
        --clean \
        -v \
        > "$log_file" 2>&1 &
    
    echo $!
}

# 显示帮助
show_help() {
    cat << EOF
Usage: $(basename "$0") [options] [config1.cfg config2.cfg ...]

批量运行 race-collector 收集脚本

Options:
  -h, --help          显示帮助
  -l, --list          列出所有可用配置
  -s, --single <cfg>  只运行指定配置
  -p, --parallel      并行运行所有配置（后台）
  -j, --jobs <N>      设置最大并发数（默认不限制）
  -k, --kill          只关闭之前的任务，不运行新任务
  --debug             开启 Debug 模式（显示详细信息）
  --dry-run           只显示将要运行的命令

默认行为：顺序运行所有 Collect-*.cfg 文件，每个运行 24 小时

参数:
  Duration:        $((DURATION / 3600)) hours ($DURATION seconds)
  Interval:        $INTERVAL seconds
  Race threshold:  ${RACE_THRESHOLD}ns (1ms)
  Max parallel:    $MAX_PARALLEL (0 = unlimited)
  Debug mode:      $DEBUG_MODE
  Log directory:   $LOG_DIR

Examples:
  # 顺序运行所有配置
  sudo ./batch_run.sh
  
  # 并行运行，最多 3 个并发
  sudo ./batch_run.sh -p -j 3
  
  # 并行运行所有配置（不限制并发）
  sudo ./batch_run.sh -p
  
  # 开启 debug 模式
  sudo ./batch_run.sh --debug -p -j 2
  
  # 只运行指定配置
  sudo ./batch_run.sh Collect-xfs.cfg Collect-btrfs.cfg
  
  # 列出所有配置
  ./batch_run.sh --list
  
  # 只关闭所有任务
  sudo ./batch_run.sh -k
EOF
}

# 列出所有配置
list_configs() {
    log_info "Available configurations:"
    for cfg in $(get_cfg_files); do
        local cfg_name=$(basename "$cfg" .cfg)
        # 去掉 Collect- 前缀来匹配 workdir
        local short_name="${cfg_name#Collect-}"
        local workdir="$SCRIPT_DIR/workdir-$short_name"
        if [[ -d "$workdir" ]]; then
            echo "  - $cfg_name (workdir: workdir-$short_name)"
        else
            echo "  - $cfg_name (no workdir)"
        fi
    done
}

# Dry run
dry_run() {
    log_info "Dry run - commands that would be executed:"
    echo ""
    for cfg in $(get_cfg_files); do
        local cfg_name=$(basename "$cfg" .cfg)
        echo "sudo $COLLECTOR_SCRIPT \\"
        echo "    -c $cfg \\"
        echo "    -d $DURATION \\"
        echo "    -i $INTERVAL \\"
        echo "    --race-threshold=$RACE_THRESHOLD \\"
        echo "    --clean \\"
        echo "    -v \\"
        echo "    > $LOG_DIR/${cfg_name}_${TIMESTAMP}.log 2>&1"
        echo ""
    done
}

# 主函数
main() {
    # 先解析全局选项
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -j|--jobs)
                if [[ -z "${2:-}" ]] || [[ ! "$2" =~ ^[0-9]+$ ]]; then
                    log_error "Please specify a valid number for --jobs"
                    exit 1
                fi
                MAX_PARALLEL=$2
                log_info "Max parallel jobs set to: $MAX_PARALLEL"
                shift 2
                ;;
            --debug)
                DEBUG_MODE=true
                log_info "Debug mode enabled"
                shift
                ;;
            *)
                break
                ;;
        esac
    done

    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
            list_configs
            exit 0
            ;;
        -k|--kill)
            kill_previous_tasks
            log_info "All previous tasks have been killed. No new tasks started."
            exit 0
            ;;
        -s|--single)
            if [[ -z "${2:-}" ]]; then
                log_error "Please specify a config file"
                exit 1
            fi
            local cfg_path="$SCRIPT_DIR/$2"
            if [[ ! -f "$cfg_path" ]]; then
                log_error "Config not found: $cfg_path"
                exit 1
            fi
            # 先关闭之前的任务
            kill_previous_tasks
            run_single "$cfg_path"
            exit $?
            ;;
        -p|--parallel)
            # 先关闭之前的任务
            kill_previous_tasks
            log_info "Starting all configs in parallel..."
            if [[ $MAX_PARALLEL -gt 0 ]]; then
                log_info "Max concurrent jobs: $MAX_PARALLEL"
            else
                log_info "Max concurrent jobs: unlimited"
            fi
            local pids=()
            for cfg in $(get_cfg_files); do
                pid=$(run_parallel "$cfg")
                pids+=("$pid")
                sleep 2  # 避免同时启动太多
            done
            log_info "Started ${#pids[@]} background processes"
            log_info "PIDs: ${pids[*]}"
            log_info "Use 'tail -f $LOG_DIR/<config>_*.log' to monitor"
            exit 0
            ;;
        --dry-run)
            dry_run
            exit 0
            ;;
        "")
            # 默认：顺序运行所有
            run_sequential
            exit 0
            ;;
        *)
            # 运行指定的配置列表
            # 先关闭之前的任务
            kill_previous_tasks
            for arg in "$@"; do
                local cfg_path="$SCRIPT_DIR/$arg"
                if [[ -f "$cfg_path" ]]; then
                    run_single "$cfg_path"
                else
                    log_warn "Config not found, skipping: $cfg_path"
                fi
            done
            exit 0
            ;;
    esac
}

main "$@"
