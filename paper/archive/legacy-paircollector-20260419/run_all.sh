#!/bin/bash

# 批量运行 DDRD-Fuzz 的脚本
# 用法: ./run_all.sh [start|stop|stopall|status|restart] [选项] [target1 target2 ...]
# 示例: ./run_all.sh start                  # 启动所有目标
#       ./run_all.sh start btrfs xfs        # 只启动 btrfs 和 xfs
#       ./run_all.sh start --debug btrfs    # 以 debug 模式启动 btrfs
#       ./run_all.sh start -t 1h            # 启动所有目标，1小时后自动停止
#       ./run_all.sh start --duration=30m   # 启动所有目标，30分钟后停止
#       ./run_all.sh stop                   # 停止所有目标
#       ./run_all.sh stopall                # 强制关闭所有 syz-manager 进程
#       ./run_all.sh status                 # 查看运行状态

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_BIN="/home/zzzccc/BASS/DDRD-syzkaller/bin/syz-manager"
LOG_DIR="${SCRIPT_DIR}/logs"
DEBUG_MODE=0
DURATION=0  # 运行时长（秒），0 表示不限制
CLEAN_MODE=0
EXCLUDES=()

# 所有可用的配置及其端口
declare -A CONFIGS=(
    ["btrfs"]="btrfs.cfg:61001"
    ["dsp"]="dsp.cfg:61002"
    ["f2fs"]="f2fs.cfg:61003"
    ["floppy"]="floppy.cfg:61004"
    ["jfs"]="jfs.cfg:61005"
    ["ptmx"]="ptmx.cfg:61006"
    ["usb"]="usb-driver.cfg:61007"
    ["video"]="video.cfg:61008"
    ["wifi"]="wifi.cfg:61009"
    ["xfs"]="xfs.cfg:61010"
    ["bt"]="bt-stack.cfg:61011"
)

# 各目标对应的工作目录（用于可选清理）
declare -A WORKDIRS=(
    ["btrfs"]="workdir-btrfs"
    ["dsp"]="workdir-dsp"
    ["f2fs"]="workdir-f2fs"
    ["floppy"]="workdir-floppy"
    ["jfs"]="workdir-jfs"
    ["ptmx"]="workdir-ptmx"
    ["usb"]="workdir-usb"
    ["video"]="workdir-video"
    ["wifi"]="workdir-wifi"
    ["xfs"]="workdir-xfs"
    ["bt"]="workdir-bt-stack"
)

# 创建日志目录
mkdir -p "${LOG_DIR}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 获取指定目标的 PID
get_pid() {
    local target=$1
    local cfg_file="${CONFIGS[$target]%%:*}"
    local cfg_path="${SCRIPT_DIR}/${cfg_file}"
    pgrep -f "syz-manager.*-config.*${cfg_path}" 2>/dev/null
}

# 启动单个目标
start_target() {
    local target=$1
    local cfg_info="${CONFIGS[$target]}"
    local cfg_file="${cfg_info%%:*}"
    local port="${cfg_info##*:}"
    
    if [ -z "$cfg_info" ]; then
        print_error "未知目标: $target"
        return 1
    fi
    
    local pid=$(get_pid "$target")
    if [ -n "$pid" ]; then
        print_warning "$target 已经在运行 (PID: $pid, 端口: $port)"
        return 0
    fi
    
    local cfg_path="${SCRIPT_DIR}/${cfg_file}"
    local log_file="${LOG_DIR}/${target}.log"
    
    if [ ! -f "$cfg_path" ]; then
        print_error "配置文件不存在: $cfg_path"
        return 1
    fi
    
    print_info "启动 $target (配置: $cfg_file, 端口: $port)..."
    
    # Debug 模式：前台运行并显示输出
    if [ "$DEBUG_MODE" -eq 1 ]; then
        print_info "[DEBUG] 以前台模式运行，输出将直接显示..."
        "${SYZKALLER_BIN}" -config "${cfg_path}" -debug
        return $?
    fi
    
    nohup "${SYZKALLER_BIN}" -config "${cfg_path}" > "${log_file}" 2>&1 &
    
    sleep 2
    pid=$(get_pid "$target")
    if [ -n "$pid" ]; then
        print_success "$target 启动成功 (PID: $pid)"
        echo "  日志: ${log_file}"
        echo "  Web UI: http://127.0.0.1:${port}"
    else
        print_error "$target 启动失败，请检查日志: ${log_file}"
        return 1
    fi
}

# 停止单个目标
stop_target() {
    local target=$1
    local pid=$(get_pid "$target")
    
    if [ -z "$pid" ]; then
        print_warning "$target 未在运行"
        return 0
    fi
    
    print_info "停止 $target (PID: $pid)..."
    kill "$pid" 2>/dev/null
    
    # 等待进程结束
    local count=0
    while [ $count -lt 10 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            print_success "$target 已停止"
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    # 强制终止
    print_warning "强制终止 $target..."
    kill -9 "$pid" 2>/dev/null
    print_success "$target 已停止"
}

# 可选：清理单个目标的 uaf-corpus.db*
clean_uaf_db() {
    local target=$1
    local workdir="${WORKDIRS[$target]}"

    if [ -z "$workdir" ]; then
        print_warning "$target 未配置工作目录，跳过清理"
        return 0
    fi

    local workdir_path="${SCRIPT_DIR}/${workdir}"
    local pattern="${workdir_path}/uaf-corpus.db*"

    if [ ! -d "$workdir_path" ]; then
        print_warning "工作目录不存在: $workdir_path，跳过清理"
        return 0
    fi

    mapfile -t files < <(compgen -G "$pattern")
    if [ ${#files[@]} -eq 0 ]; then
        print_info "$target 未找到 uaf-corpus.db 文件，无需清理"
        return 0
    fi

    local backup_dir="${LOG_DIR}/backup-uaf/${target}/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"

    print_info "备份 $target 的 uaf-corpus.db* 到 $backup_dir"
    cp -a "${files[@]}" "$backup_dir/"

    print_info "清理 $target 的 uaf-corpus.db* 文件..."
    rm -f "${files[@]}"
    print_success "$target uaf-corpus.db 已备份并清理"
}

# 强制关闭所有 syz-manager 进程
stop_all_managers() {
    print_info "查找所有 syz-manager 进程..."
    
    local pids=$(pgrep -f "syz-manager" 2>/dev/null)
    
    if [ -z "$pids" ]; then
        print_warning "没有发现运行中的 syz-manager 进程"
        return 0
    fi
    
    echo ""
    print_info "发现以下 syz-manager 进程:"
    ps -fp $pids 2>/dev/null
    echo ""
    
    print_info "正在终止所有 syz-manager 进程..."
    for pid in $pids; do
        print_info "终止进程 PID: $pid"
        kill "$pid" 2>/dev/null
    done
    
    # 等待进程结束
    sleep 3
    
    # 检查是否还有残留进程
    local remaining=$(pgrep -f "syz-manager" 2>/dev/null)
    if [ -n "$remaining" ]; then
        print_warning "部分进程未响应，强制终止..."
        for pid in $remaining; do
            kill -9 "$pid" 2>/dev/null
        done
        sleep 1
    fi
    
    # 最终检查
    remaining=$(pgrep -f "syz-manager" 2>/dev/null)
    if [ -z "$remaining" ]; then
        print_success "所有 syz-manager 进程已停止"
    else
        print_error "以下进程无法停止: $remaining"
        return 1
    fi
}

# 显示状态
show_status() {
    local target=$1
    local cfg_info="${CONFIGS[$target]}"
    local port="${cfg_info##*:}"
    local pid=$(get_pid "$target")
    
    if [ -n "$pid" ]; then
        echo -e "  ${GREEN}●${NC} $target (PID: $pid, 端口: $port) - 运行中"
    else
        echo -e "  ${RED}○${NC} $target (端口: $port) - 已停止"
    fi
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [命令] [选项] [目标...]"
    echo ""
    echo "命令:"
    echo "  start   - 启动指定目标（默认启动所有）"
    echo "  stop    - 停止指定目标（默认停止所有）"
    echo "  stopall - 强制关闭所有 syz-manager 进程"
    echo "  restart - 重启指定目标（默认重启所有）"
    echo "  status  - 显示运行状态"
    echo "  list    - 列出所有可用目标"
    echo "  help    - 显示此帮助信息"
    echo ""
    echo "选项:"
    echo "  --debug, -d              以 debug 模式启动（前台运行，显示详细输出）"
    echo "  --duration=TIME, -t TIME 指定运行时长，到期后自动停止所有进程"
    echo "                           TIME 格式: 3600 (秒), 1h, 30m, 1h30m, 2h30m15s"
    echo "  --exclude=LIST, -x LIST  启动/重启时排除指定目标，LIST 可用逗号分隔"
    echo "  --clean-uaf              启动前清理对应工作目录下的 uaf-corpus.db*"
    echo ""
    echo "可用目标:"
    for target in "${!CONFIGS[@]}"; do
        local cfg_info="${CONFIGS[$target]}"
        local cfg_file="${cfg_info%%:*}"
        local port="${cfg_info##*:}"
        echo "  $target - $cfg_file (端口: $port)"
    done | sort
    echo ""
    echo "示例:"
    echo "  $0 start                      # 启动所有目标"
    echo "  $0 start btrfs xfs            # 只启动 btrfs 和 xfs"
    echo "  $0 start --debug btrfs        # 以 debug 模式启动 btrfs"
    echo "  $0 start -t 1h                # 启动所有目标，1小时后自动停止"
    echo "  $0 start --duration=30m btrfs # 启动 btrfs，30分钟后自动停止"
    echo "  $0 start -t 2h30m             # 启动所有目标，2小时30分钟后停止"
    echo "  $0 stop                       # 停止所有目标"
    echo "  $0 stopall                    # 强制关闭所有 syz-manager 进程"
    echo "  $0 status                     # 查看所有目标状态"
}

# 获取目标列表（过滤掉选项参数）
get_targets() {
    local targets=()
    local skip_next=0
    for arg in "$@"; do
        if [ $skip_next -eq 1 ]; then
            skip_next=0
            continue
        fi
        if [ "$arg" == "--debug" ] || [ "$arg" == "-d" ]; then
            continue
        elif [ "$arg" == "--duration" ] || [ "$arg" == "-t" ]; then
            skip_next=1
            continue
        elif [[ "$arg" =~ ^--duration= ]] || [[ "$arg" =~ ^-t= ]]; then
            continue
        elif [ "$arg" == "--exclude" ] || [ "$arg" == "-x" ]; then
            skip_next=1
            continue
        elif [[ "$arg" =~ ^--exclude= ]] || [[ "$arg" =~ ^-x= ]]; then
            continue
        elif [ "$arg" == "--clean-uaf" ]; then
            continue
        fi
        targets+=("$arg")
    done
    
    if [ ${#targets[@]} -eq 0 ]; then
        echo "${!CONFIGS[@]}"
    else
        echo "${targets[@]}"
    fi
}

# 检查是否有 --debug 参数
check_debug_mode() {
    for arg in "$@"; do
        if [ "$arg" == "--debug" ] || [ "$arg" == "-d" ]; then
            DEBUG_MODE=1
            return 0
        fi
    done
    return 1
}

# 解析 --duration 参数（支持 1h, 30m, 3600, 1h30m 等格式）
parse_duration() {
    local duration_str="$1"
    local total_seconds=0
    
    # 如果是纯数字，直接作为秒数
    if [[ "$duration_str" =~ ^[0-9]+$ ]]; then
        echo "$duration_str"
        return
    fi
    
    # 解析 XhYmZs 格式
    local remaining="$duration_str"
    
    # 提取小时
    if [[ "$remaining" =~ ([0-9]+)h ]]; then
        total_seconds=$((total_seconds + ${BASH_REMATCH[1]} * 3600))
        remaining="${remaining/${BASH_REMATCH[0]}/}"
    fi
    
    # 提取分钟
    if [[ "$remaining" =~ ([0-9]+)m ]]; then
        total_seconds=$((total_seconds + ${BASH_REMATCH[1]} * 60))
        remaining="${remaining/${BASH_REMATCH[0]}/}"
    fi
    
    # 提取秒
    if [[ "$remaining" =~ ([0-9]+)s ]]; then
        total_seconds=$((total_seconds + ${BASH_REMATCH[1]}))
    fi
    
    echo "$total_seconds"
}

# 检查并解析 --duration 参数
check_duration() {
    local i=0
    local args=("$@")
    for arg in "${args[@]}"; do
        if [[ "$arg" == "--duration" ]] || [[ "$arg" == "-t" ]]; then
            local next_idx=$((i + 1))
            if [ $next_idx -lt ${#args[@]} ]; then
                DURATION=$(parse_duration "${args[$next_idx]}")
                return 0
            fi
        elif [[ "$arg" =~ ^--duration= ]]; then
            DURATION=$(parse_duration "${arg#--duration=}")
            return 0
        elif [[ "$arg" =~ ^-t= ]]; then
            DURATION=$(parse_duration "${arg#-t=}")
            return 0
        fi
        ((i++))
    done
    return 1
}

# 检查 --exclude 参数
check_excludes() {
    EXCLUDES=()
    local args=("$@")
    local i=0
    while [ $i -lt ${#args[@]} ]; do
        local arg="${args[$i]}"
        if [ "$arg" == "--exclude" ] || [ "$arg" == "-x" ]; then
            local next_idx=$((i + 1))
            if [ $next_idx -lt ${#args[@]} ]; then
                IFS=',' read -ra parts <<< "${args[$next_idx]}"
                EXCLUDES+=("${parts[@]}")
            fi
            i=$((i + 2))
            continue
        elif [[ "$arg" =~ ^--exclude= ]]; then
            IFS=',' read -ra parts <<< "${arg#--exclude=}"
            EXCLUDES+=("${parts[@]}")
        elif [[ "$arg" =~ ^-x= ]]; then
            IFS=',' read -ra parts <<< "${arg#-x=}"
            EXCLUDES+=("${parts[@]}")
        fi
        i=$((i + 1))
    done
}

# 检查清理标志
check_clean_flag() {
    CLEAN_MODE=0
    for arg in "$@"; do
        if [ "$arg" == "--clean-uaf" ]; then
            CLEAN_MODE=1
            return 0
        fi
    done
    return 1
}

# 过滤排除列表
filter_excludes() {
    local filtered=()
    for t in "$@"; do
        local skip=0
        for ex in "${EXCLUDES[@]}"; do
            if [ "$t" == "$ex" ]; then
                skip=1
                break
            fi
        done
        if [ $skip -eq 0 ]; then
            filtered+=("$t")
        fi
    done
    echo "${filtered[@]}"
}

# 格式化时长显示
format_duration() {
    local seconds=$1
    local hours=$((seconds / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))
    
    if [ $hours -gt 0 ]; then
        printf "%dh%dm%ds" $hours $minutes $secs
    elif [ $minutes -gt 0 ]; then
        printf "%dm%ds" $minutes $secs
    else
        printf "%ds" $secs
    fi
}

# 等待指定时长后停止所有进程
wait_and_stop() {
    local duration=$1
    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    
    print_info "将在 $(format_duration $duration) 后自动停止所有进程..."
    print_info "预计结束时间: $(date -d "@$end_time" '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # 显示倒计时（每分钟更新一次，最后10秒每秒更新）
    while true; do
        local now=$(date +%s)
        local remaining=$((end_time - now))
        
        if [ $remaining -le 0 ]; then
            break
        fi
        
        if [ $remaining -le 10 ]; then
            printf "\r${YELLOW}[COUNTDOWN]${NC} 剩余 %ds ...   " $remaining
            sleep 1
        elif [ $remaining -le 60 ]; then
            printf "\r${YELLOW}[COUNTDOWN]${NC} 剩余 %ds ...   " $remaining
            sleep 5
        else
            printf "\r${YELLOW}[COUNTDOWN]${NC} 剩余 $(format_duration $remaining) ...   "
            sleep 30
        fi
    done
    
    echo ""
    echo ""
    print_info "时间到！正在停止所有进程..."
    stop_all_managers
}

# 主逻辑
main() {
    local command="${1:-help}"
    shift 2>/dev/null || true
    
    # 检查 debug 模式
    check_debug_mode "$@"
    # 检查 duration 参数
    check_duration "$@"
    # 检查 exclude 参数
    check_excludes "$@"
    # 检查清理选项
    check_clean_flag "$@"
    
    case "$command" in
        start)
            local targets_arr=($(get_targets "$@"))
            targets_arr=($(filter_excludes "${targets_arr[@]}"))
            if [ ${#targets_arr[@]} -eq 0 ]; then
                print_error "没有可启动的目标（可能被全部排除）"
                exit 1
            fi
            if [ "$DEBUG_MODE" -eq 1 ]; then
                print_info "[DEBUG] 以 debug 模式启动..."
            fi
            if [ "$DURATION" -gt 0 ]; then
                print_info "运行时长限制: $(format_duration $DURATION)"
            fi
            if [ ${#EXCLUDES[@]} -gt 0 ]; then
                print_info "已排除目标: ${EXCLUDES[*]}"
            fi
            if [ "$CLEAN_MODE" -eq 1 ]; then
                print_info "启动前将清理各目标工作目录中的 uaf-corpus.db*"
            fi
            print_info "开始启动目标..."
            echo ""
            for target in "${targets_arr[@]}"; do
                if [ "$CLEAN_MODE" -eq 1 ]; then
                    clean_uaf_db "$target"
                fi
                start_target "$target"
                echo ""
            done
            
            # 如果设置了时长，等待后停止
            if [ "$DURATION" -gt 0 ]; then
                wait_and_stop "$DURATION"
            fi
            ;;
        stop)
            local targets=$(get_targets "$@")
            print_info "开始停止目标..."
            echo ""
            for target in $targets; do
                stop_target "$target"
            done
            ;;
        stopall|killall)
            stop_all_managers
            ;;
        restart)
            local targets_arr=($(get_targets "$@"))
            targets_arr=($(filter_excludes "${targets_arr[@]}"))
            if [ ${#targets_arr[@]} -eq 0 ]; then
                print_error "没有可重启的目标（可能被全部排除）"
                exit 1
            fi
            if [ ${#EXCLUDES[@]} -gt 0 ]; then
                print_info "已排除目标: ${EXCLUDES[*]}"
            fi
            print_info "开始重启目标..."
            echo ""
            for target in "${targets_arr[@]}"; do
                stop_target "$target"
                sleep 1
                start_target "$target"
                echo ""
            done
            ;;
        status)
            echo ""
            echo "DDRD-Fuzz 运行状态:"
            echo "===================="
            for target in $(echo "${!CONFIGS[@]}" | tr ' ' '\n' | sort); do
                show_status "$target"
            done
            echo ""
            ;;
        list)
            echo ""
            echo "可用目标列表:"
            echo "=============="
            for target in $(echo "${!CONFIGS[@]}" | tr ' ' '\n' | sort); do
                local cfg_info="${CONFIGS[$target]}"
                local cfg_file="${cfg_info%%:*}"
                local port="${cfg_info##*:}"
                echo "  $target - $cfg_file (端口: $port)"
            done
            echo ""
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "未知命令: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
