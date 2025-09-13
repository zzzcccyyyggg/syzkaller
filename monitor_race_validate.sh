#!/bin/bash

# 监视脚本：自动运行 syz-race-validate
# 每5分钟检查一次，如果程序没有运行则启动它

# 配置参数
PROGRAM_NAME="syz-race-validate"
PROGRAM_CMD="sudo ./bin/syz-race-validate -config=./test/usb/usb.cfg -workdir=./test/usb-workdir2 -count=1"
CHECK_INTERVAL=300  # 5分钟 = 300秒
SCRIPT_DIR="/home/zzzccc/syzkaller"
LOG_FILE="$SCRIPT_DIR/monitor_race_validate.log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# 检查程序是否在运行
is_program_running() {
    # 检查进程名包含 syz-race-validate 的进程
    local pid=$(pgrep -f "$PROGRAM_NAME")
    if [ -n "$pid" ]; then
        return 0  # 程序正在运行
    else
        return 1  # 程序未运行
    fi
}

# 检查监视器是否在运行（更精确的检测）
is_monitor_running() {
    # 使用ps检查是否有monitor_loop函数在运行
    local monitor_processes=$(ps aux | grep "monitor_race_validate.sh start" | grep -v grep | grep -v $$)
    if [ -n "$monitor_processes" ]; then
        return 0  # 监视器正在运行
    else
        return 1  # 监视器未运行
    fi
}

# 获取监视器PID
get_monitor_pid() {
    ps aux | grep "monitor_race_validate.sh start" | grep -v grep | grep -v $$ | awk '{print $2}' | head -1
}

# 启动程序
start_program() {
    log_message "${GREEN}INFO${NC}" "启动程序: $PROGRAM_CMD"
    cd "$SCRIPT_DIR" || {
        log_message "${RED}ERROR${NC}" "无法切换到目录: $SCRIPT_DIR"
        return 1
    }
    
    # 在后台运行程序，并重定向输出到日志文件
    nohup $PROGRAM_CMD >> "$LOG_FILE" 2>&1 &
    local new_pid=$!
    
    # 等待一下检查程序是否成功启动
    sleep 3
    if kill -0 $new_pid 2>/dev/null; then
        log_message "${GREEN}SUCCESS${NC}" "程序已成功启动，PID: $new_pid"
        return 0
    else
        log_message "${RED}ERROR${NC}" "程序启动失败"
        return 1
    fi
}

# 获取程序运行时间
get_program_runtime() {
    local pid=$(pgrep -f "$PROGRAM_NAME")
    if [ -n "$pid" ]; then
        local runtime=$(ps -o etime= -p $pid 2>/dev/null | tr -d ' ')
        echo "$runtime"
    else
        echo "N/A"
    fi
}

# 主监视循环
monitor_loop() {
    log_message "${BLUE}START${NC}" "开始监视 $PROGRAM_NAME (检查间隔: ${CHECK_INTERVAL}秒)"
    
    while true; do
        if is_program_running; then
            local pid=$(pgrep -f "$PROGRAM_NAME")
            local runtime=$(get_program_runtime)
            log_message "${YELLOW}MONITOR${NC}" "程序正在运行 (PID: $pid, 运行时间: $runtime)"
        else
            log_message "${YELLOW}MONITOR${NC}" "程序未运行，尝试启动..."
            if start_program; then
                log_message "${GREEN}SUCCESS${NC}" "程序启动成功"
            else
                log_message "${RED}ERROR${NC}" "程序启动失败，将在下次检查时重试"
            fi
        fi
        
        # 等待指定时间后再次检查
        sleep $CHECK_INTERVAL
    done
}

# 显示使用帮助
show_help() {
    cat << EOF
用法: $0 [选项]

选项:
  start     启动监视器
  stop      停止监视器
  status    显示程序状态
  log       显示日志
  help      显示此帮助信息

配置:
  程序名称: $PROGRAM_NAME
  命令: $PROGRAM_CMD
  检查间隔: ${CHECK_INTERVAL}秒
  日志文件: $LOG_FILE

EOF
}

# 停止监视器
stop_monitor() {
    # 查找监视器进程（排除当前进程和grep进程）
    if is_monitor_running; then
        local monitor_pid=$(get_monitor_pid)
        log_message "${YELLOW}STOP${NC}" "停止监视器 (PID: $monitor_pid)"
        kill $monitor_pid
        echo "监视器已停止"
    else
        echo "监视器未运行"
    fi
    
    # 询问是否也停止被监视的程序
    read -p "是否也停止 $PROGRAM_NAME 程序? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local program_pid=$(pgrep -f "$PROGRAM_NAME")
        if [ -n "$program_pid" ]; then
            log_message "${YELLOW}STOP${NC}" "停止程序 (PID: $program_pid)"
            kill $program_pid
            echo "程序已停止"
        else
            echo "程序未运行"
        fi
    fi
}

# 显示状态
show_status() {
    echo "=== 监视器状态 ==="
    # 查找监视器进程（排除当前进程）
    if is_monitor_running; then
        local monitor_pid=$(get_monitor_pid)
        echo -e "监视器: ${GREEN}运行中${NC} (PID: $monitor_pid)"
    else
        echo -e "监视器: ${RED}未运行${NC}"
    fi
    
    echo
    echo "=== 程序状态 ==="
    if is_program_running; then
        local pid=$(pgrep -f "$PROGRAM_NAME")
        local runtime=$(get_program_runtime)
        echo -e "程序: ${GREEN}运行中${NC} (PID: $pid, 运行时间: $runtime)"
    else
        echo -e "程序: ${RED}未运行${NC}"
    fi
    
    echo
    echo "=== 配置信息 ==="
    echo "程序名称: $PROGRAM_NAME"
    echo "命令: $PROGRAM_CMD"
    echo "检查间隔: ${CHECK_INTERVAL}秒"
    echo "日志文件: $LOG_FILE"
}

# 显示日志
show_log() {
    if [ -f "$LOG_FILE" ]; then
        echo "=== 最近20行日志 ==="
        tail -20 "$LOG_FILE"
        echo
        echo "完整日志文件: $LOG_FILE"
    else
        echo "日志文件不存在: $LOG_FILE"
    fi
}

# 主程序入口
main() {
    case "${1:-start}" in
        start)
            # 检查是否已经有监视器在运行（排除当前进程）
            if is_monitor_running; then
                local existing_monitor=$(get_monitor_pid)
                echo "监视器已经在运行 (PID: $existing_monitor)"
                exit 1
            fi
            monitor_loop
            ;;
        stop)
            stop_monitor
            ;;
        status)
            show_status
            ;;
        log)
            show_log
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "未知选项: $1"
            echo "使用 '$0 help' 查看帮助信息"
            exit 1
            ;;
    esac
}

# 确保脚本在正确的目录运行
if [ ! -f "./bin/syz-race-validate" ]; then
    echo "错误: 在当前目录找不到 ./bin/syz-race-validate"
    echo "请在 syzkaller 根目录运行此脚本"
    exit 1
fi

# 创建日志文件目录
mkdir -p "$(dirname "$LOG_FILE")"

# 设置信号处理
trap 'log_message "${YELLOW}SIGNAL${NC}" "收到中断信号，正在退出..."; exit 0' INT TERM

# 运行主程序
main "$@"
