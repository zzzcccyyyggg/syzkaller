#!/bin/bash

# 蓝牙设备监控脚本
# 监控 Intel Corp. AX201 Bluetooth 设备状态
# 当设备消失或bus/addr发生变化时，重启syz-manager并更新配置

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/test/bluetooth.cfg"
MANAGER_BIN="$SCRIPT_DIR/bin/syz-manager"
LOG_FILE="$SCRIPT_DIR/bluetooth_monitor.log"

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 获取蓝牙设备信息
get_bluetooth_device() {
    lsusb | grep "Intel Corp. AX201 Bluetooth" | head -1
}

# 解析bus和addr
parse_device_info() {
    local device_line="$1"
    if [ -z "$device_line" ]; then
        echo ""
        return
    fi
    
    # 从 "Bus 003 Device 016:" 中提取bus=3, addr=16，去掉前导零
    local bus=$(echo "$device_line" | sed -n 's/Bus 0*\([0-9]\+\) Device.*/\1/p')
    local addr=$(echo "$device_line" | sed -n 's/Bus [0-9]\+ Device 0*\([0-9]\+\):.*/\1/p')
    
    echo "${bus},${addr}"
}

# 杀死syz-manager进程
kill_syz_manager() {
    log "正在杀死 syz-manager 进程..."
    
    # 查找并杀死所有syz-manager进程
    local pids=$(pgrep -f "syz-manager")
    if [ -n "$pids" ]; then
        log "找到 syz-manager 进程: $pids"
        echo "$pids" | xargs kill -TERM
        sleep 3
        
        # 如果还没死，强制杀死
        local remaining_pids=$(pgrep -f "syz-manager")
        if [ -n "$remaining_pids" ]; then
            log "强制杀死剩余进程: $remaining_pids"
            echo "$remaining_pids" | xargs kill -KILL
        fi
        log "syz-manager 进程已终止"
    else
        log "未找到运行中的 syz-manager 进程"
    fi
}

# 更新配置文件
update_config() {
    local bus="$1"
    local addr="$2"
    
    log "更新配置文件: hostbus=$bus,hostaddr=$addr"
    
    # 备份配置文件
    cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%s)"
    
    # 更新配置
    sed -i "s/hostbus=[0-9]\+,hostaddr=[0-9]\+/hostbus=$bus,hostaddr=$addr/g" "$CONFIG_FILE"
    
    log "配置文件已更新"
}

# 启动syz-manager
start_syz_manager() {
    log "启动 syz-manager..."
    
    cd "$SCRIPT_DIR"
    nohup sudo "$MANAGER_BIN" -config="$CONFIG_FILE" > syz_manager.log 2>&1 &
    local pid=$!
    
    log "syz-manager 已启动，PID: $pid"
    
    # 等待一下确保启动成功
    sleep 3
    if pgrep -f "syz-manager" > /dev/null; then
        log "syz-manager 启动成功"
    else
        log "警告: syz-manager 可能启动失败，请检查日志"
    fi
}

# 主监控循环
main() {
    log "开始监控蓝牙设备..."
    
    # 获取初始状态
    local initial_device=$(get_bluetooth_device)
    local initial_info=$(parse_device_info "$initial_device")
    
    if [ -z "$initial_device" ]; then
        log "错误: 未找到 Intel Corp. AX201 Bluetooth 设备"
        exit 1
    fi
    
    log "初始蓝牙设备: $initial_device"
    log "初始设备信息: bus,addr = $initial_info"
    
    local last_info="$initial_info"
    
    while true; do
        sleep 30  # 每30秒检查一次
        
        local current_device=$(get_bluetooth_device)
        local current_info=$(parse_device_info "$current_device")
        
        # 检查设备是否消失
        if [ -z "$current_device" ]; then
            log "警告: 蓝牙设备消失了！"
            log "等待设备重新出现..."
            
            # 等待设备重新出现，每秒检查一次
            while [ -z "$current_device" ]; do
                sleep 1
                current_device=$(get_bluetooth_device)
                if [ -n "$current_device" ]; then
                    log "检测到设备重新出现: $current_device"
                fi
            done
            
            current_info=$(parse_device_info "$current_device")
            log "蓝牙设备已稳定重新出现: $current_device"
            log "新设备信息: bus,addr = $current_info"
            
            # 重启管理器
            kill_syz_manager
            
            if [ -n "$current_info" ] && [ "$current_info" != "$last_info" ]; then
                local bus=$(echo "$current_info" | cut -d',' -f1)
                local addr=$(echo "$current_info" | cut -d',' -f2)
                update_config "$bus" "$addr"
            fi
            
            start_syz_manager
            last_info="$current_info"
            
        # 检查bus或addr是否发生变化
        elif [ "$current_info" != "$last_info" ]; then
            log "检测到设备信息变化:"
            log "  之前: $last_info"
            log "  现在: $current_info"
            
            # 重启管理器
            kill_syz_manager
            
            local bus=$(echo "$current_info" | cut -d',' -f1)
            local addr=$(echo "$current_info" | cut -d',' -f2)
            update_config "$bus" "$addr"
            
            start_syz_manager
            last_info="$current_info"
        fi
    done
}

# 信号处理
cleanup() {
    log "收到退出信号，正在清理..."
    exit 0
}

trap cleanup SIGINT SIGTERM

# 检查依赖
if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 配置文件不存在: $CONFIG_FILE"
    exit 1
fi

if [ ! -f "$MANAGER_BIN" ]; then
    echo "错误: syz-manager 二进制文件不存在: $MANAGER_BIN"
    exit 1
fi

# 启动主循环
main
