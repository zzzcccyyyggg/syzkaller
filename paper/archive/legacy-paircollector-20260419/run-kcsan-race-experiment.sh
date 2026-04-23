#!/bin/bash
# run-kcsan-race-experiment.sh
# 运行 syzkaller + KCSAN 并使用 syz-race-collector 收集 race pair 数据

set -e

# ========== 配置参数 ==========
SYZKALLER_DIR="/home/zzzccc/BASS/DDRD-syzkaller"
CONFIG="${SYZKALLER_DIR}/test/DDRD/kcsan-race-collect.cfg"
WORKDIR="${SYZKALLER_DIR}/test/DDRD/workdir-kcsan"
SSH_KEY="${SYZKALLER_DIR}/test/fs/bookworm.id_rsa"
SSH_PORT_BASE=10022
VM_COUNT=2
EXPERIMENT_DURATION=3600  # 实验时长（秒），默认1小时
OUTPUT_DIR="${WORKDIR}/race-collector-output"

# ========== 颜色输出 ==========
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ========== 检查依赖 ==========
check_dependencies() {
    log_info "检查依赖..."
    
    if [ ! -f "${SYZKALLER_DIR}/bin/syz-manager" ]; then
        log_error "syz-manager 不存在，请先编译: make manager"
        exit 1
    fi
    
    if [ ! -f "${SYZKALLER_DIR}/bin/syz-race-collector" ]; then
        log_error "syz-race-collector 不存在，请先编译"
        exit 1
    fi
    
    if [ ! -f "${CONFIG}" ]; then
        log_error "配置文件不存在: ${CONFIG}"
        exit 1
    fi
    
    log_info "依赖检查通过"
}

# ========== 创建输出目录 ==========
setup_directories() {
    log_info "创建输出目录..."
    mkdir -p "${OUTPUT_DIR}"
    mkdir -p "${WORKDIR}"
}

# ========== 启动 syz-manager ==========
start_syz_manager() {
    log_info "启动 syz-manager..."
    
    cd "${SYZKALLER_DIR}"
    sudo ./bin/syz-manager --config="${CONFIG}" &
    SYZ_MANAGER_PID=$!
    
    log_info "syz-manager PID: ${SYZ_MANAGER_PID}"
    
    # 等待 VM 启动
    log_info "等待 VM 启动 (30秒)..."
    sleep 30
}

# ========== 在每个 VM 中启动 race-collector ==========
start_race_collectors() {
    log_info "在 VM 中启动 syz-race-collector..."
    
    for i in $(seq 0 $((VM_COUNT - 1))); do
        SSH_PORT=$((SSH_PORT_BASE + i))
        VM_OUTPUT="${OUTPUT_DIR}/vm${i}"
        mkdir -p "${VM_OUTPUT}"
        
        log_info "VM${i}: SSH端口 ${SSH_PORT}"
        
        # 检查 VM 是否可达
        if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
             -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost "echo ok" 2>/dev/null; then
            log_warn "VM${i} 不可达，跳过"
            continue
        fi
        
        # 复制 syz-race-collector 到 VM
        log_info "复制 syz-race-collector 到 VM${i}..."
        scp -o StrictHostKeyChecking=no -i "${SSH_KEY}" -P "${SSH_PORT}" \
            "${SYZKALLER_DIR}/bin/syz-race-collector" root@localhost:/tmp/
        
        # 在 VM 中后台运行 syz-race-collector
        log_info "在 VM${i} 中启动 race-collector..."
        ssh -o StrictHostKeyChecking=no -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost \
            "nohup /tmp/syz-race-collector -o /tmp/race_stats.json -i 5000 > /tmp/race-collector.log 2>&1 &"
        
        log_info "VM${i}: race-collector 已启动"
    done
}

# ========== 等待实验完成 ==========
wait_for_experiment() {
    log_info "实验运行中，持续 ${EXPERIMENT_DURATION} 秒..."
    log_info "可以访问 http://127.0.0.1:56850 查看 syzkaller 状态"
    
    sleep "${EXPERIMENT_DURATION}"
}

# ========== 收集结果 ==========
collect_results() {
    log_info "收集实验结果..."
    
    for i in $(seq 0 $((VM_COUNT - 1))); do
        SSH_PORT=$((SSH_PORT_BASE + i))
        VM_OUTPUT="${OUTPUT_DIR}/vm${i}"
        
        # 检查 VM 是否可达
        if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
             -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost "echo ok" 2>/dev/null; then
            log_warn "VM${i} 不可达，跳过结果收集"
            continue
        fi
        
        log_info "从 VM${i} 收集结果..."
        
        # 停止 race-collector
        ssh -o StrictHostKeyChecking=no -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost \
            "pkill -SIGINT syz-race-collector 2>/dev/null || true"
        
        sleep 2
        
        # 复制结果文件
        scp -o StrictHostKeyChecking=no -i "${SSH_KEY}" -P "${SSH_PORT}" \
            root@localhost:/tmp/race_stats.json "${VM_OUTPUT}/" 2>/dev/null || true
        scp -o StrictHostKeyChecking=no -i "${SSH_KEY}" -P "${SSH_PORT}" \
            root@localhost:/tmp/race-collector.log "${VM_OUTPUT}/" 2>/dev/null || true
            
        log_info "VM${i} 结果已保存到 ${VM_OUTPUT}/"
    done
    
    # 收集 syzkaller 的覆盖率和 crash 信息
    log_info "收集 syzkaller 覆盖率信息..."
    if [ -d "${WORKDIR}/crashes" ]; then
        cp -r "${WORKDIR}/crashes" "${OUTPUT_DIR}/"
    fi
}

# ========== 生成汇总报告 ==========
generate_report() {
    log_info "生成汇总报告..."
    
    REPORT_FILE="${OUTPUT_DIR}/experiment_report.txt"
    
    {
        echo "=========================================="
        echo "  syzkaller + KCSAN Race Collection Report"
        echo "=========================================="
        echo ""
        echo "实验时间: $(date)"
        echo "实验时长: ${EXPERIMENT_DURATION} 秒"
        echo "VM 数量: ${VM_COUNT}"
        echo ""
        echo "=========================================="
        echo "  Race Pair 统计"
        echo "=========================================="
        
        total_races=0
        for i in $(seq 0 $((VM_COUNT - 1))); do
            VM_OUTPUT="${OUTPUT_DIR}/vm${i}"
            if [ -f "${VM_OUTPUT}/race_stats.json" ]; then
                echo ""
                echo "--- VM${i} ---"
                # 提取统计信息
                if command -v jq &> /dev/null; then
                    races=$(jq '.race_pairs_detected // 0' "${VM_OUTPUT}/race_stats.json" 2>/dev/null || echo "0")
                    echo "检测到的 Race Pairs: ${races}"
                    total_races=$((total_races + races))
                else
                    cat "${VM_OUTPUT}/race_stats.json"
                fi
            else
                echo "VM${i}: 无数据"
            fi
        done
        
        echo ""
        echo "=========================================="
        echo "  总计"
        echo "=========================================="
        echo "总 Race Pairs: ${total_races}"
        
        echo ""
        echo "=========================================="
        echo "  KCSAN Crashes (来自 syzkaller)"
        echo "=========================================="
        if [ -d "${OUTPUT_DIR}/crashes" ]; then
            kcsan_count=$(find "${OUTPUT_DIR}/crashes" -name "description" -exec grep -l "KCSAN" {} \; 2>/dev/null | wc -l)
            echo "KCSAN 报告数量: ${kcsan_count}"
        else
            echo "无 crash 数据"
        fi
        
    } > "${REPORT_FILE}"
    
    cat "${REPORT_FILE}"
    log_info "报告已保存到 ${REPORT_FILE}"
}

# ========== 清理 ==========
cleanup() {
    log_info "清理进程..."
    
    # 停止 syz-manager
    if [ -n "${SYZ_MANAGER_PID}" ]; then
        sudo kill "${SYZ_MANAGER_PID}" 2>/dev/null || true
    fi
    
    log_info "清理完成"
}

# ========== 信号处理 ==========
trap cleanup EXIT

# ========== 主流程 ==========
main() {
    log_info "=========================================="
    log_info "  syzkaller + KCSAN Race Collection"
    log_info "=========================================="
    
    check_dependencies
    setup_directories
    start_syz_manager
    start_race_collectors
    wait_for_experiment
    collect_results
    generate_report
    
    log_info "实验完成！"
}

# ========== 解析命令行参数 ==========
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            EXPERIMENT_DURATION="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-d duration_seconds] [-c config_file]"
            echo "  -d, --duration    实验时长（秒），默认 3600"
            echo "  -c, --config      syzkaller 配置文件"
            exit 0
            ;;
        *)
            log_error "未知参数: $1"
            exit 1
            ;;
    esac
done

main
