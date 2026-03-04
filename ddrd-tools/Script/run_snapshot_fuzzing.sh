#!/bin/bash

# 快照模式模糊测试启动脚本
# 使用方法：./run_snapshot_fuzzing.sh [test_cases_dir] [qemu_config_path] [random_runs]

# 参数设置
TESTCASES_DIR=${1:-"/home/zzzccc/DDRD/build/bin"}
QEMU_CONFIG=${2:-"/home/zzzccc/DDRD/Qemu/config.json"} 
RANDOM_RUNS=${3:-10}

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
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

print_info "============================================"
print_info "       DDRD 快照模式模糊测试启动器"
print_info "============================================"

# 检查参数
print_info "测试用例目录: $TESTCASES_DIR"
print_info "QEMU配置文件: $QEMU_CONFIG"
print_info "随机运行次数: $RANDOM_RUNS"

# 检查文件存在性
if [ ! -d "$TESTCASES_DIR" ]; then
    print_error "测试用例目录不存在: $TESTCASES_DIR"
    exit 1
fi

if [ ! -f "$QEMU_CONFIG" ]; then
    print_error "QEMU配置文件不存在: $QEMU_CONFIG"
    exit 1
fi

# 检查执行文件
EXECUTOR_BIN="/home/zzzccc/DDRD/build/bin/executor"
if [ ! -f "$EXECUTOR_BIN" ]; then
    print_error "执行器二进制文件不存在: $EXECUTOR_BIN"
    print_info "请先编译项目: cd /home/zzzccc/DDRD/build && make"
    exit 1
fi

# 检查测试用例数量
TESTCASE_COUNT=$(find "$TESTCASES_DIR" -type f -executable | wc -l)
print_info "发现 $TESTCASE_COUNT 个可执行测试用例"

if [ "$TESTCASE_COUNT" -eq 0 ]; then
    print_warning "没有找到可执行的测试用例"
    exit 1
fi

# 检查QEMU是否可用
QEMU_BINARY=$(jq -r '.qemu' "$QEMU_CONFIG" 2>/dev/null)
if [ "$?" -ne 0 ] || [ "$QEMU_BINARY" == "null" ]; then
    print_error "无法从配置文件中读取QEMU二进制路径"
    exit 1
fi

if [ ! -f "$QEMU_BINARY" ]; then
    print_error "QEMU二进制文件不存在: $QEMU_BINARY"
    exit 1
fi

print_success "环境检查通过"

# 计算预计测试对数量
TOTAL_PAIRS=$((TESTCASE_COUNT * (TESTCASE_COUNT - 1) / 2))
print_info "预计将测试 $TOTAL_PAIRS 个测试对"

# 预计时间估算（假设每个测试对平均10秒）
ESTIMATED_TIME=$((TOTAL_PAIRS * 10))
ESTIMATED_HOURS=$((ESTIMATED_TIME / 3600))
ESTIMATED_MINUTES=$(((ESTIMATED_TIME % 3600) / 60))

print_info "预计总耗时: ${ESTIMATED_HOURS}小时${ESTIMATED_MINUTES}分钟"

# 确认执行
read -p "是否开始执行快照模式模糊测试？(y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "用户取消执行"
    exit 0
fi

print_info "开始执行快照模式模糊测试..."

# 创建日志目录
LOG_DIR="/home/zzzccc/DDRD/logs/snapshot_fuzzing"
mkdir -p "$LOG_DIR"

# 生成日志文件名
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
LOG_FILE="$LOG_DIR/snapshot_fuzzing_$TIMESTAMP.log"

print_info "日志文件: $LOG_FILE"

# 执行模糊测试
print_info "启动快照模式模糊测试..."

# 使用nohup在后台运行，并记录日志
nohup "$EXECUTOR_BIN" \
    --bin-dir "$TESTCASES_DIR" \
    --qemu-config "$QEMU_CONFIG" \
    --random-runs "$RANDOM_RUNS" \
    --snapshot-mode \
    > "$LOG_FILE" 2>&1 &

EXECUTOR_PID=$!

print_success "快照模式模糊测试已启动"
print_info "进程ID: $EXECUTOR_PID"
print_info "实时日志: tail -f $LOG_FILE"

# 提供一些监控命令
cat << EOF

快速监控命令：
1. 查看实时日志:    tail -f $LOG_FILE
2. 查看进程状态:    ps aux | grep $EXECUTOR_PID
3. 停止测试:        kill $EXECUTOR_PID
4. 查看网络连接:    netstat -tuln | grep -E "(22|monitor_port)"

EOF

print_success "脚本执行完成"
