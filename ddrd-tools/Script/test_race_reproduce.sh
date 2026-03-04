#!/bin/bash

# DDRD 竞争复现测试脚本
# 测试无锁和单边锁竞争复现功能

set -e

echo "=== DDRD 竞争复现功能测试 ==="
echo "测试时间: $(date)"
echo

# 配置参数
EXECUTOR_PATH="/home/zzzccc/DDRD/build/bin/KCCWFExecutor"
BIN_DIR="/home/zzzccc/DDRD/build/bin"
TRACE_PATH="/sys/kernel/debug/tracing/instances/concurrency_checking/trace"

# 检查执行器是否存在
if [[ ! -f "$EXECUTOR_PATH" ]]; then
    echo "错误: 找不到执行器 $EXECUTOR_PATH"
    exit 1
fi

echo "执行器路径: $EXECUTOR_PATH"
echo "测试二进制目录: $BIN_DIR"
echo "跟踪路径: $TRACE_PATH"
echo

# 测试1: 竞争复现模式
echo "=== 测试1: 竞争复现模式 ==="
echo "运行参数: --mode race-reproduce --bin-dir $BIN_DIR --verbose"

if timeout 60s "$EXECUTOR_PATH" \
    --mode race-reproduce \
    --bin-dir "$BIN_DIR" \
    --concurrency 2 \
    --timeout 10 \
    --verbose; then
    echo "✓ 竞争复现模式测试成功"
else
    echo "✗ 竞争复现模式测试失败 (退出码: $?)"
fi
echo

# 测试2: 测试单个测试对
echo "=== 测试2: 测试单个测试对 ==="

# 查找两个测试文件
TEST_FILES=($(find "$BIN_DIR" -type f -executable | head -2))
if [[ ${#TEST_FILES[@]} -lt 2 ]]; then
    echo "警告: 测试目录中可执行文件不足2个，跳过测试对测试"
else
    echo "测试文件1: ${TEST_FILES[0]}"
    echo "测试文件2: ${TEST_FILES[1]}"
    
    if timeout 30s "$EXECUTOR_PATH" \
        --mode test-pair \
        --test-file1 "${TEST_FILES[0]}" \
        --test-file2 "${TEST_FILES[1]}" \
        --verbose; then
        echo "✓ 测试对模式测试成功"
    else
        echo "✗ 测试对模式测试失败 (退出码: $?)"
    fi
fi
echo

# 测试3: 正常模式（短时间）
echo "=== 测试3: 正常模式（短时间测试）==="
if timeout 30s "$EXECUTOR_PATH" \
    --mode normal \
    --bin-dir "$BIN_DIR" \
    --concurrency 1 \
    --timeout 5 \
    --verbose; then
    echo "✓ 正常模式测试成功"
else
    echo "✗ 正常模式测试失败 (退出码: $?)"
fi
echo

echo "=== 测试完成 ==="
echo "测试时间: $(date)"
