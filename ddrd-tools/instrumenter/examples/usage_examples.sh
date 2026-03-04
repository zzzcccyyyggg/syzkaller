#!/bin/bash

# 插桩工具使用示例脚本

INSTRUMENTER="./build/bin/instrumenter"
INPUT_FILE="test/example.ll"
LOCK_FILE="examples/locks.txt"

echo "=== Instrumenter Usage Examples ==="
echo

# 检查工具是否存在
if [ ! -f "$INSTRUMENTER" ]; then
    echo "Error: Instrumenter not found at $INSTRUMENTER"
    echo "Please compile the project first:"
    echo "  mkdir build && cd build && cmake .. && make"
    exit 1
fi

# 检查输入文件是否存在
if [ ! -f "$INPUT_FILE" ]; then
    echo "Warning: Test input file $INPUT_FILE not found"
    echo "Please provide a valid LLVM IR file"
    INPUT_FILE="<your_input_file.ll>"
fi

echo "1. Show help information:"
echo "$INSTRUMENTER -h"
echo

echo "2. Instrument only functions and variables:"
echo "$INSTRUMENTER $INPUT_FILE -f -v"
echo

echo "3. Instrument only basic blocks:"
echo "$INSTRUMENTER $INPUT_FILE -b"
echo

echo "4. Instrument with lock operations:"
echo "$INSTRUMENTER $INPUT_FILE -l $LOCK_FILE"
echo

echo "5. Instrument everything:"
echo "$INSTRUMENTER $INPUT_FILE -a -l $LOCK_FILE"
echo

echo "6. Custom combination:"
echo "$INSTRUMENTER $INPUT_FILE -f -b -l $LOCK_FILE"
echo

echo "=== End of Examples ==="
echo
echo "Note: Replace '$INPUT_FILE' with your actual LLVM IR file path"
