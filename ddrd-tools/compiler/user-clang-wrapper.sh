#!/bin/bash

# --- 动态配置区 ---
# 该脚本会根据其被调用的名称，智能地选择作为 C 编译器或 C++ 编译器的包装器。
#
# 使用方法:
# 1. 将此脚本保存 (例如，保存为 /path/to/compiler_filter.sh)。
# 2. 创建两个符号链接指向它:
#    ln -s /path/to/compiler_filter.sh /usr/local/bin/ddrace-cc
#    ln -s /path/to/compiler_filter.sh /usr/local/bin/ddrace-cxx
# 3. 在您的 CMake 或 Makefile 中，分别将 CC 设置为 ddrace-cc，将 CXX 设置为 ddrace-cxx。

script_name=$(basename "$0")

# 默认使用 C 编译器配置
CLANG="/home/zzzccc/llvm-project/build/bin/clang"
CLANG_WRAPPER="/home/zzzccc/DDRD/compiler/ddrace-cc" # 指向您的 C 编译器包装器
FLAGS=" -lstdc++"
# 如果脚本名包含 "++" 或 "cxx"，则切换到 C++ 编译器配置
if [[ "$script_name" == *"++"* || "$script_name" == *"cxx"* ]]; then
    CLANG="/home/zzzccc/llvm-project/build/bin/clang++"
    CLANG_WRAPPER="/home/zzzccc/DDRD/compiler/ddrace-cxx" # 指向您的 C++ 编译器包装器
    FLAGS=" "
fi
# --- 配置区结束 ---

# 用于存储找到的源文件路径
source_file=""

# 遍历所有传入的参数，找出第一个源文件
# 通常一个编译命令只处理一个源文件
for arg in "$@"; do
    # 检查参数是否以 .c 或 .cpp 等结尾
    if [[ "$arg" == *.c || "$arg" == *.cc || "$arg" == *.cpp || "$arg" == *.cxx ]]; then
        source_file="$arg"
        break # 找到第一个就退出循环
    fi
done

# --- 核心过滤逻辑 ---
# 首先检查源文件的路径是否包含 "/extra/"，如果是则直接使用原始编译器
if [[ -n "$source_file" && "$source_file" == *"/extra/"* ]]; then
    # echo "直接调用: $CLANG $@"
    exec "$CLANG" "$@"
fi

# 如果没有在参数中找到源文件 (这很可能是一个链接命令)
# 或者找到的文件实际上不存在，则直接使用原始 Clang/Clang++ 处理
if [[ -z "$source_file" || ! -f "$source_file" ]]; then
    exec "$CLANG_WRAPPER" -L/home/zzzccc/llvm-project/build/lib/clang/18/lib/x86_64-unknown-linux-gnu -l:libclang_rt.ddrace.so "$@"
    # exec "$CLANG_WRAPPER" -L/home/zzzccc/llvm-project/build/lib/clang/18/lib/x86_64-unknown-linux-gnu -l:libclang_rt.ddrace.a "$@"
fi

# 对于非extra路径的源文件，使用插桩编译器
echo "Compiling with instrumentation: $CLANG_WRAPPER --ddrace-functions --ddrace-variables --ddrace-debug $FLAGS"
exec "$CLANG_WRAPPER" --ddrace-functions --ddrace-variables --ddrace-debug "$@" $FLAGS
