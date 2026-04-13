#!/usr/bin/env bash
# ============================================================================
# build_ddrd_tools.sh — 编译 DDRD 工具链
#
# 用法:
#   ./scripts/build_ddrd_tools.sh              # 编译全部
#   ./scripts/build_ddrd_tools.sh compiler     # 仅编译 kernel_compiler + ddrace-cc/cxx
#   ./scripts/build_ddrd_tools.sh instrumenter # 仅编译 instrumenter (LLVM pass)
#   ./scripts/build_ddrd_tools.sh analyzer     # 仅编译 report-analyzer (VarName/IR 分析)
#   ./scripts/build_ddrd_tools.sh userspace    # 仅编译 userspace-compiler (ddrace-cc/cxx)
#   ./scripts/build_ddrd_tools.sh clean        # 清理所有构建产物
#   ./scripts/build_ddrd_tools.sh check        # 检查依赖和工具链状态
#
# 组件说明:
#   kernel_compiler  — 内核编译时的插桩包装器, 被 clang-wrapper.sh 调用
#   instrumenter     — LLVM IR 插桩 pass (需要 LLVM 18)
#   report-analyzer  — 从 instrumented.ll 反查 VarName/hash 到源码位置
#   ddrace-cc/cxx    — 用户态程序插桩编译器 (C/C++)
#
# 环境变量:
#   DDRD_LLVM        LLVM 安装路径 (默认: /home/zzzccc/llvm-15/llvm-project/build)
#   DDRD_TOOLCHAIN   工具链根目录 (默认: <项目>/ddrd-tools)
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"

TOOLS_DIR="$DDRD_TOOLCHAIN"
COMPILER_DIR="$TOOLS_DIR/compiler"
INSTRUMENTER_DIR="$TOOLS_DIR/instrumenter"
BUILD_DIR="$TOOLS_DIR/build"
ANALYZER_DIR="$TOOLS_DIR/report-analyzer"
ANALYZER_BUILD_DIR="$BUILD_DIR/report-analyzer"

COMPONENT="${1:-all}"

# --------------- 日志 ---------------
log_info()  { echo -e "\033[34m[INFO]\033[0m $*"; }
log_ok()    { echo -e "\033[32m[ OK ]\033[0m $*"; }
log_err()   { echo -e "\033[31m[ERR ]\033[0m $*"; }
log_warn()  { echo -e "\033[33m[WARN]\033[0m $*"; }
log_step()  { echo -e "\n\033[1;36m==> $*\033[0m"; }

# --------------- 查找 LLVM ---------------
find_llvm_cmake() {
    for candidate in \
        "${DDRD_LLVM}/lib/cmake/llvm" \
        "/usr/lib/llvm-18/lib/cmake/llvm" \
        "/usr/lib/cmake/llvm-18" \
        "/usr/local/lib/cmake/llvm" \
        "/usr/lib/llvm-15/lib/cmake/llvm"; do
        if [[ -d "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# --------------- 构建: kernel_compiler ---------------
build_kernel_compiler() {
    log_step "编译 kernel_compiler"
    log_info "源文件: $COMPILER_DIR/kernel-compiler.cpp"

    g++ -std=c++14 -Wall -O2 -g \
        -o "$COMPILER_DIR/kernel_compiler" \
        "$COMPILER_DIR/kernel-compiler.cpp"

    log_ok "kernel_compiler -> $COMPILER_DIR/kernel_compiler"
    log_info "  被 clang-wrapper.sh 在内核编译时调用"
    log_info "  负责: .c → .ll (IR) → instrumenter 插桩 → .o (编译)"
}

# --------------- 构建: ddrace-cc / ddrace-cxx (用户态) ---------------
build_userspace_compiler() {
    log_step "编译 ddrace-cc / ddrace-cxx (用户态编译器)"
    log_info "源文件: $COMPILER_DIR/userspace-compiler.cpp"

    g++ -std=c++14 -Wall -O2 -g \
        -o "$COMPILER_DIR/ddrace-cc" \
        "$COMPILER_DIR/userspace-compiler.cpp"

    g++ -std=c++14 -Wall -O2 -g -DDDRACE_CXX \
        -o "$COMPILER_DIR/ddrace-cxx" \
        "$COMPILER_DIR/userspace-compiler.cpp"

    log_ok "ddrace-cc  -> $COMPILER_DIR/ddrace-cc"
    log_ok "ddrace-cxx -> $COMPILER_DIR/ddrace-cxx"
    log_info "  用于用户态程序的 data-race 检测编译"
}

# --------------- 构建: instrumenter (LLVM pass) ---------------
build_instrumenter() {
    log_step "编译 instrumenter (LLVM IR 插桩工具)"

    local llvm_cmake
    if ! llvm_cmake=$(find_llvm_cmake); then
        log_err "找不到 LLVM cmake 配置"
        log_err "请确保 LLVM 18 已安装, 或设置 DDRD_LLVM 环境变量"
        log_err "  例: export DDRD_LLVM=/usr/lib/llvm-18"
        return 1
    fi

    log_info "LLVM cmake: $llvm_cmake"
    log_info "源码目录:   $INSTRUMENTER_DIR"
    log_info "构建目录:   $BUILD_DIR"

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    cmake "$INSTRUMENTER_DIR" \
        -DLLVM_DIR="$llvm_cmake" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON 2>&1 | tail -5

    make -j"$(nproc)" 2>&1 | tail -10

    [[ -x "$BUILD_DIR/bin/instrumenter" ]] \
        || { log_err "instrumenter 编译失败"; return 1; }

    log_ok "instrumenter -> $BUILD_DIR/bin/instrumenter"
    log_info "  对 LLVM IR (.ll) 进行函数/变量/锁/内存释放插桩"
}

# --------------- 构建: report-analyzer (VarName/IR 分析工具) ---------------
build_report_analyzer() {
    log_step "编译 report-analyzer (VarName/IR 分析工具)"

    local llvm_cmake
    if ! llvm_cmake=$(find_llvm_cmake); then
        log_err "找不到 LLVM cmake 配置"
        log_err "请确保 LLVM 已安装, 或设置 DDRD_LLVM 环境变量"
        return 1
    fi

    log_info "LLVM cmake: $llvm_cmake"
    log_info "源码目录:   $ANALYZER_DIR"
    log_info "构建目录:   $ANALYZER_BUILD_DIR"

    mkdir -p "$ANALYZER_BUILD_DIR"
    cd "$ANALYZER_BUILD_DIR"

    cmake "$ANALYZER_DIR" \
        -DLLVM_DIR="$llvm_cmake" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON 2>&1 | tail -5

    make -j"$(nproc)" 2>&1 | tail -10

    [[ -x "$ANALYZER_BUILD_DIR/bin/report-analyzer" ]] \
        || { log_err "report-analyzer 编译失败"; return 1; }

    log_ok "report-analyzer -> $ANALYZER_BUILD_DIR/bin/report-analyzer"
    log_info "  用于从 instrumented.ll 反查 VarName/hash 的真实访问点"
}

# --------------- 清理 ---------------
do_clean() {
    log_step "清理构建产物"
    rm -rf "$BUILD_DIR"
    rm -f "$COMPILER_DIR/kernel_compiler" \
          "$COMPILER_DIR/ddrace-cc" \
          "$COMPILER_DIR/ddrace-cxx" \
          "$COMPILER_DIR/userspace-compiler"
    find "$TOOLS_DIR" -name '*.o' -delete 2>/dev/null || true
    find "$TOOLS_DIR" -name '*.ll' -delete 2>/dev/null || true
    log_ok "已清理"
}

# --------------- 检查 ---------------
do_check() {
    log_step "检查 DDRD 工具链状态"
    echo ""

    printf "  %-30s " "DDRD_TOOLCHAIN"
    if [[ -d "$TOOLS_DIR" ]]; then
        echo -e "\033[32m$TOOLS_DIR\033[0m"
    else
        echo -e "\033[31m不存在\033[0m"
    fi

    printf "  %-30s " "DDRD_LLVM"
    echo "$DDRD_LLVM"

    echo ""
    echo "  二进制文件:"
    for bin in \
        "$COMPILER_DIR/kernel_compiler" \
        "$COMPILER_DIR/ddrace-cc" \
        "$COMPILER_DIR/ddrace-cxx" \
        "$BUILD_DIR/bin/instrumenter" \
        "$ANALYZER_BUILD_DIR/bin/report-analyzer"; do
        printf "    %-40s " "$(basename "$bin")"
        if [[ -x "$bin" ]]; then
            local sz; sz=$(du -h "$bin" | cut -f1)
            echo -e "\033[32m✓\033[0m ($sz)"
        else
            echo -e "\033[31m✗ 未编译\033[0m"
        fi
    done

    echo ""
    echo "  脚本/配置:"
    for f in \
        "$COMPILER_DIR/clang-wrapper.sh" \
        "$COMPILER_DIR/instrumentation_targets.conf" \
        "$INSTRUMENTER_DIR/LockFunc.txt"; do
        printf "    %-40s " "$(basename "$f")"
        if [[ -f "$f" ]]; then
            echo -e "\033[32m✓\033[0m"
        else
            echo -e "\033[31m✗ 缺失\033[0m"
        fi
    done

    echo ""
    echo "  编译器依赖:"
    for cmd in g++ cmake clang-18; do
        printf "    %-40s " "$cmd"
        if command -v "$cmd" &>/dev/null; then
            local ver; ver=$($cmd --version 2>&1 | head -1)
            echo -e "\033[32m✓\033[0m ($ver)"
        else
            echo -e "\033[33m✗ 未安装\033[0m"
        fi
    done

    echo ""
    printf "  %-30s " "LLVM cmake 配置"
    if llvm_cmake=$(find_llvm_cmake); then
        echo -e "\033[32m$llvm_cmake\033[0m"
    else
        echo -e "\033[31m未找到 (instrumenter 无法编译)\033[0m"
    fi
}

# --------------- 入口 ---------------
case "$COMPONENT" in
    all)
        build_kernel_compiler
        build_userspace_compiler
        build_instrumenter
        build_report_analyzer
        echo ""
        log_ok "========== 全部编译完成 =========="
        ;;
    compiler)
        build_kernel_compiler
        ;;
    userspace)
        build_userspace_compiler
        ;;
    instrumenter)
        build_instrumenter
        ;;
    analyzer|report-analyzer)
        build_report_analyzer
        ;;
    clean)
        do_clean
        ;;
    check|status)
        do_check
        ;;
    -h|--help|help)
        sed -n '3,21p' "$0" | sed 's/^# //' | sed 's/^#//'
        ;;
    *)
        log_err "未知组件: $COMPONENT"
        echo "用法: $0 [all|compiler|userspace|instrumenter|analyzer|clean|check|help]"
        exit 1
        ;;
esac
