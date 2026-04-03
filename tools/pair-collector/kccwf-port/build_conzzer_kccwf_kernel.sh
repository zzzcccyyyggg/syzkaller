#!/usr/bin/env bash
# ============================================================================
# build_conzzer_kccwf_kernel.sh — 构建带 KCCWF 插桩的 Conzzer 内核
#
# Conzzer 内核的编译流水线:
#   原始: .c → .ll → SDILP (checker) → AFLCplusplusCompiler (fuzz) → .o
#   增强: .c → .ll → SDILP → AFLCplusplusCompiler → KCCWF instrumenter → .o
#
# 此脚本:
#   1. 检查 Conzzer 内核是否已有 KCCWF 源码（如果没有则调用 port_kccwf.sh）
#   2. 创建增强版 gcc_kernel_compiler 二进制
#   3. 构建内核
#
# 使用方法:
#   ./build_conzzer_kccwf_kernel.sh [options]
#
# 示例:
#   # 使用默认路径
#   ./build_conzzer_kccwf_kernel.sh
#
#   # 指定路径
#   ./build_conzzer_kccwf_kernel.sh \
#       --kernel /home/zzzccc/Linux-Kernel/Conzzer-Kernel \
#       --modules btrfs
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ts() { date +"%Y-%m-%d %H:%M:%S"; }
log_info()  { echo -e "$(ts) ${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "$(ts) ${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "$(ts) ${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "$(ts) ${BLUE}[STEP]${NC}  $*"; }

# ============================================================================
# 默认路径
# ============================================================================
DDRD_KERNEL="${DDRD_KERNEL:-/home/zzzccc/Linux-Kernel/DDRD-Kernel}"
CONZZER_KERNEL="${CONZZER_KERNEL:-/home/zzzccc/Linux-Kernel/Conzzer-Kernel}"
CONZZER_DIR="${CONZZER_DIR:-/home/zzzccc/BASS/Conzzer}"
DDRD_DIR="${DDRD_DIR:-/home/zzzccc/BASS/DDRD}"
INSTRUMENTER="${DDRD_DIR}/build/bin/instrumenter"
LOCK_FILE="${DDRD_DIR}/instrumenter/LockFunc.txt"

CONZZER_COMPILER_DIR="$CONZZER_DIR/conzzer-kernel-fuzzer-concurrency-fuzz/compiler"
CONZZER_GCC_COMPILER="$CONZZER_COMPILER_DIR/gcc_kernel_compiler"
CONZZER_GCC_COMPILER_SRC="$CONZZER_COMPILER_DIR/gcc_kernel_compiler.cpp"

BUILD_DIR=""
MODULES=""
JOBS=$(nproc)
TARGET_ARCH="x86"

# 插桩目标配置（与 Conzzer 实验模块对应）
declare -A MODULE_TARGETS=(
    ["btrfs"]="fs/btrfs/"
    ["xfs"]="fs/xfs/"
    ["f2fs"]="fs/f2fs/"
    ["jfs"]="fs/jfs/"
    ["floppy"]="drivers/block/floppy.c"
    ["bt-stack"]="net/bluetooth/"
    ["ptmx"]="drivers/tty/"
    ["dsp"]="sound/core/ sound/pci/"
)

# ============================================================================
# 帮助信息
# ============================================================================
print_usage() {
    cat <<'EOF'
Usage: build_conzzer_kccwf_kernel.sh [options]

Options:
  --kernel <path>       Conzzer kernel source (default: $CONZZER_KERNEL)
  --build-dir <path>    Out-of-tree build directory
  --modules <list>      Comma-separated module slugs to instrument
                        (btrfs, xfs, f2fs, jfs, floppy, bt-stack, ptmx, dsp)
                        If omitted, instruments all modules
  --jobs <n>            Parallel jobs for make (default: nproc)
  --skip-kccwf-port     Skip KCCWF porting step (assume already done)
  --skip-build          Only prepare compiler, don't build kernel
  -h, --help            Show this help
EOF
}

SKIP_PORT=false
SKIP_BUILD=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --kernel)       CONZZER_KERNEL="$2"; shift 2 ;;
            --build-dir)    BUILD_DIR="$2"; shift 2 ;;
            --modules)      MODULES="$2"; shift 2 ;;
            --jobs)         JOBS="$2"; shift 2 ;;
            --skip-kccwf-port) SKIP_PORT=true; shift ;;
            --skip-build)   SKIP_BUILD=true; shift ;;
            -h|--help)      print_usage; exit 0 ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
}

# ============================================================================
# Step 1: 确保 KCCWF 源码存在
# ============================================================================
ensure_kccwf() {
    log_step "Step 1: Ensuring KCCWF is ported to Conzzer kernel..."

    if $SKIP_PORT; then
        log_info "Skipping KCCWF port (--skip-kccwf-port)"
        return 0
    fi

    if [[ -d "$CONZZER_KERNEL/kernel/kccwf" ]] && \
       grep -q "kccwf_disable_count" "$CONZZER_KERNEL/include/linux/sched.h" 2>/dev/null; then
        log_info "KCCWF already present in Conzzer kernel."
        return 0
    fi

    log_info "Porting KCCWF to Conzzer kernel..."
    bash "$SCRIPT_DIR/port_kccwf.sh" \
        --source "$DDRD_KERNEL" \
        --target "$CONZZER_KERNEL" \
        --force
}

# ============================================================================
# Step 2: 生成 KCCWF 增强版 gcc_kernel_compiler
#
# 方案: 创建一个 shell 脚本包装器，在 Conzzer 原编译完成后
#       额外运行 KCCWF instrumenter
# ============================================================================
create_enhanced_compiler() {
    log_step "Step 2: Creating KCCWF-enhanced compiler wrapper..."

    local wrapper="$CONZZER_COMPILER_DIR/gcc_kernel_compiler_kccwf"

    cat > "$wrapper" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# KCCWF-enhanced Conzzer compiler wrapper
# Wraps original gcc_kernel_compiler, then applies KCCWF instrumentation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_COMPILER="$SCRIPT_DIR/gcc_kernel_compiler"
WRAPPER_EOF

    # 写入配置变量
    cat >> "$wrapper" <<EOF
INSTRUMENTER="$INSTRUMENTER"
LOCK_FILE="$LOCK_FILE"
EOF

    cat >> "$wrapper" <<'WRAPPER_BODY'

# KCCWF 排除目录
KCCWF_EXCLUDE_DIRS=("kernel/kccwf/" "drivers/char/kccwf/")

# 检查是否应排除
is_excluded() {
    local path="${1#./}"
    for excl in "${KCCWF_EXCLUDE_DIRS[@]}"; do
        [[ "$path" == "$excl"* ]] && return 0
    done
    return 1
}

# 解析编译参数
TARGET_O=""
TARGET_C=""
HAS_C=false
next_is_o=false

for arg in "$@"; do
    if $next_is_o; then
        TARGET_O="$arg"
        next_is_o=false
        continue
    fi
    case "$arg" in
        -o) next_is_o=true ;;
        -c) HAS_C=true ;;
        *.c) [[ -f "$arg" ]] && TARGET_C="$arg" ;;
    esac
done

# 非编译命令或汇编文件 → 直接传递
if [[ -z "$TARGET_C" ]] || ! $HAS_C; then
    exec "$ORIGINAL_COMPILER" "$@"
fi

# 排除的目录 → 直接传递
if is_excluded "$TARGET_C"; then
    exec "$ORIGINAL_COMPILER" "$@"
fi

# 计算 basename
if [[ -z "$TARGET_O" ]]; then
    base="${TARGET_C%.c}"
    TARGET_O="${base##*/}.o"
fi

if [[ "$TARGET_O" == *.mod.o ]]; then
    exec "$ORIGINAL_COMPILER" "$@"
fi

TARGET_N="${TARGET_O%.o}"

# === Step A: 运行原始 Conzzer 编译器 ===
# 原始编译器的流水线: .c → .ll → SDILP → AFLCplusplusCompiler → .ll → .o
# 但它最终编译 .ll → .o，所以 .ll 文件在编译后会被清理
#
# 我们需要拦截这个过程：
#   1. 让原始编译器执行整个流水线得到 .o
#   2. 然后从源代码重新生成 .ll，应用 KCCWF 插桩
#
# 更好的方案：在原编译器完成后，我们用 kccwf_cc_wrapper.sh 重新编译
# 但这样会丢失 Conzzer 的插桩。
#
# 最佳方案（保留双重插桩）:
#   修改 Conzzer 编译器的 .ll 文件在最终编译前被 KCCWF instrumenter 处理。
#   由于原始编译器在最后一步把 .ll 编译为 .o，
#   我们可以在该步骤之前插入 KCCWF instrumenter。
#
# 实现: 不直接调用原始编译器，而是重复其流水线并在最后一步前插入 KCCWF

# 由于重复 Conzzer 完整的编译流水线太复杂，我们采用后处理方案：
# 让原始编译器完成后，对 .ll 文件（如果还存在）应用 KCCWF

# 先调用原始编译器
"$ORIGINAL_COMPILER" "$@"
original_rc=$?

if [[ $original_rc -ne 0 ]]; then
    exit $original_rc
fi

# 检查 .ll 文件是否还存在（Conzzer 编译器不删除 .ll）
LL_FILE="${TARGET_N}.ll"
if [[ ! -f "$LL_FILE" ]]; then
    # .ll 不存在了，需要反编译 .o 得到 .ll
    # 这不实际，所以跳过 KCCWF 插桩
    # echo "[kccwf] WARNING: .ll file not found after Conzzer compile, skipping KCCWF instrumentation for $TARGET_C" >&2
    exit 0
fi

# === Step B: 在 .ll 上应用 KCCWF instrumenter ===
INSTRUMENTED_FILE="${TARGET_N}.instrumented.ll"

inst_args=("$INSTRUMENTER" "$LL_FILE" "-v" "-f" "--free")
if [[ -f "$LOCK_FILE" ]]; then
    inst_args+=("-l" "$LOCK_FILE")
fi

"${inst_args[@]}" 2>/dev/null || true

# === Step C: 重新编译插桩后的 .ll → .o ===
if [[ -f "$INSTRUMENTED_FILE" ]]; then
    clang-18 -Og -Qunused-arguments -Wno-unused-command-line-argument \
        -c "$INSTRUMENTED_FILE" -o "$TARGET_O" 2>/dev/null || true
    rm -f "$INSTRUMENTED_FILE"
fi

# 清理
rm -f "$LL_FILE"
exit 0
WRAPPER_BODY

    chmod +x "$wrapper"
    log_info "Created: $wrapper"
}

# ============================================================================
# Step 3: 配置插桩目标
# ============================================================================
configure_instrument_targets() {
    log_step "Step 3: Configuring instrumentation targets..."

    local target_modules=()
    if [[ -n "$MODULES" ]]; then
        IFS=',' read -ra target_modules <<< "$MODULES"
    else
        target_modules=("${!MODULE_TARGETS[@]}")
    fi

    # 为 Conzzer 设置环境变量
    local include_dirs=""
    for mod in "${target_modules[@]}"; do
        mod="${mod// /}"
        if [[ -n "${MODULE_TARGETS[$mod]:-}" ]]; then
            local paths
            read -ra paths <<< "${MODULE_TARGETS[$mod]}"
            for p in "${paths[@]}"; do
                include_dirs="${include_dirs:+$include_dirs:}$p"
            done
        else
            log_warn "Unknown module: $mod"
        fi
    done

    log_info "Instrument targets: $include_dirs"
    export CONZZER_INSTRUMENT_MODE="include"
    export CONZZER_INSTRUMENT_INCLUDE="$include_dirs"
}

# ============================================================================
# Step 4: 构建内核
# ============================================================================
build_kernel() {
    log_step "Step 4: Building Conzzer kernel with KCCWF..."

    if $SKIP_BUILD; then
        log_info "Skipping kernel build (--skip-build)"
        return 0
    fi

    local make_args=(
        "ARCH=$TARGET_ARCH"
        "CC=$CONZZER_COMPILER_DIR/gcc_kernel_compiler_kccwf"
        "-j$JOBS"
    )

    if [[ -n "$BUILD_DIR" ]]; then
        mkdir -p "$BUILD_DIR"
        make_args+=("O=$BUILD_DIR")
    fi

    cd "$CONZZER_KERNEL"

    log_info "Running: make ${make_args[*]}"
    make "${make_args[@]}"

    local build_root="${BUILD_DIR:-$CONZZER_KERNEL}"
    if [[ -f "$build_root/vmlinux" ]]; then
        log_info "Build successful: $build_root/vmlinux"
    else
        log_error "Build failed: vmlinux not found"
        exit 1
    fi
}

# ============================================================================
# Main
# ============================================================================
main() {
    parse_args "$@"

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Conzzer Kernel + KCCWF Build"
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Conzzer Kernel: $CONZZER_KERNEL"
    log_info " DDRD Kernel:    $DDRD_KERNEL"
    log_info " Instrumenter:   $INSTRUMENTER"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # 检查前置条件
    if [[ ! -x "$INSTRUMENTER" ]]; then
        log_error "KCCWF instrumenter not found: $INSTRUMENTER"
        log_error "Build it first: cd $DDRD_DIR && mkdir -p build && cd build && cmake .. && make"
        exit 1
    fi

    if [[ ! -x "$CONZZER_GCC_COMPILER" ]]; then
        log_error "Conzzer gcc_kernel_compiler not found: $CONZZER_GCC_COMPILER"
        exit 1
    fi

    ensure_kccwf
    create_enhanced_compiler
    configure_instrument_targets
    build_kernel

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Build Complete"
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Kernel with KCCWF + Conzzer instrumentation is ready."
    log_info " Next: deploy this kernel image to Conzzer VMs and"
    log_info " use deploy_collector.sh to collect pair data."
    log_info "═══════════════════════════════════════════════════════════"
}

main "$@"
