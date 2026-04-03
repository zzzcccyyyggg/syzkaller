#!/usr/bin/env bash
# ============================================================================
# build_segfuzz_kccwf_kernel.sh — 构建带 KCCWF 插桩的 SegFuzz 内核
#
# SegFuzz 内核编译流水线:
#   原始: .c → clang (-fpass-plugin=MemcovPass.so) → .o
#   增强: .c → .ll → KCCWF instrumenter → .instrumented.ll
#                  → clang (-fpass-plugin=MemcovPass.so) → .o
#
# 关键点:
#   - KCCWF instrumenter 必须在 MemcovPass 之前运行
#   - KCCWF 在 LLVM IR 级别插入 kccwf_rec_mem_access() 调用
#   - MemcovPass 在 LLVM pass 级别替换 load/store 为 __ssb_pso 调用
#   - 两者可以共存: KCCWF 记录访问，MemcovPass 控制调度
#
# 使用方法:
#   ./build_segfuzz_kccwf_kernel.sh [options]
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
SEGFUZZ_KERNEL="${SEGFUZZ_KERNEL:-/home/zzzccc/BASS/segfuzz/kernels/linux-6.17-rc5}"
SEGFUZZ_DIR="${SEGFUZZ_DIR:-/home/zzzccc/BASS/segfuzz}"
DDRD_DIR="${DDRD_DIR:-/home/zzzccc/BASS/DDRD}"

INSTRUMENTER="${DDRD_DIR}/build/bin/instrumenter"
LOCK_FILE="${DDRD_DIR}/instrumenter/LockFunc.txt"
MEMCOV_PASS_SO="${SEGFUZZ_DIR}/tools/MemcovPass/build/pass/libMemcovPass.so"

BUILD_DIR=""
MODULES=""
JOBS=$(nproc)
TARGET_ARCH="x86_64"

# 模块定义
declare -A MODULE_TARGETS=(
    ["btrfs"]="fs/btrfs/"
    ["xfs"]="fs/xfs/"
    ["f2fs"]="fs/f2fs/"
    ["jfs"]="fs/jfs/"
    ["ext4"]="fs/ext4/"
    ["floppy"]="drivers/block/floppy.c"
    ["bt-stack"]="net/bluetooth/"
)

# ============================================================================
# 帮助
# ============================================================================
print_usage() {
    cat <<'EOF'
Usage: build_segfuzz_kccwf_kernel.sh [options]

Options:
  --kernel <path>       SegFuzz kernel source (default: $SEGFUZZ_KERNEL)
  --build-dir <path>    Out-of-tree build directory
  --modules <list>      Comma-separated modules (btrfs, xfs, f2fs, etc.)
  --jobs <n>            Parallel jobs for make (default: nproc)
  --skip-kccwf-port     Skip KCCWF porting
  --skip-build          Only prepare wrapper, don't build
  -h, --help            Show this help
EOF
}

SKIP_PORT=false
SKIP_BUILD=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --kernel)       SEGFUZZ_KERNEL="$2"; shift 2 ;;
            --build-dir)    BUILD_DIR="$2"; shift 2 ;;
            --modules)      MODULES="$2"; shift 2 ;;
            --jobs)         JOBS="$2"; shift 2 ;;
            --skip-kccwf-port) SKIP_PORT=true; shift ;;
            --skip-build)   SKIP_BUILD=true; shift ;;
            -h|--help)      print_usage; exit 0 ;;
            *) log_error "Unknown: $1"; exit 1 ;;
        esac
    done
}

# ============================================================================
# Step 1: 移植 KCCWF 到 SegFuzz 内核
# ============================================================================
ensure_kccwf() {
    log_step "Step 1: Porting KCCWF to SegFuzz kernel..."

    if $SKIP_PORT; then
        log_info "Skipping KCCWF port (--skip-kccwf-port)"
        return 0
    fi

    if [[ -d "$SEGFUZZ_KERNEL/kernel/kccwf" ]] && \
       grep -q "kccwf_disable_count" "$SEGFUZZ_KERNEL/include/linux/sched.h" 2>/dev/null; then
        log_info "KCCWF already present in SegFuzz kernel."
        return 0
    fi

    bash "$SCRIPT_DIR/port_kccwf.sh" \
        --source "$DDRD_KERNEL" \
        --target "$SEGFUZZ_KERNEL" \
        --force
}

# ============================================================================
# Step 2: 确保 KCCWF 目录不被 SegFuzz 插桩（KSSB_INSTRUMENT := N）
# ============================================================================
configure_kccwf_exclusions() {
    log_step "Step 2: Configuring KCCWF exclusions from SegFuzz instrumentation..."

    # kernel/kccwf/Makefile 需要有 KSSB_INSTRUMENT := N
    local kccwf_mf="$SEGFUZZ_KERNEL/kernel/kccwf/Makefile"
    if [[ -f "$kccwf_mf" ]]; then
        if ! grep -q "KSSB_INSTRUMENT" "$kccwf_mf"; then
            sed -i '1i KSSB_INSTRUMENT := N' "$kccwf_mf"
            log_info "Added KSSB_INSTRUMENT := N to kernel/kccwf/Makefile"
        fi
    fi

    # drivers/char/kccwf/Makefile 同理
    local ctl_mf="$SEGFUZZ_KERNEL/drivers/char/kccwf/Makefile"
    if [[ -f "$ctl_mf" ]]; then
        if ! grep -q "KSSB_INSTRUMENT" "$ctl_mf"; then
            sed -i '1i KSSB_INSTRUMENT := N' "$ctl_mf"
            log_info "Added KSSB_INSTRUMENT := N to drivers/char/kccwf/Makefile"
        fi
    fi
}

# ============================================================================
# Step 3: 创建 KCCWF CC 包装器
#
# SegFuzz 使用 LLVM=1（标准 clang 编译）+ -fpass-plugin=MemcovPass.so
# 我们需要在 MemcovPass 之前插入 KCCWF instrumenter
#
# 方案: 创建一个 CC 替代脚本:
#   对于需要 KCCWF 插桩的文件:
#     1. clang -S -emit-llvm ... → .ll
#     2. instrumenter .ll → .instrumented.ll
#     3. clang -c .instrumented.ll -fpass-plugin=MemcovPass.so → .o
#   对于其他文件:
#     直接 clang ... → .o
# ============================================================================
create_segfuzz_cc_wrapper() {
    log_step "Step 3: Creating SegFuzz CC wrapper with KCCWF..."

    # 生成 KCCWF 插桩目标文件
    local instrument_list="$SEGFUZZ_KERNEL/.kccwf_instrument_targets"
    generate_instrument_list "$instrument_list"

    # 复制通用 wrapper 并配置
    local wrapper_dir="$SEGFUZZ_KERNEL/.kccwf_compiler"
    mkdir -p "$wrapper_dir"

    # 复制通用 CC wrapper
    cp "$SCRIPT_DIR/kccwf_cc_wrapper.sh" "$wrapper_dir/kccwf_cc.sh"
    chmod +x "$wrapper_dir/kccwf_cc.sh"

    # 创建 SegFuzz 专用的入口脚本
    cat > "$wrapper_dir/segfuzz_kccwf_cc.sh" <<EOF
#!/usr/bin/env bash
# SegFuzz + KCCWF CC wrapper
# 将 KCCWF instrumenter 和 MemcovPass 组合使用

export KCCWF_CLANG="clang-18"
export KCCWF_INSTRUMENTER="$INSTRUMENTER"
export KCCWF_LOCK_FILE="$LOCK_FILE"
export KCCWF_INSTRUMENT_LIST="$instrument_list"
export KCCWF_REAL_CC="clang-18"
# MemcovPass 通过 -fpass-plugin= 传递给最终编译步骤
export KCCWF_EXTRA_CFLAGS="-fpass-plugin=$MEMCOV_PASS_SO"
# export KCCWF_DEBUG=1

exec "\$(dirname "\$0")/kccwf_cc.sh" "\$@"
EOF
    chmod +x "$wrapper_dir/segfuzz_kccwf_cc.sh"

    log_info "Created SegFuzz CC wrapper: $wrapper_dir/segfuzz_kccwf_cc.sh"
}

# ============================================================================
# 生成插桩目标列表
# ============================================================================
generate_instrument_list() {
    local outfile="$1"
    local target_modules=()

    if [[ -n "$MODULES" ]]; then
        IFS=',' read -ra target_modules <<< "$MODULES"
    else
        target_modules=("${!MODULE_TARGETS[@]}")
    fi

    {
        echo "# KCCWF instrumentation targets for SegFuzz"
        echo "# Generated: $(date)"
        for mod in "${target_modules[@]}"; do
            mod="${mod// /}"
            if [[ -n "${MODULE_TARGETS[$mod]:-}" ]]; then
                local paths
                read -ra paths <<< "${MODULE_TARGETS[$mod]}"
                for p in "${paths[@]}"; do
                    echo "$p"
                done
            fi
        done
    } > "$outfile"

    log_info "Instrument targets written to: $outfile"
    cat "$outfile"
}

# ============================================================================
# Step 4: 修补 SegFuzz Makefile.lib 以支持 KCCWF CC 包装器
#
# SegFuzz 的 KSSB 插桩通过 Makefile.lib 中的 _c_flags += $(CFLAGS_KSSB) 实现。
# 当使用 KCCWF CC wrapper 时，MemcovPass 由 wrapper 的 EXTRA_CFLAGS 传入，
# 不需要 Makefile.lib 再添加 -fpass-plugin=。
#
# 方案: 需要禁用 Makefile.lib 中的 KSSB pass-plugin 自动添加，
# 因为 CC wrapper 已经在正确的时间点（KCCWF 之后）应用了它。
# ============================================================================
patch_makefile_lib() {
    log_step "Step 4: Patching Makefile.lib for KCCWF CC wrapper..."

    local makefile_lib="$SEGFUZZ_KERNEL/scripts/Makefile.lib"

    if [[ ! -f "$makefile_lib" ]]; then
        log_warn "scripts/Makefile.lib not found, skipping patch"
        return 0
    fi

    # 检查是否已经有 KCCWF 相关改动
    if grep -q "KCCWF_CC_WRAPPER" "$makefile_lib"; then
        log_info "Makefile.lib already patched for KCCWF, skipping."
        return 0
    fi

    # 备份
    cp "$makefile_lib" "${makefile_lib}.bak.$(date +%Y%m%d%H%M%S)"

    # 在 KSSB 插桩代码块前添加条件：如果使用 KCCWF CC wrapper，
    # 则不自动添加 CFLAGS_KSSB（因为 wrapper 已处理）
    # 注意：只有在 CC 被设置为 kccwf wrapper 时才跳过
    #
    # 实际上，更简单的方案是不改 Makefile.lib，而是设置 CFLAGS_KSSB 为空。
    # 因为 kccwf_cc_wrapper.sh 已经在 KCCWF_EXTRA_CFLAGS 中传递了 MemcovPass。
    
    log_info "Note: When using KCCWF CC wrapper, set CFLAGS_KSSB= (empty) to avoid double-pass."
    log_info "The wrapper handles MemcovPass injection at the correct pipeline stage."
}

# ============================================================================
# Step 5: 构建内核
# ============================================================================
build_kernel() {
    log_step "Step 5: Building SegFuzz kernel with KCCWF..."

    if $SKIP_BUILD; then
        log_info "Skipping kernel build (--skip-build)"
        return 0
    fi

    local wrapper_cc="$SEGFUZZ_KERNEL/.kccwf_compiler/segfuzz_kccwf_cc.sh"
    if [[ ! -x "$wrapper_cc" ]]; then
        log_error "CC wrapper not found: $wrapper_cc"
        exit 1
    fi

    local make_args=(
        "ARCH=$TARGET_ARCH"
        "LLVM=1"
        "CC=$wrapper_cc"
        "CFLAGS_KSSB="
        "-j$JOBS"
    )

    if [[ -n "$BUILD_DIR" ]]; then
        mkdir -p "$BUILD_DIR"
        make_args+=("O=$BUILD_DIR")
    fi

    cd "$SEGFUZZ_KERNEL"

    # 先确保 .config 存在
    local build_root="${BUILD_DIR:-$SEGFUZZ_KERNEL}"
    if [[ ! -f "$build_root/.config" ]]; then
        log_info "Running olddefconfig..."
        make "${make_args[@]}" olddefconfig
    fi

    log_info "Running: make ${make_args[*]}"
    make "${make_args[@]}"

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
    log_info " SegFuzz Kernel + KCCWF Build"
    log_info "═══════════════════════════════════════════════════════════"
    log_info " SegFuzz Kernel:  $SEGFUZZ_KERNEL"
    log_info " DDRD Kernel:     $DDRD_KERNEL"
    log_info " MemcovPass:      $MEMCOV_PASS_SO"
    log_info " Instrumenter:    $INSTRUMENTER"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # 检查前置条件
    if [[ ! -x "$INSTRUMENTER" ]]; then
        log_error "KCCWF instrumenter not found: $INSTRUMENTER"
        log_error "Build it: cd $DDRD_DIR && mkdir -p build && cd build && cmake .. && make"
        exit 1
    fi

    if [[ ! -f "$MEMCOV_PASS_SO" ]]; then
        log_error "MemcovPass not found: $MEMCOV_PASS_SO"
        log_error "Build it: cd $SEGFUZZ_DIR/tools/MemcovPass/build && cmake .. && ninja"
        exit 1
    fi

    ensure_kccwf
    configure_kccwf_exclusions
    create_segfuzz_cc_wrapper
    patch_makefile_lib
    build_kernel

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info " Build Complete"
    log_info "═══════════════════════════════════════════════════════════"
    log_info " SegFuzz kernel with KCCWF + MemcovPass instrumentation."
    log_info " Next: deploy this kernel to SegFuzz VMs and"
    log_info " use deploy_collector.sh to collect pair data."
    log_info "═══════════════════════════════════════════════════════════"
}

main "$@"
