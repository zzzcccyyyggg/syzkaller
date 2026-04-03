#!/usr/bin/env bash
# ============================================================================
# kccwf_cc_wrapper.sh — 通用 KCCWF 插桩 CC 包装器
#
# 此脚本作为 CC= 传递给 make，在编译目标文件时额外执行 KCCWF 插桩。
# 它会判断当前文件是否在插桩目标列表中，如果是则：
#   1. .c → .ll     (编译到 LLVM IR)
#   2. instrumenter  (KCCWF 插桩：添加 kccwf_rec_mem_access 等调用)
#   3. .instrumented.ll → .o  (最终编译)
#
# 如果文件不在插桩目标中，则直接传递给底层编译器。
#
# 环境变量:
#   KCCWF_INSTRUMENTER     - instrumenter 可执行文件路径
#   KCCWF_INSTRUMENT_LIST  - 插桩目标列表文件 (每行一个目录/文件)
#   KCCWF_LOCK_FILE        - 锁函数配置文件
#   KCCWF_TRYLOCK_FILE     - trylock 配置文件
#   KCCWF_REAL_CC          - 真实的 CC 编译器 (如 clang-18 或 gcc_kernel_compiler)
#   KCCWF_CLANG            - Clang 编译器路径 (用于 .c → .ll 和 .ll → .o)
#   KCCWF_EXTRA_CFLAGS     - 最终编译时的额外 CFLAGS (如 -fpass-plugin=...)
#   KCCWF_DEBUG            - 设为 1 开启调试输出
# ============================================================================
set -euo pipefail

# ============================================================================
# 配置（通过环境变量或默认值）
# ============================================================================
CLANG="${KCCWF_CLANG:-clang-18}"
INSTRUMENTER="${KCCWF_INSTRUMENTER:-/home/zzzccc/BASS/DDRD/build/bin/instrumenter}"
LOCK_FILE="${KCCWF_LOCK_FILE:-/home/zzzccc/BASS/DDRD/instrumenter/LockFunc.txt}"
TRYLOCK_FILE="${KCCWF_TRYLOCK_FILE:-}"
INSTRUMENT_LIST_FILE="${KCCWF_INSTRUMENT_LIST:-}"
REAL_CC="${KCCWF_REAL_CC:-$CLANG}"
EXTRA_CFLAGS="${KCCWF_EXTRA_CFLAGS:-}"
DEBUG="${KCCWF_DEBUG:-0}"

# ============================================================================
# 插桩目标列表（默认覆盖常见子系统）
# ============================================================================
DEFAULT_INSTRUMENT_DIRS=(
    "fs/xfs/"
    "fs/btrfs/"
    "fs/f2fs/"
    "fs/jfs/"
    "fs/ext4/"
    "fs/overlayfs/"
    "net/bluetooth/"
    "drivers/bluetooth/"
    "drivers/tty/"
    "drivers/block/floppy.c"
    "sound/core/"
    "sound/pci/"
)

# 排除目录（KCCWF 框架本身不能被插桩）
EXCLUDE_DIRS=(
    "kernel/kccwf/"
    "drivers/char/kccwf/"
)

# ============================================================================
# 辅助函数
# ============================================================================
debug() {
    [[ "$DEBUG" == "1" ]] && echo "[kccwf-cc] $*" >&2
}

# 加载外部插桩目标列表
load_instrument_list() {
    local -n result_ref=$1
    if [[ -n "$INSTRUMENT_LIST_FILE" && -f "$INSTRUMENT_LIST_FILE" ]]; then
        result_ref=()
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"           # 去掉注释
            line="${line#"${line%%[![:space:]]*}"}"  # 去掉前导空白
            line="${line%"${line##*[![:space:]]}"}"  # 去掉尾部空白
            [[ -z "$line" ]] && continue
            result_ref+=("$line")
        done < "$INSTRUMENT_LIST_FILE"
    else
        result_ref=("${DEFAULT_INSTRUMENT_DIRS[@]}")
    fi
}

# 检查文件是否需要 KCCWF 插桩
should_instrument() {
    local source_file="$1"
    # 规范化路径
    source_file="${source_file#./}"

    # 检查排除列表
    for excl in "${EXCLUDE_DIRS[@]}"; do
        if [[ "$source_file" == "$excl"* ]]; then
            debug "Excluded: $source_file (matches $excl)"
            return 1
        fi
    done

    # 加载插桩目标
    local targets=()
    load_instrument_list targets

    # 检查匹配
    for pattern in "${targets[@]}"; do
        if [[ "$pattern" == */ ]]; then
            # 目录匹配
            if [[ "$source_file" == "$pattern"* ]]; then
                debug "Matched: $source_file (directory: $pattern)"
                return 0
            fi
        else
            # 文件匹配
            if [[ "$source_file" == "$pattern" ]]; then
                debug "Matched: $source_file (exact: $pattern)"
                return 0
            fi
        fi
    done

    debug "Not matched: $source_file"
    return 1
}

# ============================================================================
# 解析编译参数
# ============================================================================
parse_compile_args() {
    local source=""
    local output=""
    local has_c=false
    local next_is_output=false

    for arg in "$@"; do
        if $next_is_output; then
            output="$arg"
            next_is_output=false
            continue
        fi
        case "$arg" in
            -o) next_is_output=true ;;
            -c) has_c=true ;;
            *.c)
                if [[ -f "$arg" ]]; then
                    source="$arg"
                fi
                ;;
        esac
    done

    echo "$source|$output|$has_c"
}

# ============================================================================
# 构造 .c → .ll 的编译参数
# ============================================================================
compile_to_ir() {
    local source="$1"; shift
    local ll_file="$1"; shift
    local original_args=("$@")

    local ir_args=("$CLANG" "-S" "-emit-llvm" "-Og" "-g"
                   "-Qunused-arguments" "-Wno-unused-command-line-argument")

    for arg in "${original_args[@]}"; do
        case "$arg" in
            # 跳过优化选项（强制使用 -Og）
            -O0|-O1|-O2|-O3|-Os|-Oz|-Ofast) continue ;;
            # 跳过 pass plugin（在最终编译时加回）
            -fpass-plugin=*) continue ;;
            # 替换输出文件
            -o) ir_args+=("-o"); continue ;;
            # 跳过 -Werror 相关
            -Werror,-Wunused-command-line-argument) continue ;;
        esac

        if [[ "$arg" == "$source" ]]; then
            ir_args+=("$arg")
        elif [[ "$arg" == *.o ]] && [[ "$arg" != -* ]]; then
            # 这可能是 -o 后面的输出文件
            ir_args+=("$ll_file")
        else
            ir_args+=("$arg")
        fi
    done

    debug "IR compile: ${ir_args[*]}"
    "${ir_args[@]}"
}

# ============================================================================
# 运行 KCCWF instrumenter
# ============================================================================
run_instrumenter() {
    local ll_file="$1"

    local inst_args=("$INSTRUMENTER" "$ll_file" "-v")

    # 添加函数插桩
    inst_args+=("-f")

    # 添加锁文件
    if [[ -n "$LOCK_FILE" && -f "$LOCK_FILE" ]]; then
        inst_args+=("-l" "$LOCK_FILE")
    fi

    # 添加 trylock 文件
    if [[ -n "$TRYLOCK_FILE" && -f "$TRYLOCK_FILE" ]]; then
        inst_args+=("-t" "$TRYLOCK_FILE")
    fi

    # 注意: 不添加 --free，因为内核中 kccwf_rec_free 的签名与 instrumenter 期望的不匹配

    debug "Instrumenter: ${inst_args[*]}"
    "${inst_args[@]}"
}

# ============================================================================
# 编译插桩后的 .ll → .o
# ============================================================================
compile_instrumented() {
    local instrumented_ll="$1"; shift
    local source="$1"; shift
    local original_args=("$@")

    local final_args=("$CLANG" "-Og"
                      "-Qunused-arguments" "-Wno-unused-command-line-argument")

    # 添加额外的 CFLAGS（如 -fpass-plugin= for SegFuzz）
    if [[ -n "$EXTRA_CFLAGS" ]]; then
        read -ra extra_arr <<< "$EXTRA_CFLAGS"
        final_args+=("${extra_arr[@]}")
    fi

    for arg in "${original_args[@]}"; do
        case "$arg" in
            -O0|-O1|-O2|-O3|-Os|-Oz|-Ofast) continue ;;
            -Werror,-Wunused-command-line-argument) continue ;;
        esac

        if [[ "$arg" == "$source" ]]; then
            final_args+=("$instrumented_ll")
        else
            final_args+=("$arg")
        fi
    done

    debug "Final compile: ${final_args[*]}"
    "${final_args[@]}"
}

# ============================================================================
# Main
# ============================================================================

# 快速处理：汇编文件直接传递
last_arg="${!#}"
if [[ "$last_arg" == *.s || "$last_arg" == *.S ]]; then
    exec "$REAL_CC" "$@"
fi

# 解析参数
parsed=$(parse_compile_args "$@")
IFS='|' read -r SOURCE OUTPUT HAS_C <<< "$parsed"

# 没有源文件或不是编译命令 → 直接传递
if [[ -z "$SOURCE" || "$HAS_C" != "true" ]]; then
    debug "Passthrough (no source or no -c): $REAL_CC $*"
    exec "$REAL_CC" "$@"
fi

# 解析输出文件名
if [[ -z "$OUTPUT" ]]; then
    basename_noext="${SOURCE%.c}"
    OUTPUT="${basename_noext##*/}.o"
fi

# 检查是否在 .mod.o（模块链接阶段）
if [[ "$OUTPUT" == *.mod.o ]]; then
    debug "Passthrough (mod link): $REAL_CC $*"
    exec "$REAL_CC" "$@"
fi

# 检查是否应该插桩
if ! should_instrument "$SOURCE"; then
    debug "Passthrough (not in instrument list): $REAL_CC $*"
    exec "$REAL_CC" "$@"
fi

# ============================================================
# KCCWF 插桩流水线
# ============================================================
basename_noext="${OUTPUT%.o}"
LL_FILE="${basename_noext}.ll"
INSTRUMENTED_FILE="${basename_noext}.instrumented.ll"

debug "=== KCCWF Instrumenting: $SOURCE ==="
debug "  .ll file: $LL_FILE"
debug "  .instrumented.ll: $INSTRUMENTED_FILE"

# Step 1: .c → .ll
compile_to_ir "$SOURCE" "$LL_FILE" "$@"

# Step 2: instrumenter
if [[ -f "$LL_FILE" ]]; then
    run_instrumenter "$LL_FILE"
else
    debug "WARNING: .ll file not generated, falling back to plain compile"
    exec "$REAL_CC" "$@"
fi

# Step 3: .instrumented.ll → .o
if [[ -f "$INSTRUMENTED_FILE" ]]; then
    compile_instrumented "$INSTRUMENTED_FILE" "$SOURCE" "$@"
    # 清理临时文件
    rm -f "$LL_FILE" "$INSTRUMENTED_FILE"
else
    debug "WARNING: instrumented file not generated, using original .ll"
    compile_instrumented "$LL_FILE" "$SOURCE" "$@"
    rm -f "$LL_FILE"
fi

debug "=== Done: $SOURCE ==="
