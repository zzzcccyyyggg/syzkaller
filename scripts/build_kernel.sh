#!/usr/bin/env bash
# ============================================================================
# build_kernel.sh — 构建 DDRD 内核
#
# 用法:
#   ./scripts/build_kernel.sh [选项] [module1 module2 ...]
#
# 示例:
#   ./scripts/build_kernel.sh xfs btrfs           # shared 模式构建 xfs 和 btrfs
#   ./scripts/build_kernel.sh --mode=isolated xfs  # isolated 模式构建 xfs
#   ./scripts/build_kernel.sh --output-dir kernels/output-versions/20260522-snrange xfs
#   ./scripts/build_kernel.sh                      # 构建所有模块
#   ./scripts/build_kernel.sh --plain-only         # 仅构建 plain 内核
#   ./scripts/build_kernel.sh --list               # 列出可用模块
#
# 构建模式:
#   --mode=shared   (默认) 共享单个 build 目录, 增量编译
#                   优点: 快速, 省磁盘      缺点: 流程复杂
#   --mode=isolated 每个模块独立 out-of-tree build 目录
#                   优点: 简单, 改内核后重编快  缺点: 首次编译慢, 耗磁盘
#
# 默认输出: kernels/output/<slug>/vmlinux, bzImage
# 指定 --output-dir DIR 时: DIR/<slug>/vmlinux, bzImage
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

# --------------- 默认值 ---------------
ARCH="x86"
BZIMAGE_REL="arch/$ARCH/boot/bzImage"
JOBS=$(nproc)
PLAIN_ONLY=false
WITH_KCSAN=false
NO_CLEAN=false
LIST_ONLY=false
BUILD_MODE="shared"    # shared | isolated
OUTPUT_DIR_OVERRIDE=""
REQUESTED_MODULES=()

# --------------- 参数解析 ---------------
usage() {
    cat <<'EOF'
用法: build_kernel.sh [选项] [module1 module2 ...]

构建模式:
  --mode=shared     (默认) 共享 build 目录 + 增量编译, 快速但流程复杂
  --mode=isolated   每个模块独立 out-of-tree build, 简单但首次慢

选项:
  --plain-only      仅构建无插桩的 plain 内核
  --with-kcsan      同时为每个模块构建 KCSAN 版本
  --no-clean        跳过首次 plain build 的 make clean
  --output-dir DIR   将 vmlinux/bzImage 输出到 DIR/<module>/, 避免覆盖默认 kernels/output
  --list            列出可用模块
  --jobs, -j N      并行编译任务数 (默认: nproc)
  --arch NAME       内核 ARCH (默认: x86)
  -h, --help        帮助

默认输出: kernels/output/<slug>/vmlinux, bzImage
使用 --output-dir 时输出: DIR/<slug>/vmlinux, bzImage
EOF
    echo ""
    echo "可用模块:"
    list_modules | sed 's/^/  /'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)       usage; exit 0 ;;
        --mode=*)        BUILD_MODE="${1#--mode=}"; shift ;;
        --mode)          BUILD_MODE="$2"; shift 2 ;;
        --plain-only)    PLAIN_ONLY=true; shift ;;
        --with-kcsan)    WITH_KCSAN=true; shift ;;
        --no-clean)      NO_CLEAN=true; shift ;;
        --output-dir=*)  OUTPUT_DIR_OVERRIDE="${1#--output-dir=}"; shift ;;
        --output-dir)    OUTPUT_DIR_OVERRIDE="$2"; shift 2 ;;
        --list)          LIST_ONLY=true; shift ;;
        --jobs|-j)       JOBS="$2"; shift 2 ;;
        --arch)          ARCH="$2"; BZIMAGE_REL="arch/$ARCH/boot/bzImage"; shift 2 ;;
        -*)              die "未知选项: $1" ;;
        *)               REQUESTED_MODULES+=("$1"); shift ;;
    esac
done

if $LIST_ONLY; then
    echo "可用模块:"
    list_modules
    exit 0
fi

[[ "$BUILD_MODE" == "shared" || "$BUILD_MODE" == "isolated" ]] \
    || die "无效的 --mode: $BUILD_MODE (可选: shared, isolated)"

if [[ -n "$OUTPUT_DIR_OVERRIDE" ]]; then
    if [[ "$OUTPUT_DIR_OVERRIDE" = /* ]]; then
        KERNEL_OUTPUT_DIR="$OUTPUT_DIR_OVERRIDE"
    else
        KERNEL_OUTPUT_DIR="$PROJECT_HOME/$OUTPUT_DIR_OVERRIDE"
    fi
    mkdir -p "$KERNEL_OUTPUT_DIR"
fi

# --------------- 校验 ---------------
[[ -d "$DDRD_KERNEL_SRC" ]] || die "内核源码不存在: $DDRD_KERNEL_SRC"
[[ -x "$DDRD_CC" ]]         || die "clang-wrapper.sh 不可执行: $DDRD_CC"

# 检测内核源码树是否残留 in-tree 编译产物 (会导致 O= 编译失败)
if [[ -f "$DDRD_KERNEL_SRC/.config" ]] || [[ -d "$DDRD_KERNEL_SRC/include/generated" ]] || [[ -f "$DDRD_KERNEL_SRC/include/config/auto.conf" ]]; then
    log_warn "内核源码树中存在 in-tree 编译残留, 将自动清理..."
    log_info "运行 make ARCH=$ARCH mrproper (在 $DDRD_KERNEL_SRC)"
    (cd "$DDRD_KERNEL_SRC" && make ARCH="$ARCH" mrproper) \
        || die "清理失败, 请手动运行: make -C $DDRD_KERNEL_SRC ARCH=$ARCH mrproper"
    log_ok "内核源码树已清理"
fi

log_info "构建模式: $BUILD_MODE"

# =============================================
# 公共函数
# =============================================

# kernel_make_with_dir DIR [extra make args...]
kernel_make_with_dir() {
    local bdir="$1"; shift
    (cd "$DDRD_KERNEL_SRC" && make \
        ARCH="$ARCH" \
        CC="$DDRD_CC" \
        HOSTCC="$DDRD_CC" \
        O="$bdir" \
        -j"$JOBS" \
        "$@")
}

# 查找 .config 文件, 支持多种命名: x86-64.config, config.x86, x86.config
find_config_file() {
    local variant="${1:-}"  # 空 或 "kcsan"
    local candidates=()
    if [[ -n "$variant" ]]; then
        candidates+=(
            "$KERNEL_CONFIGS_DIR/${ARCH}-64-${variant}.config"
            "$KERNEL_CONFIGS_DIR/${ARCH}_64-${variant}.config"
            "$KERNEL_CONFIGS_DIR/config.${ARCH}-${variant}"
        )
    fi
    candidates+=(
        "$KERNEL_CONFIGS_DIR/${ARCH}-64.config"
        "$KERNEL_CONFIGS_DIR/${ARCH}_64.config"
        "$KERNEL_CONFIGS_DIR/config.${ARCH}"
    )
    for f in "${candidates[@]}"; do
        if [[ -f "$f" ]]; then
            echo "$f"
            return 0
        fi
    done
    return 1
}

ensure_config_in() {
    local bdir="$1"
    local variant="${2:-}"   # 空 或 "kcsan"
    if [[ ! -f "$bdir/.config" ]]; then
        local cfg
        if cfg=$(find_config_file "$variant"); then
            log_info "使用 $cfg"
            cp "$cfg" "$bdir/.config"
        else
            log_info "生成默认配置 (defconfig + kvm_guest.config)"
            kernel_make_with_dir "$bdir" defconfig kvm_guest.config
        fi
        kernel_make_with_dir "$bdir" olddefconfig
    fi
}

normalize_instrument_path() {
    local path="${1#./}"
    [[ -z "$path" ]] && return
    if [[ "$path" == *.c ]]; then
        printf "%s\n" "$path"
    else
        printf "%s/\n" "${path%/}"
    fi
}

normalize_clean_target() {
    local path="${1#./}"
    [[ -z "$path" ]] && return
    path="${path%/}"
    [[ "$path" == *.c ]] && path="$(dirname "$path")"
    printf "%s\n" "$path"
}

write_instrumentation() {
    local slug="$1"; shift
    {
        echo "# Instrumentation targets for $slug"
        for entry in "$@"; do
            [[ -n "$entry" ]] && echo "$entry"
        done
    } > "$DDRD_INSTRUMENT_CONF"
}

# 将构建产物复制到 kernels/output/<name>/
save_to_output() {
    local bdir="$1" name="$2"
    local out_dir="$KERNEL_OUTPUT_DIR/$name"
    mkdir -p "$out_dir"
    cp "$bdir/vmlinux" "$out_dir/vmlinux"
    cp "$bdir/$BZIMAGE_REL" "$out_dir/bzImage"
    log_ok "输出: $out_dir/  (vmlinux + bzImage)"
}

# 确定目标模块
resolve_target_modules() {
    if [[ ${#REQUESTED_MODULES[@]} -gt 0 ]]; then
        target_modules=("${REQUESTED_MODULES[@]}")
    else
        mapfile -t target_modules < <(list_modules)
    fi
}

# 解析模块的插桩/clean 路径
parse_module_paths() {
    local slug="$1"
    read_module "$slug"
    read -ra raw_paths <<< "$MOD_KERNEL_PATHS"
    instrument_list=()
    clean_list=()
    for raw in "${raw_paths[@]}"; do
        instrument_list+=("$(normalize_instrument_path "$raw")")
        clean_list+=("$(normalize_clean_target "$raw")")
    done
    # 去重 clean list
    declare -A _seen=()
    deduped_clean=()
    for c in "${clean_list[@]}"; do
        [[ -z "$c" || -n "${_seen[$c]:-}" ]] && continue
        _seen[$c]=1; deduped_clean+=("$c")
    done
    unset _seen
    clean_list=("${deduped_clean[@]}")
}

# 备份并在退出时恢复插桩配置
BACKUP_CONF=$(mktemp)
if [[ -f "$DDRD_INSTRUMENT_CONF" ]]; then
    cp "$DDRD_INSTRUMENT_CONF" "$BACKUP_CONF"
else
    touch "$BACKUP_CONF"
fi
trap 'cp "$BACKUP_CONF" "$DDRD_INSTRUMENT_CONF" 2>/dev/null; rm -f "$BACKUP_CONF"' EXIT
export DDRD_INSTRUMENT_LIST="$DDRD_INSTRUMENT_CONF"

# =============================================
# MODE: shared (共享 build 目录, 增量编译)
# =============================================
build_shared() {
    local BUILD_DIR="$KERNEL_BUILDS_DIR/$ARCH"
    mkdir -p "$BUILD_DIR"

    # 便捷函数: 用共享目录 make
    kernel_make() { kernel_make_with_dir "$BUILD_DIR" "$@"; }

    # 清理 build 目录中指定子目录的 .o/.cmd 文件, 强制 make 重新编译
    # 注意: make M=$target clean 仅对外部模块有效, 对内核树内子目录无效!
    #       必须直接删除 build 目录 (O=) 中的目标文件.
    clean_targets() {
        for target in "$@"; do
            [[ -z "$target" ]] && continue
            local build_target_dir="$BUILD_DIR/$target"
            if [[ -d "$build_target_dir" ]]; then
                local count
                count=$(find "$build_target_dir" \( -name "*.o" -o -name ".*.cmd" -o -name "*.ll" \) | wc -l)
                find "$build_target_dir" \( -name "*.o" -o -name ".*.cmd" -o -name "*.ll" \) -delete 2>/dev/null || true
                log_info "  Cleaning: $target ($count 个文件)"
            else
                log_warn "  构建目录不存在 (将全量编译): $target"
            fi
        done
    }

    ensure_config_in "$BUILD_DIR"

    # 追踪文件: 记录当前 build 目录中哪个模块处于已插桩态
    # 用于 --no-clean 时清理上次残留的插桩代码, 防止跨 run 交叉污染
    local INSTRUMENTED_MARKER="$BUILD_DIR/.ddrd_instrumented"

    # Step 1: plain build
    log_info "========== Plain kernel build (无插桩) =========="
    : > "$DDRD_INSTRUMENT_CONF"
    if ! $NO_CLEAN; then
        kernel_make clean
    fi

    # ── 防止跨 run 交叉污染 ──
    # 无论是否 --no-clean, 都要清理上次残留的已插桩模块 .o
    # 否则 make 认为 .o 已是最新, 不会重编, 导致 plain 输出包含插桩代码
    if [[ -f "$INSTRUMENTED_MARKER" ]]; then
        # 有追踪记录: 只清理记录的模块 (快速)
        local prev_slug
        prev_slug=$(cat "$INSTRUMENTED_MARKER")
        if [[ -n "$prev_slug" ]]; then
            log_info "清理上次残留的插桩模块: $prev_slug"
            read_module "$prev_slug" 2>/dev/null && {
                read -ra _prev_raw <<< "$MOD_KERNEL_PATHS"
                for _r in "${_prev_raw[@]}"; do
                    clean_targets "$(normalize_clean_target "$_r")"
                done
            } || log_warn "  上次插桩模块 '$prev_slug' 已不存在, 跳过"
        fi
        rm -f "$INSTRUMENTED_MARKER"
    elif $NO_CLEAN; then
        # 无追踪文件 + --no-clean: 可能是首次使用修复版本或追踪文件丢失
        # 安全起见, 清理所有已知模块的构建产物, 防止无法追踪的残留污染
        log_info "无插桩追踪记录, 清理所有模块目标 (安全检查)..."
        local _all_slugs
        mapfile -t _all_slugs < <(list_modules)
        for _s in "${_all_slugs[@]}"; do
            read_module "$_s" 2>/dev/null && {
                read -ra _prev_raw <<< "$MOD_KERNEL_PATHS"
                for _r in "${_prev_raw[@]}"; do
                    clean_targets "$(normalize_clean_target "$_r")"
                done
            } || true
        done
    fi
    # 不使用 --no-clean 时, 前面的 make clean 已删除所有 .o, 无需额外处理

    kernel_make
    save_to_output "$BUILD_DIR" "plain"

    if $PLAIN_ONLY; then
        log_ok "仅构建 plain, 退出"
        return
    fi

    resolve_target_modules

    # Step 2: 增量编译每个模块
    local previous_clean_targets=()
    for slug in "${target_modules[@]}"; do
        parse_module_paths "$slug"
        log_info "========== 构建模块: $slug =========="

        # 恢复 plain 状态 — 清理上一个模块的插桩 .o 并重编为 plain
        if [[ ${#previous_clean_targets[@]} -gt 0 ]]; then
            log_info "恢复 plain 状态..."
            : > "$DDRD_INSTRUMENT_CONF"
            clean_targets "${previous_clean_targets[@]}"
            kernel_make
        fi

        # 记录当前正在插桩的模块 (用于下次 run 的跨 run 清理)
        echo "$slug" > "$INSTRUMENTED_MARKER"

        # 写入插桩 → clean → 增量编译
        write_instrumentation "$slug" "${instrument_list[@]}"
        clean_targets "${clean_list[@]}"
        kernel_make

        [[ -f "$BUILD_DIR/vmlinux" ]] || die "vmlinux 未生成"
        [[ -f "$BUILD_DIR/$BZIMAGE_REL" ]] || die "bzImage 未生成"
        save_to_output "$BUILD_DIR" "$slug"

        # 可选: KCSAN
        if $WITH_KCSAN; then
            log_info "  构建 $slug KCSAN 版本..."
            local cfg_bak; cfg_bak=$(mktemp)
            cp "$BUILD_DIR/.config" "$cfg_bak"
            # 优先使用专用 kcsan config, 否则 sed 修改
            local kcsan_cfg
            if kcsan_cfg=$(find_config_file "kcsan"); then
                log_info "  使用 KCSAN 配置: $kcsan_cfg"
                cp "$kcsan_cfg" "$BUILD_DIR/.config"
            else
                sed -i 's/^CONFIG_KCSAN=.*/CONFIG_KCSAN=y/' "$BUILD_DIR/.config" 2>/dev/null \
                    || echo "CONFIG_KCSAN=y" >> "$BUILD_DIR/.config"
                sed -i 's/^CONFIG_KASAN=.*/CONFIG_KASAN=n/' "$BUILD_DIR/.config" 2>/dev/null \
                    || echo "CONFIG_KASAN=n" >> "$BUILD_DIR/.config"
            fi
            kernel_make olddefconfig
            clean_targets "${clean_list[@]}"
            kernel_make
            save_to_output "$BUILD_DIR" "${slug}-kcsan"
            cp "$cfg_bak" "$BUILD_DIR/.config"
            kernel_make olddefconfig
            rm -f "$cfg_bak"
        fi

        previous_clean_targets=("${clean_list[@]}")
    done

    # ── 循环结束: 将最后一个模块恢复为 plain 态 ──
    # 保证 build 目录始终处于干净的 plain 状态
    # 这样下次 --no-clean 时即使没有追踪文件也不会泄露插桩代码
    if [[ ${#previous_clean_targets[@]} -gt 0 ]]; then
        log_info "恢复最后一个模块的 plain 状态..."
        : > "$DDRD_INSTRUMENT_CONF"
        clean_targets "${previous_clean_targets[@]}"
        kernel_make
        rm -f "$INSTRUMENTED_MARKER"
        log_ok "build 目录已恢复为完全 plain 状态"
    fi
}

# =============================================
# MODE: isolated (每个模块独立 out-of-tree build)
# =============================================
build_isolated() {
    # plain build
    local plain_dir="$KERNEL_BUILDS_DIR/plain"
    mkdir -p "$plain_dir"
    ensure_config_in "$plain_dir"

    log_info "========== Plain kernel build (无插桩, isolated) =========="
    : > "$DDRD_INSTRUMENT_CONF"
    if ! $NO_CLEAN && [[ ! -f "$plain_dir/vmlinux" ]]; then
        kernel_make_with_dir "$plain_dir" clean
    fi
    kernel_make_with_dir "$plain_dir"
    save_to_output "$plain_dir" "plain"

    if $PLAIN_ONLY; then
        log_ok "仅构建 plain, 退出"
        return
    fi

    resolve_target_modules

    for slug in "${target_modules[@]}"; do
        parse_module_paths "$slug"
        log_info "========== 构建模块: $slug (isolated) =========="

        local mod_build_dir="$KERNEL_BUILDS_DIR/$slug"
        mkdir -p "$mod_build_dir"

        # 首次构建时从 plain 复制 .config
        if [[ ! -f "$mod_build_dir/.config" ]]; then
            if [[ -f "$plain_dir/.config" ]]; then
                log_info "  从 plain 复制 .config"
                cp "$plain_dir/.config" "$mod_build_dir/.config"
                kernel_make_with_dir "$mod_build_dir" olddefconfig
            else
                ensure_config_in "$mod_build_dir"
            fi
        fi

        # 写入插桩目标
        write_instrumentation "$slug" "${instrument_list[@]}"

        # 构建 (如果已有历史构建, 直接增量; 否则全量)
        kernel_make_with_dir "$mod_build_dir"

        [[ -f "$mod_build_dir/vmlinux" ]] || die "[$slug] vmlinux 未生成"
        [[ -f "$mod_build_dir/$BZIMAGE_REL" ]] || die "[$slug] bzImage 未生成"
        save_to_output "$mod_build_dir" "$slug"

        # 可选: KCSAN
        if $WITH_KCSAN; then
            log_info "  构建 $slug KCSAN 版本 (isolated)..."
            local kcsan_dir="$KERNEL_BUILDS_DIR/${slug}-kcsan"
            mkdir -p "$kcsan_dir"
            if [[ ! -f "$kcsan_dir/.config" ]]; then
                # 优先使用专用 kcsan config, 否则从模块 config sed 修改
                local kcsan_cfg
                if kcsan_cfg=$(find_config_file "kcsan"); then
                    log_info "  使用 KCSAN 配置: $kcsan_cfg"
                    cp "$kcsan_cfg" "$kcsan_dir/.config"
                else
                    cp "$mod_build_dir/.config" "$kcsan_dir/.config"
                    sed -i 's/^CONFIG_KCSAN=.*/CONFIG_KCSAN=y/' "$kcsan_dir/.config" 2>/dev/null \
                        || echo "CONFIG_KCSAN=y" >> "$kcsan_dir/.config"
                    sed -i 's/^CONFIG_KASAN=.*/CONFIG_KASAN=n/' "$kcsan_dir/.config" 2>/dev/null \
                        || echo "CONFIG_KASAN=n" >> "$kcsan_dir/.config"
                fi
                kernel_make_with_dir "$kcsan_dir" olddefconfig
            fi
            write_instrumentation "$slug" "${instrument_list[@]}"
            kernel_make_with_dir "$kcsan_dir"
            save_to_output "$kcsan_dir" "${slug}-kcsan"
        fi
    done
}

# =============================================
# 入口
# =============================================
case "$BUILD_MODE" in
    shared)   build_shared ;;
    isolated) build_isolated ;;
esac

# 汇总
log_ok "========== 所有模块构建完成 =========="
log_info "输出目录: $KERNEL_OUTPUT_DIR"
echo ""
for d in "$KERNEL_OUTPUT_DIR"/*/; do
    [[ -d "$d" ]] || continue
    name=$(basename "$d")
    if [[ -f "$d/vmlinux" && -f "$d/bzImage" ]]; then
        vmlinux_mb=$(( $(stat -c%s "$d/vmlinux") / 1048576 ))
        bzimage_mb=$(( $(stat -c%s "$d/bzImage") / 1048576 ))
        printf "  %-20s vmlinux=%sMB  bzImage=%sMB\n" "$name" "$vmlinux_mb" "$bzimage_mb"
    else
        printf "  %-20s (缺少文件)\n" "$name"
    fi
done
