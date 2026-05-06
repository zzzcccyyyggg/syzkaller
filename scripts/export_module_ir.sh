#!/usr/bin/env bash
set -euo pipefail

# ==========================================================================
# export_module_ir.sh — 重新编译指定模块并导出 .ll / .instrumented.ll
#
# 设计目标:
#   - 复用现有 DDRD 内核编译与插桩链路
#   - 在模块编译完成、shared build 恢复 plain 之前拷走 IR
#   - 不改变现有 build_kernel.sh 的默认行为
#
# 默认导出模块:
#   xfs btrfs f2fs jfs ptmx floppy
#
# 输出目录:
#   kernels/ir-exports/<timestamp>-<slug-list>/
#     ├── manifest.txt
#     ├── <slug>/
#     │   ├── manifest.txt
#     │   ├── raw-ll/
#     │   └── instrumented-ll/
#     └── ...
# ==========================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

ARCH="x86"
JOBS="$(nproc)"
BZIMAGE_REL="arch/$ARCH/boot/bzImage"
EXPORT_PARENT="$KERNELS_DIR/ir-exports"
DEFAULT_MODULES=(xfs btrfs f2fs jfs ptmx floppy)
REQUESTED_MODULES=()

usage() {
    cat <<'EOF'
用法: export_module_ir.sh [选项] [module1 module2 ...]

选项:
  --output-root DIR   IR 导出父目录 (默认: kernels/ir-exports)
  --jobs, -j N        并行编译任务数 (默认: nproc)
  --arch NAME         内核 ARCH (默认: x86)
  -h, --help          帮助

若未指定模块, 默认导出: xfs btrfs f2fs jfs ptmx floppy
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)
            EXPORT_PARENT="$2"
            shift 2
            ;;
        --jobs|-j)
            JOBS="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            BZIMAGE_REL="arch/$ARCH/boot/bzImage"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            die "未知选项: $1"
            ;;
        *)
            REQUESTED_MODULES+=("$1")
            shift
            ;;
    esac
done

if [[ ${#REQUESTED_MODULES[@]} -eq 0 ]]; then
    REQUESTED_MODULES=("${DEFAULT_MODULES[@]}")
fi

[[ -d "$DDRD_KERNEL_SRC" ]] || die "内核源码不存在: $DDRD_KERNEL_SRC"
[[ -x "$DDRD_CC" ]] || die "clang-wrapper.sh 不可执行: $DDRD_CC"

BUILD_DIR="$KERNEL_BUILDS_DIR/$ARCH"
INSTRUMENTED_MARKER="$BUILD_DIR/.ddrd_instrumented"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
MODULE_LABEL="$(IFS=-; echo "${REQUESTED_MODULES[*]}")"
EXPORT_DIR="$EXPORT_PARENT/$TIMESTAMP-$MODULE_LABEL"

mkdir -p "$EXPORT_DIR"

BACKUP_CONF="$(mktemp)"
if [[ -f "$DDRD_INSTRUMENT_CONF" ]]; then
    cp "$DDRD_INSTRUMENT_CONF" "$BACKUP_CONF"
else
    : > "$BACKUP_CONF"
fi
trap 'cp "$BACKUP_CONF" "$DDRD_INSTRUMENT_CONF" 2>/dev/null || true; rm -f "$BACKUP_CONF"' EXIT

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

kernel_make() {
    kernel_make_with_dir "$BUILD_DIR" "$@"
}

find_config_file() {
    local variant="${1:-}"
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
    if [[ ! -f "$bdir/.config" ]]; then
        local cfg
        if cfg=$(find_config_file); then
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

clean_targets() {
    for target in "$@"; do
        [[ -z "$target" ]] && continue
        local build_target_dir="$BUILD_DIR/$target"
        if [[ -d "$build_target_dir" ]]; then
            find "$build_target_dir" \( -name '*.o' -o -name '.*.cmd' -o -name '*.ll' \) -delete 2>/dev/null || true
        fi
    done
}

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

    declare -A seen=()
    deduped_clean=()
    for entry in "${clean_list[@]}"; do
        [[ -z "$entry" || -n "${seen[$entry]:-}" ]] && continue
        seen[$entry]=1
        deduped_clean+=("$entry")
    done
    unset seen
    clean_list=("${deduped_clean[@]}")
}

collect_ir_files() {
    local mode="$1"; shift
    local tmp
    tmp="$(mktemp)"

    for entry in "$@"; do
        local rel="${entry#./}"
        rel="${rel%/}"
        if [[ "$entry" == */ ]]; then
            local dir="$BUILD_DIR/$rel"
            [[ -d "$dir" ]] || continue
            if [[ "$mode" == raw ]]; then
                find "$dir" -type f -name '*.ll' ! -name '*.instrumented.ll' >> "$tmp"
            else
                find "$dir" -type f -name '*.instrumented.ll' >> "$tmp"
            fi
        else
            local prefix="$BUILD_DIR/${rel%.c}"
            if [[ "$mode" == raw ]]; then
                [[ -f "$prefix.ll" ]] && echo "$prefix.ll" >> "$tmp"
            else
                [[ -f "$prefix.instrumented.ll" ]] && echo "$prefix.instrumented.ll" >> "$tmp"
            fi
        fi
    done

    sort -u "$tmp"
    rm -f "$tmp"
}

copy_ir_set() {
    local mode="$1"
    local slug="$2"
    shift 2
    local dest="$EXPORT_DIR/$slug/$mode"
    local count=0

    mkdir -p "$dest"
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        local rel="${file#$BUILD_DIR/}"
        mkdir -p "$dest/$(dirname "$rel")"
        cp "$file" "$dest/$rel"
        count=$((count + 1))
    done < <(collect_ir_files "$mode" "$@")

    printf "%s" "$count"
}

write_root_manifest() {
    cat > "$EXPORT_DIR/manifest.txt" <<EOF
generated_at=$TIMESTAMP
kernel_src=$DDRD_KERNEL_SRC
build_dir=$BUILD_DIR
modules=${REQUESTED_MODULES[*]}
analyzer=/home/zzzccc/BASS/DDRD-syzkaller/ddrd-tools/build/report-analyzer/bin/report-analyzer

说明:
- raw-ll/ 保存 clang -S -emit-llvm 生成的原始 IR
- instrumented-ll/ 保存 instrumenter 输出的 .instrumented.ll
- 各 module 目录下的 manifest.txt 记录了源路径与文件数
EOF
}

write_module_manifest() {
    local slug="$1"
    local raw_count="$2"
    local inst_count="$3"
    {
        echo "module=$slug"
        echo "generated_at=$TIMESTAMP"
        echo "kernel_paths=$MOD_KERNEL_PATHS"
        echo "build_dir=$BUILD_DIR"
        echo "raw_ll_count=$raw_count"
        echo "instrumented_ll_count=$inst_count"
        echo "source_logical_paths=${instrument_list[*]}"
    } > "$EXPORT_DIR/$slug/manifest.txt"
}

recover_plain_if_needed() {
    if [[ -f "$INSTRUMENTED_MARKER" ]]; then
        local prev_slug
        prev_slug="$(cat "$INSTRUMENTED_MARKER")"
        if [[ -n "$prev_slug" ]]; then
            log_info "清理上次残留的插桩模块: $prev_slug"
            read_module "$prev_slug" 2>/dev/null && {
                read -ra prev_raw <<< "$MOD_KERNEL_PATHS"
                for entry in "${prev_raw[@]}"; do
                    clean_targets "$(normalize_clean_target "$entry")"
                done
            } || true
        fi
        : > "$DDRD_INSTRUMENT_CONF"
        kernel_make
        rm -f "$INSTRUMENTED_MARKER"
    fi
}

mkdir -p "$BUILD_DIR"
ensure_config_in "$BUILD_DIR"
write_root_manifest

log_info "IR 导出目录: $EXPORT_DIR"
log_info "目标模块: ${REQUESTED_MODULES[*]}"

recover_plain_if_needed

: > "$DDRD_INSTRUMENT_CONF"
kernel_make

previous_clean_targets=()
for slug in "${REQUESTED_MODULES[@]}"; do
    parse_module_paths "$slug"
    log_info "========== 导出模块 IR: $slug =========="

    if [[ ${#previous_clean_targets[@]} -gt 0 ]]; then
        log_info "恢复上一模块的 plain 状态..."
        : > "$DDRD_INSTRUMENT_CONF"
        clean_targets "${previous_clean_targets[@]}"
        kernel_make
    fi

    echo "$slug" > "$INSTRUMENTED_MARKER"
    write_instrumentation "$slug" "${instrument_list[@]}"
    clean_targets "${clean_list[@]}"
    kernel_make

    [[ -f "$BUILD_DIR/vmlinux" ]] || die "[$slug] vmlinux 未生成"
    [[ -f "$BUILD_DIR/$BZIMAGE_REL" ]] || die "[$slug] bzImage 未生成"

    mkdir -p "$EXPORT_DIR/$slug"
    raw_count="$(copy_ir_set raw-ll "$slug" "${instrument_list[@]}")"
    inst_count="$(copy_ir_set instrumented-ll "$slug" "${instrument_list[@]}")"
    write_module_manifest "$slug" "$raw_count" "$inst_count"

    log_ok "[$slug] raw .ll: $raw_count, instrumented .ll: $inst_count"
    previous_clean_targets=("${clean_list[@]}")
done

if [[ ${#previous_clean_targets[@]} -gt 0 ]]; then
    log_info "恢复最后一个模块的 plain 状态..."
    : > "$DDRD_INSTRUMENT_CONF"
    clean_targets "${previous_clean_targets[@]}"
    kernel_make
    rm -f "$INSTRUMENTED_MARKER"
fi

log_ok "IR 导出完成: $EXPORT_DIR"