#!/usr/bin/env bash
# ============================================================================
# manage_corpus.sh — corpus 管理 (备份 / 导入 / 迁移 / 统计)
#
# 用法:
#   ./scripts/manage_corpus.sh backup  [选项] [module1 ...]   # 备份 corpus
#   ./scripts/manage_corpus.sh import  [选项] [module1 ...]   # 导入 corpus
#   ./scripts/manage_corpus.sh migrate [选项] [module1 ...]   # 从旧目录迁移
#   ./scripts/manage_corpus.sh stat    [module1 ...]          # 显示统计
#   ./scripts/manage_corpus.sh list                           # 列出可用模块
#
# 子命令:
#   backup   将 workdir 中的 corpus.db / uaf-corpus.db 复制到备份目录
#   import   从备份目录 (或 DDRD-Corpus) 导入 corpus 到 workdir
#   migrate  从旧 test/ 目录迁移 corpus 到新 exp/ 目录
#   stat     显示各模块 corpus 文件大小和状态
#
# 选项:
#   --dest DIR           备份目标目录 (backup 默认: corpus-backup/)
#   --src DIR            导入源目录 (import 默认: DDRD-Corpus/)
#   --include-uaf        同时处理 uaf-corpus.db
#   --include-validated   同时处理 validated_uaf.db, invalid_uaf.db
#   --all-db             处理所有 .db 文件
#   --force              覆盖已存在的文件
#   --dry-run            仅显示将执行的操作
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

# --------------- 默认值 ---------------
CORPUS_BACKUP_DIR="$PROJECT_HOME/corpus-backup"
DDRD_CORPUS_DIR="/home/zzzccc/BASS/DDRD-Corpus"
OLD_TEST_DIR="$PROJECT_HOME/test/DDRD-PairCollector/test"

INCLUDE_UAF=false
INCLUDE_VALIDATED=false
ALL_DB=false
FORCE=false
DRY_RUN=false
TARGETS=()

# --------------- 旧目录映射 ---------------
# 旧 workdir 名 -> 新 slug (处理命名不一致的情况)
declare -A OLD_WORKDIR_MAP=(
    ["workdir-btrfs"]="btrfs"
    ["workdir-dsp"]="dsp"
    ["workdir-f2fs"]="f2fs"
    ["workdir-floppy"]="floppy"
    ["workdir-jfs"]="jfs"
    ["workdir-ptmx"]="ptmx"
    ["workdir-usb"]="usb-driver"
    ["workdir-usb-corpus"]=""        # 跳过
    ["workdir-video"]="video"
    ["workdir-wifi"]="wifi-stack"
    ["workdir-xfs"]="xfs"
    ["workdir-bt-stack"]="bt-stack"
)

# DDRD-Corpus 文件名 -> slug
declare -A CORPUS_FILE_MAP=(
    ["btrfs-corpus.db"]="btrfs"
    ["dsp-corpus.db"]="dsp"
    ["f2fs-corpus.db"]="f2fs"
    ["floppy-corpus.db"]="floppy"
    ["jfs-corpus.db"]="jfs"
    ["ptmx-corpus.db"]="ptmx"
    ["usb-corpus.db"]="usb-driver"
    ["video-corpus.db"]="video"
    ["wifi-corpus.db"]="wifi-stack"
    ["xfs-corpus.db"]="xfs"
    ["bt-corpus.db"]="bt-stack"
)

# slug -> DDRD-Corpus 中的文件名前缀
declare -A SLUG_TO_CORPUS_PREFIX=(
    ["btrfs"]="btrfs"
    ["dsp"]="dsp"
    ["f2fs"]="f2fs"
    ["floppy"]="floppy"
    ["jfs"]="jfs"
    ["ptmx"]="ptmx"
    ["usb-driver"]="usb"
    ["video"]="video"
    ["wifi-stack"]="wifi"
    ["xfs"]="xfs"
    ["bt-stack"]="bt"
    ["ext4"]="ext4"
    ["overlayfs"]="overlayfs"
)

# --------------- 参数解析 ---------------
ACTION="${1:-help}"; shift || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dest)             CORPUS_BACKUP_DIR="$2"; shift 2 ;;
        --src)              DDRD_CORPUS_DIR="$2"; shift 2 ;;
        --include-uaf)      INCLUDE_UAF=true; shift ;;
        --include-validated) INCLUDE_VALIDATED=true; shift ;;
        --all-db)           ALL_DB=true; shift ;;
        --force|-f)         FORCE=true; shift ;;
        --dry-run|-n)       DRY_RUN=true; shift ;;
        --help|-h)          sed -n '3,28p' "$0" | sed 's/^# //' | sed 's/^#//'; exit 0 ;;
        -*)                 die "未知选项: $1" ;;
        *)                  TARGETS+=("$1"); shift ;;
    esac
done

# --------------- 工具函数 ---------------

# 获取所有可用模块 slug
get_available_modules() {
    if [[ -d "$EXP_DIR" ]]; then
        for d in "$EXP_DIR"/*/; do
            [[ -d "$d" ]] && basename "$d"
        done
    fi
}

# 确定目标模块
resolve_modules() {
    if [[ ${#TARGETS[@]} -gt 0 ]]; then
        echo "${TARGETS[@]}"
    else
        get_available_modules
    fi
}

# 获取要处理的 db 文件列表
get_db_patterns() {
    local patterns=("corpus.db")
    if $ALL_DB; then
        patterns=("*.db")
    else
        $INCLUDE_UAF && patterns+=("uaf-corpus.db")
        if $INCLUDE_VALIDATED; then
            patterns+=("validated_uaf.db" "invalid_uaf.db" "varname_backoff_stats.db" "varname_hb_stats.db")
        fi
    fi
    echo "${patterns[@]}"
}

# 格式化文件大小
human_size() {
    local file="$1"
    if [[ -f "$file" ]]; then
        du -h "$file" | cut -f1
    else
        echo "—"
    fi
}

# 安全复制
safe_copy() {
    local src="$1" dst="$2" desc="$3"
    if [[ ! -f "$src" ]]; then
        return 1
    fi
    if [[ -f "$dst" ]] && ! $FORCE; then
        log_warn "跳过 $desc (已存在, 使用 --force 覆盖)"
        return 2
    fi
    if $DRY_RUN; then
        log_info "[dry-run] $desc"
        log_info "  $src -> $dst"
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    local sz; sz=$(human_size "$dst")
    log_ok "$desc ($sz)"
    return 0
}

# =============================================
# backup: 从 workdir 备份到 backup 目录
# =============================================
do_backup() {
    local dest="$CORPUS_BACKUP_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    dest="$dest/$timestamp"

    log_info "备份 corpus 到: $dest"
    $DRY_RUN || mkdir -p "$dest"

    local ok=0 fail=0 skip=0
    local patterns; read -ra patterns <<< "$(get_db_patterns)"

    for slug in $(resolve_modules); do
        local workdir="$EXP_DIR/$slug/workdir"
        [[ -d "$workdir" ]] || continue

        for pattern in "${patterns[@]}"; do
            for dbfile in $workdir/$pattern; do
                [[ -f "$dbfile" ]] || continue
                local basename_f; basename_f=$(basename "$dbfile")
                local dst="$dest/${slug}/${basename_f}"

                if safe_copy "$dbfile" "$dst" "[$slug] $basename_f"; then
                    ((ok++)) || true
                else
                    local rc=$?
                    if [[ $rc -eq 2 ]]; then ((skip++)) || true; else ((fail++)) || true; fi
                fi
            done
        done
    done

    echo ""
    log_info "备份完成: 成功=$ok 跳过=$skip 失败=$fail"
    [[ $ok -gt 0 ]] && log_info "备份目录: $dest"
}

# =============================================
# import: 从外部目录导入 corpus 到 workdir
# =============================================

# 从源 corpus 目录自动发现可导入的模块
_discover_importable_modules() {
    local src_dir="$1"
    local -A seen
    # 已有 exp 目录的模块
    for m in $(get_available_modules); do seen[$m]=1; done
    # 从源目录的 *-corpus.db 文件名反推模块
    for f in "$src_dir"/*-corpus.db; do
        [[ -f "$f" ]] || continue
        local fname; fname=$(basename "$f")
        local slug="${CORPUS_FILE_MAP[$fname]:-}"
        [[ -n "$slug" ]] && seen[$slug]=1
    done
    echo "${!seen[@]}"
}

do_import() {
    local src_dir="$DDRD_CORPUS_DIR"
    [[ -d "$src_dir" ]] || die "源目录不存在: $src_dir (使用 --src 指定)"

    log_info "从 $src_dir 导入 corpus"

    local ok=0 fail=0 skip=0

    # 解析目标模块: 用户指定 > 自动发现 (exp 目录 + 源目录)
    local modules
    if [[ ${#TARGETS[@]} -gt 0 ]]; then
        modules=("${TARGETS[@]}")
    else
        read -ra modules <<< "$(_discover_importable_modules "$src_dir")"
    fi

    for slug in "${modules[@]}"; do
        local prefix="${SLUG_TO_CORPUS_PREFIX[$slug]:-$slug}"

        # 在源目录中查找匹配的 corpus 文件
        local corpus_file="$src_dir/${prefix}-corpus.db"
        local uaf_file="$src_dir/${prefix}-uaf-corpus.db"
        local workdir="$EXP_DIR/$slug/workdir"

        # corpus.db
        if [[ -f "$corpus_file" ]]; then
            $DRY_RUN || mkdir -p "$workdir"
            if safe_copy "$corpus_file" "$workdir/corpus.db" \
                "[$slug] corpus.db <- ${prefix}-corpus.db"; then
                ((ok++)) || true
            else
                local rc=$?
                [[ $rc -eq 2 ]] && { ((skip++)) || true; } || { ((fail++)) || true; }
            fi
        else
            log_warn "[$slug] 源文件不存在: ${prefix}-corpus.db"
        fi

        # uaf-corpus.db (如果请求)
        if $INCLUDE_UAF && [[ -f "$uaf_file" ]]; then
            $DRY_RUN || mkdir -p "$workdir"
            if safe_copy "$uaf_file" "$workdir/uaf-corpus.db" \
                "[$slug] uaf-corpus.db <- ${prefix}-uaf-corpus.db"; then
                ((ok++)) || true
            else
                local rc=$?
                [[ $rc -eq 2 ]] && { ((skip++)) || true; } || { ((fail++)) || true; }
            fi
        fi
    done

    echo ""
    log_info "导入完成: 成功=$ok 跳过=$skip 失败=$fail"
}

# =============================================
# migrate: 从旧 test/ 目录迁移到新 exp/ 目录
# =============================================
do_migrate() {
    local old_dir="$OLD_TEST_DIR"
    [[ -d "$old_dir" ]] || die "旧目录不存在: $old_dir"

    log_info "从旧目录迁移 corpus: $old_dir -> exp/"

    local ok=0 fail=0 skip=0
    local patterns; read -ra patterns <<< "$(get_db_patterns)"

    for old_workdir in "$old_dir"/workdir-*/; do
        [[ -d "$old_workdir" ]] || continue
        local old_name; old_name=$(basename "$old_workdir")
        local slug="${OLD_WORKDIR_MAP[$old_name]:-}"

        if [[ -z "$slug" ]]; then
            log_warn "跳过 $old_name (无映射)"
            continue
        fi

        # 如果指定了目标模块, 检查是否匹配
        if [[ ${#TARGETS[@]} -gt 0 ]]; then
            local match=false
            for t in "${TARGETS[@]}"; do
                [[ "$t" == "$slug" ]] && match=true
            done
            $match || continue
        fi

        local new_workdir="$EXP_DIR/$slug/workdir"

        for pattern in "${patterns[@]}"; do
            for dbfile in $old_workdir/$pattern; do
                [[ -f "$dbfile" ]] || continue
                $DRY_RUN || mkdir -p "$new_workdir"
                local basename_f; basename_f=$(basename "$dbfile")
                local dst="$new_workdir/$basename_f"

                if safe_copy "$dbfile" "$dst" \
                    "[$slug] $basename_f (from $old_name)"; then
                    ((ok++)) || true
                else
                    local rc=$?
                    [[ $rc -eq 2 ]] && { ((skip++)) || true; } || { ((fail++)) || true; }
                fi
            done
        done
    done

    echo ""
    log_info "迁移完成: 成功=$ok 跳过=$skip 失败=$fail"
}

# =============================================
# stat: 显示 corpus 统计
# =============================================
do_stat() {
    echo ""
    printf "%-15s %-12s %-12s %-12s %-12s\n" \
        "MODULE" "corpus.db" "uaf-corpus" "validated" "invalid"
    printf "%-15s %-12s %-12s %-12s %-12s\n" \
        "------" "---------" "----------" "---------" "-------"

    for slug in $(resolve_modules); do
        local workdir="$EXP_DIR/$slug/workdir"
        if [[ ! -d "$workdir" ]]; then
            printf "%-15s %-12s\n" "$slug" "(无 workdir)"
            continue
        fi

        local corpus_sz; corpus_sz=$(human_size "$workdir/corpus.db")
        local uaf_sz; uaf_sz=$(human_size "$workdir/uaf-corpus.db")
        local valid_sz; valid_sz=$(human_size "$workdir/validated_uaf.db")
        local invalid_sz; invalid_sz=$(human_size "$workdir/invalid_uaf.db")

        printf "%-15s %-12s %-12s %-12s %-12s\n" \
            "$slug" "$corpus_sz" "$uaf_sz" "$valid_sz" "$invalid_sz"
    done

    # 如果有旧目录也显示
    if [[ -d "$OLD_TEST_DIR" ]]; then
        echo ""
        echo "旧目录 (test/DDRD-PairCollector/test/):"
        printf "%-25s %-12s %-12s\n" "WORKDIR" "corpus.db" "uaf-corpus"
        printf "%-25s %-12s %-12s\n" "-------" "---------" "----------"
        for old_workdir in "$OLD_TEST_DIR"/workdir-*/; do
            [[ -d "$old_workdir" ]] || continue
            local name; name=$(basename "$old_workdir")
            local c_sz; c_sz=$(human_size "$old_workdir/corpus.db")
            local u_sz; u_sz=$(human_size "$old_workdir/uaf-corpus.db")
            printf "%-25s %-12s %-12s\n" "$name" "$c_sz" "$u_sz"
        done
    fi

    # DDRD-Corpus 也显示
    if [[ -d "$DDRD_CORPUS_DIR" ]]; then
        echo ""
        echo "外部 Corpus ($DDRD_CORPUS_DIR):"
        for f in "$DDRD_CORPUS_DIR"/*-corpus.db; do
            [[ -f "$f" ]] || continue
            local sz; sz=$(human_size "$f")
            printf "  %-30s %s\n" "$(basename "$f")" "$sz"
        done
    fi
    echo ""
}

# =============================================
# 入口
# =============================================
case "$ACTION" in
    backup)   do_backup ;;
    import)   do_import ;;
    migrate)  do_migrate ;;
    stat|status|info)
              do_stat ;;
    list)
        echo "可用模块:"
        get_available_modules | sed 's/^/  /'
        ;;
    help|--help|-h)
        sed -n '3,28p' "$0" | sed 's/^# //' | sed 's/^#//'
        echo ""
        echo "示例:"
        echo "  ./scripts/manage_corpus.sh stat"
        echo "  ./scripts/manage_corpus.sh backup --include-uaf"
        echo "  ./scripts/manage_corpus.sh import --src /path/to/corpus xfs btrfs"
        echo "  ./scripts/manage_corpus.sh migrate --include-uaf --force"
        echo "  ./scripts/manage_corpus.sh backup --all-db --fuzz xfs"
        ;;
    *)
        die "未知命令: $ACTION (使用 backup|import|migrate|stat|list|help)"
        ;;
esac
