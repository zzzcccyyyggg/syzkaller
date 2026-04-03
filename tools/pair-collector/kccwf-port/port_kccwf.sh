#!/usr/bin/env bash
# ============================================================================
# port_kccwf.sh — 将 KCCWF 框架移植到目标内核源码树
#
# KCCWF (Kernel Concurrent Code Watch Framework) 是 DDRD 的内核级竞态检测框架。
# 此脚本将 KCCWF 的全部源码、头文件、设备驱动、Makefile/Kconfig 补丁
# 移植到指定的目标内核源码树中。
#
# 使用方法:
#   ./port_kccwf.sh --source /path/to/DDRD-Kernel --target /path/to/target-kernel
#   ./port_kccwf.sh --source /path/to/DDRD-Kernel --target /path/to/target-kernel --dry-run
#
# 示例:
#   # 移植到 SegFuzz 内核
#   ./port_kccwf.sh \
#       --source /home/zzzccc/Linux-Kernel/DDRD-Kernel \
#       --target /home/zzzccc/BASS/segfuzz/kernels/linux-6.17-rc5
#
#   # 移植到 Conzzer 内核（验证现有移植是否完整）
#   ./port_kccwf.sh \
#       --source /home/zzzccc/Linux-Kernel/DDRD-Kernel \
#       --target /home/zzzccc/Linux-Kernel/Conzzer-Kernel \
#       --verify-only
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ts() { date +"%Y-%m-%d %H:%M:%S"; }
log_info()  { echo -e "$(ts) ${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "$(ts) ${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "$(ts) ${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "$(ts) ${BLUE}[STEP]${NC}  $1"; }

# ============================================================================
# 默认值
# ============================================================================
DDRD_KERNEL=""           # DDRD-Kernel 源码树
TARGET_KERNEL=""         # 目标内核源码树
DRY_RUN=false
VERIFY_ONLY=false
FORCE=false
BACKUP=true

# ============================================================================
# KCCWF 组件清单
# ============================================================================
# 核心框架 (kernel/kccwf/)
KCCWF_CORE_FILES=(
    "kernel/kccwf/core.c"
    "kernel/kccwf/core.h"
    "kernel/kccwf/bb_tracer.c"
    "kernel/kccwf/bb_tracer.h"
    "kernel/kccwf/encoding.h"
    "kernel/kccwf/func_call_monitor.c"
    "kernel/kccwf/race_pairs.c"
    "kernel/kccwf/race_pairs.h"
    "kernel/kccwf/rec_free.c"
    "kernel/kccwf/rec_lock.c"
    "kernel/kccwf/rec_lock.h"
    "kernel/kccwf/report.c"
    "kernel/kccwf/report.h"
    "kernel/kccwf/tracker.c"
    "kernel/kccwf/tracker.h"
    "kernel/kccwf/wp_checker.c"
    "kernel/kccwf/wp_checker.h"
    "kernel/kccwf/Makefile"
)

# 控制设备 (drivers/char/kccwf/)
KCCWF_CTL_FILES=(
    "drivers/char/kccwf/ctl_dev.c"
    "drivers/char/kccwf/ctl_dev.h"
    "drivers/char/kccwf/Makefile"
)

# 头文件
KCCWF_HEADER_FILES=(
    "include/linux/kccwf.h"
)

# ============================================================================
# 帮助信息
# ============================================================================
print_usage() {
    cat <<'EOF'
Usage: port_kccwf.sh [options]

Required:
  --source <path>     DDRD-Kernel source tree containing KCCWF
  --target <path>     Target kernel source tree to port KCCWF into

Options:
  --verify-only       Only verify KCCWF presence, don't copy files
  --dry-run           Show what would be done without executing
  --force             Overwrite existing files without prompting
  --no-backup         Don't create backups of modified files
  -h, --help          Show this help message

Components ported:
  1. kernel/kccwf/          Core KCCWF framework (race detection, logging, etc.)
  2. drivers/char/kccwf/    Control device (/dev/kccwf_ctl_dev)
  3. include/linux/kccwf.h  Main header file
  4. kernel/Makefile         Patched to add obj-y += kccwf/
  5. drivers/char/Makefile   Patched to add obj-y += kccwf/
  6. include/linux/sched.h   Patched to add task_struct fields
EOF
}

# ============================================================================
# 参数解析
# ============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --source)       DDRD_KERNEL="$2"; shift 2 ;;
            --target)       TARGET_KERNEL="$2"; shift 2 ;;
            --verify-only)  VERIFY_ONLY=true; shift ;;
            --dry-run)      DRY_RUN=true; shift ;;
            --force)        FORCE=true; shift ;;
            --no-backup)    BACKUP=false; shift ;;
            -h|--help)      print_usage; exit 0 ;;
            *) log_error "Unknown option: $1"; print_usage; exit 1 ;;
        esac
    done

    if [[ -z "$DDRD_KERNEL" ]]; then
        log_error "--source is required"
        exit 1
    fi
    if [[ -z "$TARGET_KERNEL" ]]; then
        log_error "--target is required"
        exit 1
    fi
    if [[ ! -d "$DDRD_KERNEL/kernel/kccwf" ]]; then
        log_error "DDRD-Kernel source tree does not contain kernel/kccwf/"
        exit 1
    fi
    if [[ ! -f "$TARGET_KERNEL/Makefile" ]]; then
        log_error "Target path does not appear to be a kernel source tree"
        exit 1
    fi
}

# ============================================================================
# 验证 KCCWF 是否已存在
# ============================================================================
verify_kccwf() {
    local kernel="$1"
    local all_present=true
    local missing=()
    local present=()

    log_step "Verifying KCCWF presence in: $kernel"

    # 检查源文件
    for f in "${KCCWF_CORE_FILES[@]}" "${KCCWF_CTL_FILES[@]}" "${KCCWF_HEADER_FILES[@]}"; do
        if [[ -f "$kernel/$f" ]]; then
            present+=("$f")
        else
            missing+=("$f")
            all_present=false
        fi
    done

    # 检查 Makefile 补丁
    if grep -q "kccwf" "$kernel/kernel/Makefile" 2>/dev/null; then
        present+=("kernel/Makefile [kccwf entry]")
    else
        missing+=("kernel/Makefile [kccwf entry]")
        all_present=false
    fi

    if grep -q "kccwf" "$kernel/drivers/char/Makefile" 2>/dev/null; then
        present+=("drivers/char/Makefile [kccwf entry]")
    else
        missing+=("drivers/char/Makefile [kccwf entry]")
        all_present=false
    fi

    # 检查 sched.h task_struct 补丁
    if grep -q "kccwf_disable_count" "$kernel/include/linux/sched.h" 2>/dev/null; then
        present+=("include/linux/sched.h [kccwf fields]")
    else
        missing+=("include/linux/sched.h [kccwf fields]")
        all_present=false
    fi

    # 输出结果
    echo ""
    log_info "Present components (${#present[@]}):"
    for f in "${present[@]}"; do
        echo "  ✓ $f"
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        log_warn "Missing components (${#missing[@]}):"
        for f in "${missing[@]}"; do
            echo "  ✗ $f"
        done
    fi

    echo ""
    if $all_present; then
        log_info "KCCWF is FULLY ported in $kernel"
        return 0
    else
        log_warn "KCCWF is PARTIALLY ported or MISSING in $kernel"
        return 1
    fi
}

# ============================================================================
# 安全拷贝文件
# ============================================================================
safe_copy() {
    local src="$1"
    local dst="$2"

    if [[ ! -f "$src" ]]; then
        log_error "Source file not found: $src"
        return 1
    fi

    local dst_dir
    dst_dir="$(dirname "$dst")"

    if $DRY_RUN; then
        echo "  [DRY-RUN] cp $src → $dst"
        return 0
    fi

    mkdir -p "$dst_dir"

    if [[ -f "$dst" ]] && ! $FORCE; then
        if $BACKUP; then
            cp "$dst" "${dst}.bak.$(date +%Y%m%d%H%M%S)"
            log_info "  Backed up: $dst"
        fi
    fi

    cp "$src" "$dst"
}

# ============================================================================
# Step 1: 拷贝 KCCWF 源文件
# ============================================================================
copy_kccwf_sources() {
    log_step "Step 1: Copying KCCWF source files..."

    # 核心框架
    log_info "Copying kernel/kccwf/ ..."
    for f in "${KCCWF_CORE_FILES[@]}"; do
        safe_copy "$DDRD_KERNEL/$f" "$TARGET_KERNEL/$f"
    done

    # 控制设备
    log_info "Copying drivers/char/kccwf/ ..."
    for f in "${KCCWF_CTL_FILES[@]}"; do
        safe_copy "$DDRD_KERNEL/$f" "$TARGET_KERNEL/$f"
    done

    # 头文件
    log_info "Copying include/linux/kccwf.h ..."
    for f in "${KCCWF_HEADER_FILES[@]}"; do
        safe_copy "$DDRD_KERNEL/$f" "$TARGET_KERNEL/$f"
    done

    log_info "Source files copied successfully."
}

# ============================================================================
# Step 2: 修补 kernel/Makefile
# ============================================================================
patch_kernel_makefile() {
    local mf="$TARGET_KERNEL/kernel/Makefile"
    log_step "Step 2: Patching kernel/Makefile..."

    if grep -q "obj-y.*+=.*kccwf/" "$mf" 2>/dev/null; then
        log_info "kernel/Makefile already has kccwf entry, skipping."
        return 0
    fi

    if $DRY_RUN; then
        echo "  [DRY-RUN] Would add 'obj-y += kccwf/' to $mf"
        return 0
    fi

    if $BACKUP; then
        cp "$mf" "${mf}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    # 在文件末尾添加
    echo "" >> "$mf"
    echo "# KCCWF: Kernel Concurrent Code Watch Framework" >> "$mf"
    echo "obj-y += kccwf/" >> "$mf"

    log_info "Patched kernel/Makefile."
}

# ============================================================================
# Step 3: 修补 drivers/char/Makefile
# ============================================================================
patch_drivers_makefile() {
    local mf="$TARGET_KERNEL/drivers/char/Makefile"
    log_step "Step 3: Patching drivers/char/Makefile..."

    if grep -q "obj-y.*+=.*kccwf/" "$mf" 2>/dev/null; then
        log_info "drivers/char/Makefile already has kccwf entry, skipping."
        return 0
    fi

    if $DRY_RUN; then
        echo "  [DRY-RUN] Would add 'obj-y += kccwf/' to $mf"
        return 0
    fi

    if $BACKUP; then
        cp "$mf" "${mf}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    echo "" >> "$mf"
    echo "# KCCWF: Control device (/dev/kccwf_ctl_dev)" >> "$mf"
    echo "obj-y += kccwf/" >> "$mf"

    log_info "Patched drivers/char/Makefile."
}

# ============================================================================
# Step 4: 修补 include/linux/sched.h (task_struct)
# ============================================================================
patch_sched_h() {
    local sched_h="$TARGET_KERNEL/include/linux/sched.h"
    log_step "Step 4: Patching include/linux/sched.h (task_struct fields)..."

    if grep -q "kccwf_disable_count" "$sched_h" 2>/dev/null; then
        log_info "sched.h already has KCCWF fields, skipping."
        return 0
    fi

    if $DRY_RUN; then
        echo "  [DRY-RUN] Would add 4 KCCWF fields to task_struct in $sched_h"
        return 0
    fi

    if $BACKUP; then
        cp "$sched_h" "${sched_h}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    # 策略：在 KASAN 字段之后插入 KCCWF 字段
    # 找到 kasan_depth 定义的位置，在其 #endif 之后插入
    # 如果没有 kasan_depth，在 KCSAN 字段之前插入
    # 如果都没有，在 task_struct 的末尾 }; 之前插入

    local kccwf_fields
    kccwf_fields=$(cat <<'FIELDS'

	/* KCCWF: Kernel Concurrent Code Watch Framework */
	int kccwf_disable_count;
	int kccwf_free_enable_count;
	int kccwf_bbs_state;
	u64 kccwf_free_name;
FIELDS
    )

    if grep -q "kasan_depth" "$sched_h"; then
        # 在 kasan_depth 所在的 #endif 之后插入
        local kasan_endif_line
        kasan_endif_line=$(grep -n "kasan_depth" "$sched_h" | head -1 | cut -d: -f1)
        # 找到该行之后最近的 #endif
        local target_line
        target_line=$(awk -v start="$kasan_endif_line" 'NR > start && /^#endif/ { print NR; exit }' "$sched_h")
        if [[ -n "$target_line" ]]; then
            sed -i "${target_line}a\\${kccwf_fields}" "$sched_h"
            log_info "Inserted KCCWF fields after kasan_depth #endif (line $target_line)."
            return 0
        fi
    fi

    if grep -q "kcsan_ctx" "$sched_h"; then
        # 在 #ifdef CONFIG_KCSAN 之前插入
        local kcsan_line
        kcsan_line=$(grep -n "CONFIG_KCSAN" "$sched_h" | head -1 | cut -d: -f1)
        if [[ -n "$kcsan_line" ]]; then
            local insert_line=$((kcsan_line - 1))
            sed -i "${insert_line}a\\${kccwf_fields}" "$sched_h"
            log_info "Inserted KCCWF fields before CONFIG_KCSAN (line $insert_line)."
            return 0
        fi
    fi

    # Fallback: 在最后一个 }; 之前插入
    local last_brace
    last_brace=$(grep -n "^};" "$sched_h" | tail -1 | cut -d: -f1)
    if [[ -n "$last_brace" ]]; then
        local insert_line=$((last_brace - 1))
        sed -i "${insert_line}a\\${kccwf_fields}" "$sched_h"
        log_info "Inserted KCCWF fields before end of task_struct (line $insert_line)."
    else
        log_error "Could not find insertion point in sched.h - manual patch needed"
        return 1
    fi
}

# ============================================================================
# Step 5: 检查 kccwf.h 头文件的 #include 依赖
# ============================================================================
check_header_deps() {
    local kccwf_h="$TARGET_KERNEL/include/linux/kccwf.h"
    log_step "Step 5: Checking header dependencies..."

    if [[ ! -f "$kccwf_h" ]]; then
        log_warn "kccwf.h not found, skipping dependency check."
        return 0
    fi

    # 检查 kccwf.h 中 include 的头文件是否存在
    local missing_headers=()
    while IFS= read -r line; do
        local header
        header=$(echo "$line" | sed -n 's/.*#include.*[<"]\(.*\)[>"]/\1/p')
        if [[ -n "$header" && ! -f "$TARGET_KERNEL/include/$header" ]]; then
            # 检查是否为标准内核头文件（不必检查）
            case "$header" in
                linux/atomic.h|linux/types.h|linux/module.h|linux/percpu.h| \
                linux/fs.h|linux/kthread.h|linux/vmalloc.h|linux/ktime.h| \
                linux/sched.h|linux/mutex.h|linux/timer.h|linux/delay.h| \
                linux/kallsyms.h)
                    ;; # 标准头文件，跳过
                linux/journal-head.h)
                    # JBD2 相关，可能在某些内核中不存在
                    if [[ ! -f "$TARGET_KERNEL/include/linux/journal-head.h" ]]; then
                        log_warn "journal-head.h not found. If target kernel doesn't use JBD2, you may need to conditionally include it."
                    fi
                    ;;
                *)
                    missing_headers+=("$header")
                    ;;
            esac
        fi
    done < "$kccwf_h"

    if [[ ${#missing_headers[@]} -gt 0 ]]; then
        log_warn "Potentially missing headers in target kernel:"
        for h in "${missing_headers[@]}"; do
            echo "  ⚠ $h"
        done
    else
        log_info "All header dependencies satisfied."
    fi
}

# ============================================================================
# 生成摘要报告
# ============================================================================
generate_report() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo " KCCWF Porting Report"
    echo "═══════════════════════════════════════════════════════════════"
    echo " Source:  $DDRD_KERNEL"
    echo " Target:  $TARGET_KERNEL"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo " Ported Components:"
    echo "   • kernel/kccwf/          Core framework (${#KCCWF_CORE_FILES[@]} files)"
    echo "   • drivers/char/kccwf/    Control device (${#KCCWF_CTL_FILES[@]} files)"
    echo "   • include/linux/kccwf.h  Main header"
    echo "   • kernel/Makefile        [patched: obj-y += kccwf/]"
    echo "   • drivers/char/Makefile  [patched: obj-y += kccwf/]"
    echo "   • include/linux/sched.h  [patched: 4 task_struct fields]"
    echo ""
    echo " Next Steps:"
    echo "   1. Build the kernel with KCCWF instrumentation (see build scripts)"
    echo "   2. Deploy syz-race-collector to VMs"
    echo "   3. Run experiments and collect pair data"
    echo "═══════════════════════════════════════════════════════════════"
}

# ============================================================================
# Main
# ============================================================================
main() {
    parse_args "$@"

    echo ""
    log_info "KCCWF Porter — porting KCCWF to target kernel"
    log_info "Source: $DDRD_KERNEL"
    log_info "Target: $TARGET_KERNEL"
    echo ""

    if $VERIFY_ONLY; then
        verify_kccwf "$TARGET_KERNEL"
        exit $?
    fi

    # 先验证目标是否已有 KCCWF
    if verify_kccwf "$TARGET_KERNEL" 2>/dev/null; then
        if ! $FORCE; then
            log_info "KCCWF is already fully ported. Use --force to overwrite."
            exit 0
        fi
        log_warn "KCCWF already present, --force specified, will overwrite."
    fi

    # 执行移植
    copy_kccwf_sources
    patch_kernel_makefile
    patch_drivers_makefile
    patch_sched_h
    check_header_deps

    # 最终验证
    echo ""
    log_step "Final verification..."
    verify_kccwf "$TARGET_KERNEL"

    generate_report
}

main "$@"
