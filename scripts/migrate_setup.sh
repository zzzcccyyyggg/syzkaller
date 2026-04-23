#!/usr/bin/env bash
# ============================================================================
# migrate_setup.sh — DDRD-syzkaller 迁移后一键资源创建脚本
#
# 用法:
#   # 完整设置 (推荐, 包含所有步骤)
#   sudo ./scripts/migrate_setup.sh --full
#
#   # 分步执行
#   sudo ./scripts/migrate_setup.sh --install-deps          # 安装系统依赖
#   ./scripts/migrate_setup.sh --create-images               # 创建全部磁盘镜像
#   ./scripts/migrate_setup.sh --create-images --skip-rootfs  # 仅创建 FS 镜像
#   ./scripts/migrate_setup.sh --build-tools                 # 编译 DDRD 工具链
#   ./scripts/migrate_setup.sh --build-syzkaller             # 编译 syzkaller
#   ./scripts/migrate_setup.sh --build-kernel [modules...]   # 编译内核
#   ./scripts/migrate_setup.sh --gen-config                  # 生成实验配置
#   ./scripts/migrate_setup.sh --verify                      # 全面验收检查
#   ./scripts/migrate_setup.sh --status                      # 查看当前状态
#
# 前置条件:
#   1. DDRD-Kernel 源码已 clone 到指定位置
#   2. LLVM 18 已安装 (或 DDRD_LLVM 指向自编译 LLVM)
#   3. Ubuntu 22.04+ / Debian 12+
#
# 环境变量 (可选覆盖):
#   DDRD_KERNEL_SRC   内核源码路径 (默认: /home/$USER/Linux-Kernel/DDRD-Kernel)
#   DDRD_LLVM         LLVM 安装路径 (默认: /usr/lib/llvm-18)
#   MIRROR            镜像源 (tsinghua/ustc/aliyun/official, 默认: tsinghua)
#   ROOTFS_SIZE       rootfs 镜像大小 (默认: 20G)
#   FS_SIZE           文件系统镜像大小 (默认: 2G)
#
# 说明:
#   本脚本仅负责 DDRD-syzkaller 主环境。
#   若需继续做 DDRD vs Conzzer vs SegFuzz 对比实验，请额外迁移
#   Conzzer / SegFuzz 仓库，并在对比脚本中设置 CONZZER_HOME / SEGFUZZ_HOME。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_HOME="$(cd "$SCRIPT_DIR/.." && pwd)"

# ===== 颜色输出 =====
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[1;36m'; NC='\033[0m'
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()   { echo -e "${RED}[ERR ]${NC} $*" >&2; }
log_step()  { echo -e "\n${CYAN}========== $* ==========${NC}"; }
die()       { log_err "$@"; exit 1; }

# ===== 默认配置 =====
MIRROR="${MIRROR:-tsinghua}"
ROOTFS_SIZE="${ROOTFS_SIZE:-20G}"
FS_SIZE="${FS_SIZE:-2G}"

ACTION="${1:-help}"; shift 2>/dev/null || true

# ============================================================================
# Step 0: 状态检查
# ============================================================================
do_status() {
    log_step "DDRD-syzkaller 迁移环境状态检查"

    echo ""
    echo "===== 系统信息 ====="
    echo "  OS:       $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo "  Kernel:   $(uname -r)"
    echo "  CPU:      $(nproc) cores"
    echo "  RAM:      $(free -h | awk '/^Mem:/{print $2}')"
    echo "  Disk:     $(df -h "$PROJECT_HOME" | awk 'NR==2{print $4 " free / " $2 " total"}')"
    echo "  KVM:      $([ -e /dev/kvm ] && echo '✓ 可用' || echo '✗ 不可用 (需要 KVM 支持!)')"

    echo ""
    echo "===== 项目路径 ====="
    echo "  PROJECT_HOME:    $PROJECT_HOME"

    local kernel_src="${DDRD_KERNEL_SRC:-$HOME/Linux-Kernel/DDRD-Kernel}"
    printf "  DDRD_KERNEL_SRC: %s " "$kernel_src"
    [[ -d "$kernel_src" ]] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗ 不存在${NC}"

    local llvm_path="${DDRD_LLVM:-/usr/lib/llvm-18}"
    printf "  DDRD_LLVM:       %s " "$llvm_path"
    [[ -d "$llvm_path" ]] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗ 不存在${NC}"

    echo ""
    echo "===== 关键命令 ====="
    for cmd in go gcc g++ make cmake clang-18 clang qemu-system-x86_64 debootstrap ssh-keygen qemu-img mkfs.xfs mkfs.btrfs mkfs.f2fs mkfs.jfs mkfs.ext4 mkfs.ocfs2; do
        printf "  %-25s " "$cmd"
        if command -v "$cmd" &>/dev/null; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}✗${NC}"
        fi
    done

    echo ""
    echo "===== 磁盘镜像 ====="
    local img_dir="$PROJECT_HOME/images"
    if [[ -d "$img_dir" ]]; then
        # rootfs
        printf "  %-35s " "bookworm.img (rootfs)"
        [[ -f "$img_dir/bookworm.img" ]] && echo -e "${GREEN}✓${NC} ($(du -h "$img_dir/bookworm.img" 2>/dev/null | cut -f1))" || echo -e "${RED}✗${NC}"

        # SSH key
        printf "  %-35s " "bookworm.id_rsa (SSH key)"
        [[ -f "$img_dir/bookworm.id_rsa" ]] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"

        # FS images
        for fs in xfs btrfs f2fs jfs ext4 ocfs2; do
            local name="${fs}-2G.qcow2"
            printf "  %-35s " "$name"
            [[ -f "$img_dir/$name" ]] && echo -e "${GREEN}✓${NC} ($(du -h "$(readlink -f "$img_dir/$name")" 2>/dev/null | cut -f1))" || echo -e "${YELLOW}✗${NC}"
        done
    else
        echo "  images/ 目录不存在"
    fi

    echo ""
    echo "===== 编译产物 ====="
    # syzkaller
    printf "  %-35s " "syz-manager"
    [[ -x "$PROJECT_HOME/bin/syz-manager" ]] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"

    # DDRD tools
    local toolchain="$PROJECT_HOME/ddrd-tools"
    for bin in compiler/kernel_compiler compiler/ddrace-cc build/bin/instrumenter; do
        printf "  %-35s " "$(basename $bin)"
        [[ -x "$toolchain/$bin" ]] && echo -e "${GREEN}✓${NC}" || echo -e "${YELLOW}✗ 需编译${NC}"
    done

    echo ""
    echo "===== 内核输出 ====="
    local output_dir="$PROJECT_HOME/kernels/output"
    if [[ -d "$output_dir" ]]; then
        for d in "$output_dir"/*/; do
            [[ -d "$d" ]] || continue
            local name=$(basename "$d")
            printf "  %-15s " "$name"
            if [[ -f "$d/vmlinux" && -f "$d/bzImage" ]]; then
                echo -e "${GREEN}✓${NC} vmlinux=$(du -h "$d/vmlinux" | cut -f1) bzImage=$(du -h "$d/bzImage" | cut -f1)"
            else
                echo -e "${YELLOW}✗ 缺少文件${NC}"
            fi
        done
    else
        echo "  kernels/output/ 目录不存在"
    fi

    echo ""
    echo "===== 实验配置 ====="
    local exp_dir="$PROJECT_HOME/exp"
    local cfg_count=0
    if [[ -d "$exp_dir" ]]; then
        for slug_dir in "$exp_dir"/*/; do
            [[ -d "$slug_dir" ]] || continue
            local slug=$(basename "$slug_dir")
            [[ -f "$slug_dir/syscalls.txt" ]] || continue
            printf "  %-15s " "$slug"
            local status=""
            [[ -f "$slug_dir/fuzz.cfg" ]] && status+="fuzz.cfg✓ " || status+="fuzz.cfg✗ "
            [[ -f "$slug_dir/validate.cfg" ]] && status+="validate.cfg✓ " || status+="validate.cfg✗ "
            echo "$status"
            ((cfg_count++))
        done
    fi
    echo "  共 $cfg_count 个模块"
}

# ============================================================================
# Step 1: 安装系统依赖
# ============================================================================
do_install_deps() {
    log_step "安装系统依赖"

    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        die "安装依赖需要 root 权限, 请使用 sudo"
    fi

    bash "$SCRIPT_DIR/install_toolchain_ubuntu.sh" "$@"
}

# ============================================================================
# Step 2: 创建磁盘镜像
# ============================================================================
do_create_images() {
    log_step "创建磁盘镜像"

    local extra_args=("$@")

    # 调用 create_image.sh --create-all
    local create_args=(--create-all --mirror "$MIRROR")
    [[ "$ROOTFS_SIZE" != "20G" ]] && create_args+=(--size "$ROOTFS_SIZE")
    [[ "$FS_SIZE" != "2G" ]] && create_args+=(--fs-size "$FS_SIZE")

    # 透传额外参数 (--skip-rootfs, --force, --proxy 等)
    create_args+=("${extra_args[@]}")

    log_info "执行: create_image.sh ${create_args[*]}"
    bash "$SCRIPT_DIR/create_image.sh" "${create_args[@]}"

    # 修复 kccwf.service
    log_info "验证并修复 kccwf.service..."
    sudo bash "$SCRIPT_DIR/create_image.sh" --fix-kccwf || log_warn "fix-kccwf 需要 sudo"

    log_ok "磁盘镜像创建完成"
}

# ============================================================================
# Step 3: 编译 DDRD 工具链
# ============================================================================
do_build_tools() {
    log_step "编译 DDRD 工具链"
    source "$SCRIPT_DIR/envsetup.sh"
    bash "$SCRIPT_DIR/build_ddrd_tools.sh" "$@"
}

# ============================================================================
# Step 4: 编译 syzkaller
# ============================================================================
do_build_syzkaller() {
    log_step "编译 DDRD-syzkaller"
    source "$SCRIPT_DIR/envsetup.sh"
    bash "$SCRIPT_DIR/build_syzkaller.sh" "$@"
}

# ============================================================================
# Step 5: 编译内核
# ============================================================================
do_build_kernel() {
    log_step "编译内核"
    source "$SCRIPT_DIR/envsetup.sh"

    if [[ $# -gt 0 ]]; then
        bash "$SCRIPT_DIR/build_kernel.sh" "$@"
    else
        log_info "编译所有模块内核 (shared 模式, 这需要较长时间)..."
        bash "$SCRIPT_DIR/build_kernel.sh"
    fi
}

# ============================================================================
# Step 6: 生成实验配置
# ============================================================================
do_gen_config() {
    log_step "生成实验配置"
    source "$SCRIPT_DIR/envsetup.sh"

    # 提取模块数据
    if [[ -f "$SCRIPT_DIR/extract_module_data.py" ]]; then
        log_info "提取模块数据..."
        python3 "$SCRIPT_DIR/extract_module_data.py"
    fi

    # 生成配置
    python3 "$SCRIPT_DIR/generate_config.py" --all --force --vanilla
    log_ok "配置生成完成"
}

# ============================================================================
# Step 7: 全面验收检查
# ============================================================================
do_verify() {
    log_step "全面验收检查"
    local errors=0

    # 7.1 镜像验证
    log_info "验证磁盘镜像..."
    sudo bash "$SCRIPT_DIR/create_image.sh" --verify || ((errors++))

    # 7.2 工具链检查
    log_info "检查工具链..."
    source "$SCRIPT_DIR/envsetup.sh" 2>/dev/null || true
    bash "$SCRIPT_DIR/build_ddrd_tools.sh" check || ((errors++))

    # 7.3 syzkaller 检查
    printf "  %-35s " "syz-manager"
    if [[ -x "$PROJECT_HOME/bin/syz-manager" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ 未编译${NC}"
        ((errors++))
    fi

    # 7.4 内核输出检查
    log_info "检查内核输出..."
    local output_dir="$PROJECT_HOME/kernels/output"
    local kernel_ok=0 kernel_missing=0
    if [[ -d "$output_dir" ]]; then
        for d in "$output_dir"/*/; do
            [[ -d "$d" ]] || continue
            local name=$(basename "$d")
            if [[ -f "$d/vmlinux" && -f "$d/bzImage" ]]; then
                ((kernel_ok++))
            else
                log_warn "  缺少内核: $name"
                ((kernel_missing++))
            fi
        done
        log_info "  内核: $kernel_ok 完整, $kernel_missing 缺失"
    fi

    # 7.5 KVM 检查
    if [[ -e /dev/kvm ]]; then
        log_ok "KVM 可用"
    else
        log_err "KVM 不可用 — QEMU 将无法使用硬件加速"
        ((errors++))
    fi

    echo ""
    if [[ $errors -eq 0 ]]; then
        log_ok "全部验收通过! 可以开始实验."
    else
        log_warn "发现 $errors 个问题, 请检查上方输出"
    fi
}

# ============================================================================
# 完整设置 (一键执行所有步骤)
# ============================================================================
do_full() {
    log_step "DDRD-syzkaller 完整迁移设置"
    echo ""
    log_info "此脚本将依次执行:"
    log_info "  1. 安装系统依赖 (需要 sudo)"
    log_info "  2. 创建磁盘镜像 (rootfs + 6种文件系统)"
    log_info "  3. 编译 DDRD 工具链"
    log_info "  4. 编译 DDRD-syzkaller"
    log_info "  5. 编译内核 (耗时最长)"
    log_info "  6. 生成实验配置"
    log_info "  7. 全面验收"
    echo ""
    log_warn "整个过程可能需要数小时, 取决于机器性能和网络"
    echo ""

    # 检查前置条件
    local kernel_src="${DDRD_KERNEL_SRC:-$HOME/Linux-Kernel/DDRD-Kernel}"
    if [[ ! -d "$kernel_src" ]]; then
        die "DDRD-Kernel 源码不存在: $kernel_src\n  请先 clone: git clone <DDRD-Kernel-repo> $kernel_src"
    fi

    do_install_deps "$@"
    do_create_images
    do_build_tools
    do_build_syzkaller
    do_build_kernel
    do_gen_config
    do_verify

    echo ""
    log_ok "╔════════════════════════════════════════╗"
    log_ok "║   DDRD-syzkaller 迁移设置全部完成!     ║"
    log_ok "╚════════════════════════════════════════╝"
    echo ""
    echo "下一步:"
    echo "  source scripts/envsetup.sh"
    echo "  make fuzz MODULES=xfs           # 启动单个模块 fuzz"
    echo "  make fuzz MODULES='xfs btrfs'   # 启动多个模块 fuzz"
    echo "  make status                     # 查看运行状态"
    echo ""
    echo "如需继续做 DDRD vs Conzzer vs SegFuzz 对比:"
    echo "  export CONZZER_HOME=/path/to/Conzzer"
    echo "  export SEGFUZZ_HOME=/path/to/segfuzz"
    echo "  bash exp/pair-count-comparison/run_comparison.sh status"
}

# ============================================================================
# 帮助
# ============================================================================
do_help() {
    cat <<'HELP'
migrate_setup.sh — DDRD-syzkaller 迁移后一键资源创建

用法:
  sudo ./scripts/migrate_setup.sh --full                 # 一键完整设置
  sudo ./scripts/migrate_setup.sh --install-deps         # 仅安装依赖
  sudo ./scripts/migrate_setup.sh --create-images        # 创建磁盘镜像
  ./scripts/migrate_setup.sh --build-tools               # 编译工具链
  ./scripts/migrate_setup.sh --build-syzkaller           # 编译 syzkaller
  ./scripts/migrate_setup.sh --build-kernel [模块...]    # 编译内核
  ./scripts/migrate_setup.sh --gen-config                # 生成实验配置
  sudo ./scripts/migrate_setup.sh --verify               # 全面验收
  ./scripts/migrate_setup.sh --status                    # 查看当前状态

环境变量:
  DDRD_KERNEL_SRC    内核源码路径 (默认: ~/Linux-Kernel/DDRD-Kernel)
  DDRD_LLVM          LLVM 路径 (默认: /usr/lib/llvm-18 或自编译路径)
  MIRROR             镜像源 (tsinghua/ustc/aliyun/official)
  ROOTFS_SIZE        rootfs 大小 (默认: 20G)
  FS_SIZE            文件系统镜像大小 (默认: 2G)

示例:
  # 使用阿里云镜像 + 代理
  MIRROR=aliyun sudo ./scripts/migrate_setup.sh --full --proxy http://127.0.0.1:7890

  # 只编译 xfs 和 btrfs 的内核
  ./scripts/migrate_setup.sh --build-kernel xfs btrfs

  # rootfs 已在别处创建, 只补文件系统镜像
  ./scripts/migrate_setup.sh --create-images --skip-rootfs

说明:
  本脚本只覆盖 DDRD-syzkaller 主环境。
  如果要继续做 DDRD / Conzzer / SegFuzz 对比实验，请额外迁移 Conzzer 和 segfuzz，
  然后在运行 exp/pair-count-comparison/run_comparison.sh 前设置:
    export CONZZER_HOME=/path/to/Conzzer
    export SEGFUZZ_HOME=/path/to/segfuzz
HELP
}

# ============================================================================
# 入口
# ============================================================================
case "$ACTION" in
    --full)             do_full "$@" ;;
    --install-deps)     do_install_deps "$@" ;;
    --create-images)    do_create_images "$@" ;;
    --build-tools)      do_build_tools "$@" ;;
    --build-syzkaller)  do_build_syzkaller "$@" ;;
    --build-kernel)     do_build_kernel "$@" ;;
    --gen-config)       do_gen_config "$@" ;;
    --verify)           do_verify "$@" ;;
    --status)           do_status "$@" ;;
    help|--help|-h)     do_help ;;
    *)                  die "未知命令: $ACTION (使用 --help 查看帮助)" ;;
esac
