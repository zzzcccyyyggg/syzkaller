#!/usr/bin/env bash
# ============================================================================
# install_toolchain_ubuntu.sh — Ubuntu 一键安装 DDRD-syzkaller 工具链
#
# 用法:
#   ./scripts/install_toolchain_ubuntu.sh                 # 完整安装
#   ./scripts/install_toolchain_ubuntu.sh --minimal       # 最小安装
#   ./scripts/install_toolchain_ubuntu.sh --dry-run       # 仅打印将执行命令
#   ./scripts/install_toolchain_ubuntu.sh --no-update     # 跳过 apt update
#
# 说明:
#   - 默认安装完整依赖: syzkaller + 内核编译 + DDRD 工具链 + QEMU/镜像工具
#   - 自动检测 clang-18; 若仓库无 clang-18 则回退安装默认 clang/llvm
# ============================================================================
set -euo pipefail

DRY_RUN=false
MINIMAL=false
NO_UPDATE=false
FORCE_DISTRO=false

usage() {
    sed -n '3,20p' "$0" | sed 's/^# //' | sed 's/^#//'
}

log_info()  { echo -e "\033[34m[INFO]\033[0m $*"; }
log_ok()    { echo -e "\033[32m[ OK ]\033[0m $*"; }
log_warn()  { echo -e "\033[33m[WARN]\033[0m $*"; }
log_err()   { echo -e "\033[31m[ERR ]\033[0m $*" >&2; }

run() {
    if $DRY_RUN; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --minimal)      MINIMAL=true; shift ;;
        --dry-run|-n)   DRY_RUN=true; shift ;;
        --no-update)    NO_UPDATE=true; shift ;;
        --force-distro) FORCE_DISTRO=true; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              log_err "未知选项: $1"; usage; exit 1 ;;
    esac
done

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
else
    log_err "无法识别系统版本 (/etc/os-release 不存在)"
    exit 1
fi

if [[ "${ID:-}" != "ubuntu" ]] && ! $FORCE_DISTRO; then
    log_err "当前系统不是 Ubuntu (ID=${ID:-unknown})"
    log_err "如确认兼容, 可加参数: --force-distro"
    exit 1
fi

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    SUDO=()
else
    if ! command -v sudo >/dev/null 2>&1; then
        log_err "需要 root 权限或 sudo"
        exit 1
    fi
    SUDO=(sudo)
fi

BASE_PKGS=(
    build-essential make git curl wget ca-certificates gnupg lsb-release
    pkg-config software-properties-common
    python3 python3-pip python3-venv python3-setuptools python3-wheel
    golang-go
)

KERNEL_PKGS=(
    bc bison flex libssl-dev libelf-dev libncurses-dev libudev-dev
    dwarves cpio rsync
)

VM_PKGS=(
    qemu-system-x86 qemu-utils debootstrap kmod
)

FS_PKGS=(
    xfsprogs btrfs-progs f2fs-tools jfsutils e2fsprogs dosfstools
)

DDRD_PKGS=(
    cmake g++
)

CPUSET_PKGS=(
    cpuset util-linux
)

if apt-cache show clang-18 >/dev/null 2>&1; then
    LLVM_PKGS=(clang-18 llvm-18 llvm-18-dev lld-18)
else
    LLVM_PKGS=(clang llvm llvm-dev lld)
fi

EXTRA_PKGS=(jq tree unzip zip)

PKGS=("${BASE_PKGS[@]}" "${KERNEL_PKGS[@]}" "${VM_PKGS[@]}" "${DDRD_PKGS[@]}" "${CPUSET_PKGS[@]}" "${LLVM_PKGS[@]}")
if ! $MINIMAL; then
    PKGS+=("${FS_PKGS[@]}" "${EXTRA_PKGS[@]}")
fi

# 去重
declare -A seen=()
DEDUP_PKGS=()
for p in "${PKGS[@]}"; do
    [[ -n "${seen[$p]:-}" ]] && continue
    seen[$p]=1
    DEDUP_PKGS+=("$p")
done

log_info "系统: ${PRETTY_NAME:-$ID}"
log_info "模式: $($MINIMAL && echo minimal || echo full)"
log_info "包数量: ${#DEDUP_PKGS[@]}"

if ! $NO_UPDATE; then
    log_info "apt 更新索引..."
    run "${SUDO[@]}" apt-get update
fi

log_info "安装依赖包..."
run "${SUDO[@]}" apt-get install -y --no-install-recommends "${DEDUP_PKGS[@]}"

if ! $DRY_RUN; then
    log_ok "安装完成"
    echo ""
    log_info "关键工具版本:"
    for cmd in go gcc g++ make cmake qemu-system-x86_64 debootstrap; do
        if command -v "$cmd" >/dev/null 2>&1; then
            v=$($cmd --version 2>&1 | head -1 || true)
            echo "  - $cmd: ${v:-ok}"
        else
            echo "  - $cmd: 未找到"
        fi
    done

    echo ""
    if command -v go >/dev/null 2>&1; then
        log_info "Go 环境:"
        echo "  - GOROOT: $(go env GOROOT 2>/dev/null || echo '-')"
        echo "  - GOPATH: $(go env GOPATH 2>/dev/null || echo '-')"
        echo "  - GOBIN : $(go env GOBIN 2>/dev/null || echo '-')"
    fi

    echo ""
    log_info "建议执行: source scripts/envsetup.sh"
    log_info "envsetup 会自动设置 GOPATH/GOBIN/GOCACHE 并加入 PATH"
fi

log_ok "完成"
