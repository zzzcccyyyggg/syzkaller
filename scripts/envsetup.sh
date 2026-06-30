#!/usr/bin/env bash
# ============================================================================
# DDRD 项目环境配置
# 用法: source scripts/envsetup.sh
# ============================================================================

set -euo pipefail

# ------- 目录布局 -------
# PROJECT_HOME=/home/zzzccc/BASS/DDRD-syzkaller
#   ├── scripts/          # 本目录: 所有脚本
#   ├── bin/              # syzkaller 编译产物
#   ├── exp/              # 实验目录 (每个 module 一个子目录)
#   │   ├── xfs/
#   │   │   ├── fuzz.cfg
#   │   │   ├── validate.cfg
#   │   │   └── workdir/
#   │   └── btrfs/ ...
#   ├── images/           # 磁盘镜像 + SSH key
#   ├── kernels/          # 内核相关
#   │   ├── builds/       # 共享的 out-of-tree 增量构建目录
#   │   ├── output/       # 每个模块一个文件夹, 存放 vmlinux + bzImage
#   │   │   ├── plain/
#   │   │   ├── xfs/
#   │   │   └── btrfs/ ...
#   │   └── configs/      # .config 文件
#   └── test/             # 原有测试 (兼容保留)

_realpath() { cd "$1" && pwd; }

export SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_HOME="$(cd "$SCRIPTS_DIR/.." && pwd)"

# --------------- 可按需覆盖的环境变量 ---------------
# 内核源码位置 (默认使用 symlink, 也可直接指定)
export DDRD_KERNEL_SRC="${DDRD_KERNEL_SRC:-/home/zzzccc/Linux-Kernel/DDRD-Kernel}"
# DDRD 插桩工具链位置 (默认使用项目内 ddrd-tools/, 可覆盖指向外部 DDRD)
export DDRD_TOOLCHAIN="${DDRD_TOOLCHAIN:-$PROJECT_HOME/ddrd-tools}"
# LLVM 路径 (LD_LIBRARY_PATH 需要)
export DDRD_LLVM="${DDRD_LLVM:-/home/zzzccc/llvm-15/llvm-project/build}"
# Go 环境 (apt 安装 golang-go 后可直接使用)
export GOPATH="${GOPATH:-$HOME/go}"
export GOBIN="${GOBIN:-$GOPATH/bin}"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"

# --------------- 项目内路径 ---------------
export SYZKALLER_DIR="$PROJECT_HOME"
export SYZKALLER_BIN="$PROJECT_HOME/bin"
export SYZ_MANAGER="$SYZKALLER_BIN/syz-manager"

export KERNELS_DIR="$PROJECT_HOME/kernels"
export KERNEL_BUILDS_DIR="${KERNEL_BUILDS_DIR:-$KERNELS_DIR/builds}"
export KERNEL_OUTPUT_DIR="${KERNEL_OUTPUT_DIR:-$KERNELS_DIR/output}"
export KERNEL_CONFIGS_DIR="${KERNEL_CONFIGS_DIR:-$KERNELS_DIR/configs}"
export KERNEL_IMAGES_DIR="${KERNEL_IMAGES_DIR:-$PROJECT_HOME/images}"

export EXP_DIR="$PROJECT_HOME/exp"

# DDRD 编译器 wrapper
export DDRD_CC="$DDRD_TOOLCHAIN/compiler/clang-wrapper.sh"
export DDRD_INSTRUMENT_CONF="$DDRD_TOOLCHAIN/compiler/instrumentation_targets.conf"

# LD_LIBRARY_PATH
export LD_LIBRARY_PATH="${DDRD_LLVM}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# --------------- 确保关键目录存在 ---------------
mkdir -p "$KERNEL_BUILDS_DIR" "$KERNEL_OUTPUT_DIR" "$KERNEL_CONFIGS_DIR" \
         "$KERNEL_IMAGES_DIR" "$EXP_DIR" "$GOBIN" "$GOCACHE"

# --------------- 加入 PATH ---------------
_add_path() {
    case ":${PATH}:" in
        *:"$1":*) ;;
        *) export PATH="$1:$PATH" ;;
    esac
}
_add_path "$SYZKALLER_BIN"
_add_path "$DDRD_TOOLCHAIN/compiler"
_add_path "/usr/local/go/bin"
_add_path "$GOBIN"

echo "[envsetup] PROJECT_HOME = $PROJECT_HOME"
echo "[envsetup] KERNEL_SRC   = $DDRD_KERNEL_SRC"
echo "[envsetup] TOOLCHAIN    = $DDRD_TOOLCHAIN"
echo "[envsetup] GO_PATH      = $GOPATH"
echo "[envsetup] Environment ready."
