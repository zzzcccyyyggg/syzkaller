#!/usr/bin/env bash
# ============================================================================
# build_syzkaller.sh — 编译 syzkaller (DDRD-syzkaller)
#
# 用法:
#   ./scripts/build_syzkaller.sh            # 标准编译
#   ./scripts/build_syzkaller.sh --clean    # clean 后重新编译
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

CLEAN=false
[[ "${1:-}" == "--clean" ]] && CLEAN=true

cd "$PROJECT_HOME"

if $CLEAN; then
    log_info "清理旧编译产物..."
    make clean || true
fi

log_info "编译 DDRD-syzkaller..."
make -j"$(nproc)"

if [[ -x "$SYZ_MANAGER" ]]; then
    log_ok "编译完成: $SYZ_MANAGER"
else
    die "编译失败: $SYZ_MANAGER 不存在"
fi
