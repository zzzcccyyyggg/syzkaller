#!/usr/bin/env bash
# ============================================================================
# functions.sh — 共用辅助函数
# ============================================================================

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERR ]${NC} $*" >&2; }

die() { log_error "$@"; exit 1; }

# 确保 envsetup 已执行
require_env() {
    [[ -n "${PROJECT_HOME:-}" ]] || die "请先执行: source scripts/envsetup.sh"
}

# 解析 modules.conf, 返回指定 slug 的各字段
# 用法: read_module <slug>   => 设置 MOD_SLUG, MOD_KERNEL_PATHS, MOD_QEMU_EXTRA, ...
read_module() {
    local slug="$1"
    local conf="${SCRIPTS_DIR}/modules.conf"
    [[ -f "$conf" ]] || die "modules.conf 未找到: $conf"

    local line
    line=$(grep -E "^${slug}\|" "$conf" | head -1) || true
    [[ -n "$line" ]] || die "未知模块: $slug (检查 modules.conf)"

    IFS='|' read -r MOD_SLUG MOD_KERNEL_PATHS MOD_QEMU_EXTRA MOD_FS_IMAGE MOD_SYSCALLS <<< "$line"
    [[ "$MOD_QEMU_EXTRA" == "-" ]] && MOD_QEMU_EXTRA=""
    [[ "$MOD_FS_IMAGE" == "-" ]] && MOD_FS_IMAGE=""
    [[ "$MOD_SYSCALLS" == "-" ]] && MOD_SYSCALLS=""
    export MOD_SLUG MOD_KERNEL_PATHS MOD_QEMU_EXTRA MOD_FS_IMAGE MOD_SYSCALLS
}

# 列出所有可用的 slug
list_modules() {
    local conf="${SCRIPTS_DIR}/modules.conf"
    grep -v '^#' "$conf" | grep -v '^$' | cut -d'|' -f1
}

# 带时间戳的日志到文件
tee_log() {
    local logfile="$1"; shift
    "$@" 2>&1 | while IFS= read -r line; do
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line"
    done | tee -a "$logfile"
}

# 等待进程退出 (最多等 N 秒)
wait_pid() {
    local pid=$1 max=${2:-10} i=0
    while kill -0 "$pid" 2>/dev/null && (( i < max )); do
        sleep 1; ((i++)) || true
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
    fi
}
