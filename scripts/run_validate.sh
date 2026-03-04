#!/usr/bin/env bash
# ============================================================================
# run_validate.sh — 启动 / 停止 / 查看 validate 实验
#
# 用法:
#   ./scripts/run_validate.sh start [module1 module2 ...]
#   ./scripts/run_validate.sh stop  [module1 module2 ...]
#   ./scripts/run_validate.sh status
#   ./scripts/run_validate.sh start --all
#   ./scripts/run_validate.sh start --debug xfs
#   ./scripts/run_validate.sh log xfs
#   ./scripts/run_validate.sh list
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

ACTION="${1:-help}"; shift || true

DEBUG_MODE=false
ALL_MODE=false
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)    DEBUG_MODE=true; shift ;;
        --all|-a)   ALL_MODE=true; shift ;;
        -*) die "未知选项: $1" ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

if $ALL_MODE; then
    mapfile -t TARGETS < <(ls -d "$EXP_DIR"/*/validate.cfg 2>/dev/null | xargs -I{} dirname {} | xargs -I{} basename {})
fi

# ---------------------------------------------------------------------------
get_validate_pid() {
    local slug=$1
    local cfg="$EXP_DIR/$slug/validate.cfg"
    pgrep -f "syz-manager.*-mode=uaf-validate.*${cfg}" 2>/dev/null || true
    # 有时 -config 在 -mode 前面
    if [[ -z "$(pgrep -f "syz-manager.*${cfg}" 2>/dev/null || true)" ]]; then
        return
    fi
    pgrep -f "syz-manager.*${cfg}" 2>/dev/null || true
}

do_start() {
    local slug=$1
    local cfg="$EXP_DIR/$slug/validate.cfg"

    [[ -f "$cfg" ]] || die "配置不存在: $cfg (先运行: python3 scripts/generate_config.py --validate-only $slug)"

    # 检查共享 workdir 中是否有 uaf-corpus.db
    local shared_workdir="$EXP_DIR/$slug/workdir"
    if [[ ! -f "$shared_workdir/uaf-corpus.db" ]]; then
        log_warn "[$slug] workdir 中无 uaf-corpus.db: $shared_workdir"
        log_warn "  validate 需要 fuzz 阶段产生的 uaf corpus"
    fi

    local pid
    pid=$(get_validate_pid "$slug")
    if [[ -n "$pid" ]]; then
        log_warn "[$slug] validate 已在运行 (PID: $pid)"
        return 0
    fi

    local log_dir="$EXP_DIR/$slug/logs"
    mkdir -p "$log_dir"
    local log_file="$log_dir/validate-$(date +%Y%m%d-%H%M%S).log"

    if $DEBUG_MODE; then
        log_info "[$slug] 前台 debug 模式 (validate)..."
        exec "$SYZ_MANAGER" -mode=uaf-validate -config "$cfg" -debug
    fi

    log_info "[$slug] 启动 validate..."
    nohup "$SYZ_MANAGER" -mode=uaf-validate -config "$cfg" > "$log_file" 2>&1 &
    local new_pid=$!

    sleep 2
    if kill -0 "$new_pid" 2>/dev/null; then
        log_ok "[$slug] PID=$new_pid  日志: $log_file"
    else
        log_error "[$slug] 启动失败, 请检查: $log_file"
    fi
}

do_stop() {
    local slug=$1
    local pid
    pid=$(get_validate_pid "$slug")
    if [[ -z "$pid" ]]; then
        log_warn "[$slug] validate 未在运行"
        return 0
    fi
    log_info "[$slug] 停止 validate PID=$pid..."
    kill "$pid" 2>/dev/null || true
    wait_pid "$pid" 15
    log_ok "[$slug] 已停止"
}

do_status() {
    printf "%-15s %-10s %-8s %s\n" "MODULE" "VALIDATE" "PID" "CONFIG"
    printf "%-15s %-10s %-8s %s\n" "------" "--------" "---" "------"
    for mod_dir in "$EXP_DIR"/*/; do
        local slug
        slug=$(basename "$mod_dir")
        local cfg="$EXP_DIR/$slug/validate.cfg"
        [[ -f "$cfg" ]] || continue
        local pid
        pid=$(get_validate_pid "$slug")
        local status="stopped"
        [[ -n "$pid" ]] && status="running"
        printf "%-15s %-10s %-8s %s\n" "$slug" "$status" "${pid:-—}" "$cfg"
    done
}

do_log() {
    local slug=$1
    local log_dir="$EXP_DIR/$slug/logs"
    local latest
    latest=$(ls -t "$log_dir"/validate-*.log 2>/dev/null | head -1)
    if [[ -z "$latest" ]]; then
        die "[$slug] 无 validate 日志"
    fi
    log_info "查看: $latest"
    tail -f "$latest"
}

# ---------------------------------------------------------------------------
case "$ACTION" in
    start)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        for t in "${TARGETS[@]}"; do do_start "$t"; done
        ;;
    stop)
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            for mod_dir in "$EXP_DIR"/*/; do
                slug=$(basename "$mod_dir")
                pid=$(get_validate_pid "$slug")
                [[ -n "$pid" ]] && do_stop "$slug"
            done
        else
            for t in "${TARGETS[@]}"; do do_stop "$t"; done
        fi
        ;;
    status)
        do_status
        ;;
    log)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块"
        do_log "${TARGETS[0]}"
        ;;
    list)
        echo "可用模块 (有 validate.cfg):"
        for mod_dir in "$EXP_DIR"/*/; do
            slug=$(basename "$mod_dir")
            [[ -f "$mod_dir/validate.cfg" ]] && echo "  $slug"
        done
        ;;
    help|--help|-h)
        sed -n '3,12p' "$0" | sed 's/^# //' | sed 's/^#//'
        ;;
    *)
        die "未知命令: $ACTION"
        ;;
esac
