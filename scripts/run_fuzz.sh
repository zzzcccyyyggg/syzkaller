#!/usr/bin/env bash
# ============================================================================
# run_fuzz.sh — 启动 / 停止 / 查看 fuzz 实验
#
# 用法:
#   ./scripts/run_fuzz.sh start [module1 module2 ...]   # 启动
#   ./scripts/run_fuzz.sh stop  [module1 module2 ...]   # 停止
#   ./scripts/run_fuzz.sh status                        # 查看状态
#   ./scripts/run_fuzz.sh start --all                   # 启动全部
#   ./scripts/run_fuzz.sh start --debug xfs             # debug 模式前台运行
#   ./scripts/run_fuzz.sh start -t 2h xfs               # 2小时后自动停止
#   ./scripts/run_fuzz.sh start --throughput -t 10m xfs # 使用 fuzz-throughput.cfg
#   ./scripts/run_fuzz.sh status --config-suffix throughput
#   ./scripts/run_fuzz.sh log xfs                       # 查看实时日志
#   ./scripts/run_fuzz.sh list                          # 列出可用模块
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

ACTION="${1:-help}"; shift || true

DEBUG_MODE=false
ALL_MODE=false
DURATION=0
CONFIG_SUFFIX=""
TARGETS=()

# 解析选项
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)    DEBUG_MODE=true; shift ;;
        --all|-a)   ALL_MODE=true; shift ;;
        --throughput) CONFIG_SUFFIX="throughput"; shift ;;
        --config-suffix)
            CONFIG_SUFFIX="$2"; shift 2 ;;
        -t|--duration)
            # 支持 30m, 2h, 1d 格式
            raw="$2"; shift 2
            case "$raw" in
                *d) DURATION=$(( ${raw%d} * 86400 )) ;;
                *h) DURATION=$(( ${raw%h} * 3600 )) ;;
                *m) DURATION=$(( ${raw%m} * 60 )) ;;
                *)  DURATION="$raw" ;;
            esac
            ;;
        -*) die "未知选项: $1" ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

# ---------------------------------------------------------------------------
config_name() {
    if [[ -n "$CONFIG_SUFFIX" ]]; then
        echo "fuzz-${CONFIG_SUFFIX}.cfg"
    else
        echo "fuzz.cfg"
    fi
}

config_path() {
    local slug=$1
    echo "$EXP_DIR/$slug/$(config_name)"
}

if $ALL_MODE; then
    mapfile -t TARGETS < <(ls -d "$EXP_DIR"/*/"$(config_name)" 2>/dev/null | xargs -r -I{} dirname {} | xargs -r -I{} basename {})
fi

get_fuzz_pids() {
    local slug=$1
    local cfg
    cfg=$(config_path "$slug")
    pgrep -f "syz-manager.*${cfg}" 2>/dev/null || true
}

do_start() {
    local slug=$1
    local cfg
    cfg=$(config_path "$slug")

    [[ -f "$cfg" ]] || die "配置不存在: $cfg (先运行: python3 scripts/generate_config.py $slug)"

    local pids=()
    mapfile -t pids < <(get_fuzz_pids "$slug")
    if [[ ${#pids[@]} -gt 0 ]]; then
        log_warn "$slug 已在运行 (PID: ${pids[*]})"
        return 0
    fi

    local log_dir="$EXP_DIR/$slug/logs"
    mkdir -p "$log_dir"
    local log_prefix="fuzz"
    [[ -n "$CONFIG_SUFFIX" ]] && log_prefix="fuzz-${CONFIG_SUFFIX}"
    local log_file="$log_dir/${log_prefix}-$(date +%Y%m%d-%H%M%S).log"

    if $DEBUG_MODE; then
        log_info "[$slug] 前台 debug 模式..."
        exec "$SYZ_MANAGER" -config "$cfg" -debug
    fi

    log_info "[$slug] 启动 fuzz..."
    if (( DURATION > 0 )); then
        nohup setsid timeout "$DURATION" "$SYZ_MANAGER" -config "$cfg" > "$log_file" 2>&1 &
    else
        nohup setsid "$SYZ_MANAGER" -config "$cfg" > "$log_file" 2>&1 &
    fi
    local new_pid=$!

    sleep 2
    if kill -0 "$new_pid" 2>/dev/null; then
        log_ok "[$slug] PID=$new_pid  日志: $log_file"
        (( DURATION > 0 )) && log_info "[$slug] 将在 ${DURATION}s 后由 timeout 自动停止"
    else
        log_error "[$slug] 启动失败, 请检查: $log_file"
    fi
}

do_stop() {
    local slug=$1
    local pids=()
    mapfile -t pids < <(get_fuzz_pids "$slug")
    if [[ ${#pids[@]} -eq 0 ]]; then
        log_warn "[$slug] 未在运行"
        return 0
    fi
    log_info "[$slug] 停止 PID=${pids[*]}..."
    kill "${pids[@]}" 2>/dev/null || true
    for pid in "${pids[@]}"; do
        wait_pid "$pid" 15
    done
    log_ok "[$slug] 已停止"
}

do_status() {
    printf "%-15s %-8s %-8s %s\n" "MODULE" "STATUS" "PID" "CONFIG"
    printf "%-15s %-8s %-8s %s\n" "------" "------" "---" "------"
    for mod_dir in "$EXP_DIR"/*/; do
        local slug
        slug=$(basename "$mod_dir")
        local cfg
        cfg=$(config_path "$slug")
        [[ -f "$cfg" ]] || continue
        local pids=()
        mapfile -t pids < <(get_fuzz_pids "$slug")
        local status="stopped"
        [[ ${#pids[@]} -gt 0 ]] && status="running"
        printf "%-15s %-8s %-8s %s\n" "$slug" "$status" "${pids[*]:-—}" "$cfg"
    done
}

do_log() {
    local slug=$1
    local log_dir="$EXP_DIR/$slug/logs"
    local latest
    local log_prefix="fuzz"
    [[ -n "$CONFIG_SUFFIX" ]] && log_prefix="fuzz-${CONFIG_SUFFIX}"
    latest=$(ls -t "$log_dir"/"${log_prefix}"-*.log 2>/dev/null | head -1)
    if [[ -z "$latest" ]]; then
        die "[$slug] 无日志文件"
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
            # 停止所有正在运行的
            for mod_dir in "$EXP_DIR"/*/; do
                slug=$(basename "$mod_dir")
                pids=()
                mapfile -t pids < <(get_fuzz_pids "$slug")
                [[ ${#pids[@]} -gt 0 ]] && do_stop "$slug"
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
        echo "可用模块 (有 $(config_name)):"
        for mod_dir in "$EXP_DIR"/*/; do
            slug=$(basename "$mod_dir")
            [[ -f "$mod_dir/$(config_name)" ]] && echo "  $slug"
        done
        ;;
    help|--help|-h)
        sed -n '3,13p' "$0" | sed 's/^# //' | sed 's/^#//'
        ;;
    *)
        die "未知命令: $ACTION (使用 start|stop|status|log|list|help)"
        ;;
esac
