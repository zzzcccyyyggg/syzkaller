#!/usr/bin/env bash
# ============================================================================
# run_capability_24h.sh — 8 模块 24h 主实验总控脚本
#
# 用法:
#   ./scripts/run_capability_24h.sh check
#   ./scripts/run_capability_24h.sh prepare
#   ./scripts/run_capability_24h.sh start-shared
#   ./scripts/run_capability_24h.sh start-batch1
#   ./scripts/run_capability_24h.sh start-batch2
#   ./scripts/run_capability_24h.sh start-safe4-fuzz
#   ./scripts/run_capability_24h.sh start-safe4-validate
#   ./scripts/run_capability_24h.sh stop-safe4
#   ./scripts/run_capability_24h.sh status
#   ./scripts/run_capability_24h.sh stop
#
# 说明:
#   check         环境就绪检查
#   prepare       统一导入 corpus.db, 清理旧 uaf/validate 状态, 重生成配置
#   start-shared  8 模块一起启动, fuzz+validate 共享每模块 2 核槽位
#   start-batch1  严格 2+2 模式的第一批(推荐 6 模块): xfs btrfs f2fs jfs bt-stack ptmx
#   start-batch2  严格 2+2 模式的第二批(剩余 2 模块): floppy dsp
#   start-safe4-fuzz      4 模块保守模式: 只启动 fuzz, 资源固定为更稳的 2+2 VM 配置
#   start-safe4-validate  4 模块保守模式: 启动独立 validate 槽位, 不使用 watcher
#   stop-safe4            停止 4 模块保守模式
#   status        查看当前实验状态
#   stop          停止 8 模块主实验
#
# 可选参数:
#   --corpus-src DIR   统一 corpus 源目录 (默认: /home/zzzccc/BASS/DDRD-Corpus)
#   --sudo             通过 sudo 调用 run_experiment.sh
#   --no-pin           透传给 run_experiment.sh
# 默认延续 run_experiment.sh 的 `3+2` 策略:
#   fuzz  默认 3 VM
#   validate 默认 2 VM
# 其它常用环境变量会直接透传给 run_experiment.sh, 例如:
#   CORES_PER_MODULE=4
#   EXP_FUZZ_VM_COUNT_XFS=3
#   EXP_VALIDATE_VM_COUNT_XFS=1
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

CORPUS_SRC="${CORPUS_SRC:-/home/zzzccc/BASS/DDRD-Corpus}"
ACTION="${1:-help}"
[[ $# -gt 0 ]] && shift || true

CAP_MODULES=(xfs btrfs f2fs jfs floppy bt-stack ptmx dsp)
# 基于当前 32 核主机的实际负载观测，严格 2+2 模式下优先采用 6+2 分批：
# 6 模块占用 24 个实验核，给系统和后台任务保留 8 个核心余量。
BATCH1_MODULES=(xfs btrfs f2fs jfs bt-stack ptmx)
BATCH2_MODULES=(floppy dsp)
# 4 模块保守模式采用 2 个 fs + 2 个非 fs，避免把 4 个文件系统负载堆在同一轮。
SAFE4_MODULES=(xfs btrfs bt-stack ptmx)
RUN_EXP="$SCRIPT_DIR/run_experiment.sh"
GEN_CFG="$SCRIPT_DIR/generate_config.py"
CORPUS_MGR="$SCRIPT_DIR/manage_corpus.sh"
CAP_PROFILE_ENV=(
    "EXP_FUZZ_VM_COUNT_XFS=1"
    "EXP_VALIDATE_VM_COUNT_XFS=8"
    "EXP_FUZZ_VM_COUNT_FLOPPY=1"
    "EXP_VALIDATE_VM_COUNT_FLOPPY=8"
    "EXP_FUZZ_VM_COUNT_BTRFS=1"
    "EXP_VALIDATE_VM_COUNT_BTRFS=7"
    "EXP_FUZZ_VM_COUNT_JFS=2"
    "EXP_VALIDATE_VM_COUNT_JFS=4"
    "EXP_FUZZ_VM_COUNT_F2FS=2"
    "EXP_VALIDATE_VM_COUNT_F2FS=4"
    "EXP_FUZZ_VM_COUNT_PTMX=2"
    "EXP_VALIDATE_VM_COUNT_PTMX=4"
)

NO_PIN=false
EXTRA_RUN_EXP_ARGS=()
RUNNER_PREFIX=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus-src)
            CORPUS_SRC="$2"
            shift 2
            ;;
        --sudo)
            RUNNER_PREFIX=("sudo")
            shift
            ;;
        --no-pin)
            NO_PIN=true
            EXTRA_RUN_EXP_ARGS+=("--no-pin")
            shift
            ;;
        --help|-h)
            ACTION="help"
            shift
            ;;
        *)
            die "未知选项: $1"
            ;;
    esac
done

join_by_space() {
    local IFS=' '
    echo "$*"
}

modules_str() {
    join_by_space "$@"
}

log_safe4_profile() {
    log_info "4 模块保守模式: $(modules_str "${SAFE4_MODULES[@]}")"
    log_info "资源配置: SYSTEM_RESERVED_CORES=${SAFE4_SYSTEM_RESERVED_CORES:-8}, CORES_PER_MODULE=${SAFE4_CORES_PER_MODULE:-2}, EXP_FUZZ_VM_COUNT=${SAFE4_FUZZ_VM_COUNT:-2}, EXP_VALIDATE_VM_COUNT=${SAFE4_VALIDATE_VM_COUNT:-2}, EXP_FUZZ_VM_COUNT_BTRFS=${SAFE4_BTRFS_FUZZ_VM_COUNT:-2}, EXP_VALIDATE_VM_COUNT_BTRFS=${SAFE4_BTRFS_VALIDATE_VM_COUNT:-1}"
    log_info "fuzz 时间阈值: dynamic=true, initial=2500us, range=[500,10000]us, eval=120s, timing_phase1_floor=20000us"
}

warn_validate_watchers() {
    local pid_file pid
    for pid_file in "$PROJECT_HOME"/.experiment/validate-watch*.pid; do
        [[ -f "$pid_file" ]] || continue
        pid=$(tr -dc '0-9' < "$pid_file")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log_warn "检测到 validate watcher 仍在运行: $pid_file (pid=$pid)"
            log_warn "4 模块保守模式不需要 watcher；请先停止该循环，避免 validate 被重复补拉"
        else
            log_warn "检测到 validate watcher 残留文件: $pid_file"
            if rm -f "$pid_file" 2>/dev/null; then
                log_info "已自动清理残留 watcher 文件: $pid_file"
            else
                log_warn "4 模块保守模式不需要 watcher；可手动清理该残留文件"
            fi
        fi
    done
}

run_safe4_command() {
    local -a env_args=(
        "SYSTEM_RESERVED_CORES=${SAFE4_SYSTEM_RESERVED_CORES:-8}"
        "CORES_PER_MODULE=${SAFE4_CORES_PER_MODULE:-2}"
        "EXP_FUZZ_VM_COUNT=${SAFE4_FUZZ_VM_COUNT:-2}"
        "EXP_VALIDATE_VM_COUNT=${SAFE4_VALIDATE_VM_COUNT:-2}"
        "EXP_FUZZ_VM_COUNT_BTRFS=${SAFE4_BTRFS_FUZZ_VM_COUNT:-2}"
        "EXP_VALIDATE_VM_COUNT_BTRFS=${SAFE4_BTRFS_VALIDATE_VM_COUNT:-1}"
    )

    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
        "${RUNNER_PREFIX[@]}" env "${env_args[@]}" "$RUN_EXP" "$@"
    else
        env "${env_args[@]}" "$RUN_EXP" "$@"
    fi
}

run_cap_command() {
    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
        "${RUNNER_PREFIX[@]}" env "${CAP_PROFILE_ENV[@]}" "$RUN_EXP" "$@"
    else
        env "${CAP_PROFILE_ENV[@]}" "$RUN_EXP" "$@"
    fi
}

refresh_safe4_configs() {
    log_info "重生成 4 模块保守模式配置: $(modules_str "${SAFE4_MODULES[@]}")"
    python3 "$GEN_CFG" --force "${SAFE4_MODULES[@]}"
}

assert_safe4_manager_fresh() {
    local manager="$PROJECT_HOME/bin/syz-manager"
    local ref
    local -a refs=(
        "pkg/mgrconfig/config.go"
        "pkg/fuzzer/fuzzer.go"
        "syz-manager/manager.go"
    )

    [[ -x "$manager" ]] || die "缺少可执行文件: $manager，请先运行 'make manager' 或 'make'"

    for ref in "${refs[@]}"; do
        if [[ "$manager" -ot "$PROJECT_HOME/$ref" ]]; then
            die "bin/syz-manager 早于 $ref，请先运行 'make manager' 或 'make' 重新编译后再启动 safe4"
        fi
    done
}

show_corpus_info() {
    if [[ -d "$CORPUS_SRC" ]]; then
        log_info "统一 corpus 源: $CORPUS_SRC"
        if git -C "$CORPUS_SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            local rev
            rev=$(git -C "$CORPUS_SRC" rev-parse --short HEAD 2>/dev/null || echo "unknown")
            log_info "corpus commit: $rev"
        fi
    else
        log_warn "统一 corpus 源不存在: $CORPUS_SRC"
    fi
}

check_one_file() {
    local label=$1 path=$2
    if [[ -e "$path" ]]; then
        log_ok "$label: $path"
        return 0
    fi
    log_error "$label 缺失: $path"
    return 1
}

check_module_artifacts() {
    local ok=true
    local slug
    for slug in "${CAP_MODULES[@]}"; do
        [[ -f "$EXP_DIR/$slug/fuzz.cfg" ]] || { log_error "缺少配置: $EXP_DIR/$slug/fuzz.cfg"; ok=false; }
        [[ -f "$EXP_DIR/$slug/validate.cfg" ]] || { log_error "缺少配置: $EXP_DIR/$slug/validate.cfg"; ok=false; }
        [[ -f "$KERNEL_OUTPUT_DIR/$slug/vmlinux" ]] || { log_error "缺少内核: $KERNEL_OUTPUT_DIR/$slug/vmlinux"; ok=false; }
        [[ -f "$KERNEL_OUTPUT_DIR/$slug/bzImage" ]] || { log_error "缺少内核: $KERNEL_OUTPUT_DIR/$slug/bzImage"; ok=false; }
    done
    $ok
}

do_check() {
    local ok=true
    echo "========================================="
    log_info "检查 8 模块主实验环境"
    echo "========================================="

    check_one_file "syz-manager" "$SYZ_MANAGER" || ok=false
    check_one_file "rootfs 镜像" "$KERNEL_IMAGES_DIR/bookworm.img" || ok=false
    check_one_file "SSH key" "$KERNEL_IMAGES_DIR/bookworm.id_rsa" || ok=false

    local image
    for image in xfs-2G.qcow2 btrfs-2G.qcow2 f2fs-2G.raw jfs-2G.qcow2; do
        check_one_file "文件系统镜像" "$KERNEL_IMAGES_DIR/$image" || ok=false
    done

    show_corpus_info
    [[ -d "$CORPUS_SRC" ]] || ok=false

    if ! check_module_artifacts; then
        ok=false
    else
        log_ok "8 个目标模块的 kernel/config 已就绪"
    fi

    echo "========================================="
    if $ok; then
        log_ok "环境检查通过，可以开始主实验"
    else
        log_error "环境检查未通过，请先修复上述缺项"
        return 1
    fi
}

do_prepare() {
    do_check
    echo "========================================="
    log_info "准备 8 模块主实验"
    echo "========================================="

    show_corpus_info

    log_info "停止残留实验进程"
    "${RUNNER_PREFIX[@]}" "$RUN_EXP" stop --all || true

    log_info "清理旧 uaf / validate 状态"
    "${RUNNER_PREFIX[@]}" "$RUN_EXP" clean --all || true
    "${RUNNER_PREFIX[@]}" "$RUN_EXP" clean-validate --all || true

    log_info "统一重新生成配置"
    python3 "$GEN_CFG" --all --force "${CAP_MODULES[@]}"

    log_info "导入统一 corpus.db"
    bash "$CORPUS_MGR" import --src "$CORPUS_SRC" --force "${CAP_MODULES[@]}"

    log_info "导入后 corpus 状态"
    bash "$CORPUS_MGR" stat "${CAP_MODULES[@]}"

    log_ok "主实验准备完成"
}

start_shared() {
    local mods
    mods=$(modules_str "${CAP_MODULES[@]}")
    log_info "启动共享槽位模式: $mods"
    run_cap_command "${EXTRA_RUN_EXP_ARGS[@]}" start "${CAP_MODULES[@]}"
    run_cap_command "${EXTRA_RUN_EXP_ARGS[@]}" validate "${CAP_MODULES[@]}"
}

start_batch() {
    local batch_name=$1
    shift
    local mods=("$@")
    log_info "启动严格 2+2 分批模式 ${batch_name}: $(modules_str "${mods[@]}")"
    run_cap_command "${EXTRA_RUN_EXP_ARGS[@]}" start "${mods[@]}"
    run_cap_command --separate-validate-slot "${EXTRA_RUN_EXP_ARGS[@]}" validate "${mods[@]}"
}

start_safe4_fuzz() {
    warn_validate_watchers
    log_safe4_profile
    refresh_safe4_configs
    assert_safe4_manager_fresh
    log_info "启动 4 模块保守模式 fuzz: $(modules_str "${SAFE4_MODULES[@]}")"
    run_safe4_command "${EXTRA_RUN_EXP_ARGS[@]}" start "${SAFE4_MODULES[@]}"
}

start_safe4_validate() {
    warn_validate_watchers
    log_safe4_profile
    refresh_safe4_configs
    assert_safe4_manager_fresh
    log_info "启动 4 模块保守模式 validate: $(modules_str "${SAFE4_MODULES[@]}")"
    log_info "该模式不会自动补拉 validate；若 validate 退出，请先检查日志再决定是否重启"
    run_safe4_command --separate-validate-slot "${EXTRA_RUN_EXP_ARGS[@]}" validate "${SAFE4_MODULES[@]}"
}

stop_safe4() {
    log_info "停止 4 模块保守模式: $(modules_str "${SAFE4_MODULES[@]}")"
    "${RUNNER_PREFIX[@]}" "$RUN_EXP" "${EXTRA_RUN_EXP_ARGS[@]}" stop "${SAFE4_MODULES[@]}"
}

do_status() {
    "${RUNNER_PREFIX[@]}" "$RUN_EXP" "${EXTRA_RUN_EXP_ARGS[@]}" status
}

do_stop() {
    "${RUNNER_PREFIX[@]}" "$RUN_EXP" "${EXTRA_RUN_EXP_ARGS[@]}" stop "${CAP_MODULES[@]}"
}

do_help() {
    sed -n '3,27p' "$0" | sed 's/^# //' | sed 's/^#//'
    echo ""
    echo "示例:"
    echo "  ./scripts/run_capability_24h.sh check"
    echo "  ./scripts/run_capability_24h.sh prepare"
    echo "  ./scripts/run_capability_24h.sh start-shared"
    echo "  ./scripts/run_capability_24h.sh start-batch1"
    echo "  ./scripts/run_capability_24h.sh start-batch2"
    echo "  ./scripts/run_capability_24h.sh start-safe4-fuzz"
    echo "  ./scripts/run_capability_24h.sh start-safe4-validate"
    echo "  ./scripts/run_capability_24h.sh stop-safe4"
}

case "$ACTION" in
    check)
        do_check
        ;;
    prepare)
        do_prepare
        ;;
    start-shared)
        start_shared
        ;;
    start-batch1)
        start_batch "batch1" "${BATCH1_MODULES[@]}"
        ;;
    start-batch2)
        start_batch "batch2" "${BATCH2_MODULES[@]}"
        ;;
    start-safe4-fuzz)
        start_safe4_fuzz
        ;;
    start-safe4-validate)
        start_safe4_validate
        ;;
    stop-safe4)
        stop_safe4
        ;;
    status)
        do_status
        ;;
    stop)
        do_stop
        ;;
    help|--help|-h)
        do_help
        ;;
    *)
        die "未知命令: $ACTION (check|prepare|start-shared|start-batch1|start-batch2|start-safe4-fuzz|start-safe4-validate|stop-safe4|status|stop|help)"
        ;;
esac
