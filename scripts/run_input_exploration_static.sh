#!/usr/bin/env bash
# ============================================================================
# run_input_exploration_static.sh — 静态阈值 fuzz-side 对比实验管理脚本
#
# 目标:
#   - 复用 run_capability_24h.sh 的统一 corpus prepare 流程
#   - 为 fuzz-side ablation 生成独立的静态阈值配置
#   - 用单独脚本管理 start / stop / status / archive，避免主实验脚本继续膨胀
#
# 默认实验设计:
#   - 模块: xfs btrfs f2fs ptmx floppy dsp
#   - 变体:
#       static-full
#       static-no-timing
#       static-no-objlink
#       static-random
#   - 注意:
#       static-no-objlink 对文件系统模块存在额外设计约束。当前 kccwf syscall
#       描述本身使用固定对象池（testfile#/testdir/hardlink# 等），即使关闭
#       ObjectLinker，也会给 no-object baseline 带来“偶然落到同一对象”的偏置。
#       因此脚本默认阻止直接启动 static-no-objlink，直到我们明确指定对象空间
#       策略（runtime-randobj / sysdesc-randobj / allow-fixed-kccwf）。
#   - 静态 normal threshold: 10000us
#   - widened threshold: 20000us
#   - 物理资源: 每模块 2 cores
#   - 支持多模块并行，且同一模块的不同 variant 可并行
#   - VM 配置: 2 VMs, each 2 vCPU, 4GB, procs=2
#
# 用法:
#   ./scripts/run_input_exploration_static.sh prepare [--sudo]
#   ./scripts/run_input_exploration_static.sh start [variant] <module...> [--sudo] [--noobj-policy <mode>]
#   ./scripts/run_input_exploration_static.sh stop [variant] [module...] [--sudo]
#   ./scripts/run_input_exploration_static.sh status [--sudo]
#   ./scripts/run_input_exploration_static.sh archive <module> [variant] [label]
#   ./scripts/run_input_exploration_static.sh list
#   ./scripts/run_input_exploration_static.sh help
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

RUN_CAP="$SCRIPT_DIR/run_capability_24h.sh"
EXP_DIR="$PROJECT_HOME/exp"
ACTION="${1:-help}"
[[ $# -gt 0 ]] && shift || true

CORPUS_SRC="${CORPUS_SRC:-/home/zzzccc/BASS/DDRD-Corpus}"
STATIC_MODULES=(xfs btrfs f2fs ptmx floppy dsp)
STATIC_VARIANTS=(static-full static-no-timing static-no-objlink static-random)

STATIC_THRESHOLD_US="${STATIC_THRESHOLD_US:-10000}"
STATIC_WIDENED_THRESHOLD_US="${STATIC_WIDENED_THRESHOLD_US:-20000}"
STATIC_SYSTEM_RESERVED_CORES="${STATIC_SYSTEM_RESERVED_CORES:-8}"
STATIC_CORES_PER_MODULE="${STATIC_CORES_PER_MODULE:-2}"
STATIC_FUZZ_VM_COUNT="${STATIC_FUZZ_VM_COUNT:-2}"
STATIC_VM_CPU="${STATIC_VM_CPU:-2}"
STATIC_VM_MEM="${STATIC_VM_MEM:-4096}"
STATIC_PROCS="${STATIC_PROCS:-2}"
STATIC_RESULTS_DIRNAME="${STATIC_RESULTS_DIRNAME:-input-exploration-static}"
STATIC_NAMESPACE="${STATIC_NAMESPACE:-paper-static-input}"
STATIC_HTTP_BASE="${STATIC_HTTP_BASE:-63000}"
# block-fixed-kccwf: refuse to run static-no-objlink until the bias is addressed
# runtime-randobj: planned preferred mode; runtime path randomization in fuzzer
# sysdesc-randobj: alternative mode; separate syzlang/syscall-description build
# allow-fixed-kccwf: debugging only, not for paper numbers
STATIC_NOOBJ_POLICY="${STATIC_NOOBJ_POLICY:-block-fixed-kccwf}"

RUNNER_PREFIX=()
POSITIONAL_ARGS=()
STATIC_NO_PIN=false
START_RESERVED_SLICES=()

join_by_space() {
    local IFS=' '
    echo "$*"
}

normalize_variant() {
    case "${1:-static-full}" in
        full|static-full) echo "static-full" ;;
        no-timing|static-no-timing) echo "static-no-timing" ;;
        no-objlink|static-no-objlink) echo "static-no-objlink" ;;
        random|static-random) echo "static-random" ;;
        *)
            die "未知变体: $1 (可选: $(join_by_space "${STATIC_VARIANTS[@]}"))"
            ;;
    esac
}

normalize_module() {
    case "${1:-}" in
        bt|bluetooth) echo "bt-stack" ;;
        usb) echo "usb-driver" ;;
        *) echo "$1" ;;
    esac
}

module_index() {
    local slug=$1
    local i
    for i in "${!STATIC_MODULES[@]}"; do
        if [[ "${STATIC_MODULES[$i]}" == "$slug" ]]; then
            echo "$i"
            return 0
        fi
    done
    die "未知模块: $slug"
}

variant_index() {
    local variant
    variant=$(normalize_variant "$1")
    local i
    for i in "${!STATIC_VARIANTS[@]}"; do
        if [[ "${STATIC_VARIANTS[$i]}" == "$variant" ]]; then
            echo "$i"
            return 0
        fi
    done
    die "未知变体: $variant"
}

static_http_port() {
    local slug=$1
    local variant=$2
    local mod_idx var_idx
    mod_idx=$(module_index "$slug")
    var_idx=$(variant_index "$variant")
    echo $((STATIC_HTTP_BASE + mod_idx * ${#STATIC_VARIANTS[@]} + var_idx))
}

corpus_git_rev() {
    if [[ -d "$CORPUS_SRC" ]] && git -C "$CORPUS_SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$CORPUS_SRC" rev-parse --short HEAD 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

static_workdir_root() {
    echo "$PROJECT_HOME/exp-static/$STATIC_NAMESPACE"
}

show_profile() {
    log_info "静态阈值 fuzz-side 对比"
    log_info "模块: $(join_by_space "${STATIC_MODULES[@]}")"
    log_info "变体: $(join_by_space "${STATIC_VARIANTS[@]}")"
    log_info "阈值: normal=${STATIC_THRESHOLD_US}us, widened=${STATIC_WIDENED_THRESHOLD_US}us"
    log_info "资源: system_reserved=${STATIC_SYSTEM_RESERVED_CORES}, cores_per_module=${STATIC_CORES_PER_MODULE}, fuzz_vms=${STATIC_FUZZ_VM_COUNT}, vm_cpu=${STATIC_VM_CPU}, vm_mem=${STATIC_VM_MEM}MB, procs=${STATIC_PROCS}"
    log_info "独立 workdir 根目录: $(static_workdir_root)"
    log_info "统一 corpus 源: $CORPUS_SRC @ $(corpus_git_rev)"
    log_info "No ObjLink 策略: $STATIC_NOOBJ_POLICY"
}

generate_static_variant_cfg() {
    local slug=$1
    local variant=$2
    local src="$EXP_DIR/$slug/fuzz.cfg"
    local dst="$EXP_DIR/$slug/fuzz-${variant}.cfg"
    local http_port
    http_port=$(static_http_port "$slug" "$variant")

    [[ -f "$src" ]] || die "缺少基础配置: $src，请先执行 prepare"

    python3 - "$src" "$dst" "$variant" "$slug" "$(static_workdir_root)" "$STATIC_THRESHOLD_US" "$STATIC_WIDENED_THRESHOLD_US" "$http_port" <<'PYEOF'
import json
import os
import sys

src, dst, variant, slug, workdir_root, threshold_us, widened_us, http_port = sys.argv[1:9]
threshold_us = int(threshold_us)
widened_us = int(widened_us)
http_port = int(http_port)

with open(src) as f:
    cfg = json.load(f)

exp = cfg.setdefault("experimental", {})
cfg["workdir"] = os.path.join(workdir_root, slug, variant, "workdir")
cfg["http"] = f"127.0.0.1:{http_port}"

# Freeze the counting rule so MRP counts stay comparable across variants.
exp["enable_dynamic_threshold"] = False
exp["normal_threshold_micros"] = threshold_us
exp["widened_threshold_micros"] = widened_us
exp["dynamic_threshold_initial_us"] = threshold_us
exp["dynamic_threshold_min_us"] = threshold_us
exp["dynamic_threshold_max_us"] = threshold_us

# Set all toggles explicitly so the saved config is self-describing.
exp["uaf_mode"] = True
exp["random_baseline_mode"] = False
exp["enable_timing_exploration"] = True
exp["enable_object_linking"] = True

if variant == "static-no-timing":
    exp["enable_timing_exploration"] = False
elif variant == "static-no-objlink":
    exp["enable_object_linking"] = False
elif variant == "static-random":
    exp["random_baseline_mode"] = True
    exp["enable_timing_exploration"] = False
    exp["enable_object_linking"] = False
elif variant != "static-full":
    raise SystemExit(f"unknown static variant: {variant}")

with open(dst, "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF

    log_ok "生成静态变体配置: $dst"
}

generate_static_runtime_cfg() {
    local slug=$1
    local variant=$2
    local src="$EXP_DIR/$slug/fuzz-${variant}.cfg"
    local dst="$EXP_DIR/$slug/exp-fuzz-${variant}.cfg"

    [[ -f "$src" ]] || die "缺少静态变体配置: $src，请先执行 prepare"

    python3 - "$src" "$dst" "$STATIC_FUZZ_VM_COUNT" "$STATIC_VM_CPU" "$STATIC_VM_MEM" "$STATIC_PROCS" <<'PYEOF'
import json
import sys

src, dst, vm_count, vm_cpu, vm_mem, procs = sys.argv[1:7]
with open(src) as f:
    cfg = json.load(f)
cfg["vm"]["count"] = int(vm_count)
cfg["vm"]["cpu"] = int(vm_cpu)
cfg["vm"]["mem"] = int(vm_mem)
cfg["procs"] = int(procs)
with open(dst, "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF
}

generate_static_variant_set() {
    local slug
    for slug in "${STATIC_MODULES[@]}"; do
        local variant
        for variant in "${STATIC_VARIANTS[@]}"; do
            generate_static_variant_cfg "$slug" "$variant"
        done
    done
}

sync_static_corpus() {
    local slug=$1
    local variant=$2
    local base_corpus="$EXP_DIR/$slug/workdir/corpus.db"
    local workdir
    workdir="$(static_workdir_root)/$slug/$variant/workdir"
    mkdir -p "$workdir"
    [[ -f "$base_corpus" ]] || die "缺少基础 corpus: $base_corpus，请先执行 prepare"
    cp "$base_corpus" "$workdir/corpus.db"
}

assert_variant_policy() {
    local variant
    variant=$(normalize_variant "$1")
    [[ "$variant" == "static-no-objlink" ]] || return 0

    case "$STATIC_NOOBJ_POLICY" in
        runtime-randobj|sysdesc-randobj|allow-fixed-kccwf)
            return 0
            ;;
        block-fixed-kccwf|planned-randobj|"")
            die "static-no-objlink 默认禁止直接启动：当前 kccwf 固定对象池会给 no-object baseline 引入额外同对象偏置。请先选定策略：STATIC_NOOBJ_POLICY=runtime-randobj（推荐，后续代码实现）或 STATIC_NOOBJ_POLICY=sysdesc-randobj（单独构建 profile）；仅调试时才用 STATIC_NOOBJ_POLICY=allow-fixed-kccwf。"
            ;;
        *)
            die "未知 STATIC_NOOBJ_POLICY: $STATIC_NOOBJ_POLICY (可选: runtime-randobj, sysdesc-randobj, allow-fixed-kccwf, block-fixed-kccwf)"
            ;;
    esac
}

runtime_cfg_path() {
    echo "$EXP_DIR/$1/exp-fuzz-$2.cfg"
}

variant_cfg_path() {
    echo "$EXP_DIR/$1/fuzz-$2.cfg"
}

variant_logs_dir() {
    echo "$EXP_DIR/$1/logs"
}

variant_pid_pattern() {
    local slug=$1
    local variant_regex=$2
    echo "syz-manager.*$EXP_DIR/$slug/exp-fuzz-${variant_regex}\\.cfg"
}

get_variant_pid() {
    local slug=$1
    local variant=$2
    pgrep -f "$(variant_pid_pattern "$slug" "$variant")" 2>/dev/null | head -1 || true
}

collect_running_static_pids() {
    pgrep -f "syz-manager.*$EXP_DIR/.*/exp-fuzz-static-.*\\.cfg" 2>/dev/null || true
}

next_core_slice() {
    if $STATIC_NO_PIN; then
        echo "unbound"
        return 0
    fi

    local total
    total=$(nproc)
    local -a used_slices=()
    local pid slice start end

    while read -r pid; do
        [[ -n "$pid" ]] || continue
        slice=$(awk '/^Cpus_allowed_list:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)
        [[ -n "$slice" ]] && used_slices+=("$slice")
    done < <(collect_running_static_pids)

    used_slices+=("${START_RESERVED_SLICES[@]}")

    for ((start=STATIC_SYSTEM_RESERVED_CORES; start + STATIC_CORES_PER_MODULE - 1 < total; start+=STATIC_CORES_PER_MODULE)); do
        end=$((start + STATIC_CORES_PER_MODULE - 1))
        if (( STATIC_CORES_PER_MODULE == 1 )); then
            slice="$start"
        else
            slice="$start-$end"
        fi
        if printf '%s\n' "${used_slices[@]}" | grep -qx "$slice"; then
            continue
        fi
        echo "$slice"
        return 0
    done

    die "静态实验 CPU 槽位不足: reserved=$STATIC_SYSTEM_RESERVED_CORES width=$STATIC_CORES_PER_MODULE total=$total"
}

pid_is_alive() {
    local pid=$1
    if kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]] && "${RUNNER_PREFIX[@]}" kill -0 "$pid" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

start_one_variant() {
    local slug=$1
    local variant=$2
    assert_variant_policy "$variant"
    local existing
    existing=$(get_variant_pid "$slug" "$variant")
    if [[ -n "$existing" ]]; then
        log_warn "[$slug/$variant] 已在运行 (PID=$existing)"
        return 0
    fi

    generate_static_variant_cfg "$slug" "$variant"
    generate_static_runtime_cfg "$slug" "$variant"
    sync_static_corpus "$slug" "$variant"

    local cfg
    cfg=$(runtime_cfg_path "$slug" "$variant")
    local log_dir
    log_dir=$(variant_logs_dir "$slug")
    mkdir -p "$log_dir"

    local ts log_file slice
    ts=$(date +%Y%m%d-%H%M%S)
    log_file="$log_dir/exp-fuzz-${variant}-${ts}.log"
    slice=$(next_core_slice)
    [[ "$slice" != "unbound" ]] && START_RESERVED_SLICES+=("$slice")

    local q_mgr q_cfg q_log q_slice cmd pid
    printf -v q_mgr '%q' "$SYZ_MANAGER"
    printf -v q_cfg '%q' "$cfg"
    printf -v q_log '%q' "$log_file"

    if [[ "$slice" == "unbound" ]]; then
        cmd="nohup $q_mgr -config $q_cfg > $q_log 2>&1 < /dev/null & echo \$!"
        log_info "[$slug/$variant] 不绑定 CPU，直接启动"
    else
        printf -v q_slice '%q' "$slice"
        cmd="nohup taskset -c $q_slice $q_mgr -config $q_cfg > $q_log 2>&1 < /dev/null & echo \$!"
        log_info "[$slug/$variant] 分配核心: $slice"
    fi

    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
        pid=$("${RUNNER_PREFIX[@]}" bash -lc "$cmd")
    else
        pid=$(bash -lc "$cmd")
    fi
    pid=$(xargs <<<"$pid")

    sleep 2
    if [[ -z "$pid" ]] || ! pid_is_alive "$pid"; then
        log_error "[$slug/$variant] 启动失败 → $log_file"
        return 1
    fi

    log_ok "[$slug/$variant] fuzz 已启动  PID=$pid  cores=$slice"
}

stop_pid_list() {
    local -a pids=("$@")
    [[ ${#pids[@]} -gt 0 ]] || return 0

    local kill_cmd=(kill)
    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
        kill_cmd=("${RUNNER_PREFIX[@]}" kill)
    fi

    "${kill_cmd[@]}" "${pids[@]}" 2>/dev/null || true
    local pid tries alive
    for ((tries=0; tries<15; tries++)); do
        alive=0
        for pid in "${pids[@]}"; do
            if pid_is_alive "$pid"; then
                alive=1
                break
            fi
        done
        (( alive == 0 )) && return 0
        sleep 1
    done

    kill_cmd=(kill -9)
    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
        kill_cmd=("${RUNNER_PREFIX[@]}" kill -9)
    fi
    "${kill_cmd[@]}" "${pids[@]}" 2>/dev/null || true
}

do_prepare() {
    show_profile
    log_info "调用 capability prepare，统一清理并导入 corpus"
    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
        "$RUN_CAP" prepare --corpus-src "$CORPUS_SRC" --sudo
    else
        "$RUN_CAP" prepare --corpus-src "$CORPUS_SRC"
    fi
    log_info "生成静态阈值 fuzz-side 变体配置"
    generate_static_variant_set
    log_ok "静态阈值对比实验准备完成"
}

do_start() {
    local variant="static-full"
    if [[ $# -gt 0 ]]; then
        case "$1" in
            full|static-full|no-timing|static-no-timing|no-objlink|static-no-objlink|random|static-random)
                variant=$(normalize_variant "$1")
                shift
                ;;
        esac
    fi

    [[ $# -gt 0 ]] || die "缺少模块名"
    local modules=()
    local slug
    for slug in "$@"; do
        modules+=("$(normalize_module "$slug")")
    done

    show_profile
    log_info "启动 fuzz 对比实验: modules=$(join_by_space "${modules[@]}") variant=$variant"
    for slug in "${modules[@]}"; do
        start_one_variant "$slug" "$variant"
    done
}

do_stop() {
    local variant=""
    if [[ $# -gt 0 ]]; then
        case "$1" in
            full|static-full|no-timing|static-no-timing|no-objlink|static-no-objlink|random|static-random)
                variant=$(normalize_variant "$1")
                shift
                ;;
        esac
    fi

    local modules=()
    local slug
    if [[ $# -eq 0 ]]; then
        modules=("${STATIC_MODULES[@]}")
    else
        for slug in "$@"; do
            modules+=("$(normalize_module "$slug")")
        done
    fi

    local variant_regex='static-.*'
    if [[ -n "$variant" ]]; then
        variant_regex="$variant"
        log_info "停止静态对比实验模块: $(join_by_space "${modules[@]}") variant=$variant"
    else
        log_info "停止静态对比实验模块: $(join_by_space "${modules[@]}")"
    fi

    local -a pids=()
    local pid
    for slug in "${modules[@]}"; do
        while read -r pid; do
            [[ -n "$pid" ]] || continue
            pids+=("$pid")
        done < <(pgrep -f "$(variant_pid_pattern "$slug" "$variant_regex")" 2>/dev/null || true)
    done

    if [[ ${#pids[@]} -eq 0 ]]; then
        log_warn "没有匹配的静态 fuzz 进程"
        return 0
    fi
    stop_pid_list "${pids[@]}"
    log_ok "已停止 ${#pids[@]} 个静态 fuzz 进程"
}

collect_status_line() {
    local slug=$1
    local variant=$2
    local pid core elapsed
    pid=$(get_variant_pid "$slug" "$variant")
    if [[ -z "$pid" ]]; then
        printf "%-8s %-18s %-10s %-8s %-12s %s\n" "$slug" "$variant" "stopped" "—" "—" "—"
        return
    fi

    core=$(awk '/^Cpus_allowed_list:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo "—")
    elapsed=$(ps -p "$pid" -o etime= 2>/dev/null | xargs || echo "—")
    printf "%-8s %-18s %-10s %-8s %-12s %s\n" "$slug" "$variant" "running" "$pid" "$core" "$elapsed"
}

do_status() {
    show_profile
    printf "%-8s %-18s %-10s %-8s %-12s %s\n" "MODULE" "VARIANT" "STATE" "PID" "CORESET" "ELAPSED"
    printf "%-8s %-18s %-10s %-8s %-12s %s\n" "------" "-------" "-----" "---" "-------" "-------"

    local slug
    for slug in "${STATIC_MODULES[@]}"; do
        local variant
        for variant in "${STATIC_VARIANTS[@]}"; do
            collect_status_line "$slug" "$variant"
        done
    done
}

do_list() {
    show_profile
}

archive_one() {
    local slug=$1
    local variant=$2
    local label=$3
    local mod_dir="$EXP_DIR/$slug"
    local out_dir="$mod_dir/results/$STATIC_RESULTS_DIRNAME/$variant/$label"
    mkdir -p "$out_dir"

    local fuzz_cfg="$mod_dir/fuzz-${variant}.cfg"
    local exp_fuzz_cfg="$mod_dir/exp-fuzz-${variant}.cfg"
    local workdir
    workdir="$(static_workdir_root)/$slug/$variant/workdir"
    local corpus_db="$workdir/corpus.db"
    local uaf_db="$workdir/uaf-corpus.db"

    [[ -f "$fuzz_cfg" ]] && cp "$fuzz_cfg" "$out_dir/" || true
    [[ -f "$exp_fuzz_cfg" ]] && cp "$exp_fuzz_cfg" "$out_dir/" || true
    [[ -f "$corpus_db" ]] && cp "$corpus_db" "$out_dir/" || true
    [[ -f "$uaf_db" ]] && cp "$uaf_db" "$out_dir/" || true

    local log_dir="$mod_dir/logs"
    if [[ -d "$log_dir" ]]; then
        cp "$log_dir"/exp-fuzz-"${variant}"-*.log "$out_dir/" 2>/dev/null || true
        cp "$log_dir"/exp-fuzz-static-*.log "$out_dir/" 2>/dev/null || true
    fi

    python3 - "$out_dir/manifest.json" "$slug" "$variant" "$label" "$STATIC_THRESHOLD_US" "$STATIC_WIDENED_THRESHOLD_US" "$STATIC_SYSTEM_RESERVED_CORES" "$STATIC_CORES_PER_MODULE" "$STATIC_FUZZ_VM_COUNT" "$STATIC_VM_CPU" "$STATIC_VM_MEM" "$STATIC_PROCS" "$CORPUS_SRC" "$(corpus_git_rev)" "$(static_workdir_root)" "$STATIC_NOOBJ_POLICY" <<'PYEOF'
import json
import sys
from datetime import datetime

(out_path, slug, variant, label, threshold_us, widened_us, total_cores,
 cores_per_module, vm_count, vm_cpu, vm_mem, procs, corpus_src,
 corpus_rev, workdir_root, noobj_policy) = sys.argv[1:17]

data = {
    "timestamp": datetime.now().isoformat(timespec="seconds"),
    "module": slug,
    "variant": variant,
    "label": label,
    "threshold_us": int(threshold_us),
    "widened_threshold_us": int(widened_us),
    "system_reserved_cores": int(total_cores),
    "cores_per_module": int(cores_per_module),
    "fuzz_vm_count": int(vm_count),
    "vm_cpu": int(vm_cpu),
    "vm_mem_mb": int(vm_mem),
    "procs": int(procs),
    "corpus_src": corpus_src,
    "corpus_rev": corpus_rev,
    "workdir_root": workdir_root,
    "noobj_policy": None,
}

if variant == "static-no-objlink":
    data["noobj_policy"] = noobj_policy

with open(out_path, "w") as f:
    json.dump(data, f, indent=4)
PYEOF

    log_ok "已归档结果: $out_dir"
}

do_archive() {
    local slug
    slug=$(normalize_module "${1:-}")
    [[ -n "$slug" ]] || die "缺少模块名"
    shift || true
    local variant
    variant=$(normalize_variant "${1:-static-full}")
    shift || true
    local label="${1:-$(date +%Y%m%d-%H%M%S)}"
    archive_one "$slug" "$variant" "$label"
}

do_help() {
    sed -n '3,28p' "$0" | sed 's/^# //' | sed 's/^#//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sudo)
            RUNNER_PREFIX=("sudo")
            shift
            ;;
        --no-pin)
            STATIC_NO_PIN=true
            shift
            ;;
        --corpus-src)
            CORPUS_SRC="$2"
            shift 2
            ;;
        --threshold-us)
            STATIC_THRESHOLD_US="$2"
            shift 2
            ;;
        --widened-threshold-us)
            STATIC_WIDENED_THRESHOLD_US="$2"
            shift 2
            ;;
        --noobj-policy)
            STATIC_NOOBJ_POLICY="$2"
            shift 2
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

set -- "${POSITIONAL_ARGS[@]}"

case "$ACTION" in
    prepare)
        do_prepare
        ;;
    start)
        do_start "$@"
        ;;
    stop)
        do_stop "$@"
        ;;
    status)
        do_status
        ;;
    archive)
        do_archive "$@"
        ;;
    list)
        do_list
        ;;
    help|-h|--help)
        do_help
        ;;
    *)
        die "未知命令: $ACTION (prepare|start|stop|status|archive|list|help)"
        ;;
esac
