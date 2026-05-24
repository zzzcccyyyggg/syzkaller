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
#   - 模块: xfs btrfs f2fs jfs ptmx floppy dsp bt-stack
#   - 变体:
#       static-clean-full
#       static-no-timing
#       static-no-objlink
#       static-random
#       static-fsobj-full
#       static-fsobj-no-objlink
#       static-fsobj-full-no-timing
#       static-fsobj-no-objlink-no-timing
#       static-fsobj-tuned-full
#       static-fsobj-tuned-no-objlink
#       static-fsobj-tuned-full-no-timing
#       static-fsobj-tuned-no-objlink-no-timing
#       static-fsobj-tuned-random-no-timing
#   - 注意:
#       新实验默认关闭 coverage triage / affinity table dead feedback。
#       static-fsobj-* 会隔离 kccwf partner object 名字，避免固定 corpus
#       对象名让 no-object baseline 继续撞到同一个文件对象。
#   - 静态 normal threshold: 10000us
#   - widened threshold: 20000us
#   - 物理资源: 每模块 4 cores
#   - 支持多模块并行，且同一模块的不同 variant 可并行
#   - VM 配置: 4 VMs, each 2 vCPU, 4GB, procs=2
#
# 用法:
#   ./scripts/run_input_exploration_static.sh prepare [--sudo]
#   ./scripts/run_input_exploration_static.sh prepare-effective <module...> [--sudo]
#   ./scripts/run_input_exploration_static.sh prepare-prepared <module...> [--sudo]
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
STATIC_MODULES=(xfs btrfs f2fs jfs ptmx floppy dsp bt-stack)
STATIC_VARIANTS=(static-clean-full static-no-timing static-no-objlink static-random static-full static-full-no-dead-feedback static-fsobj-full static-fsobj-no-objlink static-fsobj-full-no-timing static-fsobj-no-objlink-no-timing static-fsobj-tuned-full static-fsobj-tuned-no-objlink static-fsobj-tuned-full-no-timing static-fsobj-tuned-no-objlink-no-timing static-fsobj-tuned-random-no-timing)

STATIC_THRESHOLD_US="${STATIC_THRESHOLD_US:-10000}"
STATIC_WIDENED_THRESHOLD_US="${STATIC_WIDENED_THRESHOLD_US:-20000}"
STATIC_SYSTEM_RESERVED_CORES="${STATIC_SYSTEM_RESERVED_CORES:-8}"
STATIC_CORES_PER_MODULE="${STATIC_CORES_PER_MODULE:-4}"
STATIC_FUZZ_VM_COUNT="${STATIC_FUZZ_VM_COUNT:-4}"
STATIC_VM_CPU="${STATIC_VM_CPU:-2}"
STATIC_VM_MEM="${STATIC_VM_MEM:-4096}"
STATIC_PROCS="${STATIC_PROCS:-2}"
STATIC_RESULTS_DIRNAME="${STATIC_RESULTS_DIRNAME:-input-exploration-static}"
STATIC_NAMESPACE="${STATIC_NAMESPACE:-paper-static-input}"
STATIC_HTTP_BASE="${STATIC_HTTP_BASE:-63000}"
# block-fixed-kccwf: refuse to run static-no-objlink
# runtime-randobj: preferred mode; runtime path randomization in fuzzer
# sysdesc-randobj: alternative mode; separate syzlang/syscall-description build
# allow-fixed-kccwf: debugging only, not for paper numbers
STATIC_NOOBJ_POLICY="${STATIC_NOOBJ_POLICY:-runtime-randobj}"

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
        clean|clean-full|static-clean-full) echo "static-clean-full" ;;
        full|static-full) echo "static-full" ;;
        full-no-dead-feedback|no-dead-feedback|static-full-no-dead-feedback) echo "static-full-no-dead-feedback" ;;
        no-timing|static-no-timing) echo "static-no-timing" ;;
        no-objlink|static-no-objlink) echo "static-no-objlink" ;;
        random|static-random) echo "static-random" ;;
        fsobj|fsobj-full|static-fsobj-full) echo "static-fsobj-full" ;;
        fsobj-no-objlink|no-fsobj|static-fsobj-no-objlink) echo "static-fsobj-no-objlink" ;;
        fsobj-no-timing|fsobj-full-no-timing|static-fsobj-full-no-timing) echo "static-fsobj-full-no-timing" ;;
        fsobj-no-objlink-no-timing|no-fsobj-no-timing|static-fsobj-no-objlink-no-timing) echo "static-fsobj-no-objlink-no-timing" ;;
        fsobj-tuned-full|fsobj-tuned-timing|static-fsobj-tuned-full) echo "static-fsobj-tuned-full" ;;
        fsobj-tuned-no-objlink-timing|static-fsobj-tuned-no-objlink) echo "static-fsobj-tuned-no-objlink" ;;
        fsobj-tuned|fsobj-tuned-full-no-timing|static-fsobj-tuned-full-no-timing) echo "static-fsobj-tuned-full-no-timing" ;;
        fsobj-tuned-no-objlink|fsobj-tuned-no-objlink-no-timing|static-fsobj-tuned-no-objlink-no-timing) echo "static-fsobj-tuned-no-objlink-no-timing" ;;
        fsobj-tuned-random|fsobj-tuned-random-no-timing|static-fsobj-tuned-random-no-timing) echo "static-fsobj-tuned-random-no-timing" ;;
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

    python3 - "$src" "$dst" "$variant" "$slug" "$(static_workdir_root)" "$STATIC_THRESHOLD_US" "$STATIC_WIDENED_THRESHOLD_US" "$http_port" "$STATIC_NOOBJ_POLICY" <<'PYEOF'
import json
import os
import sys

src, dst, variant, slug, workdir_root, threshold_us, widened_us, http_port, noobj_policy = sys.argv[1:10]
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
exp["object_link_attempt_ratio"] = 1.0
exp["static_input_exploration"] = True
exp["static_input_seed"] = 1592594996
exp["static_input_skip_builtin_seeds"] = True
exp["no_object_kccwf_namespace"] = False
exp["isolate_kccwf_partner_objects"] = False
exp["enable_coverage_triage"] = False
exp["enable_affinity_table"] = False

if variant == "static-clean-full":
    exp["object_link_attempt_ratio"] = 0.1
elif variant == "static-full":
    # Historical compatibility variant. Prefer static-clean-full for new runs.
    exp["object_link_attempt_ratio"] = 0.1
    exp["enable_coverage_triage"] = True
    exp["enable_affinity_table"] = True
elif variant == "static-full-no-dead-feedback":
    # Backward-compatible alias for the clean-full mechanism audit.
    exp["object_link_attempt_ratio"] = 0.1
elif variant == "static-no-timing":
    exp["enable_timing_exploration"] = False
    exp["object_link_attempt_ratio"] = 0.1
elif variant == "static-no-objlink":
    exp["enable_object_linking"] = False
    if noobj_policy == "runtime-randobj":
        exp["no_object_kccwf_namespace"] = True
elif variant == "static-random":
    exp["random_baseline_mode"] = True
    exp["enable_timing_exploration"] = False
    exp["enable_object_linking"] = False
    exp["no_object_kccwf_namespace"] = True
elif variant == "static-fsobj-full":
    exp["object_link_attempt_ratio"] = 0.1
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-no-objlink":
    exp["enable_object_linking"] = False
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-full-no-timing":
    exp["enable_timing_exploration"] = False
    exp["object_link_attempt_ratio"] = 0.1
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-no-objlink-no-timing":
    exp["enable_timing_exploration"] = False
    exp["enable_object_linking"] = False
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-tuned-full":
    exp["object_link_attempt_ratio"] = 0.1
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-tuned-no-objlink":
    exp["enable_object_linking"] = False
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-tuned-full-no-timing":
    exp["enable_timing_exploration"] = False
    exp["object_link_attempt_ratio"] = 0.1
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-tuned-no-objlink-no-timing":
    exp["enable_timing_exploration"] = False
    exp["enable_object_linking"] = False
    exp["isolate_kccwf_partner_objects"] = True
elif variant == "static-fsobj-tuned-random-no-timing":
    exp["random_baseline_mode"] = True
    exp["enable_timing_exploration"] = False
    exp["enable_object_linking"] = False
    exp["isolate_kccwf_partner_objects"] = True
    # Keep the same repaired corpus but perturb the frozen-pool sampling stream.
    # This makes the variant a random/no-object replicate rather than a duplicate
    # of static-fsobj-tuned-no-objlink-no-timing.
    exp["static_input_seed"] = 1592594997
else:
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
	local tuned_corpus="$EXP_DIR/$slug/workdir/tuned-prepared-corpus.db"
	local prepared_corpus="$EXP_DIR/$slug/workdir/prepared-corpus.db"
	local effective_corpus="$EXP_DIR/$slug/workdir/effective-corpus.db"
	local base_corpus="$EXP_DIR/$slug/workdir/corpus.db"
	local workdir
	workdir="$(static_workdir_root)/$slug/$variant/workdir"
	if [[ "$variant" == static-fsobj-tuned-* ]]; then
		[[ -f "$tuned_corpus" ]] || die "[$slug/$variant] 缺少 tuned corpus: $tuned_corpus，请先生成"
		base_corpus="$tuned_corpus"
		log_info "[$slug/$variant] 使用 tuned prepared corpus: $tuned_corpus"
	elif [[ -f "$prepared_corpus" ]]; then
		base_corpus="$prepared_corpus"
		log_info "[$slug/$variant] 使用共享 prepared corpus: $prepared_corpus"
	elif [[ -f "$effective_corpus" ]]; then
		base_corpus="$effective_corpus"
		log_info "[$slug/$variant] 使用共享有效 corpus: $effective_corpus"
	else
		log_warn "[$slug/$variant] 未找到共享有效 corpus，回退到基础 corpus: $base_corpus"
    fi
    [[ -f "$base_corpus" ]] || die "缺少基础 corpus: $base_corpus，请先执行 prepare"
    if [[ -d "$workdir" ]]; then
        find "$workdir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    else
        mkdir -p "$workdir"
    fi
    cp "$base_corpus" "$workdir/corpus.db"
    go run "$PROJECT_HOME/tools/syz-kccwf-corpus-fix" -os=linux -arch=amd64 -db="$workdir/corpus.db"
}

assert_variant_policy() {
    local variant
    variant=$(normalize_variant "$1")
    case "$variant" in
        static-no-objlink|static-fsobj-no-objlink|static-fsobj-no-objlink-no-timing|static-fsobj-tuned-no-objlink|static-fsobj-tuned-no-objlink-no-timing)
            ;;
        *)
            return 0
            ;;
    esac

    case "$STATIC_NOOBJ_POLICY" in
        runtime-randobj|sysdesc-randobj|allow-fixed-kccwf)
            return 0
            ;;
        block-fixed-kccwf|planned-randobj|"")
            die "static-no-objlink 当前被策略禁止。请设置 STATIC_NOOBJ_POLICY=runtime-randobj（推荐）或 STATIC_NOOBJ_POLICY=sysdesc-randobj；仅调试时才用 STATIC_NOOBJ_POLICY=allow-fixed-kccwf。"
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

    local q_mgr q_cfg q_log q_slice cmd pid pid_output
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
        pid_output=$("${RUNNER_PREFIX[@]}" setsid -f bash -lc "$cmd")
    else
        pid_output=$(setsid -f bash -lc "$cmd")
    fi
    pid=$(xargs <<<"$pid_output")
    if [[ -z "$pid" ]]; then
        sleep 1
        pid=$(get_variant_pid "$slug" "$variant")
    fi

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

prepare_effective_one() {
    local slug=$1
    local src="$EXP_DIR/$slug/fuzz.cfg"
    local cfg="$EXP_DIR/$slug/exp-fuzz-static-prefilter.cfg"
    local base_workdir="$EXP_DIR/$slug/workdir"
    local workdir="$EXP_DIR/$slug/static-prefilter-workdir"
    local log_dir="$EXP_DIR/$slug/logs"
    local log_file="$log_dir/static-corpus-prefilter-$(date +%Y%m%d-%H%M%S).log"
    [[ -f "$src" ]] || die "缺少基础配置: $src，请先执行 prepare"
    [[ -f "$base_workdir/corpus.db" ]] || die "缺少基础 corpus: $base_workdir/corpus.db，请先执行 prepare"
    mkdir -p "$log_dir"
    rm -rf "$workdir"
    mkdir -p "$workdir"
    cp "$base_workdir/corpus.db" "$workdir/corpus.db"
    go run "$PROJECT_HOME/tools/syz-kccwf-corpus-fix" -os=linux -arch=amd64 -db="$workdir/corpus.db"

    python3 - "$src" "$cfg" "$workdir" <<'PYEOF'
import json
import sys

src, dst, workdir = sys.argv[1:4]
with open(src) as f:
    cfg = json.load(f)
cfg["workdir"] = workdir
exp = cfg.setdefault("experimental", {})
exp["uaf_mode"] = False
exp["static_input_exploration"] = False
exp["static_input_skip_builtin_seeds"] = True
exp["enable_timing_exploration"] = False
exp["enable_object_linking"] = False
exp["enable_coverage_triage"] = False
exp["enable_affinity_table"] = False
with open(dst, "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF

    log_info "[$slug] 生成共享有效 corpus: $workdir/effective-corpus.db"
    local cmd=("$SYZ_MANAGER" -mode=static-corpus-prefilter -config "$cfg")
    if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
        "${RUNNER_PREFIX[@]}" "${cmd[@]}" > "$log_file" 2>&1
    else
        "${cmd[@]}" > "$log_file" 2>&1
    fi
    [[ -f "$workdir/effective-corpus.db" ]] || die "[$slug] 未生成 effective-corpus.db，日志: $log_file"
    cp "$workdir/effective-corpus.db" "$base_workdir/effective-corpus.db"
    log_ok "[$slug] 有效 corpus 已生成 → $base_workdir/effective-corpus.db"
}

do_prepare_effective() {
	[[ $# -gt 0 ]] || die "缺少模块名"
	show_profile
	local slug
	for slug in "$@"; do
		prepare_effective_one "$(normalize_module "$slug")"
	done
}

prepare_prepared_one() {
	local slug=$1
	local src="$EXP_DIR/$slug/fuzz.cfg"
	local cfg="$EXP_DIR/$slug/exp-fuzz-static-prepare.cfg"
	local base_workdir="$EXP_DIR/$slug/workdir"
	local workdir="$EXP_DIR/$slug/static-prepare-workdir"
	local log_dir="$EXP_DIR/$slug/logs"
	local log_file="$log_dir/static-corpus-prepare-$(date +%Y%m%d-%H%M%S).log"
	[[ -f "$src" ]] || die "缺少基础配置: $src，请先执行 prepare"
	[[ -f "$base_workdir/corpus.db" ]] || die "缺少基础 corpus: $base_workdir/corpus.db，请先执行 prepare"
	mkdir -p "$log_dir"
	rm -rf "$workdir"
	mkdir -p "$workdir"
	cp "$base_workdir/corpus.db" "$workdir/corpus.db"
	go run "$PROJECT_HOME/tools/syz-kccwf-corpus-fix" -os=linux -arch=amd64 -db="$workdir/corpus.db"

	python3 - "$src" "$cfg" "$workdir" <<'PYEOF'
import json
import sys

src, dst, workdir = sys.argv[1:4]
with open(src) as f:
    cfg = json.load(f)
cfg["workdir"] = workdir
exp = cfg.setdefault("experimental", {})
exp["uaf_mode"] = True
exp["static_input_exploration"] = False
exp["static_input_skip_builtin_seeds"] = True
exp["enable_timing_exploration"] = False
exp["enable_object_linking"] = False
exp["enable_coverage_triage"] = False
exp["enable_affinity_table"] = False
with open(dst, "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF

	log_info "[$slug] 生成共享 prepared corpus: $workdir/prepared-corpus.db"
	local cmd=("$SYZ_MANAGER" -mode=static-corpus-prepare -config "$cfg")
	if [[ ${#RUNNER_PREFIX[@]} -gt 0 ]]; then
		"${RUNNER_PREFIX[@]}" "${cmd[@]}" > "$log_file" 2>&1
	else
		"${cmd[@]}" > "$log_file" 2>&1
	fi
	[[ -f "$workdir/prepared-corpus.db" ]] || die "[$slug] 未生成 prepared-corpus.db，日志: $log_file"
	cp "$workdir/prepared-corpus.db" "$base_workdir/prepared-corpus.db"
	log_ok "[$slug] prepared corpus 已生成 → $base_workdir/prepared-corpus.db"
}

do_prepare_prepared() {
	[[ $# -gt 0 ]] || die "缺少模块名"
	show_profile
	local slug
	for slug in "$@"; do
		prepare_prepared_one "$(normalize_module "$slug")"
	done
}

do_start() {
    local variant="static-full"
    if [[ $# -gt 0 ]]; then
        case "$1" in
            clean|clean-full|static-clean-full|full|static-full|full-no-dead-feedback|no-dead-feedback|static-full-no-dead-feedback|no-timing|static-no-timing|no-objlink|static-no-objlink|random|static-random|fsobj|fsobj-full|static-fsobj-full|fsobj-no-objlink|no-fsobj|static-fsobj-no-objlink|fsobj-no-timing|fsobj-full-no-timing|static-fsobj-full-no-timing|fsobj-no-objlink-no-timing|no-fsobj-no-timing|static-fsobj-no-objlink-no-timing|fsobj-tuned-full|fsobj-tuned-timing|static-fsobj-tuned-full|fsobj-tuned-no-objlink-timing|static-fsobj-tuned-no-objlink|fsobj-tuned|fsobj-tuned-full-no-timing|static-fsobj-tuned-full-no-timing|fsobj-tuned-no-objlink|fsobj-tuned-no-objlink-no-timing|static-fsobj-tuned-no-objlink-no-timing|fsobj-tuned-random|fsobj-tuned-random-no-timing|static-fsobj-tuned-random-no-timing)
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
            clean|clean-full|static-clean-full|full|static-full|full-no-dead-feedback|no-dead-feedback|static-full-no-dead-feedback|no-timing|static-no-timing|no-objlink|static-no-objlink|random|static-random|fsobj|fsobj-full|static-fsobj-full|fsobj-no-objlink|no-fsobj|static-fsobj-no-objlink|fsobj-no-timing|fsobj-full-no-timing|static-fsobj-full-no-timing|fsobj-no-objlink-no-timing|no-fsobj-no-timing|static-fsobj-no-objlink-no-timing|fsobj-tuned-full|fsobj-tuned-timing|static-fsobj-tuned-full|fsobj-tuned-no-objlink-timing|static-fsobj-tuned-no-objlink|fsobj-tuned|fsobj-tuned-full-no-timing|static-fsobj-tuned-full-no-timing|fsobj-tuned-no-objlink|fsobj-tuned-no-objlink-no-timing|static-fsobj-tuned-no-objlink-no-timing|fsobj-tuned-random|fsobj-tuned-random-no-timing|static-fsobj-tuned-random-no-timing)
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

if variant in ("static-no-objlink", "static-fsobj-no-objlink", "static-fsobj-no-objlink-no-timing", "static-fsobj-tuned-no-objlink", "static-fsobj-tuned-no-objlink-no-timing"):
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
	prepare-effective)
		do_prepare_effective "$@"
		;;
	prepare-prepared)
		do_prepare_prepared "$@"
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
        die "未知命令: $ACTION (prepare|prepare-effective|prepare-prepared|start|stop|status|archive|list|help)"
        ;;
esac
