#!/usr/bin/env bash
# ============================================================================
# run_experiment.sh — 统一实验管理 (fuzz / validate 分步运行, CPU 核心隔离)
#
# 为每个模块分配指定数量的 CPU 核心 (默认 2 核):
#   • fuzz:     全部核心, 2 VMs, procs=2
#   • validate: 全部核心, 2 VMs, procs=2 (streaming 一次性处理)
# fuzz 和 validate 分步运行, 不会同时占用同一槽位
#
# 典型流程:
#   1. sudo ./scripts/run_experiment.sh start btrfs      启动 fuzz
#   2. (等 fuzz 跑够, 产生 corpus)
#   3. sudo ./scripts/run_experiment.sh validate btrfs   启动 validate
#   4. sudo ./scripts/run_experiment.sh stop btrfs       停止全部
#
# 用法:
#   sudo ./scripts/run_experiment.sh start    <mod> [...]  启动 fuzz
#   sudo ./scripts/run_experiment.sh validate <mod> [...]  启动 validate
#   sudo ./scripts/run_experiment.sh stop     [mod ...]    停止 fuzz+validate
#   sudo ./scripts/run_experiment.sh status                查看运行状态
#   sudo ./scripts/run_experiment.sh clean    <mod> [--all] 清除 uaf corpus
#   sudo ./scripts/run_experiment.sh clean-log <mod> [--all] 清除日志
#   sudo ./scripts/run_experiment.sh log      <mod> [fuzz|validate] 查看日志
#   sudo ./scripts/run_experiment.sh list                  列出可用模块
#
# 环境变量 (可选覆盖):
#   CORES_PER_MODULE=2        每模块 CPU 核心数
#   SYSTEM_RESERVED_CORES=8   预留给系统的核心数 (从 CPU0 开始)
#   EXP_VM_COUNT=2            每端 VM 数量
#   EXP_VM_CPU=2              每 VM vCPU
#   EXP_VM_MEM=4096           每 VM 内存 (MB)
#   EXP_PROCS=2               syz-manager procs
#
# 自动检测/创建 cset 布局, 使用未被 /system 占用的核心
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

# ---------------------------------------------------------------------------
# 实验参数
# ---------------------------------------------------------------------------
CORES_PER_MODULE=${CORES_PER_MODULE:-2}
SYSTEM_RESERVED_CORES=${SYSTEM_RESERVED_CORES:-8}
EXP_VM_COUNT=${EXP_VM_COUNT:-2}
EXP_VM_CPU=${EXP_VM_CPU:-2}
EXP_VM_MEM=${EXP_VM_MEM:-4096}
EXP_PROCS=${EXP_PROCS:-2}

STATE_DIR="$PROJECT_HOME/.experiment"
CPUSETS_OWNED_MARKER="$STATE_DIR/.cpuset_owned"

CPUS_AVAILABLE=()
AVAIL_CORES=0
AVAIL_DESC=""
USE_CSET=false

join_by_comma() {
    local IFS=,
    echo "$*"
}

# ---------------------------------------------------------------------------
# 自动检测可用核心范围
# 如果系统有 cset /system 分区, 从 /cpusets 读取可用核心
# ---------------------------------------------------------------------------
detect_available_cores() {
    local quiet=${1:-false}
    local cpusets_root="/cpusets"
    CPUS_AVAILABLE=()
    if [[ -f "$cpusets_root/system/cpus" ]]; then
        # 读取 /system 占用的核心, 计算剩余
        local system_cpus root_cpus
        root_cpus=$(cat "$cpusets_root/cpus" 2>/dev/null || echo "")
        system_cpus=$(cat "$cpusets_root/system/cpus" 2>/dev/null || echo "")
        if [[ -n "$system_cpus" ]] && [[ -n "$root_cpus" ]]; then
            # 展开 CPU 列表为数组, 求差集
            local -a all_cores=() sys_cores=() avail=()
            _expand_cpulist() {
                local list=$1; shift
                local -n _arr=$1
                local part
                for part in ${list//,/ }; do
                    if [[ "$part" == *-* ]]; then
                        local lo=${part%-*} hi=${part#*-}
                        local c
                        for ((c=lo; c<=hi; c++)); do _arr+=("$c"); done
                    else
                        _arr+=("$part")
                    fi
                done
            }
            _expand_cpulist "$root_cpus" all_cores
            _expand_cpulist "$system_cpus" sys_cores
            local c
            for c in "${all_cores[@]}"; do
                local in_sys=false s
                for s in "${sys_cores[@]}"; do
                    [[ "$c" == "$s" ]] && { in_sys=true; break; }
                done
                $in_sys || avail+=("$c")
            done
            if (( ${#avail[@]} > 0 )); then
                CPUS_AVAILABLE=("${avail[@]}")
                AVAIL_CORES=${#CPUS_AVAILABLE[@]}
                AVAIL_DESC=$(join_by_comma "${CPUS_AVAILABLE[@]}")
                USE_CSET=true
                $quiet || log_info "检测到 cset 分区: /system=$system_cpus, 可用核心=$AVAIL_DESC (${AVAIL_CORES}核)"
                return 0
            fi
        fi
    fi
    # 回退: 使用全部核心
    local total c
    total=$(nproc)
    for ((c=0; c<total; c++)); do
        CPUS_AVAILABLE+=("$c")
    done
    AVAIL_CORES=${#CPUS_AVAILABLE[@]}
    AVAIL_DESC=$(join_by_comma "${CPUS_AVAILABLE[@]}")
    USE_CSET=false
    $quiet || log_warn "未检测到可用 cset 分区，回退 taskset (核心=$AVAIL_DESC)"
}

ensure_cpuset_layout() {
    if ! command -v cset &>/dev/null; then
        log_warn "未安装 cset，回退 taskset（无法提供硬隔离）"
        return 0
    fi

    [[ -f /cpusets/system/cpus ]] && return 0

    local total reserved
    total=$(nproc)
    reserved=$SYSTEM_RESERVED_CORES
    if (( reserved < 1 )); then
        reserved=1
    fi

    if (( total <= reserved )); then
        log_warn "CPU 核心数=$total <= 预留系统核心数=$reserved，无法创建 cset shield，回退 taskset"
        return 0
    fi

    local user_start user_end system_desc user_desc
    user_start=$reserved
    user_end=$((total - 1))
    if (( reserved == 1 )); then
        system_desc="0"
    else
        system_desc="0-$((reserved - 1))"
    fi
    user_desc="$user_start-$user_end"

    log_info "未检测到 cpuset 布局，创建 cset shield: system=$system_desc, user=$user_desc"
    if cset shield --cpu="$user_desc" --kthread=on &>/dev/null; then
        mkdir -p "$STATE_DIR"
        echo "owned" > "$CPUSETS_OWNED_MARKER"
        log_ok "cset shield 创建完成"
    else
        log_warn "创建 cset shield 失败，回退 taskset"
    fi
}

maybe_teardown_cpuset_layout() {
    [[ -f "$CPUSETS_OWNED_MARKER" ]] || return 0
    command -v cset &>/dev/null || return 0

    purge_stale_states
    if [[ -d "$STATE_DIR" ]] && ls "$STATE_DIR"/*.state >/dev/null 2>&1; then
        return 0
    fi

    if pgrep -f "syz-manager.*$EXP_DIR/.*/exp-fuzz\\.cfg|syz-manager.*$EXP_DIR/.*/exp-validate\\.cfg" >/dev/null 2>&1; then
        log_warn "仍有实验进程存活，跳过 cset shield --reset"
        return 0
    fi

    if cset set -l 2>/dev/null | grep -q 'ddrd-'; then
        log_warn "仍存在 ddrd-* cpuset，跳过自动 reset"
        return 0
    fi

    log_info "无运行实验，恢复 cset shield"
    cset shield --reset &>/dev/null || true
    rm -f "$CPUSETS_OWNED_MARKER"
}

detect_available_cores
MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))

# ---------------------------------------------------------------------------
# 命令行解析
# ---------------------------------------------------------------------------
ACTION="${1:-help}"; shift || true
ALL_MODE=false
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all|-a)   ALL_MODE=true; shift ;;
        -*) die "未知选项: $1" ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

# --all: 找出同时有 fuzz.cfg + validate.cfg 的模块
if $ALL_MODE; then
    mapfile -t TARGETS < <(
        for d in "$EXP_DIR"/*/; do
            local_slug=$(basename "$d")
            [[ -f "$d/fuzz.cfg" ]] && [[ -f "$d/validate.cfg" ]] && echo "$local_slug"
        done
    )
fi

# ---------------------------------------------------------------------------
# 生成实验配置 (覆盖 VM 参数, 确保 validate 监控 corpus)
# ---------------------------------------------------------------------------
gen_exp_config() {
    local slug=$1 mode=$2
    local src="$EXP_DIR/$slug/${mode}.cfg"
    local dst="$EXP_DIR/$slug/exp-${mode}.cfg"

    [[ -f "$src" ]] || die "配置不存在: $src (请先运行: python3 scripts/generate_config.py $slug)"

    python3 - "$src" "$dst" "$EXP_VM_COUNT" "$EXP_VM_CPU" "$EXP_VM_MEM" "$EXP_PROCS" "$mode" <<'PYEOF'
import json, sys, os
src, dst, vm_count, vm_cpu, vm_mem, procs, mode = sys.argv[1:8]
with open(src) as f:
    cfg = json.load(f)
cfg["vm"]["count"] = int(vm_count)
cfg["vm"]["cpu"]   = int(vm_cpu)
cfg["vm"]["mem"]   = int(vm_mem)
cfg["procs"]       = int(procs)
# validate 模式: 使用独立 workdir 避免 VM 镜像写锁冲突
if mode == "validate":
    cfg["workdir"] = os.path.join(cfg["workdir"], "validate-run")
    if "experimental" in cfg:
        exp = cfg["experimental"]
        uv = exp.get("uaf_validate", {})
        uv["continuous_mode"] = False
        uv["streaming_load"] = True
        exp["uaf_validate"] = uv
with open(dst, "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF
}

# ---------------------------------------------------------------------------
# CPU 核心分配
# ---------------------------------------------------------------------------
calc_cores() {
    local idx=$1
    local start=$((idx * CORES_PER_MODULE))
    local end=$((start + CORES_PER_MODULE))
    (( end <= ${#CPUS_AVAILABLE[@]} )) || die "核心分配越界: idx=$idx cores_per_module=$CORES_PER_MODULE avail=${#CPUS_AVAILABLE[@]}"

    local slice=("${CPUS_AVAILABLE[@]:start:CORES_PER_MODULE}")
    local IFS=,
    ALL_CORES="${slice[*]}"
}

# ---------------------------------------------------------------------------
# 进程 / 状态管理
# ---------------------------------------------------------------------------
get_exp_fuzz_pid() {
    pgrep -f "syz-manager.*$EXP_DIR/$1/exp-fuzz\\.cfg" 2>/dev/null | head -1 || true
}

get_exp_validate_pid() {
    pgrep -f "syz-manager.*$EXP_DIR/$1/exp-validate\\.cfg" 2>/dev/null | head -1 || true
}

get_any_regular_pid() {
    pgrep -f "syz-manager.*$EXP_DIR/$1/fuzz\\.cfg" 2>/dev/null | head -1 || \
    pgrep -f "syz-manager.*$EXP_DIR/$1/validate\\.cfg" 2>/dev/null | head -1 || true
}

save_state() {
    mkdir -p "$STATE_DIR"
    echo "$2 $3 $4" > "$STATE_DIR/$1.state"
}

remove_state() { rm -f "$STATE_DIR/$1.state"; }

load_state() {
    STATE_IDX="" ; STATE_FUZZ_PID="" ; STATE_VAL_PID=""
    [[ -f "$STATE_DIR/$1.state" ]] && \
        read -r STATE_IDX STATE_FUZZ_PID STATE_VAL_PID < "$STATE_DIR/$1.state"
    return 0
}

# 清理过期 state (进程已死但 state 文件残留)
purge_stale_states() {
    [[ -d "$STATE_DIR" ]] || return 0
    for f in "$STATE_DIR"/*.state; do
        [[ -f "$f" ]] || continue
        local s
        s=$(basename "$f" .state)
        local fp vp
        fp=$(get_exp_fuzz_pid "$s")
        vp=$(get_exp_validate_pid "$s")
        [[ -z "$fp" ]] && [[ -z "$vp" ]] && rm -f "$f"
    done
}

# 获取下一个可用的模块索引 (核心槽位)
next_module_index() {
    purge_stale_states
    local used=()
    if [[ -d "$STATE_DIR" ]]; then
        for f in "$STATE_DIR"/*.state; do
            [[ -f "$f" ]] || continue
            used+=($(awk '{print $1}' "$f"))
        done
    fi
    local i
    for ((i = 0; i < MAX_MODULES; i++)); do
        local found=false
        local u
        for u in "${used[@]+"${used[@]}"}"; do
            [[ "$u" == "$i" ]] && { found=true; break; }
        done
        $found || { echo "$i"; return 0; }
    done
    return 1
}

# CPU 绑定 (优先 cset, 回退 taskset)
pin_to_cores() {
    local pid=$1 cores=$2 label=$3

    if $USE_CSET && command -v cset &>/dev/null; then
        # 先清理同名旧 cpuset
        cset set -d "$label" &>/dev/null || true
        # 创建 cpuset 并移动进程
        if cset set -c "$cores" -s "$label" &>/dev/null; then
            if cset proc -m -p "$pid" -t "$label" &>/dev/null; then
                return 0
            fi
        fi
        # cset 创建失败: 移进程到 root cpuset 再用 taskset
        echo "$pid" > /cpusets/tasks 2>/dev/null || true
    fi

    # 回退: taskset
    taskset -p -c "$cores" "$pid" >/dev/null 2>&1 || true
}

cleanup_cpuset() {
    command -v cset &>/dev/null || return 0
    local name="$1"
    cset set -d -s "$name" &>/dev/null || cset set -d -s "/$name" &>/dev/null || true
}

cleanup_all_ddrd_cpusets() {
    command -v cset &>/dev/null || return 0
    local n
    while read -r n; do
        [[ -n "$n" ]] || continue
        cleanup_cpuset "$n"
    done < <(cset set -l 2>/dev/null | awk '$1 ~ /^ddrd-/ {print $1}')
}

# ---------------------------------------------------------------------------
# start — 只启动 fuzz
# ---------------------------------------------------------------------------
do_start() {
    local slug=$1

    # 冲突检测
    local fp rp
    fp=$(get_exp_fuzz_pid "$slug")
    if [[ -n "$fp" ]]; then
        log_warn "[$slug] fuzz 已在运行 (PID=$fp)"
        return 0
    fi
    rp=$(get_any_regular_pid "$slug")
    if [[ -n "$rp" ]]; then
        die "[$slug] 常规 fuzz/validate 正在运行 (PID=$rp), 请先停止"
    fi

    # 分配核心
    local idx
    idx=$(next_module_index) || die "CPU 槽位不足 (最大 $MAX_MODULES)"
    calc_cores "$idx"
    log_info "[$slug] 分配核心: $ALL_CORES"

    # 生成实验配置
    gen_exp_config "$slug" "fuzz"

    local fuzz_cfg="$EXP_DIR/$slug/exp-fuzz.cfg"
    local log_dir="$EXP_DIR/$slug/logs"
    mkdir -p "$log_dir"
    local ts
    ts=$(date +%Y%m%d-%H%M%S)

    # --- 启动 fuzz ---
    local fuzz_log="$log_dir/exp-fuzz-${ts}.log"
    nohup "$SYZ_MANAGER" -config "$fuzz_cfg" > "$fuzz_log" 2>&1 &
    local fuzz_pid=$!
    pin_to_cores "$fuzz_pid" "$ALL_CORES" "ddrd-${slug}-fuzz"

    sleep 2

    if ! kill -0 "$fuzz_pid" 2>/dev/null; then
        log_error "[$slug] fuzz 启动失败 → $fuzz_log"
        return 1
    fi

    save_state "$slug" "$idx" "$fuzz_pid" ""
    log_ok "[$slug] fuzz 已启动  PID=$fuzz_pid  cores=$ALL_CORES"
    log_info "[$slug] fuzz 跑够后运行: sudo $0 validate $slug"
    return 0
}

# ---------------------------------------------------------------------------
# validate — 单独启动 validate (fuzz 可以在跑, 也可以已停止)
# ---------------------------------------------------------------------------
do_validate() {
    local slug=$1

    # 检查 validate 是否已在运行
    local vp
    vp=$(get_exp_validate_pid "$slug")
    if [[ -n "$vp" ]]; then
        log_warn "[$slug] validate 已在运行 (PID=$vp)"
        return 0
    fi

    # 检查 corpus 文件是否存在
    local main_workdir="$EXP_DIR/$slug/workdir"
    if [[ ! -f "$main_workdir/uaf-corpus.db" ]]; then
        die "[$slug] corpus 文件不存在: $main_workdir/uaf-corpus.db — 请先运行 fuzz 产生 corpus"
    fi

    # 查找核心分配: 优先复用已有 state (fuzz 在跑时), 否则分配新槽位
    local idx
    load_state "$slug"
    if [[ -n "${STATE_IDX:-}" ]]; then
        idx=$STATE_IDX
    else
        idx=$(next_module_index) || die "CPU 槽位不足 (最大 $MAX_MODULES)"
    fi
    calc_cores "$idx"
    log_info "[$slug] validate 使用核心: $ALL_CORES"

    # 生成实验配置
    gen_exp_config "$slug" "validate"

    # 准备 validate 独立 workdir (避免 VM 镜像写锁冲突)
    local val_workdir="$main_workdir/validate-run"
    mkdir -p "$val_workdir"
    if [[ ! -e "$val_workdir/uaf-corpus.db" ]]; then
        ln -sf "$main_workdir/uaf-corpus.db" "$val_workdir/uaf-corpus.db"
    fi

    local val_cfg="$EXP_DIR/$slug/exp-validate.cfg"
    local log_dir="$EXP_DIR/$slug/logs"
    mkdir -p "$log_dir"
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local val_log="$log_dir/exp-validate-${ts}.log"

    nohup "$SYZ_MANAGER" -mode=uaf-validate -config "$val_cfg" > "$val_log" 2>&1 &
    local val_pid=$!
    pin_to_cores "$val_pid" "$ALL_CORES" "ddrd-${slug}-validate"

    sleep 2

    if ! kill -0 "$val_pid" 2>/dev/null; then
        log_error "[$slug] validate 启动失败 → $val_log"
        return 1
    fi

    # 更新 state (保留 fuzz PID 如果有)
    local fp
    fp=$(get_exp_fuzz_pid "$slug")
    save_state "$slug" "$idx" "${fp:-0}" "$val_pid"
    log_ok "[$slug] validate 已启动  PID=$val_pid  cores=$ALL_CORES"
    return 0
}

# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------
do_stop() {
    local slug=$1
    local fp vp
    fp=$(get_exp_fuzz_pid "$slug")
    vp=$(get_exp_validate_pid "$slug")

    if [[ -z "$fp" ]] && [[ -z "$vp" ]]; then
        log_warn "[$slug] 未在运行"
        remove_state "$slug"
        cleanup_cpuset "ddrd-${slug}-fuzz"
        cleanup_cpuset "ddrd-${slug}-validate"
        return 0
    fi

    if [[ -n "$fp" ]]; then
        log_info "[$slug] 停止 fuzz PID=$fp..."
        kill "$fp" 2>/dev/null || true
        wait_pid "$fp" 15
    fi
    if [[ -n "$vp" ]]; then
        log_info "[$slug] 停止 validate PID=$vp..."
        kill "$vp" 2>/dev/null || true
        wait_pid "$vp" 15
    fi

    remove_state "$slug"
    cleanup_cpuset "ddrd-${slug}-fuzz"
    cleanup_cpuset "ddrd-${slug}-validate"
    log_ok "[$slug] 实验已停止"
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
do_status() {
    printf "%-14s %-9s %-8s %-9s %-8s %-10s\n" \
        "MODULE" "FUZZ" "F-PID" "VALIDATE" "V-PID" "CORES"
    printf "%-14s %-9s %-8s %-9s %-8s %-10s\n" \
        "------" "----" "-----" "--------" "-----" "-----"
    for d in "$EXP_DIR"/*/; do
        local slug
        slug=$(basename "$d")
        [[ -f "$d/fuzz.cfg" ]] || continue

        local fp vp fs vs cores="—"
        fp=$(get_exp_fuzz_pid "$slug")
        vp=$(get_exp_validate_pid "$slug")
        fs="stopped"; [[ -n "$fp" ]] && fs="running"
        vs="stopped"; [[ -n "$vp" ]] && vs="running"

        load_state "$slug"
        if [[ -n "${STATE_IDX:-}" ]]; then
            calc_cores "$STATE_IDX"
            cores="$ALL_CORES"
        fi

        printf "%-14s %-9s %-8s %-9s %-8s %-10s\n" \
            "$slug" "$fs" "${fp:-—}" "$vs" "${vp:-—}" "$cores"
    done
}

# ---------------------------------------------------------------------------
# clean — 清除 workdir 中的 uaf corpus
# ---------------------------------------------------------------------------
do_clean() {
    local slug=$1
    local fp vp
    fp=$(get_exp_fuzz_pid "$slug")
    vp=$(get_exp_validate_pid "$slug")
    if [[ -n "$fp" ]] || [[ -n "$vp" ]]; then
        die "[$slug] 正在运行, 请先停止: sudo ./scripts/run_experiment.sh stop $slug"
    fi

    # 也检查常规进程
    local rp
    rp=$(get_any_regular_pid "$slug")
    if [[ -n "$rp" ]]; then
        die "[$slug] 常规 fuzz/validate 正在运行 (PID=$rp), 请先停止"
    fi

    local workdir="$EXP_DIR/$slug/workdir"
    local val_workdir="$workdir/validate-run"
    local cnt=0
    for f in "$workdir"/uaf-corpus.db "$workdir"/*-uaf-corpus.db; do
        [[ -f "$f" ]] || continue
        rm -f "$f"
        log_ok "[$slug] 已删除 $(basename "$f")"
        ((cnt++)) || true
    done
    # 清理 validate-run 子目录
    if [[ -d "$val_workdir" ]]; then
        rm -rf "$val_workdir"
        log_ok "[$slug] 已清理 validate-run 目录"
        ((cnt++)) || true
    fi
    if (( cnt == 0 )); then
        log_warn "[$slug] workdir 中无 uaf corpus 文件"
    fi
}

# ---------------------------------------------------------------------------
# clean-log — 清除 logs 目录下日志文件
# ---------------------------------------------------------------------------
do_clean_log() {
    local slug=$1
    local fp vp
    fp=$(get_exp_fuzz_pid "$slug")
    vp=$(get_exp_validate_pid "$slug")
    if [[ -n "$fp" ]] || [[ -n "$vp" ]]; then
        die "[$slug] 正在运行, 请先停止后再清理日志: sudo ./scripts/run_experiment.sh stop $slug"
    fi

    local log_dir="$EXP_DIR/$slug/logs"
    if [[ ! -d "$log_dir" ]]; then
        log_warn "[$slug] 无日志目录"
        return 0
    fi

    local cnt=0
    local f
    for f in "$log_dir"/*.log; do
        [[ -f "$f" ]] || continue
        rm -f "$f"
        ((cnt++)) || true
    done

    if (( cnt == 0 )); then
        log_warn "[$slug] logs 目录中无日志文件"
    else
        log_ok "[$slug] 已清理日志文件 ${cnt} 个"
    fi
}

# ---------------------------------------------------------------------------
# log — 查看实验日志
# ---------------------------------------------------------------------------
do_log() {
    local slug=$1 mode=${2:-fuzz}
    local log_dir="$EXP_DIR/$slug/logs"
    local latest
    latest=$(ls -t "$log_dir"/exp-${mode}-*.log 2>/dev/null | head -1)
    # 回退到常规日志
    [[ -z "$latest" ]] && latest=$(ls -t "$log_dir"/${mode}-*.log 2>/dev/null | head -1)
    [[ -z "$latest" ]] && die "[$slug] 无 ${mode} 日志"
    log_info "查看: $latest"
    tail -f "$latest"
}

# ---------------------------------------------------------------------------
# 主逻辑
# ---------------------------------------------------------------------------
case "$ACTION" in
    start)
        ensure_cpuset_layout
        detect_available_cores
        MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        if (( ${#TARGETS[@]} > MAX_MODULES )); then
            die "模块数 ${#TARGETS[@]} 超过最大 $MAX_MODULES (${AVAIL_CORES} 可用核 ÷ ${CORES_PER_MODULE} 核/模块)"
        fi
        log_info "启动 fuzz: ${#TARGETS[@]} 个模块 (${EXP_VM_COUNT}VMs, ${CORES_PER_MODULE}核/模块)"
        echo ""
        for t in "${TARGETS[@]}"; do do_start "$t"; echo ""; done
        echo "========================================="
        do_status
        ;;
    validate)
        ensure_cpuset_layout
        detect_available_cores
        MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        log_info "启动 validate: ${#TARGETS[@]} 个模块"
        echo ""
        for t in "${TARGETS[@]}"; do do_validate "$t"; echo ""; done
        echo "========================================="
        do_status
        ;;
    stop)
        if [[ ${#TARGETS[@]} -eq 0 ]] && ! $ALL_MODE; then
            # 自动发现运行中的实验
            for d in "$EXP_DIR"/*/; do
                slug=$(basename "$d")
                fp=$(get_exp_fuzz_pid "$slug")
                vp=$(get_exp_validate_pid "$slug")
                if [[ -n "$fp" ]] || [[ -n "$vp" ]]; then
                    TARGETS+=("$slug")
                fi
            done
        fi
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_warn "无运行中的实验，尝试清理残留 cpuset"
            cleanup_all_ddrd_cpusets
            maybe_teardown_cpuset_layout
            exit 0
        fi
        for t in "${TARGETS[@]}"; do do_stop "$t"; done
        cleanup_all_ddrd_cpusets
        maybe_teardown_cpuset_layout
        ;;
    status)
        do_status
        ;;
    clean)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        for t in "${TARGETS[@]}"; do do_clean "$t"; done
        ;;
    clean-log)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        for t in "${TARGETS[@]}"; do do_clean_log "$t"; done
        ;;
    log)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "用法: $0 log <module> [fuzz|validate]"
        do_log "${TARGETS[0]}" "${TARGETS[1]:-fuzz}"
        ;;
    list)
        detect_available_cores true
        MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
        echo "可用模块 (有 fuzz.cfg + validate.cfg):"
        for d in "$EXP_DIR"/*/; do
            slug=$(basename "$d")
            [[ -f "$d/fuzz.cfg" ]] && [[ -f "$d/validate.cfg" ]] && echo "  $slug"
        done
        echo ""
        echo "CPU: 核心 ${AVAIL_DESC} 可用 (${AVAIL_CORES}核), 每模块 ${CORES_PER_MODULE} 核, 最多同时 ${MAX_MODULES} 个模块"
        ;;
    help|--help|-h)
        sed -n '2,28p' "$0" | sed 's/^# //' | sed 's/^#//'
        echo ""
        detect_available_cores true
        MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
        echo "当前系统: 核心 ${AVAIL_DESC} 可用 (${AVAIL_CORES}核), 每模块 ${CORES_PER_MODULE} 核, 最多同时 ${MAX_MODULES} 个模块"
        ;;
    *)
        die "未知命令: $ACTION (start|validate|stop|status|clean|clean-log|log|list|help)"
        ;;
esac
