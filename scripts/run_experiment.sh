#!/usr/bin/env bash
# ============================================================================
# run_experiment.sh — 统一实验管理 (fuzz / validate 分步运行, CPU 核心隔离)
#
# 为每个模块分配指定数量的 CPU 核心 (默认 2 核):
#   • fuzz:     全部核心, 默认 3 VMs, procs=2
#   • validate: 全部核心, 默认 2 VMs, procs=2 (streaming 一次性处理)
# fuzz 和 validate 分步运行, 不会同时占用同一槽位
#
# 典型流程:
#   1. sudo ./scripts/run_experiment.sh start btrfs      启动 fuzz
#   2. (等 fuzz 跑够, 产生 corpus)
#   3. sudo ./scripts/run_experiment.sh validate btrfs   启动 validate
#   4. sudo ./scripts/run_experiment.sh stop btrfs       停止全部
#
# 用法:
#   sudo ./scripts/run_experiment.sh [--vanilla] [--no-pin] <command> [...]
#   sudo ./scripts/run_experiment.sh start    <mod> [...]  启动 fuzz
#   sudo ./scripts/run_experiment.sh validate <mod> [...]  启动 validate
#   sudo ./scripts/run_experiment.sh stop     [mod ...]    停止 fuzz+validate
#   sudo ./scripts/run_experiment.sh status                查看运行状态
#   sudo ./scripts/run_experiment.sh clean    <mod> [--all] 清除 uaf corpus
#   sudo ./scripts/run_experiment.sh clean-log <mod> [--all] 清除日志
#   sudo ./scripts/run_experiment.sh clean-validate <mod> [--all] 清除 validate 数据
#   sudo ./scripts/run_experiment.sh log      <mod> [fuzz|validate] 查看日志
#   sudo ./scripts/run_experiment.sh list                  列出可用模块
#
# 选项:
#   --all / -a     操作所有可用模块
#   --vanilla      使用 vanilla 配置
#   --variant STR  使用 ablation 变体配置 (e.g. --variant no-timing → fuzz-no-timing.cfg)
#   --separate-validate-slot  validate 使用独立 CPU 槽位，不复用 fuzz 槽位
#   --no-pin       不绑定 CPU，不使用 cset / taskset，直接运行
#   --except / -e  排除指定模块 (与 --all 搭配: --all --except floppy usb-driver)
#
# 环境变量 (可选覆盖):
#   CORES_PER_MODULE=2        每模块 CPU 核心数
#   SYSTEM_RESERVED_CORES=8   预留给系统的核心数 (从 CPU0 开始)
#   EXP_VM_COUNT              fuzz / validate 共用覆盖 (仅在显式设置时生效)
#   EXP_FUZZ_VM_COUNT=3       默认 fuzz VM 数量
#   EXP_VALIDATE_VM_COUNT=2   默认 validate VM 数量
#   EXP_VM_CPU=2              默认每 VM vCPU
#   EXP_VM_MEM=4096           默认每 VM 内存 (MB)
#   EXP_PROCS=2               默认 syz-manager procs
#   EXP_VM_COUNT_XFS=3        模块级覆盖 (模块名转大写, '-' 转 '_')
#   EXP_FUZZ_VM_COUNT_XFS=3   模块级 fuzz VM 数量覆盖
#   EXP_VALIDATE_VM_COUNT_XFS=2 模块级 validate VM 数量覆盖
#   EXP_VM_CPU_XFS=2          例如: xfs 使用 3VM/2vCPU
#   EXP_PROCS_BT_STACK=4      例如: bt-stack 使用独立 procs 配置
#   NO_PIN=true               不绑定 CPU，直接运行
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
EXP_VM_COUNT=${EXP_VM_COUNT-}
EXP_FUZZ_VM_COUNT=${EXP_FUZZ_VM_COUNT:-3}
EXP_VALIDATE_VM_COUNT=${EXP_VALIDATE_VM_COUNT:-2}
EXP_VM_CPU=${EXP_VM_CPU:-2}
EXP_VM_MEM=${EXP_VM_MEM:-4096}
EXP_PROCS=${EXP_PROCS:-2}
NO_PIN=${NO_PIN:-false}
SEPARATE_VALIDATE_SLOT=${SEPARATE_VALIDATE_SLOT:-false}
EXP_VALIDATE_WORKDIR_NAME=${EXP_VALIDATE_WORKDIR_NAME:-validate-run}

STATE_DIR="$PROJECT_HOME/.experiment"
CPUSETS_OWNED_MARKER="$STATE_DIR/.cpuset_owned"

CPUS_AVAILABLE=()
AVAIL_CORES=0
AVAIL_DESC=""
USE_CSET=false
USE_CGROUP_V2_CPUSET=false
MAX_MODULES=0
declare -a BATCH_RESERVED_IDXS=()
CGROUP_V2_CPUSET_ROOT="/sys/fs/cgroup/ddrd"

join_by_comma() {
    local IFS=,
    echo "$*"
}

module_env_suffix() {
    local slug=${1^^}
    slug=${slug//[^A-Z0-9]/_}
    echo "$slug"
}

resolve_module_param() {
    local slug=$1
    local base_var=$2
    local default_value=$3
    local suffix override_name override_value

    suffix=$(module_env_suffix "$slug")
    override_name="${base_var}_${suffix}"
    override_value="${!override_name-}"

    if [[ -n "${override_value:-}" ]]; then
        echo "$override_value"
    else
        echo "$default_value"
    fi
}

resolve_env_chain() {
    local default_value=$1
    shift

    local name value
    for name in "$@"; do
        value="${!name-}"
        if [[ -n "${value:-}" ]]; then
            echo "$value"
            return 0
        fi
    done

    echo "$default_value"
}

load_module_runtime_profile() {
    local slug=$1
    local mode=${2:-fuzz}
    local suffix mode_var mode_default

    suffix=$(module_env_suffix "$slug")
    mode_var="EXP_${mode^^}_VM_COUNT"
    mode_default="${!mode_var}"

    MODULE_VM_COUNT=$(resolve_env_chain \
        "$mode_default" \
        "${mode_var}_${suffix}" \
        "EXP_VM_COUNT_${suffix}" \
        "EXP_VM_COUNT")
    MODULE_VM_CPU=$(resolve_module_param "$slug" "EXP_VM_CPU" "$EXP_VM_CPU")
    MODULE_VM_MEM=$(resolve_module_param "$slug" "EXP_VM_MEM" "$EXP_VM_MEM")
    MODULE_PROCS=$(resolve_module_param "$slug" "EXP_PROCS" "$EXP_PROCS")
}

describe_module_runtime_profile() {
    echo "VMs=$MODULE_VM_COUNT, vm_cpu=$MODULE_VM_CPU, vm_mem=${MODULE_VM_MEM}MB, procs=$MODULE_PROCS"
}

normalize_module_slug() {
    case "$1" in
        usb) echo "usb-driver" ;;
        bluetooth|bt) echo "bt-stack" ;;
        *) echo "$1" ;;
    esac
}

canonicalize_targets() {
    [[ ${#TARGETS[@]} -gt 0 ]] || return 0
    local normalized=()
    local raw slug
    for raw in "${TARGETS[@]}"; do
        slug=$(normalize_module_slug "$raw")
        if [[ "$slug" != "$raw" ]]; then
            log_info "模块别名映射: $raw -> $slug"
        fi
        normalized+=("$slug")
    done
    TARGETS=("${normalized[@]}")
}

ensure_mode_configs_exist() {
    local mode=$1
    local slug cfg
    for slug in "${TARGETS[@]}"; do
        cfg="$EXP_DIR/$slug/${mode}${CFG_SUFFIX}.cfg"
        [[ -f "$cfg" ]] || {
            if [[ -n "$CFG_SUFFIX" ]]; then
                die "配置不存在: $cfg (请先运行: python3 scripts/generate_config.py --vanilla-only $slug)"
            else
                die "配置不存在: $cfg (请先运行: python3 scripts/generate_config.py $slug)"
            fi
        }
    done
}

uses_unified_cgroup_v2() {
    [[ -f /sys/fs/cgroup/cgroup.controllers ]] || return 1
    grep -q '^0::' /proc/self/cgroup 2>/dev/null
}

can_run_privileged_noninteractive() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi
    command -v sudo &>/dev/null || return 1
    sudo -n true 2>/dev/null
}

run_privileged_noninteractive() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
        return $?
    fi
    sudo -n "$@"
}

init_cgroup_v2_cpuset_root() {
    local root_cpus=$1
    local mems
    mems=$(cat /sys/fs/cgroup/cpuset.mems.effective 2>/dev/null || echo "0")

    run_privileged_noninteractive bash -lc "
        set -euo pipefail
        mkdir -p '$CGROUP_V2_CPUSET_ROOT'
        echo +cpuset > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
        [[ -f '$CGROUP_V2_CPUSET_ROOT/cpuset.cpus' ]] && echo '$root_cpus' > '$CGROUP_V2_CPUSET_ROOT/cpuset.cpus'
        [[ -f '$CGROUP_V2_CPUSET_ROOT/cpuset.mems' ]] && echo '$mems' > '$CGROUP_V2_CPUSET_ROOT/cpuset.mems'
        echo +cpuset > '$CGROUP_V2_CPUSET_ROOT/cgroup.subtree_control' 2>/dev/null || true
    "
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
        local system_cpus root_cpus
        root_cpus=$(cat "$cpusets_root/cpus" 2>/dev/null || echo "")
        system_cpus=$(cat "$cpusets_root/system/cpus" 2>/dev/null || echo "")
        if [[ -n "$system_cpus" ]] && [[ -n "$root_cpus" ]]; then
            local -a all_cores=() sys_cores=() avail=()

            _expand_cpulist() {
                local list=$1
                local -n _arr=$2
                local part
                for part in ${list//,/ }; do
                    if [[ "$part" == *-* ]]; then
                        local lo=${part%-*} hi=${part#*-}
                        local c
                        for ((c=lo; c<=hi; c++)); do
                            _arr+=("$c")
                        done
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

    local total c reserved start_core
    total=$(nproc)
    reserved=$SYSTEM_RESERVED_CORES
    if (( reserved < 0 )); then
        reserved=0
    fi

    if (( total > reserved )); then
        start_core=$reserved
    else
        start_core=0
    fi

    for ((c=start_core; c<total; c++)); do
        CPUS_AVAILABLE+=("$c")
    done
    AVAIL_CORES=${#CPUS_AVAILABLE[@]}
    AVAIL_DESC=$(join_by_comma "${CPUS_AVAILABLE[@]}")
    USE_CSET=false
    if (( start_core > 0 )); then
        $quiet || log_warn "未检测到可用 cset 分区，回退 taskset，并保留系统核心 0-$((start_core - 1)) (实验核心=$AVAIL_DESC)"
    else
        $quiet || log_warn "未检测到可用 cset 分区，回退 taskset (核心=$AVAIL_DESC)"
    fi
}

ensure_cpuset_layout() {
    if $NO_PIN; then
        return 0
    fi

    if ! command -v cset &>/dev/null; then
        log_warn "未安装 cset，回退 taskset（无法提供硬隔离）"
        return 0
    fi

    if uses_unified_cgroup_v2; then
        local total reserved user_start user_end user_desc
        total=$(nproc)
        reserved=$SYSTEM_RESERVED_CORES
        if (( reserved < 1 )); then
            reserved=1
        fi
        if (( total <= reserved )); then
            log_warn "检测到 unified cgroup v2，但 CPU 核心数=$total <= 预留系统核心数=$reserved，回退 taskset"
            return 0
        fi

        user_start=$reserved
        user_end=$((total - 1))
        user_desc="$user_start-$user_end"

        if ! can_run_privileged_noninteractive; then
            log_warn "检测到 unified cgroup v2；可用 cpuset cgroup 做硬隔离，但当前没有可用的 sudo 凭据，回退 taskset（先执行 sudo -v 可启用硬隔离）"
            return 0
        fi

        if init_cgroup_v2_cpuset_root "$user_desc"; then
            USE_CGROUP_V2_CPUSET=true
            log_info "检测到 unified cgroup v2；使用 cpuset cgroup 进行硬隔离 (实验核心=$user_desc)"
        else
            log_warn "初始化 cgroup v2 cpuset 失败，回退 taskset"
        fi
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

    if pgrep -f "syz-manager.*$EXP_DIR/.*/exp-fuzz(-vanilla)?\\.cfg|syz-manager.*$EXP_DIR/.*/exp-validate(-vanilla)?\\.cfg" >/dev/null 2>&1; then
        log_warn "仍有实验进程存活，跳过 cset shield --reset"
        return 0
    fi

    # 使用 -v 规避 cset 版本中的 list 输出 bug
    if cset set -l -v 2>/dev/null | grep -q 'ddrd-'; then
        log_warn "仍存在 ddrd-* cpuset，跳过自动 reset"
        return 0
    fi

    log_info "无运行实验，恢复 cset shield"
    cset shield --reset &>/dev/null || true
    rm -f "$CPUSETS_OWNED_MARKER"
}

# ---------------------------------------------------------------------------
# 命令行解析
# 支持:
#   ./run_experiment.sh --vanilla --no-pin start ...
#   ./run_experiment.sh start --vanilla --no-pin ...
# ---------------------------------------------------------------------------
ACTION="help"
ALL_MODE=false
USE_VANILLA=false
VARIANT_SUFFIX=""
EXCEPT_MODULES=()
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vanilla) USE_VANILLA=true; shift ;;
        --variant) VARIANT_SUFFIX="-$2"; shift 2 ;;
        --separate-validate-slot) SEPARATE_VALIDATE_SLOT=true; shift ;;
        --no-pin)  NO_PIN=true; shift ;;
        *) ACTION="$1"; shift; break ;;
    esac
done

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all|-a)   ALL_MODE=true; shift ;;
        --vanilla)  USE_VANILLA=true; shift ;;
        --variant)  VARIANT_SUFFIX="-$2"; shift 2 ;;
        --separate-validate-slot) SEPARATE_VALIDATE_SLOT=true; shift ;;
        --no-pin)   NO_PIN=true; shift ;;
        --except|-e)
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                EXCEPT_MODULES+=("$1")
                shift
            done
            ;;
        -*) die "未知选项: $1" ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

canonicalize_targets

if [[ ${#EXCEPT_MODULES[@]} -gt 0 ]]; then
    FILTERED=()
    for t in "${TARGETS[@]}"; do
        skip=false
        for e in "${EXCEPT_MODULES[@]}"; do
            [[ "$t" == "$e" ]] && { skip=true; break; }
        done
        $skip || FILTERED+=("$t")
    done
    TARGETS=("${FILTERED[@]}")
fi

CFG_SUFFIX=""
$USE_VANILLA && CFG_SUFFIX="-vanilla"
[[ -n "$VARIANT_SUFFIX" ]] && CFG_SUFFIX="$VARIANT_SUFFIX"

if $ALL_MODE; then
    mapfile -t TARGETS < <(
        for d in "$EXP_DIR"/*/; do
            local_slug=$(basename "$d")
            [[ -f "$d/fuzz${CFG_SUFFIX}.cfg" ]] && [[ -f "$d/validate${CFG_SUFFIX}.cfg" ]] && echo "$local_slug"
        done
    )
fi

# ---------------------------------------------------------------------------
# 生成实验配置 (覆盖 VM 参数, 确保 validate 监控 corpus)
# ---------------------------------------------------------------------------
gen_exp_config() {
    local slug=$1 mode=$2
    local src="$EXP_DIR/$slug/${mode}${CFG_SUFFIX}.cfg"
    local dst="$EXP_DIR/$slug/exp-${mode}${CFG_SUFFIX}.cfg"

    if [[ ! -f "$src" ]]; then
        if [[ -n "$CFG_SUFFIX" ]]; then
            die "配置不存在: $src (请先运行: python3 scripts/generate_config.py --vanilla-only $slug)"
        else
            die "配置不存在: $src (请先运行: python3 scripts/generate_config.py $slug)"
        fi
    fi

    load_module_runtime_profile "$slug" "$mode"

    python3 - "$src" "$dst" "$MODULE_VM_COUNT" "$MODULE_VM_CPU" "$MODULE_VM_MEM" "$MODULE_PROCS" "$mode" "$EXP_VALIDATE_WORKDIR_NAME" <<'PYEOF'
import json, sys, os
src, dst, vm_count, vm_cpu, vm_mem, procs, mode, validate_dirname = sys.argv[1:9]
with open(src) as f:
    cfg = json.load(f)
cfg["vm"]["count"] = int(vm_count)
cfg["vm"]["cpu"]   = int(vm_cpu)
cfg["vm"]["mem"]   = int(vm_mem)
cfg["procs"]       = int(procs)
if mode == "validate":
    cfg["workdir"] = os.path.join(cfg["workdir"], validate_dirname)
    if "experimental" in cfg:
        exp = cfg["experimental"]
        uv = exp.get("uaf_validate", {})
        uv["continuous_mode"] = False
        uv["streaming_load"] = True
        uv["continue_after_hb"] = True
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
    local sfile="$STATE_DIR/$1.state"
    if [[ -f "$sfile" ]]; then
        local _fidx _vidx _fp _vp
        read -r _fidx _vidx _fp _vp < "$sfile" || true
        if [[ -z "${_vp:-}" ]]; then
            _vp="${_fp:-}"
            _fp="${_vidx:-}"
            _vidx=""
        fi
        if [[ -n "${_fp:-}" ]] && [[ "${_fp:-0}" != "0" ]] && kill -0 "$_fp" 2>/dev/null; then
            echo "$_fp"
            return 0
        fi
    fi
    pgrep -f "$EXP_DIR/$1/exp-fuzz(-vanilla)?\\.cfg" 2>/dev/null | head -1 || true
}

get_exp_validate_pid() {
    local sfile="$STATE_DIR/$1.state"
    if [[ -f "$sfile" ]]; then
        local _fidx _vidx _fp _vp
        read -r _fidx _vidx _fp _vp < "$sfile" || true
        if [[ -z "${_vp:-}" ]]; then
            _vp="${_fp:-}"
            _fp="${_vidx:-}"
            _vidx=""
        fi
        if [[ -n "${_vp:-}" ]] && [[ "${_vp:-0}" != "0" ]] && kill -0 "$_vp" 2>/dev/null; then
            echo "$_vp"
            return 0
        fi
    fi
    pgrep -f "$EXP_DIR/$1/exp-validate(-vanilla)?\\.cfg" 2>/dev/null | head -1 || true
}

get_any_regular_pid() {
    pgrep -f "syz-manager.*$EXP_DIR/$1/fuzz\\.cfg" 2>/dev/null | head -1 || \
    pgrep -f "syz-manager.*$EXP_DIR/$1/validate\\.cfg" 2>/dev/null | head -1 || true
}

save_state() {
    mkdir -p "$STATE_DIR"
    echo "$2 $3 $4 $5" > "$STATE_DIR/$1.state"
}

remove_state() {
    rm -f "$STATE_DIR/$1.state"
}

load_state() {
    STATE_FUZZ_IDX=""
    STATE_VAL_IDX=""
    STATE_FUZZ_PID=""
    STATE_VAL_PID=""
    if [[ -f "$STATE_DIR/$1.state" ]]; then
        read -r STATE_FUZZ_IDX STATE_VAL_IDX STATE_FUZZ_PID STATE_VAL_PID < "$STATE_DIR/$1.state" || true
        [[ "${STATE_VAL_IDX:-}" == "-" ]] && STATE_VAL_IDX=""
        if [[ -z "${STATE_VAL_PID:-}" ]]; then
            STATE_VAL_PID="${STATE_FUZZ_PID:-}"
            STATE_FUZZ_PID="${STATE_VAL_IDX:-}"
            STATE_VAL_IDX=""
        fi
        if [[ -z "${STATE_VAL_IDX:-}" ]] && [[ -n "${STATE_VAL_PID:-}" ]] && [[ "${STATE_VAL_PID:-0}" != "0" ]]; then
            STATE_VAL_IDX="$STATE_FUZZ_IDX"
        fi
    fi
    return 0
}

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

next_module_index() {
    purge_stale_states
    local used=()

    if [[ -d "$STATE_DIR" ]]; then
        for f in "$STATE_DIR"/*.state; do
            [[ -f "$f" ]] || continue
            local fidx vidx fp vp
            read -r fidx vidx fp vp < "$f" || true
            if [[ -z "${vp:-}" ]]; then
                vp="${fp:-}"
                fp="${vidx:-}"
                vidx=""
            fi
            [[ -n "${fidx:-}" ]] && [[ "${fidx:-}" != "-" ]] && used+=("$fidx")
            [[ -n "${vidx:-}" ]] && [[ "${vidx:-}" != "-" ]] && used+=("$vidx")
        done
    fi

    local b
    for b in "${BATCH_RESERVED_IDXS[@]+${BATCH_RESERVED_IDXS[@]}}"; do
        used+=("$b")
    done

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

pin_to_cores() {
    local pid=$1 cores=$2 label=$3

    $NO_PIN && return 0

    if $USE_CGROUP_V2_CPUSET; then
        local cgdir="$CGROUP_V2_CPUSET_ROOT/$label"
        local mems
        mems=$(cat /sys/fs/cgroup/cpuset.mems.effective 2>/dev/null || echo "0")
        if run_privileged_noninteractive bash -lc "
            set -euo pipefail
            mkdir -p '$cgdir'
            echo '$cores' > '$cgdir/cpuset.cpus'
            echo '$mems' > '$cgdir/cpuset.mems'
            echo '$pid' > '$cgdir/cgroup.procs'
        "; then
            return 0
        fi
        log_warn "cpuset cgroup 绑定失败，回退 taskset: label=$label cores=$cores pid=$pid"
    fi

    if $USE_CSET && command -v cset &>/dev/null; then
        cset set -d -s "$label" &>/dev/null || cset set -d -s "/$label" &>/dev/null || true
        if cset set -c "$cores" -s "$label" &>/dev/null; then
            if cset proc -m -p "$pid" -t "$label" &>/dev/null; then
                return 0
            fi
        fi
        echo "$pid" > /cpusets/tasks 2>/dev/null || true
    fi

    taskset -p -c "$cores" "$pid" >/dev/null 2>&1 || true
}

cleanup_cpuset() {
    local name="$1"

    if [[ -d "$CGROUP_V2_CPUSET_ROOT/$name" ]]; then
        run_privileged_noninteractive rmdir "$CGROUP_V2_CPUSET_ROOT/$name" &>/dev/null || true
    fi

    command -v cset &>/dev/null || return 0
    cset set -d -s "$name" &>/dev/null || cset set -d -s "/$name" &>/dev/null || true
}

cleanup_all_ddrd_cpusets() {
    if [[ -d "$CGROUP_V2_CPUSET_ROOT" ]]; then
        local cg
        while read -r cg; do
            [[ -n "$cg" ]] || continue
            run_privileged_noninteractive rmdir "$cg" &>/dev/null || true
        done < <(find "$CGROUP_V2_CPUSET_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
        run_privileged_noninteractive rmdir "$CGROUP_V2_CPUSET_ROOT" &>/dev/null || true
    fi

    command -v cset &>/dev/null || return 0
    local n
    while read -r n; do
        [[ -n "$n" ]] || continue
        cleanup_cpuset "$n"
    done < <(cset set -l -v 2>/dev/null | awk '$1 ~ /^ddrd-/ {print $1}')
}

# ---------------------------------------------------------------------------
# start — 只启动 fuzz
# ---------------------------------------------------------------------------
do_start() {
    local slug=$1

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

    local idx
    if $NO_PIN; then
        idx="-1"
        ALL_CORES="unbound"
        log_info "[$slug] 不绑定 CPU，直接启动"
    else
        idx=$(next_module_index) || die "CPU 槽位不足 (最大 $MAX_MODULES)"
        BATCH_RESERVED_IDXS+=("$idx")
        calc_cores "$idx"
        log_info "[$slug] 分配核心: $ALL_CORES"
    fi

    gen_exp_config "$slug" "fuzz"
    log_info "[$slug] fuzz 参数: $(describe_module_runtime_profile)"

    local fuzz_cfg="$EXP_DIR/$slug/exp-fuzz${CFG_SUFFIX}.cfg"
    local log_dir="$EXP_DIR/$slug/logs"
    mkdir -p "$log_dir"
    local ts
    ts=$(date +%Y%m%d-%H%M%S)

    local fuzz_log="$log_dir/exp-fuzz${CFG_SUFFIX}-${ts}.log"
    nohup "$SYZ_MANAGER" -config "$fuzz_cfg" > "$fuzz_log" 2>&1 &
    local fuzz_pid=$!

    if ! $NO_PIN; then
        pin_to_cores "$fuzz_pid" "$ALL_CORES" "ddrd-${slug}-fuzz"
    fi

    sleep 2

    if ! kill -0 "$fuzz_pid" 2>/dev/null; then
        log_error "[$slug] fuzz 启动失败 → $fuzz_log"
        return 1
    fi

    save_state "$slug" "$idx" "-" "$fuzz_pid" "0"
    log_ok "[$slug] fuzz 已启动  PID=$fuzz_pid  cores=$ALL_CORES"
    if $USE_VANILLA; then
        log_info "[$slug] fuzz 跑够后运行: sudo $0 --vanilla ${NO_PIN:+} $( $NO_PIN && echo '--no-pin' ) validate $slug" >/dev/null 2>&1 || true
    fi
    return 0
}

# ---------------------------------------------------------------------------
# validate — 单独启动 validate (fuzz 可以在跑, 也可以已停止)
# ---------------------------------------------------------------------------
do_validate() {
    local slug=$1

    local vp
    vp=$(get_exp_validate_pid "$slug")
    if [[ -n "$vp" ]]; then
        log_warn "[$slug] validate 已在运行 (PID=$vp)"
        return 0
    fi

    local main_workdir="$EXP_DIR/$slug/workdir"
    mkdir -p "$main_workdir"
    if [[ ! -f "$main_workdir/uaf-corpus.db" ]]; then
        log_warn "[$slug] corpus 文件尚不存在: $main_workdir/uaf-corpus.db — validate 将等待 fuzz 产生 corpus"
    fi

    local idx
    local val_idx=""
    if $NO_PIN; then
        idx="-1"
        val_idx="-1"
        ALL_CORES="unbound"
        log_info "[$slug] validate 不绑定 CPU，直接启动"
    else
        load_state "$slug"
        if $SEPARATE_VALIDATE_SLOT; then
            if [[ -n "${STATE_VAL_IDX:-}" ]] && [[ "$STATE_VAL_IDX" != "-1" ]]; then
                idx=$STATE_VAL_IDX
            else
                idx=$(next_module_index) || die "CPU 槽位不足 (最大 $MAX_MODULES)"
            fi
        else
            if [[ -n "${STATE_FUZZ_IDX:-}" ]] && [[ "$STATE_FUZZ_IDX" != "-1" ]]; then
                idx=$STATE_FUZZ_IDX
            else
                idx=$(next_module_index) || die "CPU 槽位不足 (最大 $MAX_MODULES)"
            fi
        fi
        val_idx=$idx
        calc_cores "$idx"
        log_info "[$slug] validate 使用核心: $ALL_CORES"
    fi

    gen_exp_config "$slug" "validate"
    log_info "[$slug] validate 参数: $(describe_module_runtime_profile)"

    local val_workdir="$main_workdir/$EXP_VALIDATE_WORKDIR_NAME"
    mkdir -p "$val_workdir"
    if [[ ! -e "$val_workdir/uaf-corpus.db" ]]; then
        ln -sf "$main_workdir/uaf-corpus.db" "$val_workdir/uaf-corpus.db"
    fi

    local val_cfg="$EXP_DIR/$slug/exp-validate${CFG_SUFFIX}.cfg"
    local log_dir="$EXP_DIR/$slug/logs"
    mkdir -p "$log_dir"
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local val_log="$log_dir/exp-validate${CFG_SUFFIX}-${ts}.log"

    nohup "$SYZ_MANAGER" -mode=uaf-validate -config "$val_cfg" > "$val_log" 2>&1 &
    local val_pid=$!

    if ! $NO_PIN; then
        pin_to_cores "$val_pid" "$ALL_CORES" "ddrd-${slug}-validate"
    fi

    sleep 2

    if ! kill -0 "$val_pid" 2>/dev/null; then
        log_error "[$slug] validate 启动失败 → $val_log"
        return 1
    fi

    local fp
    fp=$(get_exp_fuzz_pid "$slug")
    load_state "$slug"
    local fuzz_idx="${STATE_FUZZ_IDX:--1}"
    save_state "$slug" "$fuzz_idx" "$val_idx" "${fp:-0}" "$val_pid"
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
    if ! $NO_PIN && (( ${#CPUS_AVAILABLE[@]} == 0 )); then
        detect_available_cores true
    fi

    printf "%-14s %-9s %-8s %-9s %-8s %-12s %-12s\n" \
        "MODULE" "FUZZ" "F-PID" "VALIDATE" "V-PID" "F-CORES" "V-CORES"
    printf "%-14s %-9s %-8s %-9s %-8s %-12s %-12s\n" \
        "------" "----" "-----" "--------" "-----" "-------" "-------"

    for d in "$EXP_DIR"/*/; do
        local slug
        slug=$(basename "$d")
        [[ -f "$d/fuzz${CFG_SUFFIX}.cfg" ]] || continue

        local fp vp fs vs fuzz_cores="—" val_cores="—"
        fp=$(get_exp_fuzz_pid "$slug")
        vp=$(get_exp_validate_pid "$slug")
        fs="stopped"; [[ -n "$fp" ]] && fs="running"
        vs="stopped"; [[ -n "$vp" ]] && vs="running"

        load_state "$slug"
        if [[ -n "${STATE_FUZZ_IDX:-}" ]]; then
            if [[ "$STATE_FUZZ_IDX" == "-1" ]]; then
                fuzz_cores="unbound"
            elif [[ -n "$STATE_FUZZ_IDX" ]]; then
                calc_cores "$STATE_FUZZ_IDX"
                fuzz_cores="$ALL_CORES"
            fi
        fi
        if [[ -n "${STATE_VAL_IDX:-}" ]]; then
            if [[ "$STATE_VAL_IDX" == "-1" ]]; then
                val_cores="unbound"
            elif [[ -n "$STATE_VAL_IDX" ]]; then
                calc_cores "$STATE_VAL_IDX"
                val_cores="$ALL_CORES"
            fi
        fi

        printf "%-14s %-9s %-8s %-9s %-8s %-12s %-12s\n" \
            "$slug" "$fs" "${fp:-—}" "$vs" "${vp:-—}" "$fuzz_cores" "$val_cores"
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
# clean-validate — 清除 validate 相关数据库文件 (保留 uaf corpus)
# ---------------------------------------------------------------------------
do_clean_validate() {
    local slug=$1
    local fp vp
    fp=$(get_exp_fuzz_pid "$slug")
    vp=$(get_exp_validate_pid "$slug")
    if [[ -n "$fp" ]] || [[ -n "$vp" ]]; then
        die "[$slug] 正在运行, 请先停止: sudo ./scripts/run_experiment.sh stop $slug"
    fi

    local workdir="$EXP_DIR/$slug/workdir"
    local val_workdir="$workdir/validate-run"
    local cnt=0

    local db_files=(
        "invalid_uaf.db"
        "validated_uaf.db"
        "varname_backoff_stats.db"
        "varname_hb_stats.db"
    )

    for dir in "$workdir" "$val_workdir"; do
        [[ -d "$dir" ]] || continue
        for dbf in "${db_files[@]}"; do
            if [[ -f "$dir/$dbf" ]]; then
                rm -f "$dir/$dbf"
                log_ok "[$slug] 已删除 $dir/$dbf"
                ((cnt++)) || true
            fi
        done
    done

    if [[ -d "$val_workdir" ]]; then
        rm -rf "$val_workdir"
        log_ok "[$slug] 已清理 validate-run 目录"
        ((cnt++)) || true
    fi

    if (( cnt == 0 )); then
        log_warn "[$slug] 无 validate 数据可清理"
    fi
}

# ---------------------------------------------------------------------------
# log — 查看实验日志
# ---------------------------------------------------------------------------
do_log() {
    local slug=$1 mode=${2:-fuzz}
    local log_dir="$EXP_DIR/$slug/logs"
    local latest

    latest=$(ls -t "$log_dir"/exp-${mode}${CFG_SUFFIX}-*.log 2>/dev/null | head -1)
    [[ -z "$latest" ]] && latest=$(ls -t "$log_dir"/exp-${mode}-*.log 2>/dev/null | head -1)
    [[ -z "$latest" ]] && latest=$(ls -t "$log_dir"/exp-${mode}-vanilla-*.log 2>/dev/null | head -1)
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
        if ! $NO_PIN; then
            ensure_cpuset_layout
            detect_available_cores
            MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
        fi

        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        ensure_mode_configs_exist "fuzz"
        BATCH_RESERVED_IDXS=()

        if ! $NO_PIN && (( ${#TARGETS[@]} > MAX_MODULES )); then
            die "模块数 ${#TARGETS[@]} 超过最大 $MAX_MODULES (${AVAIL_CORES} 可用核 ÷ ${CORES_PER_MODULE} 核/模块)"
        fi

        if $USE_VANILLA; then
            if $NO_PIN; then
                log_info "启动 fuzz(vanilla): ${#TARGETS[@]} 个模块 (no CPU pinning)"
            else
                log_info "启动 fuzz(vanilla): ${#TARGETS[@]} 个模块 (默认 ${EXP_FUZZ_VM_COUNT}VMs, ${CORES_PER_MODULE}核/模块)"
            fi
        else
            if $NO_PIN; then
                log_info "启动 fuzz: ${#TARGETS[@]} 个模块 (no CPU pinning)"
            else
                log_info "启动 fuzz: ${#TARGETS[@]} 个模块 (默认 ${EXP_FUZZ_VM_COUNT}VMs, ${CORES_PER_MODULE}核/模块)"
            fi
        fi

        echo ""
        for t in "${TARGETS[@]}"; do
            do_start "$t"
            echo ""
        done
        echo "========================================="
        do_status
        ;;
    validate)
        if ! $NO_PIN; then
            ensure_cpuset_layout
            detect_available_cores
            MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
        fi

        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        ensure_mode_configs_exist "validate"

        if $USE_VANILLA; then
            if $NO_PIN; then
                log_info "启动 validate(vanilla): ${#TARGETS[@]} 个模块 (no CPU pinning)"
            else
                log_info "启动 validate(vanilla): ${#TARGETS[@]} 个模块"
            fi
        else
            if $NO_PIN; then
                log_info "启动 validate: ${#TARGETS[@]} 个模块 (no CPU pinning)"
            else
                log_info "启动 validate: ${#TARGETS[@]} 个模块"
            fi
        fi

        echo ""
        for t in "${TARGETS[@]}"; do
            do_validate "$t"
            echo ""
        done
        echo "========================================="
        do_status
        ;;
    stop)
        if [[ ${#TARGETS[@]} -eq 0 ]] && ! $ALL_MODE; then
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

        for t in "${TARGETS[@]}"; do
            do_stop "$t"
        done
        cleanup_all_ddrd_cpusets
        maybe_teardown_cpuset_layout
        ;;
    status)
        do_status
        ;;
    clean)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        for t in "${TARGETS[@]}"; do
            do_clean "$t"
        done
        ;;
    clean-log)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        for t in "${TARGETS[@]}"; do
            do_clean_log "$t"
        done
        ;;
    clean-validate)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "请指定模块或使用 --all"
        for t in "${TARGETS[@]}"; do
            do_clean_validate "$t"
        done
        ;;
    log)
        [[ ${#TARGETS[@]} -gt 0 ]] || die "用法: $0 log <module> [fuzz|validate]"
        do_log "${TARGETS[0]}" "${TARGETS[1]:-fuzz}"
        ;;
    list)
        if $USE_VANILLA; then
            echo "可用模块 (有 fuzz-vanilla.cfg + validate-vanilla.cfg):"
        else
            echo "可用模块 (有 fuzz.cfg + validate.cfg):"
        fi

        for d in "$EXP_DIR"/*/; do
            slug=$(basename "$d")
            [[ -f "$d/fuzz${CFG_SUFFIX}.cfg" ]] && [[ -f "$d/validate${CFG_SUFFIX}.cfg" ]] && echo "  $slug"
        done

        echo ""
        if $NO_PIN; then
            echo "当前模式: no CPU pinning"
        else
            detect_available_cores true
            MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
            echo "CPU: 核心 ${AVAIL_DESC} 可用 (${AVAIL_CORES}核), 每模块 ${CORES_PER_MODULE} 核, 最多同时 ${MAX_MODULES} 个模块"
        fi
        ;;
    help|--help|-h)
        sed -n '2,31p' "$0" | sed 's/^# //' | sed 's/^#//'
        echo ""
        if $NO_PIN; then
            echo "当前模式: no CPU pinning"
        else
            detect_available_cores true
            MAX_MODULES=$((AVAIL_CORES / CORES_PER_MODULE))
            echo "当前系统: 核心 ${AVAIL_DESC} 可用 (${AVAIL_CORES}核), 每模块 ${CORES_PER_MODULE} 核, 最多同时 ${MAX_MODULES} 个模块"
        fi
        ;;
    *)
        die "未知命令: $ACTION (start|validate|stop|status|clean|clean-log|clean-validate|log|list|help)"
        ;;
esac
