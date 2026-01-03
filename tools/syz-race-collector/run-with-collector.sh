#!/bin/bash
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# ============================================================================
# run-with-collector.sh  (time-driven version)
#
# - 启动 syz-manager
# - 周期性从 syzkaller.log 中“增量”解析 VM ready 行（不再每次 grep 全文件）
# - 周期性 deploy collector（VM 可能重启/collector 丢失就会重装）
# - 周期性从各 VM scp 回 races 文件
#
# Debug增强：
# - OUTPUT_DIR/cmd.log：关键命令输出
# - OUTPUT_DIR/vm<id>/ssh.{log,err}, scp.{log,err}：每个 VM 单独落盘
# - --verbose 输出更多状态
# - --trace 打开 set -x（带时间戳/行号）
# - 发生错误会打印 “line/cmd/rc”
# ============================================================================

set -euo pipefail

trap 'rc=$?; echo "$(date +"%F %T") [FATAL] line=$LINENO cmd=$BASH_COMMAND rc=$rc" >&2' ERR

# ============================================================================
# 关键修复：在 set -u 下，必须显式初始化关联数组，否则 ${#arr[@]} 会报 unbound
# ============================================================================
declare -A VM_PORTS=()
declare -A VM_LAST_DEPLOY_TS=()
declare -A VM_LAST_COLLECT_TS=()
declare -A VM_FAIL_DEPLOY=()
declare -A VM_FAIL_COLLECT=()
declare -A VM_SIGNALS_COLLECTED_LINES=()  # 记录每个 VM 已收集的 signals 行数
# ============================================================================
# 默认配置
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COLLECTOR_BIN="$SCRIPT_DIR/syz-race-collector"

SYZ_CONFIG=""
SYZ_MANAGER="$SYZKALLER_DIR/bin/syz-manager"

COLLECT_INTERVAL=60             # 采集间隔（秒）
COLLECTOR_SAMPLE_INTERVAL=1000  # collector 采样间隔（毫秒）
RACE_THRESHOLD=4270000          # race pair 时间阈值（纳秒），默认 ~4.27ms
UAF_THRESHOLD=10000000000       # UAF 时间阈值（纳秒），默认 10s
OUTPUT_DIR=""
OUTPUT_FORMAT="csv"

SSH_KEY=""
SSH_USER="root"
SSH_TIMEOUT=10

DURATION=0
VERBOSE=false
DRY_RUN=false
TRACE=false

# VM 发现/部署频率（time-driven）
DEPLOY_CHECK_INTERVAL=30   # 每 30 秒增量解析 log + 尝试部署
BOOT_WAIT_TIMEOUT=300      # 启动后最多等 300 秒等到至少一个 VM ready

# 数据管理选项
CLEAN_START=false          # 启动时清理旧数据
AUTO_DEDUP=true            # 每次收集后自动去重
CLEAN_TEMP_FILES=true      # 去重后删除临时文件

# ============================================================================
# 颜色输出 + 时间戳
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ts() { date +"%Y-%m-%d %H:%M:%S"; }
log_info()  { echo -e "$(ts) ${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "$(ts) ${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "$(ts) ${RED}[ERROR]${NC} $1"; }
log_debug() { $VERBOSE && echo -e "$(ts) ${BLUE}[DEBUG]${NC} $1"; }

# ============================================================================
# 帮助
# ============================================================================
print_usage() {
cat << EOF
Usage: $(basename "$0") [options] -c <syzkaller-config>

Time-driven runner: periodically parses syzkaller.log (incrementally) to discover VM SSH ports,
deploys syz-race-collector, and collects data.

Options:
  -c, --config <file>       Syzkaller configuration file (required)
  -o, --output-dir <dir>    Output directory (default: <workdir>/race-collector-data)
  -i, --interval <sec>      Collection interval seconds (default: 60)
  -s, --sample-ms <ms>      Collector sampling interval ms (default: 1000)
  -f, --format <fmt>        csv or json (default: csv)
  -d, --duration <sec>      Run duration, 0 = until Ctrl+C (default: 0)
  --race-threshold <ns>     Race pair time threshold in nanoseconds (default: 4270000, ~4.27ms)
  --uaf-threshold <ns>      UAF time threshold in nanoseconds (default: 10000000000, 10s)
  --clean                   Clean old data before starting (fresh test)
  --no-auto-dedup           Disable automatic deduplication after each collection
  --keep-temp               Keep temporary CSV files after deduplication
  -v, --verbose             Verbose output
  --trace                   set -x with timestamps/lineno
  --dry-run                 Show actions without executing
  -h, --help                Show help

Debug artifacts (in OUTPUT_DIR):
  - cmd.log
  - vm<id>/ssh.log ssh.err scp.log scp.err
  - syzkaller.log
EOF
}

# ============================================================================
# 参数解析
# ============================================================================
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c|--config)     SYZ_CONFIG="$2"; shift 2;;
      -o|--output-dir) OUTPUT_DIR="$2"; shift 2;;
      -i|--interval)   COLLECT_INTERVAL="$2"; shift 2;;
      -s|--sample-ms)  COLLECTOR_SAMPLE_INTERVAL="$2"; shift 2;;
      -f|--format)     OUTPUT_FORMAT="$2"; shift 2;;
      -d|--duration)   DURATION="$2"; shift 2;;
      --race-threshold=*) RACE_THRESHOLD="${1#*=}"; shift;;
      --race-threshold)   RACE_THRESHOLD="$2"; shift 2;;
      --uaf-threshold=*)  UAF_THRESHOLD="${1#*=}"; shift;;
      --uaf-threshold)    UAF_THRESHOLD="$2"; shift 2;;
      --clean)           CLEAN_START=true; shift;;
      --no-auto-dedup)   AUTO_DEDUP=false; shift;;
      --keep-temp)       CLEAN_TEMP_FILES=false; shift;;
      -v|--verbose)    VERBOSE=true; shift;;
      --trace)         TRACE=true; shift;;
      --dry-run)       DRY_RUN=true; shift;;
      -h|--help)       print_usage; exit 0;;
      *) log_error "Unknown option: $1"; print_usage; exit 1;;
    esac
  done

  if [[ -z "$SYZ_CONFIG" ]]; then
    log_error "Syzkaller config is required (-c)"
    exit 1
  fi
  if [[ ! -f "$SYZ_CONFIG" ]]; then
    log_error "Config not found: $SYZ_CONFIG"
    exit 1
  fi
}

# ============================================================================
# 全局日志
# ============================================================================
CMD_LOG=""
ensure_logs() {
  CMD_LOG="$OUTPUT_DIR/cmd.log"
  : > "$CMD_LOG"
}

run_cmd() {
  local desc="$1"; shift
  log_debug "RUN: $desc :: $*"
  if $DRY_RUN; then
    log_info "[DRY-RUN] $desc :: $*"
    return 0
  fi
  if $VERBOSE; then
    { echo "----- $(ts) :: $desc :: $*"; "$@"; echo "----- $(ts) :: OK :: $desc"; } 2>&1 | tee -a "$CMD_LOG"
  else
    { echo "----- $(ts) :: $desc :: $*"; "$@"; echo "----- $(ts) :: OK :: $desc"; } >>"$CMD_LOG" 2>&1
  fi
}

# ============================================================================
# 清理旧数据
# ============================================================================
clean_old_data() {
  log_info "Cleaning old data in $OUTPUT_DIR..."
  
  # 删除所有临时 CSV 文件
  local count=0
  for f in "$OUTPUT_DIR"/vm*_*.csv "$OUTPUT_DIR"/vm*_signals.csv; do
    if [[ -f "$f" ]]; then
      rm -f "$f"
      ((count++)) || true
    fi
  done
  
  # 删除合并后的文件
  rm -f "$OUTPUT_DIR"/all_races_merged.csv
  rm -f "$OUTPUT_DIR"/all_races_deduped.csv
  rm -f "$OUTPUT_DIR"/all_signals_merged.csv
  rm -f "$OUTPUT_DIR"/all_signals_unique.csv
  
  # 删除时间序列文件
  rm -f "$OUTPUT_DIR"/race_timeseries.csv
  
  # 删除 VM 子目录中的日志
  for d in "$OUTPUT_DIR"/vm*/; do
    if [[ -d "$d" ]]; then
      rm -rf "$d"
      ((count++)) || true
    fi
  done
  
  log_info "Cleaned $count files/directories. Starting fresh."
}

# ============================================================================
# 解析 config（不依赖 grep -P）
# ============================================================================
WORKDIR=""

extract_json_string_field() {
  local file="$1"
  local field="$2"
  sed -nE 's/.*"'"$field"'":[[:space:]]*"([^"]+)".*/\1/p' "$file" | head -n 1
}

parse_config() {
  log_info "Parsing configuration from $SYZ_CONFIG"

  WORKDIR="$(extract_json_string_field "$SYZ_CONFIG" workdir)"
  SSH_KEY="$(extract_json_string_field "$SYZ_CONFIG" sshkey)"

  if [[ -z "${WORKDIR:-}" ]]; then
    log_error "Cannot extract \"workdir\" from config."
    log_error "Hint: ensure config has: \"workdir\": \"/abs/path\""
    grep -n '"workdir"' "$SYZ_CONFIG" || true
    exit 1
  fi
  if [[ -z "${SSH_KEY:-}" ]]; then
    log_error "Cannot extract \"sshkey\" from config."
    log_error "Hint: ensure config has: \"sshkey\": \"/abs/path/to/id_rsa\""
    grep -n '"sshkey"' "$SYZ_CONFIG" || true
    exit 1
  fi

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$WORKDIR/race-collector-data"
  fi
  mkdir -p "$OUTPUT_DIR"
  
  # 如果指定了 --clean，清理旧数据
  if $CLEAN_START; then
    clean_old_data
  fi
  
  ensure_logs

  log_info "Output directory: $OUTPUT_DIR"
  log_info "Env summary:"
  log_info "  SYZ_MANAGER=$SYZ_MANAGER"
  log_info "  COLLECTOR_BIN=$COLLECTOR_BIN"
  log_info "  workdir=$WORKDIR"
  log_info "  sshkey=$SSH_KEY"
  log_info "  format=$OUTPUT_FORMAT collect_interval=${COLLECT_INTERVAL}s sample_ms=${COLLECTOR_SAMPLE_INTERVAL}ms"
  log_info "  race_threshold=${RACE_THRESHOLD}ns uaf_threshold=${UAF_THRESHOLD}ns"
  log_info "  deploy_check_interval=${DEPLOY_CHECK_INTERVAL}s boot_wait_timeout=${BOOT_WAIT_TIMEOUT}s"
  log_info "  clean_start=$CLEAN_START auto_dedup=$AUTO_DEDUP clean_temp=$CLEAN_TEMP_FILES"
  log_info "  DRY_RUN=$DRY_RUN VERBOSE=$VERBOSE TRACE=$TRACE"
}

# ============================================================================
# 编译 collector
# ============================================================================
build_collector() {
  if [[ -f "$COLLECTOR_BIN" ]]; then
    log_info "Collector binary exists: $COLLECTOR_BIN"
    return 0
  fi
  log_info "Building syz-race-collector..."
  run_cmd "Build collector" make -C "$SCRIPT_DIR"
  log_info "Build successful"
}

# ============================================================================
# VM 工具函数
# ============================================================================
vm_dir() { echo "$OUTPUT_DIR/vm$1"; }
vm_init_dir() { mkdir -p "$(vm_dir "$1")"; }

ssh_opts_common() {
  # ConnectTimeout: 连接超时
  # ServerAliveInterval: 每 5 秒发送 keepalive
  # ServerAliveCountMax: 3 次无响应后断开（15秒总超时）
  # -T: 禁用 pseudo-terminal 分配，避免 SSH 卡住
  echo "-T -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ServerAliveInterval=5 -o ServerAliveCountMax=3"
}

check_vm_ssh() {
  local port="$1"
  local ssh_opts; ssh_opts="$(ssh_opts_common)"
  # shellcheck disable=SC2086
  ssh $ssh_opts \
      -p "$port" -i "$SSH_KEY" \
      "${SSH_USER}@localhost" "echo ok" >/dev/null 2>&1
}

ssh_run() {
  local vm_id="$1"; local port="$2"; local cmd="$3"
  vm_init_dir "$vm_id"
  local out="$(vm_dir "$vm_id")/ssh.log"
  local err="$(vm_dir "$vm_id")/ssh.err"
  local ssh_opts; ssh_opts="$(ssh_opts_common)"
  # SSH 命令总超时时间（连接+执行），避免无限等待
  local ssh_timeout=30

  log_debug "SSH VM-$vm_id:$port :: $cmd"

  if $DRY_RUN; then
    log_info "[DRY-RUN] ssh -p $port -i $SSH_KEY ${SSH_USER}@localhost '$cmd'"
    return 0
  fi

  echo "----- $(ts) :: ssh VM-$vm_id port=$port :: $cmd" >>"$out"
  # shellcheck disable=SC2086
  if timeout "$ssh_timeout" ssh $ssh_opts -p "$port" -i "$SSH_KEY" "${SSH_USER}@localhost" "$cmd" >>"$out" 2>>"$err"; then
    echo "----- $(ts) :: ssh OK" >>"$out"
    return 0
  else
    local rc=$?
    if [[ $rc -eq 124 ]]; then
      echo "----- $(ts) :: ssh TIMEOUT (${ssh_timeout}s)" >>"$out"
    else
      echo "----- $(ts) :: ssh FAILED (rc=$rc)" >>"$out"
    fi
    return $rc
  fi
}

scp_put() {
  local vm_id="$1"; local port="$2"; local local_path="$3"; local remote_path="$4"
  vm_init_dir "$vm_id"
  local out="$(vm_dir "$vm_id")/scp.log"
  local err="$(vm_dir "$vm_id")/scp.err"
  local scp_opts; scp_opts="$(ssh_opts_common)"
  local scp_timeout=60

  log_debug "SCP PUT VM-$vm_id:$port :: $local_path -> $remote_path"

  if $DRY_RUN; then
    log_info "[DRY-RUN] scp -P $port -i $SSH_KEY $local_path ${SSH_USER}@localhost:$remote_path"
    return 0
  fi

  echo "----- $(ts) :: scp PUT VM-$vm_id port=$port :: $local_path -> $remote_path" >>"$out"
  # shellcheck disable=SC2086
  if timeout "$scp_timeout" scp $scp_opts -P "$port" -i "$SSH_KEY" "$local_path" "${SSH_USER}@localhost:$remote_path" >>"$out" 2>>"$err"; then
    echo "----- $(ts) :: scp PUT OK" >>"$out"
    return 0
  else
    local rc=$?
    [[ $rc -eq 124 ]] && echo "----- $(ts) :: scp PUT TIMEOUT" >>"$out" || echo "----- $(ts) :: scp PUT FAILED (rc=$rc)" >>"$out"
    return $rc
  fi
}

scp_get() {
  local vm_id="$1"; local port="$2"; local remote_path="$3"; local local_path="$4"
  vm_init_dir "$vm_id"
  local out="$(vm_dir "$vm_id")/scp.log"
  local err="$(vm_dir "$vm_id")/scp.err"
  local scp_opts; scp_opts="$(ssh_opts_common)"
  local scp_timeout=60

  log_debug "SCP GET VM-$vm_id:$port :: $remote_path -> $local_path"

  if $DRY_RUN; then
    log_info "[DRY-RUN] scp -P $port -i $SSH_KEY ${SSH_USER}@localhost:$remote_path $local_path"
    return 0
  fi

  echo "----- $(ts) :: scp GET VM-$vm_id port=$port :: $remote_path -> $local_path" >>"$out"
  # shellcheck disable=SC2086
  if timeout "$scp_timeout" scp $scp_opts -P "$port" -i "$SSH_KEY" "${SSH_USER}@localhost:$remote_path" "$local_path" >>"$out" 2>>"$err"; then
    echo "----- $(ts) :: scp GET OK" >>"$out"
    return 0
  else
    local rc=$?
    [[ $rc -eq 124 ]] && echo "----- $(ts) :: scp GET TIMEOUT" >>"$out" || echo "----- $(ts) :: scp GET FAILED (rc=$rc)" >>"$out"
    return $rc
  fi
}

collector_alive_on_vm() {
  local vm_id="$1"; local port="$2"
  # 使用更精确的检测方法，避免 pgrep 匹配到自己
  ssh_run "$vm_id" "$port" '
    # 检查 collector 进程是否存在（排除 grep/pgrep 自身）
    if [ -f /tmp/collector-vm'"$vm_id"'.pid ]; then
      pid=$(cat /tmp/collector-vm'"$vm_id"'.pid 2>/dev/null)
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        exit 0
      fi
    fi
    # 备选：检查进程列表
    ps aux 2>/dev/null | grep -v grep | grep -q "syz-race-collector.*-o /tmp/races"
  ' >/dev/null 2>&1
}

deploy_collector() {
  local vm_id="$1"; local port="$2"
  log_info "Deploying collector to VM-$vm_id (port $port)..."

  if ! check_vm_ssh "$port"; then
    log_warn "VM-$vm_id SSH unreachable (port $port)."
    VM_FAIL_DEPLOY["$vm_id"]=$(( ${VM_FAIL_DEPLOY["$vm_id"]:-0} + 1 ))
    return 1
  fi

  # ====== 关键修复：先杀死所有旧的 collector 进程 ======
  # 这样可以避免旧进程持有已删除文件的 inode 继续写入
  log_debug "Killing any existing collector on VM-$vm_id..."
  ssh_run "$vm_id" "$port" '
    # 先尝试用 pid 文件杀死
    if [ -f /tmp/collector-vm'"$vm_id"'.pid ]; then
      pid=$(cat /tmp/collector-vm'"$vm_id"'.pid 2>/dev/null)
      if [ -n "$pid" ]; then
        kill -9 "$pid" 2>/dev/null || true
      fi
      rm -f /tmp/collector-vm'"$vm_id"'.pid
    fi
    # 再杀死所有匹配的 collector 进程（保险起见）
    pkill -9 -f "syz-race-collector.*-o /tmp/races" 2>/dev/null || true
    # 等待进程完全退出
    sleep 0.3
  ' 2>/dev/null || true

  if ! scp_put "$vm_id" "$port" "$COLLECTOR_BIN" "/tmp/syz-race-collector"; then
    log_warn "scp_put failed VM-$vm_id (see $(vm_dir "$vm_id")/scp.err)"
    VM_FAIL_DEPLOY["$vm_id"]=$(( ${VM_FAIL_DEPLOY["$vm_id"]:-0} + 1 ))
    return 1
  fi

  # 构建远程命令 - 使用 heredoc 风格但避免复杂引号
  local remote_cmd
  local remote_signals="/tmp/races-vm${vm_id}_signals.csv"
  remote_cmd="chmod +x /tmp/syz-race-collector; "
  # 启动前先清空 signals 文件，确保写入新的 header
  remote_cmd+="rm -f ${remote_signals}; "
  remote_cmd+="/tmp/syz-race-collector "
  remote_cmd+="--interval=${COLLECTOR_SAMPLE_INTERVAL} "
  remote_cmd+="--format=${OUTPUT_FORMAT} "
  remote_cmd+="--race-threshold=${RACE_THRESHOLD} "
  remote_cmd+="--uaf-threshold=${UAF_THRESHOLD} "
  remote_cmd+="--no-lru "  # 禁用 VM 内部 LRU 过滤，由外部统一去重
  remote_cmd+="-o /tmp/races-vm${vm_id}.${OUTPUT_FORMAT} "
  remote_cmd+="--signals ${remote_signals} "
  remote_cmd+="</dev/null >/tmp/collector-vm${vm_id}.log 2>&1 & "
  remote_cmd+="echo \$! > /tmp/collector-vm${vm_id}.pid; "
  remote_cmd+="sleep 0.2; "
  remote_cmd+="echo started"

  if ! ssh_run "$vm_id" "$port" "$remote_cmd"; then
    log_warn "start collector failed VM-$vm_id (see $(vm_dir "$vm_id")/ssh.err)"
    VM_FAIL_DEPLOY["$vm_id"]=$(( ${VM_FAIL_DEPLOY["$vm_id"]:-0} + 1 ))
    return 1
  fi

  VM_LAST_DEPLOY_TS["$vm_id"]="$(date +%s)"
  VM_FAIL_DEPLOY["$vm_id"]=0
  VM_SIGNALS_COLLECTED_LINES["$vm_id"]=0  # 重置已收集行数（新 collector = 新文件）
  log_info "Collector deployed on VM-$vm_id."
  
  # 部署后等待几秒让 collector 采样，然后立即收集一次
  log_info "Waiting 2s for initial sampling, then collecting..."
  sleep 2
  collect_data "$vm_id" "$port" || true
  
  return 0
}

deploy_if_needed() {
  local vm_id="$1"; local port="$2"
  if ! check_vm_ssh "$port"; then
    log_warn "VM-$vm_id SSH not reachable yet (port $port)"
    return 1
  fi
  if collector_alive_on_vm "$vm_id" "$port"; then
    log_debug "Collector already running on VM-$vm_id"
    return 0
  fi
  log_warn "Collector missing on VM-$vm_id, redeploying..."
  deploy_collector "$vm_id" "$port" || true
  return 0
}

collect_data() {
  local vm_id="$1"; local port="$2"
  local timestamp; timestamp="$(date +%Y%m%d_%H%M%S)"

  log_debug "collect_data called: vm_id=$vm_id port=$port"

  if ! check_vm_ssh "$port"; then
    log_warn "Collect skipped: VM-$vm_id SSH unreachable (port $port)"
    VM_FAIL_COLLECT["$vm_id"]=$(( ${VM_FAIL_COLLECT["$vm_id"]:-0} + 1 ))
    return 1
  fi

  log_debug "SSH check passed, proceeding with SCP"

  local out_file="$OUTPUT_DIR/vm${vm_id}_${timestamp}.${OUTPUT_FORMAT}"
  local remote="/tmp/races-vm${vm_id}.${OUTPUT_FORMAT}"
  
  # 收集统计文件
  if scp_get "$vm_id" "$port" "$remote" "$out_file"; then
    log_info "Collected stats VM-$vm_id -> $out_file"
    ssh_run "$vm_id" "$port" "> $remote" || true
  fi
  
  # 收集 signals 文件（详细 race pair 信息）
  local signals_file="$OUTPUT_DIR/vm${vm_id}_signals.csv"
  local remote_signals="/tmp/races-vm${vm_id}_signals.csv"
  local remote_debug_log="/tmp/collector-vm${vm_id}.log"
  local local_debug_log="$OUTPUT_DIR/vm${vm_id}_collector.log"
  
  # 先 sync 文件系统，确保所有缓冲区数据写入磁盘
  ssh_run "$vm_id" "$port" "sync" 2>/dev/null || true
  
  # 调试：在 VM 上直接检查 signals 文件行数和大小（直接用 ssh 获取输出）
  local ssh_opts; ssh_opts="$(ssh_opts_common)"
  local remote_line_count remote_file_size remote_head remote_tail
  # shellcheck disable=SC2086
  remote_line_count=$(timeout 10 ssh $ssh_opts -p "$port" -i "$SSH_KEY" "${SSH_USER}@localhost" \
    "wc -l < $remote_signals 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]')
  # shellcheck disable=SC2086
  remote_file_size=$(timeout 10 ssh $ssh_opts -p "$port" -i "$SSH_KEY" "${SSH_USER}@localhost" \
    "stat -c %s $remote_signals 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]')
  # shellcheck disable=SC2086
  remote_head=$(timeout 10 ssh $ssh_opts -p "$port" -i "$SSH_KEY" "${SSH_USER}@localhost" \
    "head -2 $remote_signals 2>/dev/null || echo 'no-file'" 2>/dev/null)
  # shellcheck disable=SC2086
  remote_tail=$(timeout 10 ssh $ssh_opts -p "$port" -i "$SSH_KEY" "${SSH_USER}@localhost" \
    "tail -1 $remote_signals 2>/dev/null || echo 'no-file'" 2>/dev/null)
  log_info "VM-$vm_id: signals file on VM: lines=$remote_line_count size=${remote_file_size}B"
  log_info "VM-$vm_id: signals head: $remote_head"
  log_info "VM-$vm_id: signals tail: $remote_tail"
  
  # 先收集 collector 的 debug log
  if scp_get "$vm_id" "$port" "$remote_debug_log" "$local_debug_log.tmp" 2>/dev/null; then
    # 追加到本地 log 文件
    if [[ -f "$local_debug_log" ]]; then
      cat "$local_debug_log.tmp" >> "$local_debug_log" 2>/dev/null || true
    else
      mv "$local_debug_log.tmp" "$local_debug_log" 2>/dev/null || true
    fi
    rm -f "$local_debug_log.tmp"
    log_debug "Collected debug log VM-$vm_id -> $local_debug_log"
  fi
  
  # 收集 signals 文件
  # 使用增量收集：只获取上次收集后新增的行
  local last_collected_lines="${VM_SIGNALS_COLLECTED_LINES[$vm_id]:-0}"
  local current_lines
  # shellcheck disable=SC2086
  current_lines=$(timeout 10 ssh $ssh_opts -p "$port" -i "$SSH_KEY" "${SSH_USER}@localhost" \
    "wc -l < $remote_signals 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]')
  current_lines="${current_lines:-0}"
  
  if [[ "$current_lines" -le "$last_collected_lines" ]]; then
    log_info "VM-$vm_id: no new signals (current=$current_lines, last_collected=$last_collected_lines)"
  elif [[ "$current_lines" -gt 1 ]]; then
    # 有新数据，只收集新增的行
    local start_line=$((last_collected_lines + 1))
    # 如果是首次收集（last=0），跳过 header（从第2行开始）
    if [[ "$last_collected_lines" -eq 0 ]]; then
      start_line=2
    fi
    local new_lines=$((current_lines - start_line + 1))
    
    if [[ "$new_lines" -gt 0 ]]; then
      log_info "VM-$vm_id: collecting lines $start_line-$current_lines ($new_lines new signals)"
      
      # 使用 sed 提取新增的行（比 scp 整个文件更高效）
      local new_data
      # shellcheck disable=SC2086
      new_data=$(timeout 30 ssh $ssh_opts -p "$port" -i "$SSH_KEY" "${SSH_USER}@localhost" \
        "sed -n '${start_line},${current_lines}p' $remote_signals 2>/dev/null" 2>/dev/null)
      
      if [[ -n "$new_data" ]]; then
        # 追加到本地 signals 文件
        if [[ ! -f "$signals_file" ]]; then
          # 首次：先写入 header
          echo "signal_hash,var1,stack1,var2,stack2,addr1,addr2,delta_ns,type" > "$signals_file"
        fi
        echo "$new_data" >> "$signals_file"
        
        # 更新已收集行数
        VM_SIGNALS_COLLECTED_LINES["$vm_id"]="$current_lines"
        
        log_info "Collected signals VM-$vm_id -> $signals_file (new: $new_lines records, total on VM: $current_lines)"
      else
        log_warn "VM-$vm_id: failed to get new signals via ssh"
      fi
    fi
  fi

  VM_LAST_COLLECT_TS["$vm_id"]="$(date +%s)"
  VM_FAIL_COLLECT["$vm_id"]=0
  return 0
}

collect_all_data() {
  log_debug "collect_all_data called, VM_PORTS has ${#VM_PORTS[@]} entries"
  for vm_id in "${!VM_PORTS[@]}"; do
    log_debug "Collecting from VM-$vm_id port=${VM_PORTS[$vm_id]}"
    collect_data "$vm_id" "${VM_PORTS[$vm_id]}" || true
  done
  
  # 如果启用自动去重，执行增量去重
  if $AUTO_DEDUP; then
    incremental_dedup
  fi
}

# ============================================================================
# 增量去重（每次收集后调用）
# 使用 --varname-stats 同时统计两种指标：
#   1. unique_signals: 基于 (var1, stack1, var2, stack2) 的唯一信号
#   2. unique_varname_pairs: 基于 (var1, var2) 的唯一变量名对（与主 fuzzer 一致）
#
# 修复：timeseries 记录的是**累计总数**，不是本次新增数
# ============================================================================
incremental_dedup() {
  local dedup_script="$SCRIPT_DIR/dedup_races.py"
  local dedup_log="$OUTPUT_DIR/dedup_debug.log"
  
  echo "======== $(date -Iseconds) incremental_dedup ========" >> "$dedup_log"
  
  if [[ ! -f "$dedup_script" ]]; then
    log_debug "Dedup script not found, skipping"
    echo "ERROR: dedup script not found: $dedup_script" >> "$dedup_log"
    return 0
  fi
  
  # 去重 signals 文件
  local signals_unique="$OUTPUT_DIR/all_signals_unique.csv"
  local temp_merged="$OUTPUT_DIR/.temp_signals_merged.csv"
  local stats_file="$OUTPUT_DIR/.dedup_stats.txt"
  
  # 列出当前存在的 vm*_signals.csv 文件
  echo "Looking for vm*_signals.csv files in $OUTPUT_DIR:" >> "$dedup_log"
  ls -la "$OUTPUT_DIR"/vm*_signals.csv 2>&1 >> "$dedup_log" || echo "  (no files found)" >> "$dedup_log"
  
  # 合并所有 vm*_signals.csv 文件到临时文件
  local has_new_signals=false
  local first=true
  local merged_count=0
  for f in "$OUTPUT_DIR"/vm*_signals.csv; do
    if [[ -f "$f" && -s "$f" ]]; then
      local flines; flines=$(wc -l < "$f" 2>/dev/null || echo 0)
      echo "  Found: $f ($flines lines)" >> "$dedup_log"
      has_new_signals=true
      merged_count=$((merged_count + 1))
      if $first; then
        cat "$f" > "$temp_merged"
        first=false
      else
        tail -n +2 "$f" >> "$temp_merged" 2>/dev/null || true
      fi
    fi
  done
  
  echo "has_new_signals=$has_new_signals, merged_count=$merged_count" >> "$dedup_log"
  
  # 如果没有新数据，但有历史数据，仍然记录累计值
  if ! $has_new_signals; then
    echo "No new vm*_signals.csv files found" >> "$dedup_log"
    if [[ -f "$signals_unique" && -s "$signals_unique" ]]; then
      echo "Using existing $signals_unique for cumulative stats" >> "$dedup_log"
      # 使用 --analyze 获取累计统计
      local stats; stats=$(python3 "$dedup_script" --analyze "$signals_unique" 2>&1)
      echo "analyze output:" >> "$dedup_log"
      echo "$stats" >> "$dedup_log"
      local unique_signals=0
      local unique_varnames=0
      if [[ -n "$stats" ]]; then
        # 注意：优先匹配 "Unique signals (fuzzer):" 格式（与 fuzzer 一致的计数）
        unique_signals=$(echo "$stats" | grep -oP 'Unique signals \(fuzzer\):\s+\K\d+' 2>/dev/null || echo "")
        # 如果没找到 fuzzer 格式，回退到普通格式
        if [[ -z "$unique_signals" ]]; then
          unique_signals=$(echo "$stats" | grep -oP 'Unique signals:\s+\K\d+' 2>/dev/null | head -1 || echo 0)
        fi
        unique_varnames=$(echo "$stats" | grep -oP 'Unique VarName pairs:\s+\K\d+' 2>/dev/null || echo 0)
      fi
      echo "Parsed: unique_signals=$unique_signals, unique_varnames=$unique_varnames" >> "$dedup_log"
      log_info "No new signals, recording cumulative: signals=$unique_signals varname_pairs=$unique_varnames"
      record_timeseries "$unique_signals" "$unique_varnames"
    else
      echo "No history file exists: $signals_unique" >> "$dedup_log"
      log_debug "No new signals and no history file"
    fi
    return 0
  fi
  
  # 有新数据，合并已有去重结果
  echo "Merging with existing $signals_unique" >> "$dedup_log"
  if [[ -f "$signals_unique" && -s "$signals_unique" ]]; then
    local existing_lines; existing_lines=$(wc -l < "$signals_unique" 2>/dev/null || echo 0)
    echo "Existing unique file has $existing_lines lines" >> "$dedup_log"
    local first_line; first_line=$(head -1 "$signals_unique" 2>/dev/null || echo "")
    if [[ "$first_line" == signal_hash,* ]]; then
      tail -n +2 "$signals_unique" >> "$temp_merged" 2>/dev/null || true
    else
      cat "$signals_unique" >> "$temp_merged" 2>/dev/null || true
    fi
  else
    echo "No existing unique file" >> "$dedup_log"
  fi
  
  local merged_lines; merged_lines=$(wc -l < "$temp_merged" 2>/dev/null || echo 0)
  echo "Temp merged file has $merged_lines lines before dedup" >> "$dedup_log"
  
  # 执行去重
  echo "Running: python3 $dedup_script $temp_merged $signals_unique --format signals --varname-stats" >> "$dedup_log"
  if python3 "$dedup_script" "$temp_merged" "$signals_unique" --format signals --varname-stats 2>"$stats_file"; then
    echo "Dedup succeeded, stats_file content:" >> "$dedup_log"
    cat "$stats_file" >> "$dedup_log" 2>/dev/null || true
    
    # 解析统计结果 - 这是**累计总数**
    # 注意：现在使用 "Unique signals (fuzzer)" 作为主要的 signals 计数（与 fuzzer 一致，max 20 stacks/pair）
    local unique_signals=0
    local unique_varnames=0
    if [[ -f "$stats_file" ]]; then
      # 优先使用与 fuzzer 一致的计数方法
      unique_signals=$(grep -oP 'Unique signals \(fuzzer\):\s+\K\d+' "$stats_file" 2>/dev/null || echo 0)
      # 如果没找到 fuzzer 格式，回退到普通格式
      if [[ "$unique_signals" == "0" ]]; then
        unique_signals=$(grep -oP 'Unique signals:\s+\K\d+' "$stats_file" 2>/dev/null | head -1 || echo 0)
      fi
      unique_varnames=$(grep -oP 'Unique VarName pairs:\s+\K\d+' "$stats_file" 2>/dev/null || echo 0)
    fi
    
    echo "Parsed: unique_signals=$unique_signals, unique_varnames=$unique_varnames" >> "$dedup_log"
    log_info "Cumulative: signals=$unique_signals (fuzzer-compatible, max 20 stacks/pair) varname_pairs=$unique_varnames"
    
    # 记录累计总数到时间序列
    record_timeseries "$unique_signals" "$unique_varnames"
    
    # 清理 VM 临时文件（已合并到 signals_unique）
    if $CLEAN_TEMP_FILES; then
      echo "Cleaning vm*_signals.csv files (CLEAN_TEMP_FILES=true)" >> "$dedup_log"
      for f in "$OUTPUT_DIR"/vm*_signals.csv; do
        if [[ -f "$f" ]]; then
          echo "  Removing: $f" >> "$dedup_log"
          rm -f "$f"
        fi
      done
    else
      echo "Keeping vm*_signals.csv files (CLEAN_TEMP_FILES=false)" >> "$dedup_log"
    fi
  else
    echo "Dedup FAILED" >> "$dedup_log"
  fi
  rm -f "$temp_merged" "$stats_file"
}

# ============================================================================
# 记录时间序列数据
# 参数:
#   $1: unique_signals - 基于 (var+stack) 4元组的唯一信号数
#   $2: unique_varname_pairs - 基于 (var) 2元组的唯一变量名对数（可选，与 fuzzer 一致）
# ============================================================================
record_timeseries() {
  local unique_signals="${1:-0}"
  local unique_varnames="${2:-0}"
  local timeseries_file="$OUTPUT_DIR/race_timeseries.csv"
  local now_ts; now_ts="$(date +%s)"
  local now_iso; now_iso="$(date -Iseconds)"
  
  # 计算运行时间（秒）
  local elapsed=0
  if [[ -n "${START_TIME:-}" ]]; then
    elapsed=$((now_ts - START_TIME))
  fi
  
  # 如果文件不存在，写入 header
  if [[ ! -f "$timeseries_file" ]]; then
    echo "timestamp,elapsed_sec,elapsed_min,unique_signals,unique_varname_pairs" > "$timeseries_file"
  fi
  
  # 追加数据点
  local elapsed_min; elapsed_min=$(awk "BEGIN {printf \"%.2f\", $elapsed / 60}")
  echo "$now_iso,$elapsed,$elapsed_min,$unique_signals,$unique_varnames" >> "$timeseries_file"
  
  log_info "Timeseries: elapsed=${elapsed}s signals=$unique_signals varname_pairs=$unique_varnames"
}

deploy_to_all_vms() {
  for vm_id in "${!VM_PORTS[@]}"; do
    deploy_if_needed "$vm_id" "${VM_PORTS[$vm_id]}" || true
  done
}

print_vm_state_snapshot() {
  local now; now="$(date +%s)"
  local vm_count=0
  vm_count=${#VM_PORTS[@]}

  log_info "VM state snapshot (known_vms=$vm_count):"
  if (( vm_count == 0 )); then
    log_info "  (none)"
    return 0
  fi

  for vm_id in "${!VM_PORTS[@]}"; do
    local port="${VM_PORTS[$vm_id]}"
    local ld="${VM_LAST_DEPLOY_TS["$vm_id"]:-0}"
    local lc="${VM_LAST_COLLECT_TS["$vm_id"]:-0}"
    local fd="${VM_FAIL_DEPLOY["$vm_id"]:-0}"
    local fc="${VM_FAIL_COLLECT["$vm_id"]:-0}"
    local ld_age=$(( ld>0 ? now-ld : -1 ))
    local lc_age=$(( lc>0 ? now-lc : -1 ))
    log_info "  VM-$vm_id port=$port deploy_age=${ld_age}s collect_age=${lc_age}s fail_deploy=$fd fail_collect=$fc"
  done
}

# ============================================================================
# 增量解析 syzkaller.log
# ============================================================================
LOG_POS=1
LOG_LAST_LINES=0

parse_vm_ports_incremental() {
  local log_file="$1"
  if [[ ! -f "$log_file" ]]; then
    log_debug "Log not found yet: $log_file"
    return 0
  fi

  local total
  total="$(wc -l < "$log_file" 2>/dev/null || echo 0)"

  if (( total < LOG_LAST_LINES )); then
    log_warn "Log seems truncated (lines $LOG_LAST_LINES -> $total), reset scan."
    LOG_POS=1
  fi
  LOG_LAST_LINES="$total"

  if (( LOG_POS > total )); then
    return 0
  fi

  local new_lines=$(( total - LOG_POS + 1 ))
  log_debug "Parsing log incrementally: from line $LOG_POS, new_lines=$new_lines, total=$total"

  local found=0
  while IFS= read -r line; do
    if [[ $line =~ VM-([0-9]+)\ ready:\ ssh\ -p\ ([0-9]+) ]]; then
      local vm_id="${BASH_REMATCH[1]}"
      local port="${BASH_REMATCH[2]}"

      if [[ -z "${VM_PORTS[$vm_id]:-}" ]]; then
        log_info "Detected VM-$vm_id ready on port $port"
      elif [[ "${VM_PORTS[$vm_id]}" != "$port" ]]; then
        log_warn "VM-$vm_id port changed ${VM_PORTS[$vm_id]} -> $port (likely reboot)"
      else
        log_debug "VM-$vm_id ready again on same port $port (likely reboot)"
      fi

      VM_PORTS["$vm_id"]="$port"
      found=$((found + 1))
    fi
  done < <(sed -n "${LOG_POS},\$p" "$log_file" 2>/dev/null || true)

  LOG_POS=$(( total + 1 ))

  if (( found > 0 )); then
    log_info "parse_vm_ports: processed $new_lines new lines, found $found ready events, known_vms=${#VM_PORTS[@]}"
  else
    log_debug "parse_vm_ports: processed $new_lines new lines, found 0 ready events"
  fi
}

wait_for_any_vm_ready() {
  local log_file="$1"
  local timeout="${2:-$BOOT_WAIT_TIMEOUT}"
  local start; start="$(date +%s)"

  log_info "Waiting for at least one VM ready (timeout=${timeout}s)..."
  while true; do
    parse_vm_ports_incremental "$log_file" || true
    if (( ${#VM_PORTS[@]} > 0 )); then
      log_info "VM detected."
      print_vm_state_snapshot
      return 0
    fi
    local now; now="$(date +%s)"
    if (( now - start >= timeout )); then
      log_warn "Timeout waiting VM ready. Check $log_file for VM ready lines."
      return 1
    fi
    sleep 2
  done
}

# ============================================================================
# merge/dedup（保留你原逻辑）
# ============================================================================
merge_data() {
  local merged_file="$OUTPUT_DIR/all_races_merged.${OUTPUT_FORMAT}"

  log_info "Merging stats files into: $merged_file"

  if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
    local first=true
    # 只合并统计文件（vm*_时间戳.csv），不包括 signals 文件
    for f in "$OUTPUT_DIR"/vm*_2*.csv; do
      if [[ -f "$f" ]]; then
        if $first; then
          cat "$f" > "$merged_file"
          first=false
        else
          tail -n +2 "$f" >> "$merged_file" || true
        fi
      fi
    done

    if [[ -f "$merged_file" ]]; then
      local total_count; total_count="$(wc -l < "$merged_file" || echo 0)"
      log_info "Merged stats: $merged_file ($total_count lines)"
      # 注意：统计数据不需要去重，每行是一个采样周期的统计
      
      # 清理临时统计文件
      if $CLEAN_TEMP_FILES; then
        log_info "Cleaning temporary stats files..."
        rm -f "$OUTPUT_DIR"/vm*_2*.csv
      fi
    else
      log_info "No stats files to merge"
    fi
  else
    local temp_merged="$OUTPUT_DIR/.temp_merged.json"
    echo "[" > "$temp_merged"
    local first=true
    for f in "$OUTPUT_DIR"/vm*.json; do
      if [[ -f "$f" ]]; then
        if $first; then first=false; else echo "," >> "$temp_merged"; fi
        sed '1d;$d' "$f" >> "$temp_merged" || true
      fi
    done
    echo "]" >> "$temp_merged"
    mv "$temp_merged" "$merged_file"
    log_info "Merged JSON stats: $merged_file"
    # 注意：JSON 统计数据也不需要去重
  fi
  
  # 合并并去重 signals 文件
  merge_signals
}

merge_signals() {
  local merged_signals="$OUTPUT_DIR/all_signals_merged.csv"
  local deduped_signals="$OUTPUT_DIR/all_signals_unique.csv"
  local dedup_script="$SCRIPT_DIR/dedup_races.py"
  
  log_info "Merging signals files..."
  
  # 如果已有去重结果，先合并进来
  local first=true
  if [[ -f "$deduped_signals" && -s "$deduped_signals" ]]; then
    cat "$deduped_signals" > "$merged_signals"
    first=false
  fi
  
  for f in "$OUTPUT_DIR"/vm*_signals.csv; do
    if [[ -f "$f" && -s "$f" ]]; then
      if $first; then
        cat "$f" > "$merged_signals"
        first=false
      else
        tail -n +2 "$f" >> "$merged_signals" 2>/dev/null || true
      fi
    fi
  done
  
  if [[ -f "$merged_signals" ]]; then
    local total_count; total_count="$(wc -l < "$merged_signals" || echo 0)"
    log_info "Merged signals: $merged_signals ($total_count lines)"
    
    if [[ -f "$dedup_script" ]]; then
      log_info "Deduplicating signals..."
      python3 "$dedup_script" "$merged_signals" "$deduped_signals" --format signals -q || true
      if [[ -f "$deduped_signals" ]]; then
        local unique_count; unique_count="$(wc -l < "$deduped_signals" || echo 0)"
        log_info "Unique signals: $deduped_signals ($unique_count lines)"
        
        # 清理临时 signals 文件
        if $CLEAN_TEMP_FILES; then
          log_info "Cleaning temporary signals files..."
          rm -f "$OUTPUT_DIR"/vm*_signals.csv
          rm -f "$merged_signals"
        fi
      fi
    fi
  else
    log_info "No signals files found"
  fi
}

# ============================================================================
# 主循环（time-driven）
# ============================================================================
SYZ_PID=""
LOG_FILE=""
CLEANUP_RAN=false

cleanup() {
  $CLEANUP_RAN && return 0
  CLEANUP_RAN=true

  set +e
  log_info "Cleaning up..."

  log_info "Collecting final data..."
  collect_all_data || true

  if [[ -n "${SYZ_PID:-}" ]] && kill -0 "$SYZ_PID" 2>/dev/null; then
    log_info "Stopping syzkaller (PID: $SYZ_PID)..."
    kill -TERM "$SYZ_PID" 2>/dev/null || true
    wait "$SYZ_PID" 2>/dev/null || true
  fi

  log_info "Final VM snapshot:"
  print_vm_state_snapshot || true

  log_info "Merging collected data..."
  merge_data || true

  log_info "Cleanup complete. Data saved to: $OUTPUT_DIR"
  log_info "Debug logs: $CMD_LOG, per-VM logs: $OUTPUT_DIR/vm*/"
}

run_main_loop() {
  START_TIME="$(date +%s)"  # 全局变量，用于时间序列记录
  # 第一次收集延迟一点，等待 collector 完成初始采样
  local next_collect=$((START_TIME + 30))  # 30秒后开始第一次收集
  local next_deploy="$START_TIME"
  local next_status="$START_TIME"

  while true; do
    local now; now="$(date +%s)"
    local elapsed=$((now - START_TIME))

    if [[ $DURATION -gt 0 ]] && [[ $elapsed -ge $DURATION ]]; then
      log_info "Duration reached ($DURATION seconds), stopping..."
      break
    fi

    if ! kill -0 "$SYZ_PID" 2>/dev/null; then
      log_warn "syz-manager exited"
      break
    fi

    if (( now >= next_deploy )); then
      log_info "Deploy tick (every ${DEPLOY_CHECK_INTERVAL}s)..."
      parse_vm_ports_incremental "$LOG_FILE" || true
      deploy_to_all_vms || true
      next_deploy=$((now + DEPLOY_CHECK_INTERVAL))
    fi

    if (( now >= next_collect )); then
      log_info "Collect tick (every ${COLLECT_INTERVAL}s)..."
      collect_all_data || true
      next_collect=$((now + COLLECT_INTERVAL))
    fi

    if (( now >= next_status )); then
      log_info "Status: elapsed=${elapsed}s known_vms=${#VM_PORTS[@]} syz_pid=$SYZ_PID"
      print_vm_state_snapshot || true
      next_status=$((now + 60))
    fi

    sleep 1
  done
}

# ============================================================================
# main
# ============================================================================
main() {
  parse_args "$@"
  parse_config

  if $TRACE; then
    export PS4='+ $(date +"%Y-%m-%d %H:%M:%S") [${BASH_SOURCE}:${LINENO}] '
    set -x
    log_info "Trace enabled (set -x)."
  fi

  build_collector

  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  LOG_FILE="$OUTPUT_DIR/syzkaller.log"

  log_info "Starting syzkaller..."
  log_info "  Config: $SYZ_CONFIG"
  log_info "  Log: $LOG_FILE"

  if $DRY_RUN; then
    log_info "[DRY-RUN] Would start: $SYZ_MANAGER -config $SYZ_CONFIG"
    exit 0
  fi

  if [[ ! -x "$SYZ_MANAGER" ]]; then
    log_error "syz-manager not found or not executable: $SYZ_MANAGER"
    exit 1
  fi

  : > "$LOG_FILE"
  LOG_POS=1
  LOG_LAST_LINES=0

  log_info "Launching: $SYZ_MANAGER -config $SYZ_CONFIG"
  ($SYZ_MANAGER -config "$SYZ_CONFIG" 2>&1 | tee -a "$LOG_FILE") &
  SYZ_PID=$!
  log_info "syz-manager started with PID: $SYZ_PID"

  wait_for_any_vm_ready "$LOG_FILE" "$BOOT_WAIT_TIMEOUT" || true
  run_main_loop
}

main "$@"
