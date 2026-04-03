#!/usr/bin/env bash
# ============================================================================
# run_ocfs2_3phase.sh — ocfs2 三阶段实验流水线
#
# Phase 1: 普通 fuzz (收集 corpus)       4h  6VM  4核8G
# Phase 2: UAF mode fuzz (收集 race pairs) 4h 12VM  2核4G
# Phase 3: Validate (验证)               4h 12VM  2核4G
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_HOME="$(dirname "$SCRIPT_DIR")"
SYZ_MANAGER="$PROJECT_HOME/bin/syz-manager"
EXP_DIR="$PROJECT_HOME/exp/ocfs2"
LOG_DIR="$EXP_DIR/logs"

PHASE1_CFG="$EXP_DIR/phase1-corpus.cfg"
PHASE2_CFG="$EXP_DIR/phase2-uaf.cfg"
PHASE3_CFG="$EXP_DIR/phase3-validate.cfg"

DURATION="4h"

mkdir -p "$LOG_DIR"

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo "[$(timestamp)] $*" | tee -a "$LOG_DIR/pipeline.log"; }

run_phase() {
    local phase_name="$1"
    local cfg="$2"
    local logfile="$LOG_DIR/${phase_name}.log"

    log "========== $phase_name 开始 =========="
    log "配置: $cfg"
    log "时长: $DURATION"
    log "日志: $logfile"

    timeout "$DURATION" "$SYZ_MANAGER" -config "$cfg" > "$logfile" 2>&1 || true
    local exit_code=$?

    if [[ $exit_code -eq 124 ]]; then
        log "$phase_name 正常完成 (timeout 到时)"
    elif [[ $exit_code -eq 0 ]]; then
        log "$phase_name 正常退出"
    else
        log "$phase_name 异常退出 (code=$exit_code)"
    fi

    # 等待所有 QEMU 进程退出
    sleep 10
    log "$phase_name 日志最后 5 行:"
    tail -5 "$logfile" | while read -r line; do log "  $line"; done
    log "========== $phase_name 结束 =========="
    echo ""
}

# ============================================================================
log "ocfs2 三阶段实验流水线启动"
log "总预计时间: ~12h + 间隔"
log ""

run_phase "phase1-corpus"   "$PHASE1_CFG"
run_phase "phase2-uaf"      "$PHASE2_CFG"
run_phase "phase3-validate"  "$PHASE3_CFG"

log "所有阶段完成!"
log "工作目录: $EXP_DIR/workdir"
log "日志目录: $LOG_DIR"
