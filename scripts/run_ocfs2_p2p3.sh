#!/bin/bash
# ocfs2 Phase2 (2h) → Phase3 validate (2h) 自动流水线
set -euo pipefail
cd /home/zzzccc/BASS/DDRD-syzkaller

LOGDIR=exp/ocfs2/logs
mkdir -p "$LOGDIR"

P2_LOG="$LOGDIR/phase2-uaf-v4.log"
P3_LOG="$LOGDIR/phase3-validate.log"

# 信号处理：确保子进程被清理
cleanup() {
    echo "[$(date)] Signal received, cleaning up..."
    kill $SYZ_PID 2>/dev/null || true
    wait $SYZ_PID 2>/dev/null || true
    exit 1
}
trap cleanup SIGTERM SIGINT

echo "========================================"
echo "ocfs2 Phase2+Phase3 Pipeline"
echo "========================================"

# --- Phase 2: UAF (2h) ---
echo "[$(date)] Phase 2 (UAF) starting — 2h timeout, 6 VMs"
rm -f exp/ocfs2/workdir/vm-*-copy.qcow2
timeout 2h ./bin/syz-manager -config ./exp/ocfs2/phase2-uaf.cfg > "$P2_LOG" 2>&1 &
SYZ_PID=$!
wait $SYZ_PID || true
echo "[$(date)] Phase 2 ended"

# 提取最终统计
LAST_STAT=$(strings "$P2_LOG" | grep 'ddrd pairs total' | tail -1)
echo "[Phase 2 final] $LAST_STAT"

sleep 5

# --- Phase 3: Validate (2h) ---
echo "[$(date)] Phase 3 (Validate) starting — 2h timeout, 6 VMs"
rm -f exp/ocfs2/workdir/vm-*-copy.qcow2
timeout 2h ./bin/syz-manager -config ./exp/ocfs2/phase3-validate.cfg -mode uaf-validate > "$P3_LOG" 2>&1 &
SYZ_PID=$!
wait $SYZ_PID || true
echo "[$(date)] Phase 3 ended"

LAST_STAT3=$(strings "$P3_LOG" | tail -3)
echo "[Phase 3 final] $LAST_STAT3"

echo "========================================"
echo "[$(date)] Pipeline complete"
echo "========================================"
