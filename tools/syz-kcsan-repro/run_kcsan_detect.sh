#!/bin/bash
# run_kcsan_detect.sh - Run reproducer in QEMU with KCSAN kernel and detect races
#
# Usage:
#   ./run_kcsan_detect.sh [options]
#
# Options:
#   --kernel <path>         Path to KCSAN bzImage
#   --image <path>          Path to rootfs image (qcow2/raw)
#   --sshkey <path>         Path to SSH private key
#   --reproducer <path>     Path to compiled reproducer binary
#   --record-dir <path>     Record directory (auto-detect reproducer)
#   --output-dir <path>     Output directory for results
#   --timeout <sec>         Per-run timeout (default: 120)
#   --repeat <n>            Repeats per run (default: 200)
#   --delay-sweep           Enable delay sweep mode
#   --ssh-port <port>       SSH forwarding port (default: auto)
#   --extra-qemu <args>     Extra QEMU arguments (e.g., -hdb fs.qcow2)
#   --fs-type <name>         Filesystem type for /dev/sdb mount (auto|btrfs|xfs|f2fs|jfs|ext4)
#   --modules <path>        Path to modules directory (for insmod)
#   --mem <mb>              QEMU memory in MB (default: 4096)
#   --cpu <n>               QEMU CPUs (default: 2)
#   --adaptive              Enable adaptive timing feedback loop
#   --adaptive-batch <n>    Iterations per adaptive batch (default: 50)
#   --adaptive-max <n>      Max adaptive trials (default: 30)
#   --adaptive-max-seconds <n>  Max adaptive wall time in seconds (default: 900)
#   --adaptive-zero-hit-stop <n> Stop adaptive if both kprobes are 0-hit for N trials (default: 3)
#   --offset-us <n>         Fixed offset_us for non-adaptive runs (default: 0)
#   --udelay-task <n>       Fixed kcsan udelay_task for non-adaptive runs (default: 0=kernel default)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Global state (must be visible to cleanup trap)
QEMU_PID=""
SNAPSHOT_IMG=""
FS_DISK_SNAPSHOT=""

cleanup() {
    if [[ -n "${QEMU_PID}" ]]; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    rm -f "${SNAPSHOT_IMG}" 2>/dev/null || true
    rm -f "${FS_DISK_SNAPSHOT}" 2>/dev/null || true
}
trap cleanup EXIT

# Defaults
KERNEL_BZIMAGE=""
ROOT_IMAGE="${SYZKALLER_ROOT}/images/bookworm.img"
SSH_KEY="${SYZKALLER_ROOT}/images/bookworm.id_rsa"
REPRODUCER=""
RECORD_DIR=""
OUTPUT_DIR=""
TIMEOUT=120
REPEAT=200
DELAY_SWEEP=0
SSH_PORT=0
EXTRA_QEMU=""
MODULES_DIR=""
FS_DISK=""
FS_TYPE=""
MEM=4096
CPUS=2
KPROBE_FUNC1="btrfs_defrag_file"
KPROBE_FUNC2="btrfs_writepages"
ADAPTIVE=0
ADAPTIVE_BATCH=50
ADAPTIVE_MAX_TRIALS=30
ADAPTIVE_MAX_SECONDS=900
ADAPTIVE_ZERO_HIT_STOP=3
RUN_OFFSET_US=0
RUN_UDELAY_TASK=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)       KERNEL_BZIMAGE="$2"; shift 2 ;;
        --image)        ROOT_IMAGE="$2"; shift 2 ;;
        --sshkey)       SSH_KEY="$2"; shift 2 ;;
        --reproducer)   REPRODUCER="$2"; shift 2 ;;
        --record-dir)   RECORD_DIR="$2"; shift 2 ;;
        --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        --timeout)      TIMEOUT="$2"; shift 2 ;;
        --repeat)       REPEAT="$2"; shift 2 ;;
        --delay-sweep)  DELAY_SWEEP=1; shift ;;
        --ssh-port)     SSH_PORT="$2"; shift 2 ;;
        --extra-qemu)   EXTRA_QEMU="$2"; shift 2 ;;
        --fs-disk)      FS_DISK="$2"; shift 2 ;;
        --fs-type)      FS_TYPE="$2"; shift 2 ;;
        --modules)      MODULES_DIR="$2"; shift 2 ;;
        --mem)          MEM="$2"; shift 2 ;;
        --cpu)          CPUS="$2"; shift 2 ;;
        --kprobe1)      KPROBE_FUNC1="$2"; shift 2 ;;
        --kprobe2)      KPROBE_FUNC2="$2"; shift 2 ;;
        --adaptive)     ADAPTIVE=1; shift ;;
        --adaptive-batch) ADAPTIVE_BATCH="$2"; shift 2 ;;
        --adaptive-max) ADAPTIVE_MAX_TRIALS="$2"; shift 2 ;;
        --adaptive-max-seconds) ADAPTIVE_MAX_SECONDS="$2"; shift 2 ;;
        --adaptive-zero-hit-stop) ADAPTIVE_ZERO_HIT_STOP="$2"; shift 2 ;;
        --offset-us)    RUN_OFFSET_US="$2"; shift 2 ;;
        --udelay-task)  RUN_UDELAY_TASK="$2"; shift 2 ;;
        -h|--help)
            head -25 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Auto-detect paths
if [[ -z "${KERNEL_BZIMAGE}" ]]; then
    KERNEL_BZIMAGE="${SYZKALLER_ROOT}/kernels/output/kcsan/bzImage"
fi

if [[ -n "${RECORD_DIR}" ]] && [[ -z "${REPRODUCER}" ]]; then
    # New standalone approach: barrier_runner + prog0_bin + prog1_bin
    if [[ -f "${RECORD_DIR}/barrier_runner" ]] && [[ -f "${RECORD_DIR}/prog0_bin" ]]; then
        REPRODUCER="${RECORD_DIR}/barrier_runner"
    elif [[ -f "${RECORD_DIR}/reproducer" ]]; then
        REPRODUCER="${RECORD_DIR}/reproducer"
    fi
fi

if [[ -z "${OUTPUT_DIR}" ]]; then
    if [[ -n "${RECORD_DIR}" ]]; then
        OUTPUT_DIR="${RECORD_DIR}/kcsan_results"
    else
        OUTPUT_DIR="./kcsan_results"
    fi
fi

# Auto-detect filesystem type from record-dir/fs-disk if not specified.
if [[ -z "${FS_TYPE}" ]]; then
    case "${RECORD_DIR}" in
        */btrfs/*) FS_TYPE="btrfs" ;;
        */xfs/*)   FS_TYPE="xfs" ;;
        */f2fs/*)  FS_TYPE="f2fs" ;;
        */jfs/*)   FS_TYPE="jfs" ;;
    esac
fi
if [[ -z "${FS_TYPE}" ]] && [[ -n "${FS_DISK}" ]]; then
    case "$(basename "${FS_DISK}")" in
        *btrfs*) FS_TYPE="btrfs" ;;
        *xfs*)   FS_TYPE="xfs" ;;
        *f2fs*)  FS_TYPE="f2fs" ;;
        *jfs*)   FS_TYPE="jfs" ;;
    esac
fi
if [[ -z "${FS_TYPE}" ]]; then
    FS_TYPE="ext4"
fi

mkdir -p "${OUTPUT_DIR}"

# Resolve all paths to absolute (qcow2 backing files need absolute paths)
KERNEL_BZIMAGE="$(realpath "${KERNEL_BZIMAGE}" 2>/dev/null || echo "${KERNEL_BZIMAGE}")"
ROOT_IMAGE="$(realpath "${ROOT_IMAGE}" 2>/dev/null || echo "${ROOT_IMAGE}")"
SSH_KEY="$(realpath "${SSH_KEY}" 2>/dev/null || echo "${SSH_KEY}")"
OUTPUT_DIR="$(realpath "${OUTPUT_DIR}" 2>/dev/null || echo "${OUTPUT_DIR}")"

# Validation
if [[ ! -f "${KERNEL_BZIMAGE}" ]]; then
    echo "[detect] ERROR: KCSAN kernel not found: ${KERNEL_BZIMAGE}"
    exit 1
fi
if [[ ! -f "${ROOT_IMAGE}" ]]; then
    echo "[detect] ERROR: Root image not found: ${ROOT_IMAGE}"
    exit 1
fi
if [[ ! -f "${SSH_KEY}" ]]; then
    echo "[detect] ERROR: SSH key not found: ${SSH_KEY}"
    exit 1
fi
if [[ -z "${REPRODUCER}" ]] || [[ ! -f "${REPRODUCER}" ]]; then
    echo "[detect] ERROR: Reproducer not found: ${REPRODUCER}"
    exit 1
fi

# Find available SSH port
if [[ "${SSH_PORT}" -eq 0 ]]; then
    SSH_PORT=$(python3 -c "
import socket
s = socket.socket()
s.bind(('', 0))
print(s.getsockname()[1])
s.close()
")
fi

echo "[detect] Configuration:"
echo "  Kernel:     ${KERNEL_BZIMAGE}"
echo "  Image:      ${ROOT_IMAGE}"
echo "  Reproducer: ${REPRODUCER}"
echo "  SSH port:   ${SSH_PORT}"
echo "  Output:     ${OUTPUT_DIR}"
echo "  Timeout:    ${TIMEOUT}s"
echo "  Repeat:     ${REPEAT}"
echo "  FS type:    ${FS_TYPE}"
echo "  Fixed offset/us (non-adaptive): ${RUN_OFFSET_US}"
echo "  Fixed udelay_task (non-adaptive): ${RUN_UDELAY_TASK}"
if [[ "${ADAPTIVE}" -eq 1 ]]; then
    echo "  Adaptive max seconds: ${ADAPTIVE_MAX_SECONDS}s"
    echo "  Adaptive zero-hit stop: ${ADAPTIVE_ZERO_HIT_STOP}"
fi

# ==============================================================
# QEMU launch function
# ==============================================================
launch_qemu() {
    SNAPSHOT_IMG=$(mktemp /tmp/kcsan_rootfs_XXXXXX.img)
    
    # Create a snapshot overlay to avoid modifying the original image
    qemu-img create -f qcow2 -b "${ROOT_IMAGE}" -F raw "${SNAPSHOT_IMG}" 2>/dev/null || \
    cp "${ROOT_IMAGE}" "${SNAPSHOT_IMG}"
    
    echo "[detect] Starting QEMU..."
    
    # If no --fs-disk specified, auto-detect from the project images directory
    local FS_DISK_ARGS=""
    local TMP_FS_OVERLAY=""
    if [[ -n "${FS_DISK}" ]]; then
        # Create a snapshot overlay of the fs-disk to avoid write-lock conflicts
        FS_DISK_SNAPSHOT=$(mktemp /tmp/kcsan_fsdisk_XXXXXX.qcow2)
        local TMP_FS_OVERLAY="${FS_DISK_SNAPSHOT}"
        local FS_FMT
        FS_FMT=$(qemu-img info --output=json "${FS_DISK}" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('format','qcow2'))" 2>/dev/null || echo "qcow2")
        qemu-img create -f qcow2 -b "$(realpath "${FS_DISK}")" -F "${FS_FMT}" "${TMP_FS_OVERLAY}" 2>/dev/null || cp "${FS_DISK}" "${TMP_FS_OVERLAY}"
        FS_DISK_ARGS="-drive file=${TMP_FS_OVERLAY},format=qcow2,if=ide,index=1"
        echo "[detect] Using filesystem disk (snapshot): ${FS_DISK} -> ${TMP_FS_OVERLAY}"
    else
        # Auto-detect: look for btrfs disk in common locations
        local AUTO_FS_DISK=""
        for candidate in \
            "${SYZKALLER_ROOT}/images/btrfs.qcow2" \
            "${SYZKALLER_ROOT}/images/btrfs-2G.qcow2" \
            "${SYZKALLER_ROOT}/test/fs/btrfs.qcow2"; do
            if [[ -f "${candidate}" ]]; then
                AUTO_FS_DISK=$(realpath "${candidate}")
                break
            fi
        done
        if [[ -n "${AUTO_FS_DISK}" ]]; then
            FS_DISK_ARGS="-drive file=${AUTO_FS_DISK},format=qcow2,if=ide,index=1"
            echo "[detect] Auto-detected filesystem disk: ${AUTO_FS_DISK}"
        else
            # Create a fresh 2GB raw disk as fallback
            local TMP_FS_DISK
            TMP_FS_DISK=$(mktemp /tmp/kcsan_fsdisk_XXXXXX.img)
            qemu-img create -f raw "${TMP_FS_DISK}" 2G >/dev/null 2>&1
            FS_DISK_ARGS="-drive file=${TMP_FS_DISK},format=raw,if=ide,index=1"
            echo "[detect] Created temporary filesystem disk: ${TMP_FS_DISK}"
        fi
    fi

    qemu-system-x86_64 \
        -m "${MEM}" \
        -smp "${CPUS}" \
        -kernel "${KERNEL_BZIMAGE}" \
        -drive "file=${SNAPSHOT_IMG},format=qcow2" \
        ${FS_DISK_ARGS} \
        -append "root=/dev/sda console=ttyS0 net.ifnames=0 earlyprintk=serial" \
        -net "nic,model=virtio" \
        -net "user,hostfwd=tcp::${SSH_PORT}-:22" \
        -enable-kvm \
        -nographic \
        -pidfile "${OUTPUT_DIR}/qemu.pid" \
        ${EXTRA_QEMU} \
        > "${OUTPUT_DIR}/qemu_console.log" 2>&1 &
    
    QEMU_PID=$!
    echo "[detect] QEMU PID: ${QEMU_PID}"
    
    # Wait for SSH to become available
    echo "[detect] Waiting for VM to boot..."
    local MAX_WAIT=60
    local WAITED=0
    while ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
               -o UserKnownHostsFile=/dev/null \
               -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost "echo ok" \
               >/dev/null 2>&1; do
        sleep 2
        WAITED=$((WAITED + 2))
        if [[ ${WAITED} -ge ${MAX_WAIT} ]]; then
            echo "[detect] ERROR: VM failed to boot within ${MAX_WAIT}s"
            echo "[detect] Last console output:"
            tail -20 "${OUTPUT_DIR}/qemu_console.log"
            return 1
        fi
    done
    
    echo "[detect] VM is up (waited ${WAITED}s)"
    
    # Function to run SSH commands
    ssh_cmd() {
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost "$@"
    }
    
    scp_to() {
        scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            -i "${SSH_KEY}" -P "${SSH_PORT}" "$1" "root@localhost:$2"
    }
    
    # Upload reproducer binaries
    echo "[detect] Uploading reproducer binaries..."
    ssh_cmd "mkdir -p /root/repro"
    
    # Determine what to upload based on record dir
    REPRO_DIR=""
    if [[ -n "${RECORD_DIR}" ]]; then
        REPRO_DIR="${RECORD_DIR}"
    else
        REPRO_DIR="$(dirname "${REPRODUCER}")"
    fi
    
    # Upload all binary components
    if [[ -f "${REPRO_DIR}/barrier_runner" ]]; then
        scp_to "${REPRO_DIR}/barrier_runner" "/root/repro/barrier_runner"
        ssh_cmd "chmod +x /root/repro/barrier_runner"
    fi
    if [[ -f "${REPRO_DIR}/prog0_bin" ]]; then
        scp_to "${REPRO_DIR}/prog0_bin" "/root/repro/prog0_bin"
        ssh_cmd "chmod +x /root/repro/prog0_bin"
    fi
    if [[ -f "${REPRO_DIR}/prog1_bin" ]]; then
        scp_to "${REPRO_DIR}/prog1_bin" "/root/repro/prog1_bin"
        ssh_cmd "chmod +x /root/repro/prog1_bin"
    fi
    # Also upload the wrapper script
    if [[ -f "${REPRO_DIR}/reproducer" ]]; then
        scp_to "${REPRO_DIR}/reproducer" "/root/repro/reproducer"
        ssh_cmd "chmod +x /root/repro/reproducer"
    fi
    if [[ -f "${REPRO_DIR}/run_barrier.sh" ]]; then
        scp_to "${REPRO_DIR}/run_barrier.sh" "/root/repro/run_barrier.sh"
        ssh_cmd "chmod +x /root/repro/run_barrier.sh"
    fi
    
    # Upload history binaries if present (replay history builds FS state)
    if [[ -d "${REPRO_DIR}/history" ]]; then
        local HIST_BINS
        HIST_BINS=$(find "${REPRO_DIR}/history" -name "hist_*_bin" -type f 2>/dev/null | sort)
        local HIST_COUNT
        HIST_COUNT=$(echo "${HIST_BINS}" | grep -c . 2>/dev/null || true)
        HIST_COUNT=${HIST_COUNT:-0}
        if [[ ${HIST_COUNT} -gt 0 ]]; then
            echo "[detect] Uploading ${HIST_COUNT} history binaries..."
            ssh_cmd "mkdir -p /root/repro/history"
            for hbin in ${HIST_BINS}; do
                local hname
                hname=$(basename "${hbin}")
                scp_to "${hbin}" "/root/repro/history/${hname}"
            done
            ssh_cmd "chmod +x /root/repro/history/*"
        fi
    fi
    
    # Upload modules if provided
    if [[ -n "${MODULES_DIR}" ]] && [[ -d "${MODULES_DIR}" ]]; then
        echo "[detect] Uploading kernel modules..."
        scp_to "${MODULES_DIR}" "/root/modules"
    fi
    
    echo "${QEMU_PID}"
}

# ==============================================================
# Run reproducer and collect results
# ==============================================================
run_reproducer() {
    local DELAY_US="$1"
    local RUN_ID="$2"
    local OFFSET_US="${3:-0}"
    local UDELAY_TASK="${4:-0}"
    local RESULT_FILE="${OUTPUT_DIR}/run_${RUN_ID}_delay${DELAY_US}.json"
    
    echo "[detect] Run ${RUN_ID}: delay_us=${DELAY_US}, offset_us=${OFFSET_US}, udelay_task=${UDELAY_TASK}, repeat=${REPEAT}"
    
    # Function to run SSH commands (redefine for this scope)
    ssh_cmd() {
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost "$@"
    }
    
    # Clear dmesg
    ssh_cmd "dmesg -C" || true
    
    # Mount target filesystem on /mnt/kccwf using experiment-specific fs type.
    # We always reformat /dev/sdb to start from a clean state each trial.
    local MKFS_SETUP MKFS_CMD MOUNT_CMD
    case "${FS_TYPE}" in
        btrfs)
            MKFS_SETUP="which mkfs.btrfs || (apt-get update -qq && apt-get install -y -qq btrfs-progs)"
            MKFS_CMD="mkfs.btrfs -f /dev/sdb"
            MOUNT_CMD="mount -t btrfs /dev/sdb /mnt/kccwf"
            ;;
        xfs)
            MKFS_SETUP="which mkfs.xfs || (apt-get update -qq && apt-get install -y -qq xfsprogs)"
            MKFS_CMD="mkfs.xfs -f /dev/sdb"
            MOUNT_CMD="mount -t xfs /dev/sdb /mnt/kccwf"
            ;;
        f2fs)
            MKFS_SETUP="which mkfs.f2fs || (apt-get update -qq && apt-get install -y -qq f2fs-tools)"
            MKFS_CMD="mkfs.f2fs -f /dev/sdb"
            MOUNT_CMD="mount -t f2fs /dev/sdb /mnt/kccwf"
            ;;
        jfs)
            MKFS_SETUP="which mkfs.jfs || (apt-get update -qq && apt-get install -y -qq jfsutils)"
            MKFS_CMD="yes | mkfs.jfs -f /dev/sdb"
            MOUNT_CMD="mount -t jfs /dev/sdb /mnt/kccwf"
            ;;
        ext4|*)
            MKFS_SETUP="which mkfs.ext4 || (apt-get update -qq && apt-get install -y -qq e2fsprogs)"
            MKFS_CMD="mkfs.ext4 -F /dev/sdb"
            MOUNT_CMD="mount -t ext4 /dev/sdb /mnt/kccwf"
            ;;
    esac

    echo "[detect]   Mounting ${FS_TYPE} on /mnt/kccwf (fresh reformat)..."
    local MOUNT_LOG
    MOUNT_LOG=$(ssh_cmd "set -x; \
        mkdir -p /mnt/kccwf; \
        umount /mnt/kccwf 2>/dev/null; \
        ${MKFS_SETUP}; \
        ${MKFS_CMD} && \
        ${MOUNT_CMD} && \
        echo MOUNT_OK || echo MOUNT_FAIL; \
        mountpoint /mnt/kccwf; \
        ls -la /dev/sdb; \
        df -h /mnt/kccwf" 2>&1) || true
    echo "[detect]   Mount result: ${MOUNT_LOG}"
    
    # Determine which reproducer command to use BEFORE tuning KCSAN
    # (tuning skip_watch can slow the kernel, so detect paths first)
    local REPRO_CMD=""
    if ssh_cmd "test -x /root/repro/barrier_runner" 2>/dev/null; then
        REPRO_CMD="/root/repro/barrier_runner /root/repro/prog0_bin /root/repro/prog1_bin ${REPEAT} ${DELAY_US} ${OFFSET_US} ${UDELAY_TASK}"
    elif ssh_cmd "test -x /root/repro/reproducer" 2>/dev/null; then
        REPRO_CMD="/root/repro/reproducer ${REPEAT} ${DELAY_US}"
    else
        REPRO_CMD="/root/repro/reproducer ${REPEAT} ${DELAY_US}"
    fi
    echo "[detect]   command: ${REPRO_CMD}"
    
    # Record console log baseline (to distinguish boot-time vs reproducer KCSAN)
    local CONSOLE_BASELINE=0
    if [[ -f "${OUTPUT_DIR}/qemu_console.log" ]]; then
        CONSOLE_BASELINE=$(wc -l < "${OUTPUT_DIR}/qemu_console.log")
    fi
    
    # Clear dmesg before reproducer
    ssh_cmd "dmesg -C" || true
    
    # Disable KCSAN during history replay — we only want watchpoints on
    # the final target pair, not the state-building history programs.
    ssh_cmd "
        mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
        echo off > /sys/kernel/debug/kcsan 2>/dev/null && echo 'KCSAN disabled for replay'
    " 2>/dev/null || true
    
    # Replay history programs to build filesystem state (if history exists)
    if ssh_cmd "test -d /root/repro/history" 2>/dev/null; then
        echo "[detect]   Replaying history programs to build FS state (KCSAN OFF)..."
        local HIST_REPLAY_LOG
        HIST_REPLAY_LOG=$(ssh_cmd "
            cd /root/repro/history
            # Find all unique history indices
            INDICES=\$(ls hist_*_prog*_bin 2>/dev/null | sed 's/hist_\\([0-9]*\\)_.*/\\1/' | sort -u)
            TOTAL=\$(echo \"\$INDICES\" | wc -w)
            DONE=0
            for idx in \$INDICES; do
                # Find all program binaries for this history entry
                PROGS=\$(ls hist_\${idx}_prog*_bin 2>/dev/null | sort)
                if [ -z \"\$PROGS\" ]; then
                    continue
                fi
                # Run them concurrently (like the original barrier execution)
                PIDS=''
                for prog in \$PROGS; do
                    timeout 15 ./\$prog &
                    PIDS=\"\$PIDS \$!\"
                done
                # Wait for all
                for pid in \$PIDS; do
                    wait \$pid 2>/dev/null
                done
                DONE=\$((DONE + 1))
            done
            echo \"Replayed \$DONE/\$TOTAL history entries\"
        " 2>&1) || true
        echo "[detect]   History replay: ${HIST_REPLAY_LOG}"
    fi
    
    # Re-enable KCSAN now, before the target pair execution
    ssh_cmd "echo on > /sys/kernel/debug/kcsan 2>/dev/null && echo 'KCSAN re-enabled for target pair'" || true
    
    # Read KCSAN counters before reproducer (if available)
    echo "[detect]   KCSAN counters BEFORE (after re-enable):"
    ssh_cmd "cat /sys/kernel/debug/kcsan 2>/dev/null || echo 'debugfs not mounted'" || true
    
    # Enable kprobe for target functions to verify code path execution
    ssh_cmd "
        echo 0 > /sys/kernel/debug/tracing/tracing_on 2>/dev/null
        echo 0 > /sys/kernel/debug/tracing/events/kprobes/kp_func1/enable 2>/dev/null
        echo 0 > /sys/kernel/debug/tracing/events/kprobes/kp_func2/enable 2>/dev/null
        echo '-:kp_func1' >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null
        echo '-:kp_func2' >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null
        echo 'p:kp_func1 ${KPROBE_FUNC1}' >> /sys/kernel/debug/tracing/kprobe_events
        echo 'p:kp_func2 ${KPROBE_FUNC2}' >> /sys/kernel/debug/tracing/kprobe_events
        echo 1 > /sys/kernel/debug/tracing/events/kprobes/kp_func1/enable
        echo 1 > /sys/kernel/debug/tracing/events/kprobes/kp_func2/enable
        echo > /sys/kernel/debug/tracing/trace
        echo 1 > /sys/kernel/debug/tracing/tracing_on
        echo '[detect] kprobe enabled for ${KPROBE_FUNC1} + ${KPROBE_FUNC2}'
    " 2>/dev/null || true
    
    # Run the reproducer directly with generous SSH timeouts.
    # barrier_runner internally handles KCSAN tuning (skip_watch=50).
    local START_TIME
    START_TIME=$(date +%s)
    
    # Use very long keepalive tolerance (10min no-response) since the
    # reproducer can take up to TIMEOUT seconds and KCSAN reports in
    # interrupt context may briefly block network IO.
    local LOCAL_SSH_TIMEOUT
    LOCAL_SSH_TIMEOUT=$((TIMEOUT + 60))
    timeout --kill-after=15 "${LOCAL_SSH_TIMEOUT}" \
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 \
        -o ServerAliveInterval=30 -o ServerAliveCountMax=20 \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost \
        "timeout --kill-after=10 ${TIMEOUT} ${REPRO_CMD}" \
        > "${OUTPUT_DIR}/reproducer_stdout_${RUN_ID}.log" 2>&1 || true
    
    local END_TIME
    END_TIME=$(date +%s)
    local DURATION=$((END_TIME - START_TIME))
    
    # Fetch reproducer output from VM (append, do not overwrite SSH stdout)
    ssh_cmd "cat /root/repro_stdout.log" >> "${OUTPUT_DIR}/reproducer_stdout_${RUN_ID}.log" 2>/dev/null || true
    
    # Collect dmesg
    ssh_cmd "dmesg" > "${OUTPUT_DIR}/dmesg_${RUN_ID}.log" 2>/dev/null || true
    
    # Read KCSAN counters after reproducer
    echo "[detect]   KCSAN counters AFTER:"
    ssh_cmd "cat /sys/kernel/debug/kcsan 2>/dev/null || echo 'debugfs not mounted'" || true

    # Save full ftrace output for adaptive timing analysis BEFORE kprobe teardown.
    # Some probe operations can clear trace buffers, so capture first.
    local FTRACE_LOCAL
    FTRACE_LOCAL="${OUTPUT_DIR}/ftrace_${RUN_ID}.log"
    ssh_cmd "cat /sys/kernel/debug/tracing/trace 2>/dev/null" \
        > "${FTRACE_LOCAL}" 2>/dev/null || true
    
    # Check kprobe hit count for target functions
    echo "[detect]   kprobe ${KPROBE_FUNC1} + ${KPROBE_FUNC2} hits:"
    local F1_HITS F2_HITS
    F1_HITS=$(grep -c 'kp_func1:' "${FTRACE_LOCAL}" 2>/dev/null || true)
    F2_HITS=$(grep -c 'kp_func2:' "${FTRACE_LOCAL}" 2>/dev/null || true)
    F1_HITS=${F1_HITS:-0}
    F2_HITS=${F2_HITS:-0}
    echo "${KPROBE_FUNC1} hits:"
    echo "${F1_HITS}"
    echo "${KPROBE_FUNC2} hits:"
    echo "${F2_HITS}"
    echo "Last 10 hits:"
    grep -E 'kp_func1:|kp_func2:' "${FTRACE_LOCAL}" 2>/dev/null | tail -10 || true

    # Teardown kprobes after we captured trace and local hit counts.
    ssh_cmd "
        echo 0 > /sys/kernel/debug/tracing/tracing_on 2>/dev/null
        echo 0 > /sys/kernel/debug/tracing/events/kprobes/kp_func1/enable 2>/dev/null
        echo 0 > /sys/kernel/debug/tracing/events/kprobes/kp_func2/enable 2>/dev/null
        echo '-:kp_func1' >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null
        echo '-:kp_func2' >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null
    " 2>/dev/null || true
    
    # Also check console log for NEW KCSAN reports (after baseline, to avoid boot-time false positives)
    local KCSAN_IN_CONSOLE=0
    if [[ -f "${OUTPUT_DIR}/qemu_console.log" ]] && [[ ${CONSOLE_BASELINE} -gt 0 ]]; then
        if tail -n +$((CONSOLE_BASELINE + 1)) "${OUTPUT_DIR}/qemu_console.log" 2>/dev/null | grep -q "BUG: KCSAN"; then
            KCSAN_IN_CONSOLE=1
        fi
    elif grep -q "BUG: KCSAN" "${OUTPUT_DIR}/qemu_console.log" 2>/dev/null; then
        KCSAN_IN_CONSOLE=1
    fi
    
    # Check for KCSAN reports (try dmesg first, fall back to console log)
    local KCSAN_COUNT=0
    local KCSAN_FOUND=0
    
    if grep -q "BUG: KCSAN" "${OUTPUT_DIR}/dmesg_${RUN_ID}.log" 2>/dev/null; then
        KCSAN_FOUND=1
        KCSAN_COUNT=$(grep -c "BUG: KCSAN" "${OUTPUT_DIR}/dmesg_${RUN_ID}.log" || echo 0)
        
        # Extract KCSAN reports
        grep -A 40 "BUG: KCSAN" "${OUTPUT_DIR}/dmesg_${RUN_ID}.log" \
            > "${OUTPUT_DIR}/kcsan_reports_${RUN_ID}.txt" 2>/dev/null || true
        
        echo "[detect] *** KCSAN REPORT FOUND (dmesg)! count=${KCSAN_COUNT} ***"
    elif [[ ${KCSAN_IN_CONSOLE} -eq 1 ]]; then
        # Fallback: dmesg was empty but console log has NEW KCSAN reports
        KCSAN_FOUND=1
        KCSAN_COUNT=$(tail -n +$((CONSOLE_BASELINE + 1)) "${OUTPUT_DIR}/qemu_console.log" 2>/dev/null | grep -c "BUG: KCSAN" || echo 0)
        
        tail -n +$((CONSOLE_BASELINE + 1)) "${OUTPUT_DIR}/qemu_console.log" 2>/dev/null | grep -A 40 "BUG: KCSAN" \
            > "${OUTPUT_DIR}/kcsan_reports_${RUN_ID}.txt" 2>/dev/null || true
        
        echo "[detect] *** KCSAN REPORT FOUND (console)! count=${KCSAN_COUNT} ***"
    fi
    
    # Write result JSON
    cat > "${RESULT_FILE}" <<EOF
{
  "run_id": "${RUN_ID}",
  "delay_us": ${DELAY_US},
  "repeat": ${REPEAT},
  "timeout": ${TIMEOUT},
  "duration_seconds": ${DURATION},
  "kcsan_found": ${KCSAN_FOUND},
  "kcsan_count": ${KCSAN_COUNT},
  "dmesg_log": "dmesg_${RUN_ID}.log",
  "kcsan_reports": "kcsan_reports_${RUN_ID}.txt"
}
EOF
    
    # Return: 0 = found KCSAN, 1 = not found
    if [[ ${KCSAN_FOUND} -eq 1 ]]; then
        return 0
    else
        return 1
    fi
}

# ==============================================================
# VM liveness check
# ==============================================================
check_vm_alive() {
    # Check if QEMU process is running
    if [[ -z "${QEMU_PID}" ]] || ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        echo "[detect] WARNING: QEMU process is dead!"
        return 1
    fi
    # Quick SSH check
    if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
             -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
             -i "${SSH_KEY}" -p "${SSH_PORT}" root@localhost "echo alive" \
             >/dev/null 2>&1; then
        echo "[detect] WARNING: VM is not responding to SSH!"
        return 1
    fi
    return 0
}

# ==============================================================
# Main execution
# ==============================================================

# Launch QEMU
launch_qemu
if [[ $? -ne 0 ]]; then
    echo "[detect] Failed to launch QEMU"
    exit 1
fi

TOTAL_FOUND=0

if [[ "${ADAPTIVE}" -eq 1 ]]; then
    # ======================================================================
    # Adaptive timing feedback loop
    # ======================================================================
    # Strategy:
    #   1. Run short batches with current offset_us
    #   2. Parse ftrace to measure timing gap between kp_func1 and kp_func2
    #   3. Adjust offset_us to minimize the gap
    #   4. If both functions fire but race not detected, widen udelay_task
    #   5. Stop on KCSAN detection or max trials
    # ======================================================================
    
    echo "[detect] =========================================="
    echo "[detect] ADAPTIVE TIMING MODE"
    echo "[detect] batch_size=${ADAPTIVE_BATCH}, max_trials=${ADAPTIVE_MAX_TRIALS}"
    echo "[detect] kprobe1=${KPROBE_FUNC1}  kprobe2=${KPROBE_FUNC2}"
    echo "[detect] max_seconds=${ADAPTIVE_MAX_SECONDS}, zero_hit_stop=${ADAPTIVE_ZERO_HIT_STOP}"
    echo "[detect] =========================================="
    
    # Adaptive state
    CURRENT_OFFSET_US=0
    CURRENT_UDELAY=0        # 0 = kernel default (80us)
    BEST_OFFSET_US=0
    BEST_GAP_US=999999999    # infinity initially
    TRIAL=0
    ZERO_HIT_STREAK=0
    ADAPTIVE_START_TS=$(date +%s)
    
    # udelay_task values to try (progressively wider watchpoint windows)
    UDELAY_VALUES=(0 200 500 1000 2000 5000 10000)
    UDELAY_IDX=0
    
    # Track offset candidates for binary search
    OFFSET_TRIED=()
    
    # Ftrace timing gap analysis function
    # Parses ftrace output and computes the median minimum gap between
    # kp_func1 and kp_func2 timestamps (in microseconds).
    # Returns: gap_us via stdout. Positive = func2 fires after func1.
    # Returns "NONE" if either function has zero hits.
    analyze_ftrace_gap() {
        local FTRACE_FILE="$1"
        
        if [[ ! -f "${FTRACE_FILE}" ]] || [[ ! -s "${FTRACE_FILE}" ]]; then
            echo "NONE"
            return
        fi
        
        # Extract timestamps for each probe.
        # ftrace format: <task>-<pid> [<cpu>] <flags> <timestamp>: <event>: ...
        # Timestamp is a float in seconds (e.g., 123.456789)
        local F1_TIMES F2_TIMES
        F1_TIMES=$(grep 'kp_func1:' "${FTRACE_FILE}" | awk '{
            for(i=1;i<=NF;i++) {
                if ($i ~ /^[0-9]+\.[0-9]+:$/) {
                    gsub(/:$/,"",$i);
                    print $i;
                    break;
                }
            }
        }' | sort -n)
        
        F2_TIMES=$(grep 'kp_func2:' "${FTRACE_FILE}" | awk '{
            for(i=1;i<=NF;i++) {
                if ($i ~ /^[0-9]+\.[0-9]+:$/) {
                    gsub(/:$/,"",$i);
                    print $i;
                    break;
                }
            }
        }' | sort -n)
        
        local F1_COUNT F2_COUNT
        F1_COUNT=$(echo "${F1_TIMES}" | grep -c '[0-9]' 2>/dev/null || true)
        F1_COUNT=${F1_COUNT:-0}
        F2_COUNT=$(echo "${F2_TIMES}" | grep -c '[0-9]' 2>/dev/null || true)
        F2_COUNT=${F2_COUNT:-0}
        
        echo "[adaptive] ftrace: func1_hits=${F1_COUNT}, func2_hits=${F2_COUNT}" >&2
        
        if [[ ${F1_COUNT} -eq 0 ]] || [[ ${F2_COUNT} -eq 0 ]]; then
            echo "NONE"
            return
        fi
        
        # For each func2 timestamp, find the nearest func1 timestamp
        # and compute the gap. Output: median gap in microseconds.
        # Positive gap = func2 fires AFTER nearest func1.
        # Negative gap = func2 fires BEFORE nearest func1.
        local GAPS
        GAPS=$(python3 -c "
import sys

f1 = [float(x) for x in '''${F1_TIMES}'''.strip().split()]
f2 = [float(x) for x in '''${F2_TIMES}'''.strip().split()]

if not f1 or not f2:
    print('NONE')
    sys.exit(0)

gaps = []
for t2 in f2:
    # Find nearest f1 timestamp (binary search)
    best = None
    best_dist = float('inf')
    for t1 in f1:
        dist = abs(t2 - t1)
        if dist < best_dist:
            best_dist = dist
            best = t1
    gap_us = (t2 - best) * 1e6  # seconds to microseconds
    gaps.append(gap_us)

# Compute median
gaps.sort()
n = len(gaps)
if n % 2 == 1:
    median = gaps[n // 2]
else:
    median = (gaps[n // 2 - 1] + gaps[n // 2]) / 2.0

print(f'STATS:min={min(gaps):.0f},max={max(gaps):.0f},median={median:.0f},count={n}')
print(f'{median:.0f}')
" 2>/dev/null)
        
        if [[ -z "${GAPS}" ]]; then
            echo "NONE"
            return
        fi
        
        # Print stats line to stderr, return median on stdout
        local STATS_LINE
        STATS_LINE=$(echo "${GAPS}" | head -1)
        echo "[adaptive] gap ${STATS_LINE}" >&2
        echo "${GAPS}" | tail -1
    }
    
    SAVED_REPEAT="${REPEAT}"
    REPEAT="${ADAPTIVE_BATCH}"
    
    while [[ ${TRIAL} -lt ${ADAPTIVE_MAX_TRIALS} ]] && [[ ${TOTAL_FOUND} -eq 0 ]]; do
        TRIAL=$((TRIAL + 1))
        CURRENT_UDELAY=${UDELAY_VALUES[$UDELAY_IDX]}
        
        echo ""
        echo "[adaptive] ====== Trial ${TRIAL}/${ADAPTIVE_MAX_TRIALS} ======"
        echo "[adaptive] offset_us=${CURRENT_OFFSET_US}, udelay_task=${CURRENT_UDELAY}"

        NOW_TS=$(date +%s)
        ELAPSED=$((NOW_TS - ADAPTIVE_START_TS))
        if [[ ${ELAPSED} -ge ${ADAPTIVE_MAX_SECONDS} ]]; then
            echo "[adaptive] Reached wall-time limit (${ADAPTIVE_MAX_SECONDS}s), stopping loop"
            break
        fi
        
        # Check VM health
        if ! check_vm_alive; then
            echo "[adaptive] VM died, stopping adaptive loop"
            break
        fi
        
        RUN_ID="adaptive_t${TRIAL}_off${CURRENT_OFFSET_US}_ud${CURRENT_UDELAY}"
        
        if run_reproducer 0 "${RUN_ID}" "${CURRENT_OFFSET_US}" "${CURRENT_UDELAY}"; then
            TOTAL_FOUND=$((TOTAL_FOUND + 1))
            echo ""
            echo "[adaptive] *** SUCCESS! KCSAN race detected at trial ${TRIAL} ***"
            echo "[adaptive] offset_us=${CURRENT_OFFSET_US}, udelay_task=${CURRENT_UDELAY}"
            break
        fi
        
        # Analyze ftrace timing gap
        GAP_RESULT=$(analyze_ftrace_gap "${OUTPUT_DIR}/ftrace_${RUN_ID}.log")

        FTRACE_FILE="${OUTPUT_DIR}/ftrace_${RUN_ID}.log"
        F1_HITS=$(grep -c 'kp_func1:' "${FTRACE_FILE}" 2>/dev/null || true)
        F2_HITS=$(grep -c 'kp_func2:' "${FTRACE_FILE}" 2>/dev/null || true)
        F1_HITS=${F1_HITS:-0}
        F2_HITS=${F2_HITS:-0}
        if [[ ${F1_HITS} -eq 0 && ${F2_HITS} -eq 0 ]]; then
            ZERO_HIT_STREAK=$((ZERO_HIT_STREAK + 1))
            echo "[adaptive] zero-hit streak: ${ZERO_HIT_STREAK}/${ADAPTIVE_ZERO_HIT_STOP}"
            if [[ ${ZERO_HIT_STREAK} -ge ${ADAPTIVE_ZERO_HIT_STOP} ]]; then
                echo "[adaptive] Both probes had zero hits for ${ADAPTIVE_ZERO_HIT_STOP} consecutive trials, stopping early"
                break
            fi
        else
            ZERO_HIT_STREAK=0
        fi
        
        echo "[adaptive] gap_result=${GAP_RESULT}"
        
        if [[ "${GAP_RESULT}" == "NONE" ]]; then
            # One or both functions didn't fire.
            # Try: sweep different offset values to trigger both paths
            echo "[adaptive] Insufficient probe hits. Trying different offset..."
            
            # Cycle through a set of offsets to find one that triggers both probes
            OFFSET_CANDIDATES=(-5000 -2000 -1000 -500 -200 -100 0 100 200 500 1000 2000 5000 10000 50000 100000)
            CAND_IDX=$(( (TRIAL - 1) % ${#OFFSET_CANDIDATES[@]} ))
            CURRENT_OFFSET_US=${OFFSET_CANDIDATES[$CAND_IDX]}
            
            # Every full cycle of offsets, advance udelay_task
            if [[ ${CAND_IDX} -eq 0 ]] && [[ ${TRIAL} -gt 1 ]]; then
                UDELAY_IDX=$(( (UDELAY_IDX + 1) % ${#UDELAY_VALUES[@]} ))
                echo "[adaptive] Advancing udelay_task to ${UDELAY_VALUES[$UDELAY_IDX]}"
            fi
        else
            # Got a valid gap measurement
            GAP_US="${GAP_RESULT}"
            ABS_GAP=${GAP_US#-}  # absolute value
            
            echo "[adaptive] Measured gap: ${GAP_US} us"
            
            # Track best gap
            if [[ ${ABS_GAP} -lt ${BEST_GAP_US} ]]; then
                BEST_GAP_US=${ABS_GAP}
                BEST_OFFSET_US=${CURRENT_OFFSET_US}
                echo "[adaptive] New best gap: ${ABS_GAP} us at offset=${CURRENT_OFFSET_US}"
            fi
            
            # If gap is small enough but no race detected, try widening the
            # watchpoint window (udelay_task) to catch it
            if [[ ${ABS_GAP} -lt 100 ]]; then
                echo "[adaptive] Gap < 100us — functions nearly overlapping!"
                echo "[adaptive] Widening watchpoint window..."
                UDELAY_IDX=$(( (UDELAY_IDX + 1) % ${#UDELAY_VALUES[@]} ))
                # Keep the same offset that's working well
            elif [[ ${ABS_GAP} -lt 1000 ]]; then
                # Gap is moderate — fine-tune offset
                # Adjust: if func2 fires after func1, we want prog1 to start earlier
                # (reduce offset or make it negative)
                ADJUST=$(( GAP_US / 2 ))
                CURRENT_OFFSET_US=$(( CURRENT_OFFSET_US - ADJUST ))
                echo "[adaptive] Moderate gap, adjusting offset by -${ADJUST} → ${CURRENT_OFFSET_US}"
            else
                # Gap is large — coarse adjustment
                ADJUST=$(( GAP_US * 3 / 4 ))
                CURRENT_OFFSET_US=$(( CURRENT_OFFSET_US - ADJUST ))
                echo "[adaptive] Large gap, adjusting offset by -${ADJUST} → ${CURRENT_OFFSET_US}"
            fi
            
            # Clamp offset to reasonable range (-500ms to +500ms)
            if [[ ${CURRENT_OFFSET_US} -gt 500000 ]]; then
                CURRENT_OFFSET_US=500000
            elif [[ ${CURRENT_OFFSET_US} -lt -500000 ]]; then
                CURRENT_OFFSET_US=-500000
            fi
        fi
        
        OFFSET_TRIED+=("${CURRENT_OFFSET_US}")
    done
    
    REPEAT="${SAVED_REPEAT}"
    
    echo ""
    echo "[adaptive] =========================================="
    echo "[adaptive] Adaptive loop finished after ${TRIAL} trials"
    echo "[adaptive] Best offset: ${BEST_OFFSET_US} us (gap: ${BEST_GAP_US} us)"
    echo "[adaptive] Races found: ${TOTAL_FOUND}"
    echo "[adaptive] =========================================="

elif [[ "${DELAY_SWEEP}" -eq 1 ]]; then
    # Delay sweep mode: try multiple delay values
    DELAYS=(0 10 50 100 200 500 1000 2000 5000)
    echo "[detect] Delay sweep mode: testing ${#DELAYS[@]} delay values"
    
    for i in "${!DELAYS[@]}"; do
        DELAY=${DELAYS[$i]}
        RUN_ID="sweep_${i}"
        
        # Check VM is still alive before each run
        if ! check_vm_alive; then
            echo "[detect] VM died, stopping sweep at delay=${DELAY}us"
            # Grab whatever dmesg we can from console log
            echo "[detect] Last console output:"
            tail -30 "${OUTPUT_DIR}/qemu_console.log" 2>/dev/null || true
            break
        fi
        
        if run_reproducer "${DELAY}" "${RUN_ID}" "${RUN_OFFSET_US}" "${RUN_UDELAY_TASK}"; then
            TOTAL_FOUND=$((TOTAL_FOUND + 1))
            echo "[detect] Delay ${DELAY}us: KCSAN detected!"
        else
            echo "[detect] Delay ${DELAY}us: no KCSAN report"
        fi
    done
else
    # Single run mode
    if run_reproducer 0 "single" "${RUN_OFFSET_US}" "${RUN_UDELAY_TASK}"; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
    fi
fi

# ==============================================================
# Summary
# ==============================================================
echo ""
echo "=============================================="
echo "[detect] Detection Summary"
echo "=============================================="
echo "  Total runs:   $( [[ ${DELAY_SWEEP} -eq 1 ]] && echo ${#DELAYS[@]} || echo 1 )"
echo "  KCSAN found:  ${TOTAL_FOUND}"
echo "  Output dir:   ${OUTPUT_DIR}"

if [[ ${TOTAL_FOUND} -gt 0 ]]; then
    echo ""
    echo "[detect] KCSAN Reports:"
    for f in "${OUTPUT_DIR}"/kcsan_reports_*.txt; do
        if [[ -f "$f" ]] && [[ -s "$f" ]]; then
            echo "--- ${f} ---"
            cat "$f"
            echo ""
        fi
    done
    
    # Consolidate all KCSAN reports
    cat "${OUTPUT_DIR}"/kcsan_reports_*.txt > "${OUTPUT_DIR}/all_kcsan_reports.txt" 2>/dev/null || true
    echo "[detect] All reports consolidated in: ${OUTPUT_DIR}/all_kcsan_reports.txt"
fi

# Generate final summary JSON
cat > "${OUTPUT_DIR}/summary.json" <<EOF
{
  "total_kcsan_found": ${TOTAL_FOUND},
  "delay_sweep": ${DELAY_SWEEP},
  "kernel": "${KERNEL_BZIMAGE}",
  "reproducer": "${REPRODUCER}",
  "repeat_per_run": ${REPEAT},
  "timeout_per_run": ${TIMEOUT}
}
EOF

# Cleanup: stop QEMU
kill "${QEMU_PID}" 2>/dev/null || true

exit $(( TOTAL_FOUND > 0 ? 0 : 1 ))
