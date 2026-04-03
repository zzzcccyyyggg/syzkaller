#!/bin/bash
# batch_detect_races.sh - Batch run generated reproducers in KCSAN VM and detect races
#
# Usage:
#   ./batch_detect_races.sh [options]
#
# Options:
#   --repros-dir <dir>       Parsed record directory (default: batch_repros_final in SYZKALLER_ROOT)
#   --kcsan-kernel <path>    KCSAN bzImage (default: kernels/output/kcsan-clean-v617rc5/bzImage)
#   --image <path>           Root FS image (default: images/bookworm.img)
#   --sshkey <path>          SSH key (default: images/bookworm.id_rsa)
#   --output-dir <dir>       Results output dir (default: batch_detect_results/)
#   --repeat <n>             Reproducer repeat count per trial (default: 50)
#   --trials <n>             Number of detection trials per record (default: 3)
#   --timeout <sec>          Per-trial timeout passed to run_kcsan_detect.sh (default: 120)
#   --max-records <n>        Stop after testing N records (default: 0 = all)
#   --delay-sweep            Enable delay sweep mode
#   --filter-exp <exp>       Only process records from this experiment (e.g. xfs)
#   --kernel-src <path>      Kernel source root for per-record patch+rebuild
#   --vmlinux <path>         vmlinux with debug info (for locate_source fallback)
#   --analyzer <path>        DDRD Analyzer binary (optional)
#   --ll-dir <path>          LLVM IR dir for analyzer mode (optional)
#   --build-jobs <n>         Jobs for incremental kernel rebuild (default: nproc)
#   --api-key <key>          DeepSeek API key (or env DEEPSEEK_API_KEY)
#   --no-auto-patch-rebuild  Disable per-record patch+rebuild (default: enabled)
#   --help

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DETECT_SCRIPT="${SCRIPT_DIR}/run_kcsan_detect.sh"
PATCH_SCRIPT="${SCRIPT_DIR}/patch_kernel_kcsan.py"
LOCATE_SCRIPT="${SCRIPT_DIR}/locate_source.py"

REPROS_DIR="${SYZKALLER_ROOT}/batch_repros"
KCSAN_KERNEL="${SYZKALLER_ROOT}/kernels/output/kcsan-clean-v617rc5/bzImage"
ROOT_IMAGE="${SYZKALLER_ROOT}/images/bookworm.img"
SSH_KEY="${SYZKALLER_ROOT}/images/bookworm.id_rsa"
OUTPUT_DIR="${SYZKALLER_ROOT}/batch_detect_results"
REPEAT=50
TRIALS=3
TIMEOUT=120
MAX_RECORDS=0
DELAY_SWEEP=0
FILTER_EXP=""
AUTO_PATCH_REBUILD=1
KERNEL_SRC=""
VMLINUX=""
ANALYZER_BIN=""
LL_DIR=""
BUILD_JOBS="$(nproc)"
PATCH_API_KEY="${DEEPSEEK_API_KEY:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[batch-detect]${NC} $*"; }
ok()   { echo -e "${GREEN}[batch-detect]${NC} $*"; }
warn() { echo -e "${YELLOW}[batch-detect]${NC} $*"; }
err()  { echo -e "${RED}[batch-detect]${NC} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repros-dir)    REPROS_DIR="$2"; shift 2 ;;
        --kcsan-kernel)  KCSAN_KERNEL="$2"; shift 2 ;;
        --image)         ROOT_IMAGE="$2"; shift 2 ;;
        --sshkey)        SSH_KEY="$2"; shift 2 ;;
        --output-dir)    OUTPUT_DIR="$2"; shift 2 ;;
        --repeat)        REPEAT="$2"; shift 2 ;;
        --trials)        TRIALS="$2"; shift 2 ;;
        --timeout)       TIMEOUT="$2"; shift 2 ;;
        --max-records)   MAX_RECORDS="$2"; shift 2 ;;
        --delay-sweep)   DELAY_SWEEP=1; shift ;;
        --filter-exp)    FILTER_EXP="$2"; shift 2 ;;
        --kernel-src)    KERNEL_SRC="$2"; shift 2 ;;
        --vmlinux)       VMLINUX="$2"; shift 2 ;;
        --analyzer)      ANALYZER_BIN="$2"; shift 2 ;;
        --ll-dir)        LL_DIR="$2"; shift 2 ;;
        --build-jobs)    BUILD_JOBS="$2"; shift 2 ;;
        --api-key)       PATCH_API_KEY="$2"; shift 2 ;;
        --no-auto-patch-rebuild) AUTO_PATCH_REBUILD=0; shift ;;
        --auto-patch-rebuild)    AUTO_PATCH_REBUILD=1; shift ;;
        --help|-h) head -20 "$0" | grep '^#' | sed 's/^# \?//'; exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate inputs
if [[ ! -f "${KCSAN_KERNEL}" ]]; then
    err "KCSAN kernel not found: ${KCSAN_KERNEL}"
    exit 1
fi
if [[ ! -f "${ROOT_IMAGE}" ]]; then
    err "Root image not found: ${ROOT_IMAGE}"
    exit 1
fi
if [[ ! -f "${DETECT_SCRIPT}" ]]; then
    err "run_kcsan_detect.sh not found: ${DETECT_SCRIPT}"
    exit 1
fi

if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
    if [[ ! -f "${PATCH_SCRIPT}" ]]; then
        err "patch_kernel_kcsan.py not found: ${PATCH_SCRIPT}"
        exit 1
    fi
    if [[ ! -f "${LOCATE_SCRIPT}" ]]; then
        err "locate_source.py not found: ${LOCATE_SCRIPT}"
        exit 1
    fi

    if [[ -z "${KERNEL_SRC}" ]]; then
        if [[ "${KCSAN_KERNEL}" == *"/arch/x86/boot/bzImage" ]]; then
            KERNEL_SRC="${KCSAN_KERNEL%/arch/x86/boot/bzImage}"
        fi
    fi

    if [[ -z "${KERNEL_SRC}" ]]; then
        for candidate in \
            "${SYZKALLER_ROOT}/kernels/output/kcsan-clean-v617rc5/linux-src" \
            "${SYZKALLER_ROOT}/kernels/output/kcsan/linux-src"; do
            if [[ -d "${candidate}" ]] && [[ -f "${candidate}/Makefile" ]]; then
                KERNEL_SRC="${candidate}"
                break
            fi
        done
    fi

    if [[ -z "${KERNEL_SRC}" ]] || [[ ! -f "${KERNEL_SRC}/Makefile" ]]; then
        err "AUTO patch+rebuild enabled but kernel source not found. Use --kernel-src <path>."
        exit 1
    fi

    if [[ -z "${VMLINUX}" ]] && [[ -f "${KERNEL_SRC}/vmlinux" ]]; then
        VMLINUX="${KERNEL_SRC}/vmlinux"
    fi

    if [[ -z "${PATCH_API_KEY}" ]]; then
        err "AUTO patch+rebuild enabled but DeepSeek API key is empty."
        err "Set DEEPSEEK_API_KEY env var or pass --api-key <key>."
        exit 1
    fi
fi

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"   # convert to absolute path
SUMMARY_FILE="${OUTPUT_DIR}/detect_summary.txt"
CSV_FILE="${OUTPUT_DIR}/detect_results.csv"
TRIGGERED_FILE="${OUTPUT_DIR}/triggered_records.txt"

: > "${SUMMARY_FILE}"
echo "experiment,record,kcsan_found,trial,detect_time_s,kernel_mode,note" > "${CSV_FILE}"
: > "${TRIGGERED_FILE}"

log "=========================================="
log "Batch KCSAN Race Detection"
log "KCSAN kernel: ${KCSAN_KERNEL}"
log "Root image:   ${ROOT_IMAGE}"
log "Repros dir:   ${REPROS_DIR}"
log "Trials:       ${TRIALS}  Repeat: ${REPEAT}"
log "Timeout:      ${TIMEOUT}s"
log "Max records:  ${MAX_RECORDS} (0=all)"
log "Auto patch+rebuild: ${AUTO_PATCH_REBUILD}"
if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
    log "Kernel source: ${KERNEL_SRC}"
    log "Build jobs:    ${BUILD_JOBS}"
fi
log "Output dir:   ${OUTPUT_DIR}"
log "=========================================="
echo ""

TOTAL=0
TRIGGERED=0
SKIPPED=0
PATCH_FAILED=0
BUILD_FAILED=0
LOCATE_FAILED=0

# Robust kernel source restore: find ALL .kcsan_orig backups and revert them,
# AND restore Makefile.kcsan.orig (global KCSAN instrumentation flag).
restore_kernel_clean() {
    local count=0

    # 1) Restore Makefile.kcsan (global CFLAGS_KCSAN)
    local mkfile_orig="${KERNEL_SRC}/scripts/Makefile.kcsan.orig"
    if [[ -f "${mkfile_orig}" ]]; then
        cp -f "${mkfile_orig}" "${mkfile_orig%.orig}"
        rm -f "${mkfile_orig}"
        count=$((count + 1))
    fi

    # 2) Restore all .kcsan_orig source file backups
    while IFS= read -r -d '' orig; do
        local target="${orig%.kcsan_orig}"
        cp -f "${orig}" "${target}"
        rm -f "${orig}"
        count=$((count + 1))
    done < <(find "${KERNEL_SRC}" -name "*.kcsan_orig" -print0 2>/dev/null)

    if [[ ${count} -gt 0 ]]; then
        log "    Restored ${count} kernel file(s) to clean state (incl. Makefile.kcsan)"
    fi
}

# Iterate experiments
for exp_dir in "${REPROS_DIR}"/*/; do
    [[ -d "${exp_dir}" ]] || continue
    exp_name="$(basename "${exp_dir}")"
    [[ -f "${exp_dir}/summary.json" ]] || continue  # not a valid exp dir

    # Apply filter if set
    if [[ -n "${FILTER_EXP}" && "${exp_name}" != "${FILTER_EXP}" ]]; then
        continue
    fi

    log "==== Experiment: ${exp_name} ===="

    # Determine secondary disk (fs-disk) for this experiment
    FS_DISK_ARG=""
    FS_TYPE_ARG="ext4"
    case "${exp_name}" in
        btrfs|xfs|f2fs|jfs)
            FS_TYPE_ARG="${exp_name}"
            ;;
    esac
    for candidate in \
        "${SYZKALLER_ROOT}/images/${exp_name}-2G.qcow2" \
        "${SYZKALLER_ROOT}/images/${exp_name}.qcow2" \
        "${SYZKALLER_ROOT}/images/${exp_name}.img" \
        "${SYZKALLER_ROOT}/images/${exp_name}-2G.img"; do
        if [[ -f "${candidate}" ]]; then
            FS_DISK_ARG="${candidate}"
            log "  Secondary disk: ${candidate}"
            break
        fi
    done
    if [[ -z "${FS_DISK_ARG}" ]]; then
        warn "  No secondary disk found for ${exp_name}, will use auto-create"
    fi
    log "  Filesystem type: ${FS_TYPE_ARG}"

    for rec_dir in "${exp_dir}"record_*/; do
        [[ -d "${rec_dir}" ]] || continue
        rec_name="$(basename "${rec_dir}")"

        if [[ "${MAX_RECORDS}" -gt 0 && "${TOTAL}" -ge "${MAX_RECORDS}" ]]; then
            warn "Reached --max-records=${MAX_RECORDS}, stopping batch"
            break 2
        fi

        # Must have barrier_runner compiled
        if [[ ! -f "${rec_dir}/barrier_runner" ]]; then
            warn "  [SKIP] ${exp_name}/${rec_name}: no barrier_runner"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi
        if [[ ! -f "${rec_dir}/prog0_bin" ]] || [[ ! -f "${rec_dir}/prog1_bin" ]]; then
            warn "  [SKIP] ${exp_name}/${rec_name}: no prog binaries"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        TOTAL=$((TOTAL + 1))
        log "  [${TOTAL}] ${exp_name}/${rec_name}"

        REC_OUT="${OUTPUT_DIR}/${exp_name}/${rec_name}"
        mkdir -p "${REC_OUT}"

        RECORD_KERNEL="${KCSAN_KERNEL}"

        if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
            SRC_LOCS="${rec_dir}/source_locations.json"

            if [[ ! -f "${SRC_LOCS}" ]]; then
                LOCATE_ARGS=("${LOCATE_SCRIPT}" "${rec_dir}" "--output" "${SRC_LOCS}")
                [[ -n "${VMLINUX}" && -f "${VMLINUX}" ]] && LOCATE_ARGS+=("--vmlinux" "${VMLINUX}")
                [[ -n "${ANALYZER_BIN}" && -f "${ANALYZER_BIN}" ]] && [[ -n "${LL_DIR}" && -d "${LL_DIR}" ]] && LOCATE_ARGS+=("--analyzer" "${ANALYZER_BIN}" "--ll-dir" "${LL_DIR}")

                log "    Locating source lines..."
                if ! python3 "${LOCATE_ARGS[@]}" >> "${REC_OUT}/detect_stderr.log" 2>&1; then
                    warn "    [SKIP] locate_source failed for ${exp_name}/${rec_name}"
                fi
            fi

            if [[ ! -f "${SRC_LOCS}" ]]; then
                warn "    [SKIP] ${exp_name}/${rec_name}: missing source_locations.json"
                SKIPPED=$((SKIPPED + 1))
                LOCATE_FAILED=$((LOCATE_FAILED + 1))
                echo "${exp_name},${rec_name},0,,0,targeted,locate_failed" >> "${CSV_FILE}"
                continue
            fi

            log "    Patching kernel for this record..."

            # Ensure clean kernel before patching: restore ALL previous modifications
            restore_kernel_clean

            PATCH_ARGS=("${KERNEL_SRC}" "${SRC_LOCS}" "--record-dir" "${rec_dir}" "--output-log" "${REC_OUT}/kcsan_patch.log")
            [[ -n "${PATCH_API_KEY}" ]] && PATCH_ARGS+=("--api-key" "${PATCH_API_KEY}")

            if ! http_proxy= https_proxy= python3 "${PATCH_SCRIPT}" "${PATCH_ARGS[@]}" >> "${REC_OUT}/detect_stderr.log" 2>&1; then
                warn "    [SKIP] ${exp_name}/${rec_name}: kernel patch failed"
                # Restore any partial patches from this failed attempt
                restore_kernel_clean
                SKIPPED=$((SKIPPED + 1))
                PATCH_FAILED=$((PATCH_FAILED + 1))
                echo "${exp_name},${rec_name},0,,0,targeted,patch_failed" >> "${CSV_FILE}"
                continue
            fi

            log "    Incremental rebuild..."
            if ! make -C "${KERNEL_SRC}" -j"${BUILD_JOBS}" bzImage >> "${REC_OUT}/build.log" 2>&1; then
                warn "    [SKIP] ${exp_name}/${rec_name}: kernel rebuild failed"
                # Restore patches so next record starts clean
                restore_kernel_clean
                SKIPPED=$((SKIPPED + 1))
                BUILD_FAILED=$((BUILD_FAILED + 1))
                echo "${exp_name},${rec_name},0,,0,targeted,build_failed" >> "${CSV_FILE}"
                continue
            fi

            if [[ ! -f "${KERNEL_SRC}/arch/x86/boot/bzImage" ]]; then
                warn "    [SKIP] ${exp_name}/${rec_name}: rebuilt bzImage missing"
                SKIPPED=$((SKIPPED + 1))
                BUILD_FAILED=$((BUILD_FAILED + 1))
                echo "${exp_name},${rec_name},0,,0,targeted,bzimage_missing" >> "${CSV_FILE}"
                continue
            fi

            RECORD_KERNEL="${KERNEL_SRC}/arch/x86/boot/bzImage"
            log "    Targeted kernel ready: ${RECORD_KERNEL}"
        fi

        FOUND=0
        FOUND_TRIAL=""
        T_START=$(date +%s)

        for trial in $(seq 1 "${TRIALS}"); do
            log "    Trial ${trial}/${TRIALS}..."

            DETECT_ARGS=(
                "--kernel"     "${RECORD_KERNEL}"
                "--image"      "${ROOT_IMAGE}"
                "--sshkey"     "${SSH_KEY}"
                "--record-dir" "${rec_dir}"
                "--fs-type"    "${FS_TYPE_ARG}"
                "--output-dir" "${REC_OUT}/trial_${trial}"
                "--timeout"    "${TIMEOUT}"
                "--repeat"     "${REPEAT}"
            )
            [[ -n "${FS_DISK_ARG}" ]] && DETECT_ARGS+=("--fs-disk" "${FS_DISK_ARG}")
            [[ "${DELAY_SWEEP}" -eq 1 ]] && DETECT_ARGS+=("--delay-sweep")

            if bash "${DETECT_SCRIPT}" "${DETECT_ARGS[@]}" 2>>"${REC_OUT}/detect_stderr.log"; then
                FOUND=1
                FOUND_TRIAL="${trial}"
                ok "    *** KCSAN triggered at trial ${trial}! ***"
                break
            else
                warn "    Trial ${trial}: no KCSAN report"
            fi
        done

        T_END=$(date +%s)
        ELAPSED=$((T_END - T_START))

        # After all trials: restore kernel to clean state for next record
        if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
            restore_kernel_clean
        fi

        if [[ "${FOUND}" -eq 1 ]]; then
            TRIGGERED=$((TRIGGERED + 1))
            ok "  [TRIGGERED] ${exp_name}/${rec_name} (trial ${FOUND_TRIAL}, ${ELAPSED}s)"
            if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
                echo "${exp_name},${rec_name},1,${FOUND_TRIAL},${ELAPSED},targeted,triggered" >> "${CSV_FILE}"
            else
                echo "${exp_name},${rec_name},1,${FOUND_TRIAL},${ELAPSED},baseline,triggered" >> "${CSV_FILE}"
            fi
            echo "[TRIGGERED] ${exp_name}/${rec_name} trial=${FOUND_TRIAL} elapsed=${ELAPSED}s" >> "${SUMMARY_FILE}"
            echo "${exp_name}/${rec_name}" >> "${TRIGGERED_FILE}"
        else
            warn "  [NOT-TRIGGERED] ${exp_name}/${rec_name} (${TRIALS} trials, ${ELAPSED}s)"
            if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
                echo "${exp_name},${rec_name},0,,${ELAPSED},targeted,not_triggered" >> "${CSV_FILE}"
            else
                echo "${exp_name},${rec_name},0,,${ELAPSED},baseline,not_triggered" >> "${CSV_FILE}"
            fi
            echo "[NOT-TRIGGERED] ${exp_name}/${rec_name} trials=${TRIALS} elapsed=${ELAPSED}s" >> "${SUMMARY_FILE}"
        fi
    done
    echo ""
done

# Final cleanup: ensure kernel source tree is clean
if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
    log "Final cleanup: restoring kernel source tree..."
    restore_kernel_clean
fi

echo "" | tee -a "${SUMMARY_FILE}"
echo "========== FINAL RESULTS ==========" | tee -a "${SUMMARY_FILE}"
echo "Total tested:     ${TOTAL}"  | tee -a "${SUMMARY_FILE}"
echo "KCSAN triggered:  ${TRIGGERED}" | tee -a "${SUMMARY_FILE}"
echo "Skipped:          ${SKIPPED}" | tee -a "${SUMMARY_FILE}"
if [[ "${AUTO_PATCH_REBUILD}" -eq 1 ]]; then
    echo "Locate failed:    ${LOCATE_FAILED}" | tee -a "${SUMMARY_FILE}"
    echo "Patch failed:     ${PATCH_FAILED}" | tee -a "${SUMMARY_FILE}"
    echo "Build failed:     ${BUILD_FAILED}" | tee -a "${SUMMARY_FILE}"
fi
if [[ "${TOTAL}" -gt 0 ]]; then
    RATE=$(( TRIGGERED * 100 / TOTAL ))
    echo "Trigger rate:     ${TRIGGERED}/${TOTAL} = ${RATE}%" | tee -a "${SUMMARY_FILE}"
fi
echo "Results CSV:      ${CSV_FILE}" | tee -a "${SUMMARY_FILE}"
echo "Triggered list:   ${TRIGGERED_FILE}" | tee -a "${SUMMARY_FILE}"
echo "Finished: $(date)" | tee -a "${SUMMARY_FILE}"
