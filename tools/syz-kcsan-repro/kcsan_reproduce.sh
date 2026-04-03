#!/bin/bash
# kcsan_reproduce.sh - Fully automated KCSAN race reproducer pipeline
#
# Takes a validated_uaf.db and produces KCSAN data-race reports.
#
# Usage:
#   ./kcsan_reproduce.sh <validated_uaf.db> [options]
#
# Options:
#   --target <name>          Target filesystem/module name (e.g., btrfs, xfs)
#   --kernel-src <path>      Path to existing kernel source (skip download)
#   --kernel-version <ver>   Kernel version tag (default: v6.17-rc5)
#   --vmlinux <path>         Existing vmlinux for addr2line (skip build)
#   --kcsan-kernel <path>    Existing KCSAN bzImage (skip build)
#   --image <path>           Root filesystem image
#   --sshkey <path>          SSH private key
#   --analyzer <path>        DDRD Analyzer binary
#   --ll-dir <path>          LLVM IR files directory
#   --output-dir <path>      Output directory (default: ./kcsan_output)
#   --record-index <n>       Process only record N (default: all)
#   --skip-build             Skip kernel build (use existing KCSAN kernel)
#   --skip-detect            Skip detection (only generate reproducers)
#   --delay-sweep            Enable delay sweep mode
#   --extra-qemu <args>      Extra QEMU arguments
#   --jobs <n>               Parallel build jobs
#   --help                   Show this help
#
# Pipeline Steps:
#   1. Parse validated_uaf.db → extract records
#   2. Locate source code (Analyzer / addr2line)
#   3. Generate C reproducers (syz-prog2c + barrier merge)
#   4. Build KCSAN kernel (if needed)
#   5. Run detection in QEMU
#   6. Collect KCSAN reports
#
# Environment:
#   SYZKALLER_ROOT     Auto-detected from script location
#   DDRD_ROOT          Path to DDRD project (default: ~/BASS/DDRD)
#   KERNEL_SRC_ROOT    Path to kernel sources (default: ~/Linux-Kernel)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DDRD_ROOT="${DDRD_ROOT:-/home/zzzccc/BASS/DDRD}"
KERNEL_SRC_ROOT="${KERNEL_SRC_ROOT:-/home/zzzccc/Linux-Kernel}"

# ============================================
# Color output
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[kcsan-repro]${NC} $*"; }
warn()  { echo -e "${YELLOW}[kcsan-repro]${NC} $*"; }
error() { echo -e "${RED}[kcsan-repro]${NC} $*" >&2; }
ok()    { echo -e "${GREEN}[kcsan-repro]${NC} $*"; }

# ============================================
# Default values
# ============================================
DB_PATH=""
TARGET_NAME=""
KERNEL_SRC=""
KERNEL_VERSION="v6.17-rc5"
VMLINUX=""
KCSAN_KERNEL=""
ROOT_IMAGE="${SYZKALLER_ROOT}/images/bookworm.img"
SSH_KEY="${SYZKALLER_ROOT}/images/bookworm.id_rsa"
ANALYZER_BIN="${DDRD_ROOT}/Analyzer/report_analyzer/build/analyzer"
LL_DIR=""
OUTPUT_DIR=""
RECORD_INDEX=""
SKIP_BUILD=0
SKIP_DETECT=0
DELAY_SWEEP=0
EXTRA_QEMU=""
BUILD_JOBS="$(nproc)"

# ============================================
# Parse arguments
# ============================================
if [[ $# -lt 1 ]]; then
    head -35 "$0" | grep '^#' | sed 's/^# \?//'
    exit 1
fi

DB_PATH="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)         TARGET_NAME="$2"; shift 2 ;;
        --kernel-src)     KERNEL_SRC="$2"; shift 2 ;;
        --kernel-version) KERNEL_VERSION="$2"; shift 2 ;;
        --vmlinux)        VMLINUX="$2"; shift 2 ;;
        --kcsan-kernel)   KCSAN_KERNEL="$2"; shift 2 ;;
        --image)          ROOT_IMAGE="$2"; shift 2 ;;
        --sshkey)         SSH_KEY="$2"; shift 2 ;;
        --analyzer)       ANALYZER_BIN="$2"; shift 2 ;;
        --ll-dir)         LL_DIR="$2"; shift 2 ;;
        --output-dir)     OUTPUT_DIR="$2"; shift 2 ;;
        --record-index)   RECORD_INDEX="$2"; shift 2 ;;
        --skip-build)     SKIP_BUILD=1; shift ;;
        --skip-detect)    SKIP_DETECT=1; shift ;;
        --delay-sweep)    DELAY_SWEEP=1; shift ;;
        --extra-qemu)     EXTRA_QEMU="$2"; shift 2 ;;
        --jobs)           BUILD_JOBS="$2"; shift 2 ;;
        -h|--help)
            head -35 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ============================================
# Validate inputs
# ============================================
if [[ ! -f "${DB_PATH}" ]]; then
    error "Database not found: ${DB_PATH}"
    exit 1
fi

# Auto-detect target name from db path
if [[ -z "${TARGET_NAME}" ]]; then
    # Try to extract from path like exp/btrfs/workdir/validate-run/validated_uaf.db
    TARGET_NAME=$(echo "${DB_PATH}" | grep -oP 'exp/\K[^/]+' || echo "unknown")
fi

# Set output directory
if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="${SYZKALLER_ROOT}/kcsan_output/${TARGET_NAME}"
fi

# Auto-detect vmlinux
if [[ -z "${VMLINUX}" ]]; then
    CANDIDATE="${SYZKALLER_ROOT}/kernels/output/${TARGET_NAME}/vmlinux"
    if [[ -f "${CANDIDATE}" ]]; then
        VMLINUX="${CANDIDATE}"
    fi
fi

# Auto-detect extra QEMU args (e.g., for btrfs needs btrfs.qcow2)
if [[ -z "${EXTRA_QEMU}" ]]; then
    QCOW_CANDIDATE="${SYZKALLER_ROOT}/images/${TARGET_NAME}.qcow2"
    if [[ -f "${QCOW_CANDIDATE}" ]]; then
        EXTRA_QEMU="-enable-kvm -hdb ${QCOW_CANDIDATE}"
        info "Auto-detected extra disk: ${QCOW_CANDIDATE}"
    fi
fi

mkdir -p "${OUTPUT_DIR}"

# ============================================
# Print configuration
# ============================================
echo ""
echo "=============================================="
info "KCSAN Reproducer Pipeline"
echo "=============================================="
echo "  Database:       ${DB_PATH}"
echo "  Target:         ${TARGET_NAME}"
echo "  Kernel version: ${KERNEL_VERSION}"
echo "  VMLINUX:        ${VMLINUX:-<none>}"
echo "  Image:          ${ROOT_IMAGE}"
echo "  Output:         ${OUTPUT_DIR}"
echo "  Skip build:     ${SKIP_BUILD}"
echo "  Skip detect:    ${SKIP_DETECT}"
echo "  Delay sweep:    ${DELAY_SWEEP}"
echo "=============================================="
echo ""

# ============================================
# Step 1: Parse Database
# ============================================
PARSE_DIR="${OUTPUT_DIR}/parsed"

info "Step 1/6: Parsing validated_uaf.db..."

python3 "${SCRIPT_DIR}/parse_validated_db.py" \
    "${DB_PATH}" "${PARSE_DIR}" \
    --syz-db "${SYZKALLER_ROOT}/bin/syz-db"

RECORD_COUNT=$(python3 -c "import json; d=json.load(open('${PARSE_DIR}/summary.json')); print(len(d))")
ok "Parsed ${RECORD_COUNT} records"

# ============================================
# Step 2: Locate Source (for each record)
# ============================================
info "Step 2/6: Locating source code..."

process_record() {
    local REC_DIR="$1"
    local REC_INDEX="$2"
    
    info "  Record ${REC_INDEX}: $(basename "${REC_DIR}")"
    
    # Locate source
    LOCATE_ARGS=("${SCRIPT_DIR}/locate_source.py" "${REC_DIR}")
    
    if [[ -n "${VMLINUX}" ]] && [[ -f "${VMLINUX}" ]]; then
        LOCATE_ARGS+=("--vmlinux" "${VMLINUX}")
    fi
    
    if [[ -f "${ANALYZER_BIN}" ]] && [[ -n "${LL_DIR}" ]] && [[ -d "${LL_DIR}" ]]; then
        LOCATE_ARGS+=("--analyzer" "${ANALYZER_BIN}" "--ll-dir" "${LL_DIR}")
    fi
    
    python3 "${LOCATE_ARGS[@]}" || warn "  Source location failed for record ${REC_INDEX}"
}

# Determine which records to process
RECORD_DIRS=()
if [[ -n "${RECORD_INDEX}" ]]; then
    # Process specific record
    for d in "${PARSE_DIR}"/record_*; do
        if [[ -d "$d" ]]; then
            IDX=$(basename "$d" | grep -oP 'record_\K\d+')
            if [[ "${IDX}" == "$(printf '%04d' "${RECORD_INDEX}")" ]]; then
                RECORD_DIRS+=("$d")
            fi
        fi
    done
else
    # Process all records
    for d in "${PARSE_DIR}"/record_*; do
        if [[ -d "$d" ]]; then
            RECORD_DIRS+=("$d")
        fi
    done
fi

for i in "${!RECORD_DIRS[@]}"; do
    process_record "${RECORD_DIRS[$i]}" "$i"
done

ok "Source location complete"

# ============================================
# Step 3: Generate Reproducers
# ============================================
info "Step 3/6: Generating C reproducers..."

SYZ_PROG2C="${SYZKALLER_ROOT}/bin/syz-prog2c"

if [[ ! -f "${SYZ_PROG2C}" ]]; then
    warn "syz-prog2c not found at ${SYZ_PROG2C}, trying to build..."
    cd "${SYZKALLER_ROOT}"
    make prog2c 2>/dev/null || error "Cannot build syz-prog2c"
fi

for REC_DIR in "${RECORD_DIRS[@]}"; do
    info "  Generating reproducer for $(basename "${REC_DIR}")..."
    
    python3 "${SCRIPT_DIR}/gen_reproducer.py" \
        "${REC_DIR}" \
        --syz-prog2c "${SYZ_PROG2C}" \
        --compile \
        || warn "  Reproducer generation failed for $(basename "${REC_DIR}")"
done

ok "Reproducer generation complete"

# ============================================
# Step 4: Build KCSAN Kernel (if needed)
# ============================================
# In targeted mode, we build PER RECORD because each record patches different
# source locations. Incremental rebuild is fast (only 1-2 files change).
# In non-targeted mode, one kernel is shared across all records.

KERNEL_SRC_FOR_BUILD=""

if [[ "${SKIP_BUILD}" -eq 0 ]] && [[ -z "${KCSAN_KERNEL}" ]]; then
    info "Step 4/6: Building baseline KCSAN kernel..."
    
    BUILD_ARGS=("--kernel-version" "${KERNEL_VERSION}")
    BUILD_ARGS+=("--output-dir" "${OUTPUT_DIR}/kernel")
    BUILD_ARGS+=("--jobs" "${BUILD_JOBS}")
    
    if [[ -n "${KERNEL_SRC}" ]]; then
        BUILD_ARGS+=("--kernel-src" "${KERNEL_SRC}")
    fi
    
    "${SCRIPT_DIR}/build_kcsan_kernel.sh" "${BUILD_ARGS[@]}"
    
    KCSAN_KERNEL="${OUTPUT_DIR}/kernel/bzImage"
    KERNEL_SRC_FOR_BUILD="${OUTPUT_DIR}/kernel/linux-src"
    ok "Baseline KCSAN kernel built: ${KCSAN_KERNEL}"
else
    if [[ -z "${KCSAN_KERNEL}" ]]; then
        KCSAN_KERNEL="${SYZKALLER_ROOT}/kernels/output/kcsan/bzImage"
    fi
    info "Step 4/6: Skipping kernel build (using ${KCSAN_KERNEL})"
fi

# If kernel-src is provided, use it for targeted builds
if [[ -n "${KERNEL_SRC}" ]]; then
    KERNEL_SRC_FOR_BUILD="${KERNEL_SRC}"
elif [[ -z "${KERNEL_SRC_FOR_BUILD}" ]]; then
    # Try auto-detect from existing builds
    for candidate in "${OUTPUT_DIR}/kernel/linux-src" \
                     "${SYZKALLER_ROOT}/kernels/output/kcsan-clean-v617rc5/linux-src" \
                     "${SYZKALLER_ROOT}/kernels/output/kcsan/linux-src"; do
        if [[ -d "${candidate}" ]] && [[ -f "${candidate}/Makefile" ]]; then
            KERNEL_SRC_FOR_BUILD="${candidate}"
            break
        fi
    done
fi

if [[ ! -f "${KCSAN_KERNEL}" ]] && [[ "${SKIP_DETECT}" -eq 0 ]]; then
    error "KCSAN kernel not found: ${KCSAN_KERNEL}"
    error "Build it first with: ${SCRIPT_DIR}/build_kcsan_kernel.sh"
    exit 1
fi

# ============================================
# Step 5-6: Run Detection (with per-record targeted kernel rebuild)
# ============================================
if [[ "${SKIP_DETECT}" -eq 1 ]]; then
    info "Step 5-6/6: Skipping detection (--skip-detect)"
else
    info "Step 5-6/6: Running KCSAN detection..."
    
    TOTAL_KCSAN=0
    TOTAL_TESTED=0
    
    for REC_DIR in "${RECORD_DIRS[@]}"; do
        # Check for barrier_runner (new approach) or reproducer (legacy)
        if [[ ! -f "${REC_DIR}/barrier_runner" ]] && [[ ! -f "${REC_DIR}/reproducer" ]]; then
            warn "  No reproducer binary for $(basename "${REC_DIR}"), skipping"
            continue
        fi
        
        TOTAL_TESTED=$((TOTAL_TESTED + 1))
        info "  [${TOTAL_TESTED}] Testing $(basename "${REC_DIR}")..."
        
        # --- Targeted mode: per-record kernel rebuild ---
        RECORD_KERNEL="${KCSAN_KERNEL}"
        SRC_LOCS="${REC_DIR}/source_locations.json"
        
        if [[ -f "${SRC_LOCS}" ]] && [[ -n "${KERNEL_SRC_FOR_BUILD}" ]] && [[ "${SKIP_BUILD}" -eq 0 ]]; then
            info "  Targeted mode: patching kernel for $(basename "${REC_DIR}")..."
            
            # Restore previous patches first
            python3 "${SCRIPT_DIR}/patch_kernel_kcsan.py" \
                "${KERNEL_SRC_FOR_BUILD}" "${SRC_LOCS}" --restore 2>/dev/null || true
            
            # Apply new targeted patches (bypass proxy for DeepSeek API)
            PATCH_ARGS=("${KERNEL_SRC_FOR_BUILD}" "${SRC_LOCS}"
                        "--record-dir" "${REC_DIR}"
                        "--output-log" "${REC_DIR}/kcsan_patch.log")
            if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
                PATCH_ARGS+=("--api-key" "${DEEPSEEK_API_KEY}")
            fi
            
            http_proxy= https_proxy= python3 "${SCRIPT_DIR}/patch_kernel_kcsan.py" "${PATCH_ARGS[@]}"
            
            # Incremental rebuild (only patched files recompile)
            info "  Rebuilding kernel (incremental)..."
            (cd "${KERNEL_SRC_FOR_BUILD}" && make -j"${BUILD_JOBS}" bzImage 2>&1 | tail -10)
            
            if [[ -f "${KERNEL_SRC_FOR_BUILD}/arch/x86/boot/bzImage" ]]; then
                RECORD_KERNEL="${KERNEL_SRC_FOR_BUILD}/arch/x86/boot/bzImage"
                ok "  Targeted kernel rebuilt: ${RECORD_KERNEL}"
            else
                warn "  Kernel rebuild failed, using baseline kernel"
            fi
        fi
        
        # --- Run detection ---
        DETECT_ARGS=()
        DETECT_ARGS+=("--kernel" "${RECORD_KERNEL}")
        DETECT_ARGS+=("--image" "${ROOT_IMAGE}")
        DETECT_ARGS+=("--sshkey" "${SSH_KEY}")
        DETECT_ARGS+=("--record-dir" "${REC_DIR}")
        DETECT_ARGS+=("--output-dir" "${REC_DIR}/kcsan_results")
        
        if [[ "${DELAY_SWEEP}" -eq 1 ]]; then
            DETECT_ARGS+=("--delay-sweep")
        fi
        
        if [[ -n "${EXTRA_QEMU}" ]]; then
            DETECT_ARGS+=("--extra-qemu" "${EXTRA_QEMU}")
        fi
        
        if "${SCRIPT_DIR}/run_kcsan_detect.sh" "${DETECT_ARGS[@]}"; then
            TOTAL_KCSAN=$((TOTAL_KCSAN + 1))
            ok "  KCSAN report found for $(basename "${REC_DIR}")!"
        else
            warn "  No KCSAN report for $(basename "${REC_DIR}")"
        fi
    done
    
    # Restore kernel source after all records
    if [[ -n "${KERNEL_SRC_FOR_BUILD}" ]] && [[ "${SKIP_BUILD}" -eq 0 ]]; then
        info "Restoring kernel source..."
        # Find the last source_locations.json used to restore
        LAST_SRC_LOCS=""
        for REC_DIR in "${RECORD_DIRS[@]}"; do
            if [[ -f "${REC_DIR}/source_locations.json" ]]; then
                LAST_SRC_LOCS="${REC_DIR}/source_locations.json"
            fi
        done
        if [[ -n "${LAST_SRC_LOCS}" ]]; then
            python3 "${SCRIPT_DIR}/patch_kernel_kcsan.py" \
                "${KERNEL_SRC_FOR_BUILD}" "${LAST_SRC_LOCS}" --restore 2>/dev/null || true
        fi
    fi
    
    ok "Detection complete: ${TOTAL_KCSAN}/${TOTAL_TESTED} records triggered KCSAN"
fi

# ============================================
# Final Summary
# ============================================
echo ""
echo "=============================================="
ok "Pipeline Complete!"
echo "=============================================="
echo "  Records processed: ${#RECORD_DIRS[@]}"
echo "  Output directory:  ${OUTPUT_DIR}"
echo ""
echo "  Parsed records:    ${PARSE_DIR}/"
echo "  Each record contains:"
echo "    - crash_report.txt        Original crash report"
echo "    - prog0.syz / prog1.syz   Syzkaller programs"
echo "    - source_locations.json   Source code locations"
echo "    - prog0.c / prog1.c       Standalone C programs"
echo "    - prog0_bin / prog1_bin   Compiled program binaries"
echo "    - barrier_runner           Barrier synchronizer binary"
echo "    - reproducer              Runner wrapper script"
echo "    - kcsan_results/          Detection results"
echo ""
echo "  To re-run detection only:"
echo "    ${SCRIPT_DIR}/run_kcsan_detect.sh \\"
echo "      --kernel ${KCSAN_KERNEL:-<kcsan_bzImage>} \\"
echo "      --record-dir <record_dir> \\"
echo "      --delay-sweep"
echo ""
echo "=============================================="
