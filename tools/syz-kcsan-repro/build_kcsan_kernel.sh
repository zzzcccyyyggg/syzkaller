#!/bin/bash
# build_kcsan_kernel.sh - Download and build a KCSAN-enabled kernel
#
# Usage:
#   ./build_kcsan_kernel.sh [options]
#
# Options:
#   --kernel-version <ver>    Kernel version tag (default: v6.17-rc5)
#   --kernel-src <path>       Path to existing kernel source (skip download)
#   --kcsan-config <path>     Path to KCSAN .config file
#   --output-dir <path>       Output directory for built kernel
#   --jobs <n>                Parallel build jobs (default: nproc)
#   --llvm                    Use LLVM/Clang for building (default: yes)
#   --targeted <json>         Enable targeted mode: disable global instrumentation,
#                             insert __kcsan_check_access() at locations from JSON
#   --restore                 Restore kernel source from .orig backups
#
# This script:
#   1. Downloads vanilla kernel source if not provided
#   2. Applies KCSAN config (KCSAN=y, KASAN=n)
#   3. (Targeted) Patches source to disable global instrumentation + insert checks
#   4. Builds kernel
#   5. Outputs bzImage and vmlinux for QEMU boot

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults
KERNEL_VERSION="v6.17-rc5"
KERNEL_SRC=""
KCSAN_CONFIG="${SYZKALLER_ROOT}/kernels/configs/x86-64-kcsan.config"
OUTPUT_DIR="${SYZKALLER_ROOT}/kernels/output/kcsan"
JOBS="$(nproc)"
USE_LLVM=1
TARGETED_JSON=""
RESTORE_MODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel-version) KERNEL_VERSION="$2"; shift 2 ;;
        --kernel-src)     KERNEL_SRC="$2"; shift 2 ;;
        --kcsan-config)   KCSAN_CONFIG="$2"; shift 2 ;;
        --output-dir)     OUTPUT_DIR="$2"; shift 2 ;;
        --jobs)           JOBS="$2"; shift 2 ;;
        --no-llvm)        USE_LLVM=0; shift ;;
        --llvm)           USE_LLVM=1; shift ;;
        --targeted)       TARGETED_JSON="$2"; shift 2 ;;
        --restore)        RESTORE_MODE=1; shift ;;
        -h|--help)
            head -20 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "${OUTPUT_DIR}"

CONFIG_ARGS=""
if [[ "${USE_LLVM}" -eq 1 ]]; then
    CONFIG_ARGS="LLVM=1"
fi

# ==============================================================
# Step 1: Obtain kernel source
# ==============================================================
if [[ -z "${KERNEL_SRC}" ]]; then
    KERNEL_SRC="${OUTPUT_DIR}/linux-src"
    
    if [[ -d "${KERNEL_SRC}" ]] && [[ -f "${KERNEL_SRC}/Makefile" ]]; then
        echo "[build_kcsan] Using existing kernel source at ${KERNEL_SRC}"
    else
        echo "[build_kcsan] Downloading kernel ${KERNEL_VERSION}..."
        
        # Try git clone with specific tag (shallow)
        KERNEL_GIT_URL="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
        
        if command -v git &>/dev/null; then
            echo "[build_kcsan] Shallow clone ${KERNEL_VERSION} from git.kernel.org..."
            git clone --depth 1 --branch "${KERNEL_VERSION}" \
                "${KERNEL_GIT_URL}" "${KERNEL_SRC}" || {
                echo "[build_kcsan] Git clone failed, trying tarball download..."
                
                # Fallback: download tarball
                # For rc versions: https://git.kernel.org/torvalds/t/linux-6.17-rc5.tar.gz
                VERSION_NUM="${KERNEL_VERSION#v}"
                TARBALL_URL="https://git.kernel.org/torvalds/t/linux-${VERSION_NUM}.tar.gz"
                
                mkdir -p "${KERNEL_SRC}"
                echo "[build_kcsan] Downloading ${TARBALL_URL}..."
                curl -L "${TARBALL_URL}" | tar xz --strip-components=1 -C "${KERNEL_SRC}" || {
                    echo "[build_kcsan] ERROR: Cannot download kernel source"
                    exit 1
                }
            }
        else
            echo "[build_kcsan] ERROR: git not found"
            exit 1
        fi
    fi
fi

if [[ ! -f "${KERNEL_SRC}/Makefile" ]]; then
    echo "[build_kcsan] ERROR: Invalid kernel source at ${KERNEL_SRC}"
    exit 1
fi

echo "[build_kcsan] Kernel source: ${KERNEL_SRC}"

# ==============================================================
# Step 2: Configure kernel with KCSAN
# ==============================================================
echo "[build_kcsan] Configuring kernel with KCSAN..."

if [[ -f "${KCSAN_CONFIG}" ]]; then
    cp "${KCSAN_CONFIG}" "${KERNEL_SRC}/.config"
    echo "[build_kcsan] Applied KCSAN config from ${KCSAN_CONFIG}"
    (cd "${KERNEL_SRC}" && make ${CONFIG_ARGS} olddefconfig)
else
    echo "[build_kcsan] WARNING: KCSAN config not found at ${KCSAN_CONFIG}"
    echo "[build_kcsan] Generating minimal KCSAN config..."
    
    cd "${KERNEL_SRC}"
    
    # Start with defconfig
    make ${CONFIG_ARGS} defconfig
    
    # Enable KCSAN, disable KASAN
    ./scripts/config --enable CONFIG_KCSAN
    ./scripts/config --enable CONFIG_KCSAN_SELFTEST
    ./scripts/config --enable CONFIG_KCSAN_EARLY_ENABLE
    ./scripts/config --set-val CONFIG_KCSAN_NUM_WATCHPOINTS 64
    ./scripts/config --set-val CONFIG_KCSAN_UDELAY_TASK 80
    ./scripts/config --set-val CONFIG_KCSAN_UDELAY_INTERRUPT 20
    ./scripts/config --enable CONFIG_KCSAN_DELAY_RANDOMIZE
    ./scripts/config --set-val CONFIG_KCSAN_SKIP_WATCH 4000
    ./scripts/config --enable CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE
    ./scripts/config --set-val CONFIG_KCSAN_REPORT_ONCE_IN_MS 3000
    ./scripts/config --enable CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
    ./scripts/config --enable CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY
    ./scripts/config --enable CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
    ./scripts/config --disable CONFIG_KASAN
    
    # Enable debug info for addr2line
    ./scripts/config --enable CONFIG_DEBUG_INFO
    ./scripts/config --enable CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
    
    # Enable common filesystem modules
    ./scripts/config --enable CONFIG_BTRFS_FS
    ./scripts/config --enable CONFIG_XFS_FS
    ./scripts/config --enable CONFIG_JFS_FS
    ./scripts/config --enable CONFIG_EXT4_FS
    
    # KVM/virtio for QEMU
    ./scripts/config --enable CONFIG_VIRTIO
    ./scripts/config --enable CONFIG_VIRTIO_PCI
    ./scripts/config --enable CONFIG_VIRTIO_BLK
    ./scripts/config --enable CONFIG_VIRTIO_NET
    ./scripts/config --enable CONFIG_NET_9P
    ./scripts/config --enable CONFIG_NET_9P_VIRTIO
    ./scripts/config --enable CONFIG_9P_FS
    
    # Required for syz networking
    ./scripts/config --enable CONFIG_CONFIGFS_FS
    ./scripts/config --enable CONFIG_SECURITYFS
    
    make ${CONFIG_ARGS} olddefconfig
fi

cd "${KERNEL_SRC}"

# Ensure KCSAN is enabled and KASAN is disabled in .config
if ! grep -q 'CONFIG_KCSAN=y' .config; then
    echo "[build_kcsan] ERROR: KCSAN is not enabled in .config"
    echo "[build_kcsan] This may be because the compiler doesn't support KCSAN"
    exit 1
fi

if grep -q 'CONFIG_KASAN=y' .config; then
    echo "[build_kcsan] WARNING: KASAN is enabled alongside KCSAN. Disabling KASAN..."
    sed -i 's/CONFIG_KASAN=y/# CONFIG_KASAN is not set/' .config
    make ${CONFIG_ARGS} olddefconfig
fi

echo "[build_kcsan] Config verification:"
grep -E 'CONFIG_(KCSAN|KASAN)=' .config || true

# ==============================================================
# Step 2.5: Targeted KCSAN patching (if --targeted)
# ==============================================================
if [[ "${RESTORE_MODE}" -eq 1 ]]; then
    echo "[build_kcsan] Restoring kernel source from backups..."
    if [[ -n "${TARGETED_JSON}" ]]; then
        python3 "${SCRIPT_DIR}/patch_kernel_kcsan.py" "${KERNEL_SRC}" "${TARGETED_JSON}" --restore
    else
        # Restore Makefile.kcsan at minimum
        if [[ -f "${KERNEL_SRC}/scripts/Makefile.kcsan.orig" ]]; then
            cp "${KERNEL_SRC}/scripts/Makefile.kcsan.orig" "${KERNEL_SRC}/scripts/Makefile.kcsan"
            rm -f "${KERNEL_SRC}/scripts/Makefile.kcsan.orig"
            echo "[build_kcsan] Restored scripts/Makefile.kcsan"
        fi
        # Restore any .kcsan_orig files
        find "${KERNEL_SRC}" -name '*.kcsan_orig' | while read orig; do
            real="${orig%.kcsan_orig}"
            cp "$orig" "$real"
            rm -f "$orig"
            echo "[build_kcsan] Restored $(basename "$real")"
        done
    fi
    echo "[build_kcsan] Restore complete."
    exit 0
fi

if [[ -n "${TARGETED_JSON}" ]]; then
    echo "[build_kcsan] === Targeted KCSAN mode ==="
    echo "[build_kcsan] Patching kernel source with targeted __kcsan_check_access()..."
    
    PATCH_ARGS=("${KERNEL_SRC}" "${TARGETED_JSON}")
    
    # Pass API key if available
    if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
        PATCH_ARGS+=("--api-key" "${DEEPSEEK_API_KEY}")
    fi
    
    # Auto-detect record-dir from targeted JSON path
    TARGETED_DIR="$(dirname "$(realpath "${TARGETED_JSON}")")"
    if [[ -f "${TARGETED_DIR}/crash_report.txt" ]]; then
        PATCH_ARGS+=("--record-dir" "${TARGETED_DIR}")
    fi
    
    http_proxy= https_proxy= python3 "${SCRIPT_DIR}/patch_kernel_kcsan.py" "${PATCH_ARGS[@]}"
    
    echo "[build_kcsan] Targeted patches applied."
    echo "[build_kcsan] Global instrumentation DISABLED (CFLAGS_KCSAN := empty)"
    echo "[build_kcsan] Only targeted locations will trigger KCSAN."
fi

# ==============================================================
# Step 3: Build kernel
# ==============================================================
echo "[build_kcsan] Building kernel with ${JOBS} jobs..."

BUILD_ARGS=""
if [[ "${USE_LLVM}" -eq 1 ]]; then
    BUILD_ARGS="LLVM=1"
fi

make ${BUILD_ARGS} -j"${JOBS}" bzImage 2>&1 | tail -20

if [[ ! -f "arch/x86/boot/bzImage" ]]; then
    echo "[build_kcsan] ERROR: bzImage not found after build"
    exit 1
fi

# ==============================================================
# Step 4: Copy outputs
# ==============================================================
echo "[build_kcsan] Copying build outputs..."

cp arch/x86/boot/bzImage "${OUTPUT_DIR}/bzImage"
cp vmlinux "${OUTPUT_DIR}/vmlinux"

echo "[build_kcsan] Build complete!"
echo "[build_kcsan] bzImage: ${OUTPUT_DIR}/bzImage"
echo "[build_kcsan] vmlinux: ${OUTPUT_DIR}/vmlinux"
echo ""
echo "[build_kcsan] KCSAN config summary:"
grep -E 'KCSAN_(NUM_WATCHPOINTS|UDELAY_TASK|SKIP_WATCH|REPORT_ONCE_IN_MS)' .config

# Also build filesystem modules if configured as modules
if grep -q 'CONFIG_BTRFS_FS=m' .config; then
    echo "[build_kcsan] Building filesystem modules..."
    make ${BUILD_ARGS} -j"${JOBS}" modules 2>&1 | tail -5
    INSTALL_DIR="${OUTPUT_DIR}/modules"
    mkdir -p "${INSTALL_DIR}"
    make ${BUILD_ARGS} INSTALL_MOD_PATH="${INSTALL_DIR}" modules_install 2>&1 | tail -5
    echo "[build_kcsan] Modules installed to ${INSTALL_DIR}"
fi

echo "[build_kcsan] All done!"
