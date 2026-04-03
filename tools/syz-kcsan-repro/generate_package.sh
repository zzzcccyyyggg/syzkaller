#!/bin/bash
# generate_package.sh - Generate a complete KCSAN reproducer package for developers
#
# Produces:
#   patches/0001-kcsan-targeted-common.patch   (public: shared across all records)
#   patches/0002-kcsan-<record>-instrumentation.patch (private: per-record check_access)
#   config/kcsan_config.diff                   (.config changes)
#   config/kcsan_kconfig_fragment               (Kconfig fragment for merge_config.sh)
#   reproducer/                                (prog0.c, prog1.c, barrier_runner.c, history/)
#   scripts/run_kcsan_detect.sh                (detection script)
#   scripts/apply_and_build.sh                 (one-click build script)
#   README.md                                  (reproduction instructions)
#   KCSAN_REPORT.txt                           (detected race reports)
#
# Usage:
#   ./generate_package.sh --record-dir <path> --kernel-src <path> [--output-dir <path>]

set -euo pipefail

# ─── Defaults ───────────────────────────────────────────────────────
RECORD_DIR=""
KERNEL_SRC=""
OUTPUT_DIR=""
SYZKALLER_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ─── Parse args ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --record-dir)   RECORD_DIR="$2"; shift 2 ;;
        --kernel-src)   KERNEL_SRC="$2"; shift 2 ;;
        --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        *)              echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "${RECORD_DIR}" ]]; then
    echo "ERROR: --record-dir is required"
    exit 1
fi

# Resolve to absolute paths
RECORD_DIR="$(cd "${RECORD_DIR}" && pwd)"

# Auto-detect kernel source
if [[ -z "${KERNEL_SRC}" ]]; then
    KERNEL_SRC="${SYZKALLER_ROOT}/kernels/output/kcsan-clean-v617rc5/linux-src"
fi

# Resolve kernel src to absolute
KERNEL_SRC="$(cd "${KERNEL_SRC}" && pwd)"

if [[ ! -d "${KERNEL_SRC}/.git" ]]; then
    echo "ERROR: kernel source not found or not a git repo: ${KERNEL_SRC}"
    exit 1
fi

# Derive record name
RECORD_NAME="$(basename "${RECORD_DIR}")"

# Auto output dir
if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="${RECORD_DIR}/kcsan_package"
fi

echo "=================================================================="
echo "  KCSAN Reproducer Package Generator"
echo "=================================================================="
echo "  Record:     ${RECORD_NAME}"
echo "  Kernel src: ${KERNEL_SRC}"
echo "  Output:     ${OUTPUT_DIR}"
echo ""

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"/{patches,config,reproducer,scripts}

# ─── 1. Generate common (public) kernel patch ───────────────────────
echo "[1/7] Generating common kernel patch..."

cd "${KERNEL_SRC}"

# Common patch: core.c changes + Makefile.kcsan
git diff HEAD -- kernel/kcsan/core.c scripts/Makefile.kcsan > "${OUTPUT_DIR}/patches/0001-kcsan-targeted-common.patch"

# Add proper patch header
TMPFILE=$(mktemp)
cat > "${TMPFILE}" << 'PATCH_HEADER'
From: DDRD KCSAN Reproducer <ddrd@kcsan-repro>
Subject: [PATCH 1/2] kcsan: targeted instrumentation support (common)

This patch modifies KCSAN to support targeted data race detection:

1. scripts/Makefile.kcsan: Disable global compiler KCSAN instrumentation
   (CFLAGS_KCSAN := empty). This prevents compiler-inserted __tsan_*
   calls, so only manually inserted __kcsan_check_access() calls trigger
   watchpoints. This dramatically reduces noise and focuses detection
   budget on specific variables.

2. kernel/kcsan/core.c - check_access(): Filter out KCSAN_ACCESS_ASSERT
   accesses. Kernel-internal ASSERT_EXCLUSIVE_* macros (scheduler, RCU,
   memory allocator, etc.) would otherwise consume the skip_watch counter
   budget, starving our targeted watchpoints.

3. kernel/kcsan/core.c - reset_kcsan_skip(): Guard against divide-by-zero
   when CONFIG_KCSAN_SKIP_WATCH is set to 0 or 1 with randomization
   enabled.

These changes are COMMON across all targeted KCSAN reproductions.
Apply this patch first, then apply the per-record instrumentation patch.

---
PATCH_HEADER
cat "${OUTPUT_DIR}/patches/0001-kcsan-targeted-common.patch" >> "${TMPFILE}"
mv "${TMPFILE}" "${OUTPUT_DIR}/patches/0001-kcsan-targeted-common.patch"

echo "  -> patches/0001-kcsan-targeted-common.patch"

# ─── 2. Generate per-record (private) kernel patch ──────────────────
echo "[2/7] Generating per-record instrumentation patch..."

git diff HEAD -- fs/btrfs/extent_io.c fs/btrfs/defrag.c > "${OUTPUT_DIR}/patches/0002-kcsan-${RECORD_NAME}-instrumentation.patch" 2>/dev/null || true

# If no btrfs changes (other subsystem), try all changed files except common ones
if [[ ! -s "${OUTPUT_DIR}/patches/0002-kcsan-${RECORD_NAME}-instrumentation.patch" ]]; then
    # Find all modified files except common ones
    git diff HEAD --name-only | grep -v 'kernel/kcsan/core.c\|scripts/Makefile.kcsan' | while read -r f; do
        git diff HEAD -- "$f"
    done > "${OUTPUT_DIR}/patches/0002-kcsan-${RECORD_NAME}-instrumentation.patch"
fi

# Add header
TMPFILE=$(mktemp)
# Read crash_report.txt to extract race info
RACE_INFO=""
if [[ -f "${RECORD_DIR}/crash_report.txt" ]]; then
    RACE_INFO=$(grep -E 'Function:.*\+0x|VarName|is write|BlockLineNumber' "${RECORD_DIR}/crash_report.txt" | head -20)
fi

cat > "${TMPFILE}" << PATCH_HEADER
From: DDRD KCSAN Reproducer <ddrd@kcsan-repro>
Subject: [PATCH 2/2] kcsan: ${RECORD_NAME} targeted instrumentation

Per-record KCSAN instrumentation for data race reproduction.

Insert __kcsan_check_access() calls at the exact racing variable
locations identified from the original KCCWF crash report.

Original crash report race info:
${RACE_INFO}

Apply this patch AFTER the common patch (0001).

---
PATCH_HEADER
cat "${OUTPUT_DIR}/patches/0002-kcsan-${RECORD_NAME}-instrumentation.patch" >> "${TMPFILE}"
mv "${TMPFILE}" "${OUTPUT_DIR}/patches/0002-kcsan-${RECORD_NAME}-instrumentation.patch"

echo "  -> patches/0002-kcsan-${RECORD_NAME}-instrumentation.patch"

# ─── 3. Generate .config diff and Kconfig fragment ──────────────────
echo "[3/7] Generating kernel config..."

# Kconfig fragment (for scripts/kconfig/merge_config.sh)
cat > "${OUTPUT_DIR}/config/kcsan_kconfig_fragment" << 'EOF'
# KCSAN Targeted Instrumentation - Kconfig Fragment
# Usage: scripts/kconfig/merge_config.sh .config this_fragment
#
# Core KCSAN
CONFIG_KCSAN=y
CONFIG_KCSAN_VERBOSE=y

# Skip watch = 1: set watchpoint on (almost) every check_access call
CONFIG_KCSAN_SKIP_WATCH=1

# Disable randomization to make behavior deterministic
# CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE is not set

# Report ALL races, not just value-change ones
# (writeback_index may be written with same value → still a race)
# CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY is not set

# Keep plain-writes-atomic assumption (we use KCSAN_ACCESS_COMPOUND to bypass)
CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y

# Do not permissively ignore any races
# CONFIG_KCSAN_PERMISSIVE is not set

# Not strict mode (we do targeted, not global)
# CONFIG_KCSAN_STRICT is not set
EOF

# Also capture the actual config keys
grep -E '^CONFIG_KCSAN' "${KERNEL_SRC}/.config" | sort > "${OUTPUT_DIR}/config/kcsan_config_actual.txt"

echo "  -> config/kcsan_kconfig_fragment"
echo "  -> config/kcsan_config_actual.txt"

# ─── 4. Copy reproducer sources ────────────────────────────────────
echo "[4/7] Copying reproducer sources..."

# Copy prog sources
for f in prog0.c prog1.c prog0.syz prog1.syz barrier_runner.c; do
    if [[ -f "${RECORD_DIR}/${f}" ]]; then
        cp "${RECORD_DIR}/${f}" "${OUTPUT_DIR}/reproducer/"
    fi
done

# Copy history
if [[ -d "${RECORD_DIR}/history" ]]; then
    mkdir -p "${OUTPUT_DIR}/reproducer/history"
    cp "${RECORD_DIR}"/history/*.syz "${OUTPUT_DIR}/reproducer/history/" 2>/dev/null || true
    cp "${RECORD_DIR}"/history/*.c   "${OUTPUT_DIR}/reproducer/history/" 2>/dev/null || true
    HIST_COUNT=$(ls "${RECORD_DIR}"/history/*.syz 2>/dev/null | wc -l)
    echo "  -> reproducer/history/ (${HIST_COUNT} programs)"
fi

# Copy metadata
for f in crash_report.txt metadata.json barrier_info.json replay_plan.json; do
    if [[ -f "${RECORD_DIR}/${f}" ]]; then
        cp "${RECORD_DIR}/${f}" "${OUTPUT_DIR}/reproducer/"
    fi
done

# Copy KCSAN results
if [[ -f "${RECORD_DIR}/kcsan_results/all_kcsan_reports.txt" ]]; then
    cp "${RECORD_DIR}/kcsan_results/all_kcsan_reports.txt" "${OUTPUT_DIR}/KCSAN_REPORT.txt"
    RACE_COUNT=$(grep -c 'BUG: KCSAN' "${OUTPUT_DIR}/KCSAN_REPORT.txt" 2>/dev/null || echo 0)
    echo "  -> KCSAN_REPORT.txt (${RACE_COUNT} races detected)"
fi

echo "  -> reproducer/ (prog0.c, prog1.c, barrier_runner.c)"

# ─── 5. Copy detection script ──────────────────────────────────────
echo "[5/7] Copying detection script..."

SCRIPT_DIR="${SYZKALLER_ROOT}/tools/syz-kcsan-repro"
cp "${SCRIPT_DIR}/run_kcsan_detect.sh" "${OUTPUT_DIR}/scripts/"
echo "  -> scripts/run_kcsan_detect.sh"

# ─── 6. Generate apply_and_build.sh ────────────────────────────────
echo "[6/7] Generating build script..."

cat > "${OUTPUT_DIR}/scripts/apply_and_build.sh" << 'BUILDSCRIPT'
#!/bin/bash
# apply_and_build.sh - Apply KCSAN patches and build the kernel
#
# Usage:
#   ./apply_and_build.sh <kernel-source-dir> [--jobs N]
#
# Prerequisites:
#   - Clean Linux kernel source (v6.17-rc5 recommended)
#   - GCC toolchain (KCSAN works with GCC, no LLVM needed)
#   - Standard kernel build dependencies

set -euo pipefail

KERNEL_SRC="${1:?Usage: $0 <kernel-source-dir> [--jobs N]}"
JOBS=$(nproc)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$(dirname "${SCRIPT_DIR}")"

if [[ "${2:-}" == "--jobs" ]]; then
    JOBS="${3:-$(nproc)}"
fi

cd "${KERNEL_SRC}"

echo "=================================================================="
echo "  KCSAN Targeted Kernel Build"
echo "=================================================================="
echo "  Kernel:  ${KERNEL_SRC}"
echo "  Jobs:    ${JOBS}"
echo ""

# Step 1: Apply common patch
echo "[1/4] Applying common KCSAN patch..."
if git apply --check "${PKG_DIR}/patches/0001-kcsan-targeted-common.patch" 2>/dev/null; then
    git apply "${PKG_DIR}/patches/0001-kcsan-targeted-common.patch"
    echo "  Applied successfully."
else
    echo "  WARNING: patch may already be applied or conflicts exist."
    echo "  Trying with --reverse --check..."
    if git apply --reverse --check "${PKG_DIR}/patches/0001-kcsan-targeted-common.patch" 2>/dev/null; then
        echo "  Patch already applied, skipping."
    else
        echo "  ERROR: Cannot apply patch. Please check manually."
        exit 1
    fi
fi

# Step 2: Apply per-record instrumentation patch
echo "[2/4] Applying per-record instrumentation patch..."
RECORD_PATCH=$(ls "${PKG_DIR}/patches/0002-kcsan-"*".patch" 2>/dev/null | head -1)
if [[ -n "${RECORD_PATCH}" ]]; then
    if git apply --check "${RECORD_PATCH}" 2>/dev/null; then
        git apply "${RECORD_PATCH}"
        echo "  Applied successfully."
    else
        echo "  WARNING: patch may already be applied or conflicts exist."
        if git apply --reverse --check "${RECORD_PATCH}" 2>/dev/null; then
            echo "  Patch already applied, skipping."
        else
            echo "  ERROR: Cannot apply patch. Please check manually."
            exit 1
        fi
    fi
fi

# Step 3: Apply Kconfig fragment
echo "[3/4] Applying KCSAN kernel config..."
if [[ ! -f .config ]]; then
    echo "  No .config found, generating default + KCSAN..."
    make defconfig
fi

if [[ -f scripts/kconfig/merge_config.sh ]]; then
    scripts/kconfig/merge_config.sh -m .config "${PKG_DIR}/config/kcsan_kconfig_fragment"
else
    echo "  merge_config.sh not found, applying manually..."
    # Manually set critical options
    sed -i 's/.*CONFIG_KCSAN_SKIP_WATCH.*/CONFIG_KCSAN_SKIP_WATCH=1/' .config
    sed -i 's/CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=y/# CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY is not set/' .config
fi
make olddefconfig

# Step 4: Build
echo "[4/4] Building kernel (this may take a while)..."
make -j"${JOBS}" bzImage 2>&1 | tail -5

BZIMAGE="arch/x86/boot/bzImage"
if [[ -f "${BZIMAGE}" ]]; then
    echo ""
    echo "=================================================================="
    echo "  BUILD SUCCESS"
    echo "  bzImage: ${KERNEL_SRC}/${BZIMAGE}"
    echo "  Size:    $(du -h "${BZIMAGE}" | cut -f1)"
    echo "=================================================================="
else
    echo "ERROR: bzImage not found after build."
    exit 1
fi
BUILDSCRIPT
chmod +x "${OUTPUT_DIR}/scripts/apply_and_build.sh"
echo "  -> scripts/apply_and_build.sh"

# ─── 7. Generate README ────────────────────────────────────────────
echo "[7/7] Generating README..."

# Extract key info from metadata
RECORD_HASH=""
if [[ -f "${RECORD_DIR}/metadata.json" ]]; then
    RECORD_HASH=$(python3 -c "import json; d=json.load(open('${RECORD_DIR}/metadata.json')); print(d.get('hash','N/A'))" 2>/dev/null || echo "N/A")
fi

# Count history
HIST_COUNT=$(ls "${RECORD_DIR}"/history/*.syz 2>/dev/null | wc -l || echo 0)

# Extract race function names from crash report
RACE_FUNC1=""
RACE_FUNC2=""
if [[ -f "${RECORD_DIR}/crash_report.txt" ]]; then
    RACE_FUNC1=$(grep -A2 'is write 1' "${RECORD_DIR}/crash_report.txt" | grep 'Function:' | head -1 | sed 's/Function: //' | cut -d+ -f1 || echo "N/A")
    RACE_FUNC2=$(grep -A3 'OTHER_INFO' "${RECORD_DIR}/crash_report.txt" | grep 'Function:' | tail -1 | sed 's/Function: //' | cut -d+ -f1 || echo "N/A")
fi

# Count KCSAN reports
KCSAN_COUNT=0
if [[ -f "${OUTPUT_DIR}/KCSAN_REPORT.txt" ]]; then
    KCSAN_COUNT=$(grep -c 'BUG: KCSAN' "${OUTPUT_DIR}/KCSAN_REPORT.txt" 2>/dev/null || echo 0)
fi

cat > "${OUTPUT_DIR}/README.md" << README_EOF
# KCSAN Data Race Reproducer: ${RECORD_NAME}

## Summary

| Item | Value |
|------|-------|
| Record | \`${RECORD_NAME}\` |
| Record Hash | \`${RECORD_HASH}\` |
| Race Variable | \`mapping->writeback_index\` (address_space) |
| Race Type | read-write vs read-write (8 bytes) |
| Stack 1 (WRITE) | \`${RACE_FUNC1}\` (writeback worker) |
| Stack 2 (READ) | \`${RACE_FUNC2}\` (syscall / defrag ioctl) |
| KCSAN Reports | **${KCSAN_COUNT} races detected** |
| History Programs | ${HIST_COUNT} (for FS state setup) |
| Kernel Version | v6.17-rc5 |

## Package Contents

\`\`\`
patches/
  0001-kcsan-targeted-common.patch       # Common: disable global instrumentation,
                                          #   ASSERT filter, skip_watch guard
  0002-kcsan-*-instrumentation.patch      # Per-record: __kcsan_check_access() insertions
config/
  kcsan_kconfig_fragment                  # Kconfig options for merge_config.sh
  kcsan_config_actual.txt                 # Actual CONFIG_KCSAN_* values used
reproducer/
  prog0.c / prog1.c                      # Reproducer programs (C source)
  prog0.syz / prog1.syz                  # Original syzkaller programs
  barrier_runner.c                        # Barrier-synchronized runner
  crash_report.txt                        # Original KCCWF crash report
  history/                                # History programs for FS state setup
scripts/
  apply_and_build.sh                      # One-click: apply patches + build kernel
  run_kcsan_detect.sh                     # Run KCSAN detection in QEMU VM
KCSAN_REPORT.txt                          # Detected race reports (from our test)
README.md                                 # This file
\`\`\`

## Quick Reproduction

### Prerequisites
- Linux kernel v6.17-rc5 source
- GCC toolchain (no LLVM/Clang needed)
- QEMU with KVM support
- Debian bookworm rootfs image (\`bookworm.img\` + \`bookworm.id_rsa\`)
- btrfs filesystem image (\`btrfs.qcow2\`, 2GB)

### Step 1: Apply Patches & Build Kernel

\`\`\`bash
# Option A: One-click build
./scripts/apply_and_build.sh /path/to/linux-src --jobs 8

# Option B: Manual
cd /path/to/linux-src
git apply patches/0001-kcsan-targeted-common.patch
git apply patches/0002-kcsan-*-instrumentation.patch
scripts/kconfig/merge_config.sh -m .config config/kcsan_kconfig_fragment
make olddefconfig
make -j\$(nproc) bzImage
\`\`\`

### Step 2: Compile Reproducer Programs

\`\`\`bash
cd reproducer
gcc -static -o prog0_bin prog0.c -lpthread
gcc -static -o prog1_bin prog1.c -lpthread
gcc -static -o barrier_runner barrier_runner.c -lpthread
# Compile history programs
for f in history/hist_*.c; do
    gcc -static -o "\${f%.c}_bin" "\$f" -lpthread
done
\`\`\`

### Step 3: Run KCSAN Detection

\`\`\`bash
./scripts/run_kcsan_detect.sh \\
    --record-dir ./reproducer \\
    --kernel /path/to/bzImage \\
    --image /path/to/bookworm.img \\
    --sshkey /path/to/bookworm.id_rsa \\
    --repeat 500 \\
    --timeout 180
\`\`\`

### Expected Output

After ~3 minutes, you should see KCSAN reports in dmesg like:

\`\`\`
BUG: KCSAN: data-race in extent_write_cache_pages / extent_write_cache_pages

read-write to 0xffff...  of 8 bytes by task N on cpu M:
  extent_write_cache_pages+0xe45/0xee0
  btrfs_writepages+0x92/0xd0
  ...
  wb_workfn+0xd9/0x590       <-- writeback worker

read-write to 0xffff...  of 8 bytes by task K on cpu L:
  extent_write_cache_pages+0xe45/0xee0
  btrfs_writepages+0x92/0xd0
  ...
  vfs_write+0x561/0x6c0      <-- user write syscall
\`\`\`

## Technical Details

### Why Targeted KCSAN?

Standard KCSAN uses compiler instrumentation (\`-fsanitize=thread\`) which
instruments **every** memory access. This creates overwhelming noise and
the skip_watch budget is consumed by irrelevant accesses before reaching
the target code path.

Our approach:
1. **Disable** global compiler instrumentation (\`CFLAGS_KCSAN :=\` empty)
2. **Manually insert** \`__kcsan_check_access()\` only at the racing variable
3. **Filter** ASSERT accesses that waste the watchpoint budget
4. **Set** \`KCSAN_SKIP_WATCH=1\` to watch (almost) every targeted access

### Key Config Options

| Option | Value | Why |
|--------|-------|-----|
| \`CONFIG_KCSAN_SKIP_WATCH\` | 1 | Watch every targeted access |
| \`CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY\` | n | Report even if value didn't change |
| \`CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC\` | y | We use COMPOUND flag to bypass |

### Reproducer Fixes Applied

1. **EEXIST on mkdir**: Added \`errno != EEXIST\` check for \`./syz-tmp\`
   sandbox directory to survive across iterations
2. **Empty file defrag**: Added data write (512KB) before
   \`BTRFS_IOC_DEFRAG_RANGE\` so \`btrfs_defrag_file()\` doesn't bail
   out on \`isize == 0\`
README_EOF

echo "  -> README.md"

# ─── Summary ───────────────────────────────────────────────────────
echo ""
echo "=================================================================="
echo "  Package generated successfully!"
echo "=================================================================="
echo "  Output: ${OUTPUT_DIR}"
echo ""
echo "  Contents:"
find "${OUTPUT_DIR}" -type f | sort | while read -r f; do
    echo "    $(realpath --relative-to="${OUTPUT_DIR}" "$f")"
done
echo ""
echo "  To create a tarball:"
echo "    tar czf kcsan-repro-${RECORD_NAME}.tar.gz -C $(dirname "${OUTPUT_DIR}") $(basename "${OUTPUT_DIR}")"
