#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: module_instrument_build.sh [options]

Options:
  --kernel <path>        Path to the kernel source tree (default: repo_root/kernel_src)
  --build-dir <path>     Out-of-tree build directory passed as O=<path>
  --arch <name>          Kernel ARCH to use (default: x86)
  --bzimage <relative>   Relative path to the bzImage inside the build tree (default: arch/<ARCH>/boot/bzImage)
    --output <path>        Directory to store renamed kernel images (default: <kernel>/ddrd-artifacts)
    --inline-output        Copy artifacts next to the originals (vmlinux -> vmlinux-<slug>)
    --kcsan-only           Only build a KCSAN-enabled kernel artifact
    --with-kcsan           Also build module artifacts with KCSAN enabled
  --no-clean             Skip initial 'make clean' before plain build
  --modules <a,b,c>      Only rebuild the listed module slugs (comma separated)
  -j, --jobs <n>         Parallel jobs for make (default: nproc)
  -h, --help             Show this help message

Available module slugs:
  intel-hda, bt-driver, bt-stack, floppy, wifi-stack, tty,
  xfs, btrfs, f2fs, overlayfs, ext4, v4l2,jfs
EOF
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
WRAPPER="$REPO_ROOT/compiler/clang-wrapper.sh"
INSTRUMENT_FILE="$REPO_ROOT/compiler/instrumentation_targets.conf"
DEFAULT_KERNEL_DIR="$REPO_ROOT/kernel_src"

KERNEL_DIR=""
BUILD_DIR=""
ARCH="x86"
BZIMAGE_REL=""
OUTPUT_DIR=""
JOBS=$(nproc)
REQUESTED_MODULES=()
all_modules=()
INLINE_OUTPUT=false
KCSAN_ONLY=false
WITH_KCSAN=false
SKIP_INITIAL_CLEAN=false

MODULE_DEFS=(
    "intel-hda|sound/hda/ sound/core/"
    "bt-driver|drivers/bluetooth/"
    "bt-stack|net/bluetooth/"
    "floppy|drivers/block/floppy.c"
    "wifi-stack|net/wireless/ net/mac80211/"
    "tty|drivers/tty/"
    "xfs|fs/xfs/"
    "btrfs|fs/btrfs/"
    "f2fs|fs/f2fs/"
    "overlayfs|fs/overlayfs/"
    "ext4|fs/ext4/"
    "v4l2|drivers/media/v4l2-core/"
    "usb|drivers/usb/"
    "jfs|fs/jfs/"
)

KCSAN_CONFIGS=(
    "CONFIG_KCSAN=y"
    "CONFIG_KASAN=n"
)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)
            if [[ ! -d "$2" ]]; then
                echo "Kernel directory does not exist: $2" >&2
                exit 1
            fi
            KERNEL_DIR=$(readlink -f "$2"); shift 2 ;;
        --build-dir)
            mkdir -p "$2"
            BUILD_DIR=$(readlink -f "$2"); shift 2 ;;
        --arch)
            ARCH="$2"; shift 2 ;;
        --bzimage)
            BZIMAGE_REL="$2"; shift 2 ;;
        --output)
            mkdir -p "$2"
            OUTPUT_DIR=$(readlink -f "$2"); shift 2 ;;
        --modules)
            IFS=',' read -ra REQUESTED_MODULES <<< "$2"
            for idx in "${!REQUESTED_MODULES[@]}"; do
                REQUESTED_MODULES[$idx]="${REQUESTED_MODULES[$idx]//[[:space:]]/}"
            done
            shift 2 ;;
        --inline-output)
            INLINE_OUTPUT=true; shift ;;
        --kcsan-only)
            KCSAN_ONLY=true; shift ;;
        --with-kcsan)
            WITH_KCSAN=true; shift ;;
        --no-clean)
            SKIP_INITIAL_CLEAN=true; shift ;;
        -j|--jobs)
            JOBS="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1 ;;
    esac
done

if [[ ${#REQUESTED_MODULES[@]} -gt 0 ]]; then
    filtered_modules=()
    for slug in "${REQUESTED_MODULES[@]}"; do
        [[ -z "$slug" ]] && continue
        filtered_modules+=("$slug")
    done
    REQUESTED_MODULES=("${filtered_modules[@]}")
fi

if [[ -z "$KERNEL_DIR" ]]; then
    KERNEL_DIR="$DEFAULT_KERNEL_DIR"
fi

if [[ ! -d "$KERNEL_DIR" ]]; then
    echo "Kernel directory not found: $KERNEL_DIR" >&2
    exit 1
fi

if [[ -n "$BUILD_DIR" && ! -d "$BUILD_DIR" ]]; then
    mkdir -p "$BUILD_DIR"
fi

if [[ "$INLINE_OUTPUT" == true ]]; then
    OUTPUT_DIR=""
else
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$KERNEL_DIR/ddrd-artifacts"
    fi
    mkdir -p "$OUTPUT_DIR"
fi

if [[ ! -x "$WRAPPER" ]]; then
    echo "clang-wrapper.sh is not executable: $WRAPPER" >&2
    exit 1
fi

if [[ ! -f "$INSTRUMENT_FILE" ]]; then
    touch "$INSTRUMENT_FILE"
fi

export DDRD_INSTRUMENT_LIST="$INSTRUMENT_FILE"

if [[ -z "$BZIMAGE_REL" ]]; then
    BZIMAGE_REL="arch/$ARCH/boot/bzImage"
fi

build_root="$KERNEL_DIR"
if [[ -n "$BUILD_DIR" ]]; then
    build_root="$BUILD_DIR"
fi
vmlinux_path="$build_root/vmlinux"
if [[ "$BZIMAGE_REL" == /* ]]; then
    bzimage_path="$BZIMAGE_REL"
else
    bzimage_path="$build_root/$BZIMAGE_REL"
fi

log() {
    echo "[module-build] $*"
}

normalize_instrument_path() {
    local path="${1#./}"
    if [[ -z "$path" ]]; then
        return
    fi
    if [[ "$path" == *.c ]]; then
        printf "%s\n" "$path"
    else
        path="${path%/}"
        printf "%s/\n" "$path"
    fi
}

normalize_clean_target() {
    local path="${1#./}"
    [[ -z "$path" ]] && return
    path="${path%/}"
    if [[ "$path" == *.c ]]; then
        path="$(dirname "$path")"
    fi
    printf "%s\n" "$path"
}

write_instrumentation() {
    local module="$1"; shift
    {
        echo "# Instrumentation targets for $module"
        for entry in "$@"; do
            [[ -z "$entry" ]] && continue
            echo "$entry"
        done
    } > "$INSTRUMENT_FILE"
}

clean_targets() {
    declare -A seen=()
    for target in "$@"; do
        [[ -z "$target" ]] && continue
        if [[ -n "${seen[$target]+x}" ]]; then
            continue
        fi
        seen[$target]=1
        log "Cleaning $target"
        kernel_make "M=$target" clean
    done
}

dedupe_targets() {
    local -n in_ref=$1
    local -n out_ref=$2
    declare -A seen=()
    out_ref=()
    for entry in "${in_ref[@]}"; do
        [[ -z "$entry" ]] && continue
        if [[ -z "${seen[$entry]:-}" ]]; then
            seen[$entry]=1
            out_ref+=("$entry")
        fi
    done
}

restore_plain_state() {
    local targets=("$@")
    [[ ${#targets[@]} -eq 0 ]] && return
    log "Restoring plain objects before next module"
    : > "$INSTRUMENT_FILE"
    clean_targets "${targets[@]}"
    kernel_make
}

kernel_make() {
    local args=("ARCH=$ARCH" "CC=$WRAPPER" "HOSTCC=$WRAPPER")
    if [[ -n "$BUILD_DIR" ]]; then
        args+=("O=$BUILD_DIR")
    fi
    args+=("-j$JOBS")
    args+=("$@")
    (cd "$KERNEL_DIR" && make "${args[@]}")
}

plain_kernel_build() {
    log "Starting plain kernel build without instrumentation"
    : > "$INSTRUMENT_FILE"
    if [[ "$SKIP_INITIAL_CLEAN" != true ]]; then
        kernel_make clean
    fi
    kernel_make
}

set_config_option() {
    local file=$1
    local key=$2
    local value=$3
    if grep -q "^$key=" "$file"; then
        sed -i "s|^$key=.*|$key=$value|" "$file"
    elif grep -q "^# $key is not set" "$file"; then
        sed -i "s|^# $key is not set|$key=$value|" "$file"
    else
        echo "$key=$value" >> "$file"
    fi
}

enable_kcsan_config() {
    local config_path="$build_root/.config"
    if [[ ! -f "$config_path" ]]; then
        echo ".config not found at $config_path" >&2
        exit 1
    fi
    for cfg in "${KCSAN_CONFIGS[@]}"; do
        key="${cfg%%=*}"
        value="${cfg#*=}"
        set_config_option "$config_path" "$key" "$value"
    done
    log "Regenerating config with KCSAN options (KASAN disabled)"
    kernel_make olddefconfig
}

restore_config() {
    local backup_path="$1"
    local config_path="$build_root/.config"
    if [[ -f "$backup_path" ]]; then
        cp "$backup_path" "$config_path"
        kernel_make olddefconfig
    fi
}

run_kcsan_build() {
    local config_path="$build_root/.config"
    if [[ ! -f "$config_path" ]]; then
        echo ".config not found at $config_path" >&2
        exit 1
    fi
    local config_backup
    config_backup=$(mktemp)
    cp "$config_path" "$config_backup"

    enable_kcsan_config

    log "Building KCSAN kernel"
    kernel_make clean
    kernel_make

    if [[ ! -f "$vmlinux_path" ]]; then
        echo "vmlinux not found at $vmlinux_path" >&2
        cp "$config_backup" "$config_path"
        rm -f "$config_backup"
        exit 1
    fi
    if [[ ! -f "$bzimage_path" ]]; then
        echo "bzImage not found at $bzimage_path" >&2
        cp "$config_backup" "$config_path"
        rm -f "$config_backup"
        exit 1
    fi

    if [[ "$INLINE_OUTPUT" == true ]]; then
        cp "$vmlinux_path" "${vmlinux_path}-kcsan"
        cp "$bzimage_path" "${bzimage_path}-kcsan"
    else
        cp "$vmlinux_path" "$OUTPUT_DIR/vmlinux-kcsan"
        cp "$bzimage_path" "$OUTPUT_DIR/bzImage-kcsan"
    fi
    log "KCSAN artifacts generated"

    cp "$config_backup" "$config_path"
    rm -f "$config_backup"
}

backup_file=$(mktemp)
restore_mode="copy"
if [[ -f "$INSTRUMENT_FILE" ]]; then
    cp "$INSTRUMENT_FILE" "$backup_file"
else
    restore_mode="remove"
fi
cleanup() {
    if [[ "$restore_mode" == "copy" ]]; then
        cp "$backup_file" "$INSTRUMENT_FILE"
    else
        rm -f "$INSTRUMENT_FILE"
    fi
    rm -f "$backup_file"
}
trap cleanup EXIT

plain_kernel_build

if [[ "$KCSAN_ONLY" == true ]]; then
    run_kcsan_build
    exit 0
fi

# If --with-kcsan is enabled, also build KCSAN-only kernel first
if [[ "$WITH_KCSAN" == true ]]; then
    run_kcsan_build
fi

declare -A module_paths=()
for entry in "${MODULE_DEFS[@]}"; do
    slug="${entry%%|*}"
    paths="${entry#*|}"
    module_paths[$slug]="$paths"
    all_modules+=("$slug")
done

target_modules=()
if [[ ${#REQUESTED_MODULES[@]} -gt 0 ]]; then
    for slug in "${REQUESTED_MODULES[@]}"; do
        if [[ -z "${module_paths[$slug]:-}" ]]; then
            echo "Unknown module slug: $slug" >&2
            exit 1
        fi
        target_modules+=("$slug")
    done
else
    target_modules=("${all_modules[@]}")
fi

# Backup config for KCSAN builds
config_backup_for_kcsan=""
if [[ "$WITH_KCSAN" == true ]]; then
    config_backup_for_kcsan=$(mktemp)
    cp "$build_root/.config" "$config_backup_for_kcsan"
fi

previous_clean_targets=()
for module in "${target_modules[@]}"; do
    if [[ ${#previous_clean_targets[@]} -gt 0 ]]; then
        restore_plain_state "${previous_clean_targets[@]}"
    fi
    log "Rebuilding module: $module"
    read -ra raw_paths <<< "${module_paths[$module]}"
    instrument_list=()
    clean_list=()
    for raw in "${raw_paths[@]}"; do
        instrument_list+=("$(normalize_instrument_path "$raw")")
        clean_list+=("$(normalize_clean_target "$raw")")
    done
    deduped_clean_list=()
    dedupe_targets clean_list deduped_clean_list
    clean_list=("${deduped_clean_list[@]}")
    write_instrumentation "$module" "${instrument_list[@]}"
    clean_targets "${clean_list[@]}"
    kernel_make
    if [[ ! -f "$vmlinux_path" ]]; then
        echo "vmlinux not found at $vmlinux_path" >&2
        exit 1
    fi
    if [[ ! -f "$bzimage_path" ]]; then
        echo "bzImage not found at $bzimage_path" >&2
        exit 1
    fi
    if [[ "$INLINE_OUTPUT" == true ]]; then
        vmlinux_dest="${vmlinux_path}-${module}"
        bzimage_dest="${bzimage_path}-${module}"
        cp "$vmlinux_path" "$vmlinux_dest"
        cp "$bzimage_path" "$bzimage_dest"
        log "Artifacts stored in place for $module"
    else
        cp "$vmlinux_path" "$OUTPUT_DIR/vmlinux-$module"
        cp "$bzimage_path" "$OUTPUT_DIR/bzImage-$module"
        log "Artifacts stored in $OUTPUT_DIR for $module"
    fi

    # Build module with KCSAN if --with-kcsan is enabled
    if [[ "$WITH_KCSAN" == true ]]; then
        log "Rebuilding module with KCSAN: $module"
        enable_kcsan_config
        clean_targets "${clean_list[@]}"
        kernel_make
        if [[ ! -f "$vmlinux_path" ]]; then
            echo "vmlinux not found at $vmlinux_path" >&2
            exit 1
        fi
        if [[ ! -f "$bzimage_path" ]]; then
            echo "bzImage not found at $bzimage_path" >&2
            exit 1
        fi
        if [[ "$INLINE_OUTPUT" == true ]]; then
            cp "$vmlinux_path" "${vmlinux_path}-${module}-kcsan"
            cp "$bzimage_path" "${bzimage_path}-${module}-kcsan"
            log "KCSAN artifacts stored in place for $module"
        else
            cp "$vmlinux_path" "$OUTPUT_DIR/vmlinux-${module}-kcsan"
            cp "$bzimage_path" "$OUTPUT_DIR/bzImage-${module}-kcsan"
            log "KCSAN artifacts stored in $OUTPUT_DIR for $module"
        fi
        # Restore original config for next module plain build
        restore_config "$config_backup_for_kcsan"
    fi

    previous_clean_targets=("${clean_list[@]}")
done

# Cleanup KCSAN config backup
if [[ -n "$config_backup_for_kcsan" && -f "$config_backup_for_kcsan" ]]; then
    rm -f "$config_backup_for_kcsan"
fi

if [[ "$INLINE_OUTPUT" == true ]]; then
    log "All module builds finished. Artifacts stored next to originals"
else
    log "All module builds finished. Artifacts in $OUTPUT_DIR"
fi
