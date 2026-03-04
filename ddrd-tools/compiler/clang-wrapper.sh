#!/bin/bash

CLANG=${CLANG:-clang-18}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CLANG_WRAPPER=${CLANG_WRAPPER:-"$SCRIPT_DIR/kernel_compiler"}
DEFAULT_INSTRUMENT_FILE="$SCRIPT_DIR/instrumentation_targets.conf"
INSTRUMENT_FILE=${DDRD_INSTRUMENT_LIST:-$DEFAULT_INSTRUMENT_FILE}

instrument_patterns=()
if [[ -f "$INSTRUMENT_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line#${line%%[![:space:]]*}}"
        line="${line%${line##*[![:space:]]}}"
        [[ -z "$line" ]] && continue
        instrument_patterns+=("$line")
    done < "$INSTRUMENT_FILE"
else
    instrument_patterns=(
        "net/bluetooth/"
        "drivers/bluetooth/"
        "net/wireless/"
        "net/mac80211/"
        "drivers/tty/"
        "fs/devpts/"
        "drivers/media/v4l2-core/"
        "drivers/media/platform/"
        "drivers/media/pci/"
        "drivers/media/usb/"
        "drivers/gpu/drm/"
        "sound/core/"
        "sound/pci/"
        "sound/pci/hda/"
        "sound/soc/"
        "fs/xfs/"
        "fs/btrfs/"
        "fs/f2fs/"
        "fs/nilfs2/"
        "fs/gfs2/"
        "fs/overlayfs/"
        "fs/ext4/"
        "drivers/block/floppy.c"
    )
fi

exclude_patterns=(
    "drivers/firmware/efi/libstub/"
    "kernel/kccwf/"
    "drivers/char/kccwf/"
)

source_files=""
for arg in "$@"; do
    if [[ "$arg" == *.c ]]; then
        source_files="$arg"
    fi
done

if [[ -z "$source_files" ]]; then
        "$CLANG" "$@"
        exit
fi

source_files=${source_files#./}

# out-of-tree (O=) 编译时, make 传入绝对路径如 /path/to/kernel/fs/xfs/foo.c
# 需要提取相对于内核源码树的路径用于模式匹配
rel_source="$source_files"
for kernel_root in "${DDRD_KERNEL_SRC:-}" "${srctree:-}"; do
    if [[ -n "$kernel_root" && "$rel_source" == "$kernel_root/"* ]]; then
        rel_source="${rel_source#"$kernel_root"/}"
        break
    fi
done

if [[ -f "$source_files" && "$source_files" == *.c ]]; then
    should_instrument=false
    for pattern in "${instrument_patterns[@]}"; do
        if [[ "$pattern" == */ ]]; then
            prefix="${pattern%/}/"
            if [[ "$rel_source" == "$prefix"* ]]; then
                should_instrument=true
                break
            fi
        else
            if [[ "$rel_source" == "$pattern" ]]; then
                should_instrument=true
                break
            fi
        fi
    done

    if [[ "$should_instrument" == true ]]; then
        for pattern in "${exclude_patterns[@]}"; do
            if [[ "$rel_source" == "$pattern"* ]]; then
                should_instrument=false
                break
            fi
        done
    fi

    if [[ "$should_instrument" == true ]]; then
        "$CLANG_WRAPPER" "$@"
    else
        "$CLANG" "$@"
    fi
else
    "$CLANG" "$@"
fi
