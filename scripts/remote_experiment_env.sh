#!/usr/bin/env bash

set -eu

MRPFUZZ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export MRPFUZZ_ROOT
export PATH="$MRPFUZZ_ROOT/.tools/go/bin:$MRPFUZZ_ROOT/.venv/bin:$PATH"
export GOCACHE="$MRPFUZZ_ROOT/.cache/go-build"
export GOMODCACHE="$MRPFUZZ_ROOT/.cache/go-mod"

QEMU_COMPAT_ROOT="$MRPFUZZ_ROOT/.tools/qemu-6.2"
if [[ -x "$QEMU_COMPAT_ROOT/bin/qemu-system-x86_64" ]]; then
    export PATH="$QEMU_COMPAT_ROOT/bin:$PATH"
    export LD_LIBRARY_PATH="$QEMU_COMPAT_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

if (echo > /dev/tcp/127.0.0.1/7890) >/dev/null 2>&1; then
    export http_proxy="http://127.0.0.1:7890"
    export https_proxy="http://127.0.0.1:7890"
fi

mkdir -p "$GOCACHE" "$GOMODCACHE"
