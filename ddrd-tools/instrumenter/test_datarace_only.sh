#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLANG="${CLANG:-clang-18}"
INSTRUMENTER="${INSTRUMENTER:-$ROOT/build/bin/instrumenter}"
WORKDIR="${TMPDIR:-/tmp}/ddrd-instrumenter-datarace-only.$$"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$WORKDIR"

"$CLANG" -S -emit-llvm -g -O0 -Xclang -disable-O0-optnone \
	-Wno-atomic-alignment \
	"$ROOT/test/datarace_only_cases.c" -o "$WORKDIR/cases.O0.ll"

"$INSTRUMENTER" "$WORKDIR/cases.O0.ll" --datarace-only >"$WORKDIR/instrumenter.log"
OUT="$WORKDIR/cases.O0.instrumented.ll"

body_call_count() {
	local fn="$1"
	awk -v fn="$fn" '
		$0 ~ "^define .*@" fn "\\(" { in_fn = 1; seen = 1; next }
		in_fn && /call void @kccwf_rec_mem_access/ { count++ }
		in_fn && /^}/ { print count + 0; found = 1; exit }
		END {
			if (!seen || !found)
				exit 2
		}
	' "$OUT"
}

require_body_calls_at_least() {
	local fn="$1"
	local min="$2"
	local count
	count="$(body_call_count "$fn")"
	if (( count < min )); then
		echo "FAIL: expected $fn to have at least $min memory record call(s), got $count" >&2
		exit 1
	fi
}

require_body_calls_exact() {
	local fn="$1"
	local want="$2"
	local count
	count="$(body_call_count "$fn")"
	if (( count != want )); then
		echo "FAIL: expected $fn to have exactly $want memory record call(s), got $count" >&2
		exit 1
	fi
}

require_body_calls_at_least plain_global_read 1
require_body_calls_at_least plain_global_write 1
require_body_calls_at_least atomic_load_case 1
require_body_calls_at_least atomic_store_case 1
require_body_calls_at_least atomic_rmw_case 1
require_body_calls_at_least atomic_nonatomic_side 1
require_body_calls_at_least flags_bit0 1
require_body_calls_at_least flags_bit1 1
require_body_calls_at_least bitfield_a 1
require_body_calls_at_least bitfield_b 1
require_body_calls_at_least memcpy_globals 2
require_body_calls_at_least helper_return_load 1
require_body_calls_at_least phi_select_case 1
require_body_calls_exact stack_spill_only 0

if grep -q "kccwf_rec_func_enter\\|kccwf_rec_func_exit\\|kccwf_rec_bbs\\|kccwf_rec_memory_free" "$OUT"; then
	echo "FAIL: datarace-only output unexpectedly contains non-datarace hooks" >&2
	exit 1
fi

cat >"$WORKDIR/atomic_mem.ll" <<'EOF'
; ModuleID = 'atomic_mem'
source_filename = "atomic_mem.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@src = global [64 x i8] zeroinitializer, align 1
@dst = global [64 x i8] zeroinitializer, align 1

declare void @llvm.memcpy.element.unordered.atomic.p0.p0.i64(ptr nocapture writeonly, ptr nocapture readonly, i64, i32 immarg)
declare void @llvm.memset.element.unordered.atomic.p0.i64(ptr nocapture writeonly, i8, i64, i32 immarg)

define void @atomic_memcpy_case() {
entry:
  call void @llvm.memcpy.element.unordered.atomic.p0.p0.i64(ptr align 1 @dst, ptr align 1 @src, i64 16, i32 1)
  ret void
}

define void @atomic_memset_case() {
entry:
  call void @llvm.memset.element.unordered.atomic.p0.i64(ptr align 1 @dst, i8 0, i64 16, i32 1)
  ret void
}
EOF

"$INSTRUMENTER" "$WORKDIR/atomic_mem.ll" --datarace-only >"$WORKDIR/atomic_mem.instrumenter.log"
OUT="$WORKDIR/atomic_mem.instrumented.ll"

require_body_calls_at_least atomic_memcpy_case 2
require_body_calls_at_least atomic_memset_case 1

echo "datarace-only instrumenter regression passed"
