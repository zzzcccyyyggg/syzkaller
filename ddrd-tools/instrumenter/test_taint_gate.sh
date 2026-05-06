#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLANG="${CLANG:-clang-18}"
INSTRUMENTER="${INSTRUMENTER:-$ROOT/build/bin/instrumenter}"
WORKDIR="${TMPDIR:-/tmp}/ddrd-instrumenter-taint-gate.$$"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$WORKDIR"

cat >"$WORKDIR/plain_taint_cases.c" <<'EOF'
#define NOINLINE __attribute__((noinline))
#define USED __attribute__((used))

int g;
int h;

NOINLINE USED int direct_global_read(void)
{
	return g;
}

NOINLINE USED void direct_global_write(int v)
{
	g = v;
}

NOINLINE USED int param_read(int *p)
{
	return *p;
}

NOINLINE USED int *helper_return_global(void)
{
	return &g;
}

NOINLINE USED int helper_return_read(void)
{
	return *helper_return_global();
}

NOINLINE USED int phi_param_read(int cond, int *p)
{
	int *q = cond ? p : &h;
	return *q;
}

NOINLINE USED int scalar_index_local(int idx)
{
	int local[4] = {0};
	local[idx & 3] = 1;
	return local[0];
}
EOF

"$CLANG" -S -emit-llvm -g -O0 -Xclang -disable-O0-optnone \
	"$WORKDIR/plain_taint_cases.c" -o "$WORKDIR/cases.O0.ll"

"$INSTRUMENTER" "$WORKDIR/cases.O0.ll" -v >"$WORKDIR/instrumenter.log"
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

require_body_calls_exact direct_global_read 1
require_body_calls_exact direct_global_write 1
require_body_calls_exact param_read 1
require_body_calls_exact helper_return_read 1
require_body_calls_exact phi_param_read 1
require_body_calls_exact scalar_index_local 0

if ! grep -q "Variable instrumentation mode: taint-gated" "$WORKDIR/instrumenter.log"; then
	echo "FAIL: default -v mode should remain taint-gated" >&2
	exit 1
fi

echo "taint-gated plain access regression passed"
