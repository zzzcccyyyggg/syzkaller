#!/bin/bash
# batch_gen_repros.sh - Batch generate C reproducers from all validated_uaf.db files
#
# Usage:
#   ./batch_gen_repros.sh [--output-dir <dir>] [--compile] [--db-glob <glob>]
#
# Default: processes all exp/*/workdir/validate-run/validated_uaf.db
# Output: ./batch_repros/<fs_name>/<record_dir>/

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYZKALLER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PARSE_SCRIPT="${SCRIPT_DIR}/parse_validated_db.py"
GEN_SCRIPT="${SCRIPT_DIR}/gen_reproducer.py"
SYZ_DB="${SYZKALLER_ROOT}/bin/syz-db"

OUTPUT_BASE="${SYZKALLER_ROOT}/batch_repros"
COMPILE=1
DB_GLOB="exp/*/workdir/validate-run/validated_uaf.db"

# ---- arg parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_BASE="$2"; shift 2 ;;
        --no-compile) COMPILE=0; shift ;;
        --compile)    COMPILE=1; shift ;;
        --db-glob)    DB_GLOB="$2"; shift 2 ;;
        --help|-h)
            head -10 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "${OUTPUT_BASE}"

# Counters
total_dbs=0
total_records=0
prog2c_ok=0
prog2c_fail=0
compile_ok=0
compile_fail=0

SUMMARY_FILE="${OUTPUT_BASE}/batch_summary.txt"
: > "${SUMMARY_FILE}"

log() { echo "$*" | tee -a "${SUMMARY_FILE}"; }

log "===== batch_gen_repros.sh ====="
log "Started: $(date)"
log "Output:  ${OUTPUT_BASE}"
log "Compile: ${COMPILE}"
log ""

cd "${SYZKALLER_ROOT}"

for db_path in ${DB_GLOB}; do
    [[ -f "${db_path}" ]] || continue

    # Derive a friendly name: exp/<name>/workdir/... → <name>
    fs_name="$(echo "${db_path}" | sed 's|exp/\([^/]*\)/.*|\1|')"
    total_dbs=$((total_dbs + 1))

    out_dir="${OUTPUT_BASE}/${fs_name}"
    mkdir -p "${out_dir}"

    log "---- [${fs_name}] ${db_path} ----"

    # Step 1: Parse db → extract records
    parse_out=$(python3 "${PARSE_SCRIPT}" "${db_path}" "${out_dir}" \
            --syz-db "${SYZ_DB}" 2>&1) || true
    echo "${parse_out}" | tee -a "${SUMMARY_FILE}"
    if ! echo "${parse_out}" | grep -q "Summary written"; then
        log "  [ERROR] parse_validated_db.py failed for ${db_path}"
        continue
    fi

    # Step 2: For each record dir, run gen_reproducer.py
    for record_dir in "${out_dir}"/record_*/; do
        [[ -d "${record_dir}" ]] || continue
        [[ -f "${record_dir}/prog0.syz" ]] || continue
        [[ -f "${record_dir}/prog1.syz" ]] || continue

        total_records=$((total_records + 1))
        record_name="$(basename "${record_dir}")"

        compile_flag=""
        [[ "${COMPILE}" == "1" ]] && compile_flag="--compile"

        gen_out=""
        if gen_out=$(python3 "${GEN_SCRIPT}" "${record_dir}" ${compile_flag} 2>&1); then
            echo "${gen_out}" >> "${SUMMARY_FILE}"

            # Check if C files were generated
            if [[ -f "${record_dir}/prog0.c" && -f "${record_dir}/prog1.c" ]]; then
                if [[ "${COMPILE}" == "1" ]]; then
                    if [[ -f "${record_dir}/prog0_bin" && -f "${record_dir}/prog1_bin" ]]; then
                        compile_ok=$((compile_ok + 1))
                        log "  [OK]  ${fs_name}/${record_name}: prog2c+compile OK"
                    else
                        compile_fail=$((compile_fail + 1))
                        log "  [WARN] ${fs_name}/${record_name}: prog2c OK, compile FAILED"
                    fi
                else
                    prog2c_ok=$((prog2c_ok + 1))
                    log "  [OK]  ${fs_name}/${record_name}: prog2c OK"
                fi
            else
                prog2c_fail=$((prog2c_fail + 1))
                log "  [FAIL] ${fs_name}/${record_name}: prog2c FAILED (no .c output)"
            fi
        else
            echo "${gen_out}" >> "${SUMMARY_FILE}"
            prog2c_fail=$((prog2c_fail + 1))
            log "  [FAIL] ${fs_name}/${record_name}: gen_reproducer.py error"
        fi
    done
    log ""
done

log "===== SUMMARY ====="
log "Databases processed:  ${total_dbs}"
log "Total records:        ${total_records}"
if [[ "${COMPILE}" == "1" ]]; then
    log "Compile OK:           ${compile_ok}"
    log "Compile FAIL:         ${compile_fail}"
    log "prog2c FAIL:          ${prog2c_fail}"
    log "Success rate:         $(( total_records > 0 ? compile_ok * 100 / total_records : 0 ))%"
else
    log "prog2c OK:            ${prog2c_ok}"
    log "prog2c FAIL:          ${prog2c_fail}"
    log "Success rate:         $(( total_records > 0 ? prog2c_ok * 100 / total_records : 0 ))%"
fi
log ""
log "Output directory: ${OUTPUT_BASE}"
log "Finished: $(date)"
