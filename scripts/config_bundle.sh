#!/usr/bin/env bash
# ============================================================================
# config_bundle.sh — 配置文件导入/导出
#
# 目标:
#   - 导出 exp/<module>/ 下的配置相关文件到一个 tar.gz
#   - 在另一台设备导入并自动修复配置里的绝对路径
#
# 用法:
#   ./scripts/config_bundle.sh export <bundle.tar.gz> [--all|module1 module2 ...]
#   ./scripts/config_bundle.sh import <bundle.tar.gz> [--force] [--dry-run]
#   ./scripts/config_bundle.sh list
#
# 导出内容:
#   exp/<slug>/*.cfg
#   exp/<slug>/syscalls.txt
#   exp/<slug>/overrides.json
#   manifest.json (源路径、时间、模块、文件列表)
#
# 导入路径修复:
#   对 *.cfg 与 overrides.json 做 JSON 递归替换:
#   所有字符串中的 old_project_home -> current_project_home
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

BUNDLE_VERSION=1
FORCE=false
DRY_RUN=false

usage() {
    sed -n '3,28p' "$0" | sed 's/^# //' | sed 's/^#//'
}

list_modules_with_configs() {
    for d in "$EXP_DIR"/*/; do
        [[ -d "$d" ]] || continue
        local slug
        slug=$(basename "$d")
        local has_cfg=false
        for f in "$d"/*.cfg; do
            [[ -f "$f" ]] && { has_cfg=true; break; }
        done
        $has_cfg && echo "$slug"
    done
}

rewrite_json_paths() {
    local src="$1" dst="$2" old_root="$3" new_root="$4"
    python3 - "$src" "$dst" "$old_root" "$new_root" <<'PY'
import json
import sys

src, dst, old_root, new_root = sys.argv[1:5]

with open(src) as f:
    obj = json.load(f)

def rewrite(v):
    if isinstance(v, str):
        if old_root:
            return v.replace(old_root, new_root)
        return v
    if isinstance(v, list):
        return [rewrite(i) for i in v]
    if isinstance(v, dict):
        return {k: rewrite(val) for k, val in v.items()}
    return v

obj = rewrite(obj)
with open(dst, "w") as f:
    json.dump(obj, f, indent=4)
    f.write("\n")
PY
}

do_export() {
    local bundle_path="$1"; shift || true
    local all_mode=false
    local targets=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all|-a) all_mode=true; shift ;;
            -*) die "未知选项: $1" ;;
            *) targets+=("$1"); shift ;;
        esac
    done

    if $all_mode || [[ ${#targets[@]} -eq 0 ]]; then
        mapfile -t targets < <(list_modules_with_configs)
    fi
    [[ ${#targets[@]} -gt 0 ]] || die "未找到可导出的模块配置"

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN

    local root="$tmp/bundle"
    mkdir -p "$root"

    local files_txt="$tmp/files.txt"
    local mods_txt="$tmp/modules.txt"
    : > "$files_txt"
    : > "$mods_txt"

    local count=0
    for slug in "${targets[@]}"; do
        local mod_dir="$EXP_DIR/$slug"
        [[ -d "$mod_dir" ]] || { log_warn "[$slug] 目录不存在, 跳过"; continue; }

        local added=false
        local f
        for f in "$mod_dir"/*.cfg "$mod_dir"/syscalls.txt "$mod_dir"/overrides.json; do
            [[ -f "$f" ]] || continue
            local rel="${f#$PROJECT_HOME/}"
            local dst="$root/$rel"
            mkdir -p "$(dirname "$dst")"
            cp -a "$f" "$dst"
            echo "$rel" >> "$files_txt"
            added=true
            ((count++)) || true
        done

        if $added; then
            echo "$slug" >> "$mods_txt"
            log_ok "[$slug] 已收集配置"
        else
            log_warn "[$slug] 无可导出配置文件, 跳过"
        fi
    done

    [[ $count -gt 0 ]] || die "未收集到任何文件"

    sort -u "$files_txt" -o "$files_txt"
    sort -u "$mods_txt" -o "$mods_txt"

    local manifest="$root/manifest.json"
    python3 - "$manifest" "$PROJECT_HOME" "$files_txt" "$mods_txt" "$BUNDLE_VERSION" <<'PY'
import json
import sys
from datetime import datetime, timezone

manifest_path, project_home, files_txt, mods_txt, version = sys.argv[1:6]

with open(files_txt) as f:
    files = [line.strip() for line in f if line.strip()]
with open(mods_txt) as f:
    modules = [line.strip() for line in f if line.strip()]

manifest = {
    "bundle_version": int(version),
    "exported_at": datetime.now(timezone.utc).isoformat(),
    "source_project_home": project_home,
    "modules": modules,
    "files": files,
}

with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=4)
    f.write("\n")
PY

    mkdir -p "$(dirname "$bundle_path")"
    tar -czf "$bundle_path" -C "$root" .
    log_ok "导出完成: $bundle_path"
    log_info "模块数: $(wc -l < "$mods_txt" | tr -d ' ')  文件数: $(wc -l < "$files_txt" | tr -d ' ')"
}

do_import() {
    local bundle_path="$1"; shift || true

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force|-f) FORCE=true; shift ;;
            --dry-run|-n) DRY_RUN=true; shift ;;
            -*) die "未知选项: $1" ;;
            *) die "未知参数: $1" ;;
        esac
    done

    [[ -f "$bundle_path" ]] || die "bundle 不存在: $bundle_path"

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN

    tar -xzf "$bundle_path" -C "$tmp"

    local manifest="$tmp/manifest.json"
    [[ -f "$manifest" ]] || die "bundle 缺少 manifest.json"

    local old_root filelist
    old_root=$(python3 - "$manifest" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    m = json.load(f)
print(m.get("source_project_home", ""))
PY
)

    filelist="$tmp/files.list"
    python3 - "$manifest" "$filelist" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    m = json.load(f)
files = m.get("files", [])
with open(sys.argv[2], "w") as out:
    for rel in files:
        out.write(rel + "\n")
PY

    log_info "导入 bundle: $bundle_path"
    log_info "路径修复: $old_root -> $PROJECT_HOME"

    local ok=0 skip=0 fail=0
    local rel
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        local src="$tmp/$rel"
        local dst="$PROJECT_HOME/$rel"

        if [[ ! -f "$src" ]]; then
            log_warn "文件缺失, 跳过: $rel"
            ((skip++)) || true
            continue
        fi

        if [[ -f "$dst" ]] && ! $FORCE; then
            log_warn "已存在, 跳过: $rel (使用 --force 覆盖)"
            ((skip++)) || true
            continue
        fi

        if $DRY_RUN; then
            log_info "[dry-run] 导入: $rel"
            ((ok++)) || true
            continue
        fi

        mkdir -p "$(dirname "$dst")"
        case "$rel" in
            *.cfg|*/overrides.json)
                if rewrite_json_paths "$src" "$dst" "$old_root" "$PROJECT_HOME"; then
                    ((ok++)) || true
                else
                    log_error "导入失败: $rel"
                    ((fail++)) || true
                fi
                ;;
            *)
                if cp -a "$src" "$dst"; then
                    ((ok++)) || true
                else
                    log_error "导入失败: $rel"
                    ((fail++)) || true
                fi
                ;;
        esac
    done < "$filelist"

    echo ""
    log_info "导入完成: 成功=$ok 跳过=$skip 失败=$fail"
    (( fail == 0 )) || exit 1
}

ACTION="${1:-help}"; shift || true

case "$ACTION" in
    export)
        [[ $# -ge 1 ]] || die "用法: $0 export <bundle.tar.gz> [--all|module1 module2 ...]"
        do_export "$@"
        ;;
    import)
        [[ $# -ge 1 ]] || die "用法: $0 import <bundle.tar.gz> [--force] [--dry-run]"
        do_import "$@"
        ;;
    list)
        list_modules_with_configs
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        die "未知命令: $ACTION (export|import|list|help)"
        ;;
esac
