#!/bin/bash

# 脚本: 将 DDRD-Corpus 目录中的 db 文件复制到各个对应的 workdir 文件夹
# 用法: ./import_corpus.sh [模块名]
# 示例: ./import_corpus.sh          # 导入所有模块
#       ./import_corpus.sh bt       # 只导入 bt 模块
#       ./import_corpus.sh btrfs    # 只导入 btrfs 模块

CORPUS_DIR="/home/zzzccc/BASS/DDRD-Corpus"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_MODULE="$1"  # 可选参数：指定要导入的模块

# 定义映射关系: corpus文件名 -> workdir文件夹名
declare -A CORPUS_MAP=(
    ["btrfs-corpus.db"]="workdir-btrfs"
    ["dsp-corpus.db"]="workdir-dsp"
    ["f2fs-corpus.db"]="workdir-f2fs"
    ["floppy-corpus.db"]="workdir-floppy"
    ["jfs-corpus.db"]="workdir-jfs"
    ["ptmx-corpus.db"]="workdir-ptmx"
    ["usb-corpus.db"]="workdir-usb"
    ["usb-corpus-corpus.db"]="workdir-usb-corpus"
    ["video-corpus.db"]="workdir-video"
    ["wifi-corpus.db"]="workdir-wifi"
    ["xfs-corpus.db"]="workdir-xfs"
    ["bt-corpus.db"]="workdir-bt-stack"
)

# 定义模块名到corpus文件名的映射（用于参数匹配）
declare -A MODULE_TO_CORPUS=(
    ["btrfs"]="btrfs-corpus.db"
    ["dsp"]="dsp-corpus.db"
    ["f2fs"]="f2fs-corpus.db"
    ["floppy"]="floppy-corpus.db"
    ["jfs"]="jfs-corpus.db"
    ["ptmx"]="ptmx-corpus.db"
    ["usb"]="usb-corpus.db"
    ["usb-corpus"]="usb-corpus-corpus.db"
    ["video"]="video-corpus.db"
    ["wifi"]="wifi-corpus.db"
    ["xfs"]="xfs-corpus.db"
    ["bt"]="bt-corpus.db"
    ["bt-stack"]="bt-corpus.db"
)

# 显示帮助信息
show_help() {
    echo "用法: $0 [模块名]"
    echo ""
    echo "可用模块:"
    echo "  btrfs, dsp, f2fs, floppy, jfs, ptmx, usb, usb-corpus,"
    echo "  video, wifi, xfs, bt (或 bt-stack)"
    echo ""
    echo "示例:"
    echo "  $0           # 导入所有模块"
    echo "  $0 bt        # 只导入 bt 模块"
    echo "  $0 btrfs     # 只导入 btrfs 模块"
}

# 检查模块参数是否有效
if [[ -n "$TARGET_MODULE" ]]; then
    if [[ "$TARGET_MODULE" == "-h" || "$TARGET_MODULE" == "--help" ]]; then
        show_help
        exit 0
    fi
    if [[ -z "${MODULE_TO_CORPUS[$TARGET_MODULE]}" ]]; then
        echo "错误: 未知模块 '$TARGET_MODULE'"
        echo ""
        show_help
        exit 1
    fi
fi

echo "=========================================="
if [[ -n "$TARGET_MODULE" ]]; then
    echo "导入 DDRD-Corpus 到 workdir (模块: $TARGET_MODULE)"
else
    echo "导入 DDRD-Corpus 到各 workdir"
fi
echo "=========================================="
echo "源目录: $CORPUS_DIR"
echo "目标目录: $SCRIPT_DIR"
echo ""

success_count=0
fail_count=0
skip_count=0

for corpus_file in "${!CORPUS_MAP[@]}"; do
    workdir="${CORPUS_MAP[$corpus_file]}"
    
    # 如果指定了模块，只处理该模块
    if [[ -n "$TARGET_MODULE" ]]; then
        target_corpus="${MODULE_TO_CORPUS[$TARGET_MODULE]}"
        if [[ "$corpus_file" != "$target_corpus" ]]; then
            continue
        fi
    fi
    
    src="$CORPUS_DIR/$corpus_file"
    dst="$SCRIPT_DIR/$workdir/corpus.db"
    
    if [[ -f "$src" ]]; then
        if [[ -d "$SCRIPT_DIR/$workdir" ]]; then
            echo -n "复制: $corpus_file -> $workdir/corpus.db ... "
            cp "$src" "$dst"
            if [[ $? -eq 0 ]]; then
                echo "✓ 成功"
                ((success_count++))
            else
                echo "✗ 失败"
                ((fail_count++))
            fi
        else
            echo "跳过: $workdir 目录不存在"
            ((skip_count++))
        fi
    else
        echo "跳过: $corpus_file 源文件不存在"
        ((skip_count++))
    fi
done

echo ""
echo "=========================================="
echo "完成! 成功: $success_count, 失败: $fail_count, 跳过: $skip_count"
echo "=========================================="
