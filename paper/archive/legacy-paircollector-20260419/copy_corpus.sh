#!/bin/bash

# 脚本: 将所有 workdir 目录的 corpus.db 复制到指定文件夹
# 用法: ./copy_corpus.sh <目标文件夹>

# 不使用 set -e，改为手动处理错误，避免单个文件失败导致整个脚本退出

# 检查参数
if [ $# -lt 1 ]; then
    echo "用法: $0 <目标文件夹> [--include-uaf]"
    echo ""
    echo "参数:"
    echo "  <目标文件夹>    corpus 文件将被复制到此目录"
    echo "  --include-uaf   同时复制 uaf-corpus.db 文件 (可选)"
    echo ""
    echo "示例:"
    echo "  $0 /path/to/backup"
    echo "  $0 /path/to/backup --include-uaf"
    exit 1
fi

DEST_DIR="$1"
INCLUDE_UAF=false

# 检查是否包含 uaf-corpus
if [ "$2" == "--include-uaf" ]; then
    INCLUDE_UAF=true
fi

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# workdir 目录列表
WORKDIRS=(
    "workdir-btrfs"
    "workdir-dsp"
    "workdir-f2fs"
    "workdir-floppy"
    "workdir-jfs"
    "workdir-ptmx"
    "workdir-usb"
    "workdir-usb-corpus"
    "workdir-video"
    "workdir-wifi"
    "workdir-xfs"
)

# 创建目标目录
mkdir -p "$DEST_DIR"

echo "============================================"
echo "复制 corpus 文件到: $DEST_DIR"
echo "============================================"
echo ""

# 计数器
SUCCESS_COUNT=0
FAIL_COUNT=0

for workdir in "${WORKDIRS[@]}"; do
    SRC_DIR="$SCRIPT_DIR/$workdir"
    
    if [ ! -d "$SRC_DIR" ]; then
        echo "[跳过] $workdir - 目录不存在"
        continue
    fi
    
    # 提取子系统名称 (去掉 workdir- 前缀)
    SUBSYS="${workdir#workdir-}"
    
    # 复制 corpus.db
    CORPUS_FILE="$SRC_DIR/corpus.db"
    if [ -f "$CORPUS_FILE" ]; then
        DEST_FILE="$DEST_DIR/${SUBSYS}-corpus.db"
        if cp "$CORPUS_FILE" "$DEST_FILE" 2>/dev/null; then
            FILE_SIZE=$(du -h "$CORPUS_FILE" | cut -f1)
            echo "[成功] $workdir/corpus.db -> ${SUBSYS}-corpus.db ($FILE_SIZE)"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            echo "[失败] $workdir/corpus.db - 复制失败 (权限问题?)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    else
        echo "[跳过] $workdir/corpus.db - 文件不存在"
    fi
    
    # 如果需要，复制 uaf-corpus.db
    if [ "$INCLUDE_UAF" = true ]; then
        UAF_CORPUS_FILE="$SRC_DIR/uaf-corpus.db"
        if [ -f "$UAF_CORPUS_FILE" ]; then
            DEST_UAF_FILE="$DEST_DIR/${SUBSYS}-uaf-corpus.db"
            if cp "$UAF_CORPUS_FILE" "$DEST_UAF_FILE" 2>/dev/null; then
                FILE_SIZE=$(du -h "$UAF_CORPUS_FILE" | cut -f1)
                echo "[成功] $workdir/uaf-corpus.db -> ${SUBSYS}-uaf-corpus.db ($FILE_SIZE)"
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                echo "[失败] $workdir/uaf-corpus.db - 复制失败 (权限问题?)"
                FAIL_COUNT=$((FAIL_COUNT + 1))
            fi
        else
            echo "[跳过] $workdir/uaf-corpus.db - 文件不存在"
        fi
    fi
done

echo ""
echo "============================================"
echo "复制完成!"
echo "成功: $SUCCESS_COUNT 个文件"
echo "失败: $FAIL_COUNT 个文件"
echo "目标目录: $DEST_DIR"
echo "============================================"

# 显示目标目录内容
echo ""
echo "目标目录内容:"
ls -lh "$DEST_DIR"
