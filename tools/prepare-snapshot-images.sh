#!/bin/bash
# 快照模式镜像准备脚本
# 使用方法: ./tools/prepare-snapshot-images.sh <原始镜像路径>
# 例如: ./tools/prepare-snapshot-images.sh /path/to/bookworm.img

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <source_image_path> [output_dir]"
    echo ""
    echo "This script prepares disk images for VM snapshot mode."
    echo "It converts raw images to qcow2 format, which is required for QEMU savevm/loadvm."
    echo ""
    echo "Example:"
    echo "  $0 /home/user/images/bookworm.img"
    echo "  $0 /home/user/images/bookworm.img /home/user/images/"
    exit 1
fi

SOURCE_IMAGE="$1"
OUTPUT_DIR="${2:-$(dirname "$SOURCE_IMAGE")}"

if [ ! -f "$SOURCE_IMAGE" ]; then
    echo "Error: Source image not found: $SOURCE_IMAGE"
    exit 1
fi

# 获取文件名（不含扩展名）
BASENAME=$(basename "$SOURCE_IMAGE")
NAME="${BASENAME%.*}"

# 检查镜像格式
echo "Checking image format..."
FORMAT=$(qemu-img info "$SOURCE_IMAGE" 2>/dev/null | grep "file format:" | awk '{print $3}')
echo "  Source image format: $FORMAT"

if [ "$FORMAT" == "qcow2" ]; then
    echo "  Image is already in qcow2 format."
    QCOW2_IMAGE="$SOURCE_IMAGE"
else
    # 转换为 qcow2 格式
    QCOW2_IMAGE="${OUTPUT_DIR}/${NAME}-validate.qcow2"
    
    if [ -f "$QCOW2_IMAGE" ]; then
        echo "  Existing qcow2 image found: $QCOW2_IMAGE"
        read -p "  Overwrite? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "  Using existing image."
        else
            echo "  Converting to qcow2 format..."
            echo "  This may take a few minutes for large images..."
            qemu-img convert -f "$FORMAT" -O qcow2 "$SOURCE_IMAGE" "$QCOW2_IMAGE"
            echo "  Created: $QCOW2_IMAGE"
        fi
    else
        echo "  Converting to qcow2 format..."
        echo "  This may take a few minutes for large images..."
        qemu-img convert -f "$FORMAT" -O qcow2 "$SOURCE_IMAGE" "$QCOW2_IMAGE"
        echo "  Created: $QCOW2_IMAGE"
    fi
fi

# 显示结果
echo ""
echo "=========================================="
echo "Image preparation complete!"
echo "=========================================="
echo ""
echo "qcow2 image: $QCOW2_IMAGE"
echo ""
echo "To use snapshot mode, update your config file with:"
echo ""
echo '  "image": "'$QCOW2_IMAGE'",'
echo '  "vm": {'
echo '    ...'
echo '    "snapshot": false'
echo '  },'
echo '  "experimental": {'
echo '    ...'
echo '    "uaf_validate": {'
echo '      ...'
echo '      "enable_vm_snapshot": true'
echo '    }'
echo '  }'
echo ""
echo "IMPORTANT: For multi-VM snapshot mode, ensure each VM has its own"
echo "disk images. If using shared drives (like floppy), set vm.count = 1"
echo "or create separate copies for each VM."
