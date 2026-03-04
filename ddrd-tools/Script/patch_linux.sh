#!/bin/bash

# KCCWF自动patch脚本
# 该脚本会自动添加kccwf相关的patch到内核源码中
KCCWF_DIR="/path/to/kccwf" # 请替换为实际的kccwf源码路径
KERNEL_DIR="/path/to/kernel" # 请替换为实际的内核源码路径

# 检查目录是否存在
if [ ! -d "$KCCWF_DIR" ]; then
    echo "错误: KCCWF目录不存在: $KCCWF_DIR"
    exit 1
fi

if [ ! -d "$KERNEL_DIR" ]; then
    echo "错误: 内核目录不存在: $KERNEL_DIR"
    exit 1
fi

# 进入内核目录
cd "$KERNEL_DIR" || exit 1

echo "开始复制KCCWF源码..."
cp -r "$KCCWF_DIR/kccwf" "$KERNEL_DIR/kccwf"
cp -r "$KCCWF_DIR/drivers/char/kccwf" "$KERNEL_DIR/drivers/char/kccwf"
echo "开始应用KCCWF patches..."

# 1. 在drivers/char/Makefile中添加kccwf目录
echo "正在修改 drivers/char/Makefile..."
sed -i '/obj-$(CONFIG_ADI).*+= adi.o/a obj-y\t\t\t\t+= kccwf/' "$KERNEL_DIR/drivers/char/Makefile"

# 2. 在kernel/Makefile中添加kccwf目录 
echo "正在修改 kernel/Makefile..."
sed -i '/obj-y += entry\//a obj-y += kccwf/' "$KERNEL_DIR/kernel/Makefile"

# 3. 在init/main.c中添加kccwf头文件
echo "正在修改 init/main.c..."
sed -i '/^#include <linux\/kcsan\.h>/a #include <linux/kccwf.h>' "$KERNEL_DIR/init/main.c"

# 4. 在mm/page_alloc.c中添加kccwf头文件
echo "正在修改 mm/page_alloc.c..."
sed -i '/^#include <linux\/kmsan\.h>/a #include <linux/kccwf.h>' "$KERNEL_DIR/mm/page_alloc.c"

# 5. 在mm/slub.c中添加kccwf头文件
echo "正在修改 mm/slub.c..."
sed -i '/^#include <linux\/kmsan\.h>/a #include <linux/kccwf.h>' "$KERNEL_DIR/mm/slub.c"

# 6. 在include/uapi/linux/lsm.h中添加KCCWF LSM ID
echo "正在修改 include/uapi/linux/lsm.h..."
sed -i '/^#define LSM_ID_IPE\s\+113$/a #define LSM_ID_KCCWF    114' "$KERNEL_DIR/include/uapi/linux/lsm.h"

# 7. 在include/linux/lsm_count.h中添加KCCWF_ENABLED定义
echo "正在修改 include/linux/lsm_count.h..."
sed -i '/^#define IPE_ENABLED 1,$/a #define KCCWF_ENABLED 1,' "$KERNEL_DIR/include/linux/lsm_count.h"

# 8. 在include/linux/lsm_count.h的MAX_LSM_COUNT计算中添加KCCWF_ENABLED
echo "正在修改 MAX_LSM_COUNT 计算..."
sed -i '/IPE_ENABLED \\/a \		KCCWF_ENABLED)' "$KERNEL_DIR/include/linux/lsm_count.h"

echo "KCCWF patches应用完成！"
echo "请确保您已经创建了相应的kccwf源码目录和文件。"