#!/bin/bash

# 脚本: 为所有 cfg 文件生成对应的 -validate.cfg 版本
# 用法: ./generate_validate_cfg.sh [--force]
#       --force: 强制覆盖已存在的 validate 配置文件
#
# validate 版本的主要改动:
# 1. procs: 2 -> 4
# 2. vm.count: 1 -> 8
# 3. vm.cpu: 2 -> 4
# 4. vm.mem: 4096 -> 8192
# 5. uaf_validate.max_concurrent: 1 -> 8
# 6. uaf_validate.repeat_count: 3 -> 1
# 7. 新增 uaf_validate.disable_async_split: true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORCE_MODE=false

# 解析参数
if [[ "$1" == "--force" || "$1" == "-f" ]]; then
    FORCE_MODE=true
fi

# 需要生成 validate 版本的 cfg 文件列表
CFG_FILES=(
    "btrfs.cfg"
    "dsp.cfg"
    "f2fs.cfg"
    "floppy.cfg"
    "jfs.cfg"
    "ptmx.cfg"
    "usb-driver.cfg"
    "video.cfg"
    "wifi.cfg"
    "xfs.cfg"
    "bt-stack.cfg"
)

echo "=========================================="
echo "生成 validate 配置文件"
echo "=========================================="

success_count=0
fail_count=0
skip_count=0

for cfg_file in "${CFG_FILES[@]}"; do
    src="$SCRIPT_DIR/$cfg_file"
    # 生成 validate 文件名: xxx.cfg -> xxx-validate.cfg
    validate_file="${cfg_file%.cfg}-validate.cfg"
    dst="$SCRIPT_DIR/$validate_file"
    
    # 先检查源文件是否存在
    if [[ ! -f "$src" ]]; then
        echo "跳过: $cfg_file 源文件不存在"
        ((skip_count++))
        continue
    fi
    
    # 如果已存在 validate 文件
    if [[ -f "$dst" ]]; then
        if [[ "$FORCE_MODE" == true ]]; then
            echo -n "覆盖: $cfg_file -> $validate_file ... "
        else
            echo "跳过: $validate_file 已存在 (使用 --force 覆盖)"
            ((skip_count++))
            continue
        fi
    else
        echo -n "生成: $cfg_file -> $validate_file ... "
    fi
    
    # 使用 Python 处理 JSON 配置文件
    python3 << EOF
import json
import sys

try:
    with open("$src", 'r') as f:
        config = json.load(f)
    
    # 1. procs: 2 -> 4
    if 'procs' in config:
        config['procs'] = 4
    
    # 2-4. vm 相关修改
    if 'vm' in config:
        # vm.count: -> 8
        config['vm']['count'] = 8
        # vm.cpu: -> 4
        config['vm']['cpu'] = 4
        # vm.mem: -> 8192
        config['vm']['mem'] = 8192
    
    # 5-7. uaf_validate 相关修改
    if 'experimental' in config and 'uaf_validate' in config['experimental']:
        uaf_validate = config['experimental']['uaf_validate']
        # max_concurrent: -> 8
        uaf_validate['max_concurrent'] = 8
        # repeat_count: -> 1
        uaf_validate['repeat_count'] = 1
        # 新增 disable_async_split: true
        uaf_validate['disable_async_split'] = True
    
    # 写入新配置文件
    with open("$dst", 'w') as f:
        json.dump(config, f, indent=4)
    
    sys.exit(0)
except Exception as e:
    print(f"错误: {e}", file=sys.stderr)
    sys.exit(1)
EOF
    
    if [[ $? -eq 0 ]]; then
        echo "✓ 成功"
        ((success_count++))
    else
        echo "✗ 失败"
        ((fail_count++))
    fi
done

echo ""
echo "=========================================="
echo "完成! 成功: $success_count, 失败: $fail_count, 跳过: $skip_count"
echo "=========================================="
