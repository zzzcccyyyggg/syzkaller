# DDRD-PairCollector 测试工具集

本目录包含用于 DDRD（Data Race Driven）UAF 漏洞检测的配置文件和辅助脚本。

## 目录结构

```
test/
├── *.cfg                    # 各模块的 Discover 配置文件
├── *-validate.cfg           # 各模块的 Validate 配置文件（自动生成）
├── workdir-*/               # 各模块的工作目录
├── logs/                    # 日志目录
└── 脚本文件
```

## 配置文件说明

### 模块列表

| 模块 | Discover 配置 | Validate 配置 | 工作目录 |
|------|--------------|---------------|----------|
| BTRFS 文件系统 | `btrfs.cfg` | `btrfs-validate.cfg` | `workdir-btrfs/` |
| DSP 音频 | `dsp.cfg` | `dsp-validate.cfg` | `workdir-dsp/` |
| F2FS 文件系统 | `f2fs.cfg` | `f2fs-validate.cfg` | `workdir-f2fs/` |
| Floppy 软驱 | `floppy.cfg` | `floppy-validate.cfg` | `workdir-floppy/` |
| JFS 文件系统 | `jfs.cfg` | `jfs-validate.cfg` | `workdir-jfs/` |
| PTMX 伪终端 | `ptmx.cfg` | `ptmx-validate.cfg` | `workdir-ptmx/` |
| USB 驱动 | `usb-driver.cfg` | `usb-driver-validate.cfg` | `workdir-usb/` |
| Video V4L2 | `video.cfg` | `video-validate.cfg` | `workdir-video/` |
| WiFi 无线 | `wifi.cfg` | `wifi-validate.cfg` | `workdir-wifi/` |
| XFS 文件系统 | `xfs.cfg` | `xfs-validate.cfg` | `workdir-xfs/` |
| Bluetooth 蓝牙 | `bt-stack.cfg` | `bt-stack-validate.cfg` | `workdir-bt-stack/` |

### Discover vs Validate 配置差异

| 参数 | Discover | Validate | 说明 |
|------|----------|----------|------|
| `procs` | 2 | 4 | 并发进程数 |
| `vm.count` | 1 | 8 | 虚拟机数量 |
| `vm.cpu` | 2 | 4 | 每个 VM 的 CPU 核数 |
| `vm.mem` | 4096 | 8192 | 每个 VM 的内存 (MB) |
| `uaf_validate.max_concurrent` | 1 | 8 | 最大并发验证数 |
| `uaf_validate.repeat_count` | 3 | 1 | 重复验证次数 |
| `uaf_validate.disable_async_split` | - | true | 禁用异步分割 |

## 脚本说明

### generate_validate_cfg.sh

为所有 cfg 文件自动生成对应的 `-validate.cfg` 版本。

```bash
# 生成 validate 配置（跳过已存在的）
./generate_validate_cfg.sh

# 强制覆盖所有 validate 配置
./generate_validate_cfg.sh --force
```

### import_corpus.sh

从 DDRD-Corpus 目录导入语料库到各工作目录。

```bash
# 导入所有模块的 corpus
./import_corpus.sh

# 只导入指定模块的 corpus
./import_corpus.sh bt        # 导入蓝牙模块
./import_corpus.sh btrfs     # 导入 BTRFS 模块
./import_corpus.sh floppy    # 导入 Floppy 模块
```

**可用模块名**: `btrfs`, `dsp`, `f2fs`, `floppy`, `jfs`, `ptmx`, `usb`, `usb-corpus`, `video`, `wifi`, `xfs`, `bt` (或 `bt-stack`)

### run_all.sh

批量管理所有模块的运行。

```bash
# 启动指定模块
sudo ./run_all.sh start bt -t 18h

# 停止指定模块
sudo ./run_all.sh stop btrfs
```

### 其他脚本

| 脚本 | 说明 |
|------|------|
| `copy_corpus.sh` | 复制语料库 |
| `rename_uaf_db.sh` | 重命名 UAF 数据库文件 |
| `sync_to_server.sh` | 同步到服务器 |
| `plot_uaf_pairs.py` | 绘制 UAF pairs 统计图 |
| `update.py` | 更新工具 |

## 使用流程

### 1. Discover 阶段（发现 UAF）

```bash
# 使用普通配置运行 fuzzing
sudo ./bin/syz-manager --config=./test/DDRD-PairCollector/test/floppy.cfg
```

### 2. Validate 阶段（验证 UAF）

```bash
# 生成 validate 配置
./generate_validate_cfg.sh

# 运行验证模式
sudo ./bin/syz-manager --config=./test/DDRD-PairCollector/test/floppy-validate.cfg --mode uaf-validate
```

### 3. 导入已有语料库

```bash
# 从 DDRD-Corpus 导入
./import_corpus.sh floppy
```

## 工作目录结构

每个 `workdir-*` 目录包含：

```
workdir-xxx/
├── corpus.db           # 语料库数据库
├── uaf-corpus.db.1     # UAF 语料库
├── instance-lock       # 实例锁文件
├── threshold_config.json # 阈值配置
├── crashes/            # 崩溃报告目录
└── instance-*/         # 实例目录
```

## 注意事项

1. **权限**: 运行 syz-manager 需要 root 权限
2. **资源**: Validate 模式需要更多 CPU 和内存资源
3. **验证结果**: `verified=0` 不代表代码有问题，可能是：
   - 不存在真实的 race（正确过滤了误报）
   - 时序窗口太小，难以稳定复现
   - 访问受锁保护
