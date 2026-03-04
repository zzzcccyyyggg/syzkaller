# DDRD-syzkaller 完整测试流程

## 概览

```
                    ┌───────────────────────────────────────────────────────┐
                    │                  完整测试流程                          │
                    │                                                       │
                    │  Step 0: 环境准备 (一次性)                             │
                    │    ├── 编译 DDRD 工具链                               │
                    │    ├── 编译 syzkaller                                 │
                    │    └── 准备磁盘镜像                                   │
                    │                                                       │
                    │  Step 1: 构建内核                                     │
                    │    ├── plain 内核 (无插桩, 基准)                       │
                    │    └── 各模块插桩内核 (xfs, btrfs, ...)              │
                    │                                                       │
                    │  Step 2: 生成配置                                     │
                    │    ├── fuzz.cfg                                       │
                    │    └── validate.cfg                                   │
                    │                                                       │
                    │  Step 3: 运行 Fuzz                                    │
                    │    └── syz-manager → 发现 data race                   │
                    │                                                       │
                    │  Step 4: 运行 Validate (可选)                         │
                    │    └── syz-manager -mode=uaf-validate → 验证/复现     │
                    └───────────────────────────────────────────────────────┘
```

---

## 可用模块

| 类别       | 模块 slug      | 内核路径                  | 额外设备               |
|-----------|---------------|--------------------------|----------------------|
| 文件系统   | `xfs`         | fs/xfs/                  | -hdb xfs-2G.qcow2   |
| 文件系统   | `btrfs`       | fs/btrfs/                | -hdb btrfs-2G.qcow2 |
| 文件系统   | `f2fs`        | fs/f2fs/                 | -hdb f2fs-2G.qcow2  |
| 文件系统   | `jfs`         | fs/jfs/                  | -hdb jfs-2G.qcow2   |
| 文件系统   | `ext4`        | fs/ext4/                 | -hdb ext4-2G.qcow2  |
| 文件系统   | `overlayfs`   | fs/overlayfs/            | 专用 rootfs          |
| 驱动       | `floppy`      | drivers/block/floppy.c   | floppy drive         |
| 驱动       | `usb-driver`  | drivers/usb/             | USB XHCI             |
| 驱动       | `video`       | drivers/media/v4l2-core/ | —                    |
| 网络       | `wifi-stack`  | net/wireless/ net/mac80211/ | —                 |
| 蓝牙       | `bt-stack`    | net/bluetooth/           | —                    |
| TTY        | `ptmx`        | drivers/tty/             | —                    |
| 音频       | `dsp`         | sound/pci/hda/           | AC97 声卡            |

查看所有模块: `./scripts/build_kernel.sh --list`

---

## Step 0: 环境准备 (一次性)

### 0.1 编译 DDRD 工具链

```bash
./scripts/build_ddrd_tools.sh          # 编译全部组件
./scripts/build_ddrd_tools.sh check    # 验证所有组件可用
```

### 0.2 编译 syzkaller

```bash
./scripts/build_syzkaller.sh           # 编译 syz-manager 等
```

### 0.3 准备磁盘镜像

```bash
./scripts/create_image.sh --import               # 从 test/fs/ 导入镜像+key
sudo ./scripts/create_image.sh --fix-kccwf       # 统一修复 kccwf.service

# 如需创建新的文件系统镜像:
./scripts/create_image.sh --create-fs xfs 2G
./scripts/create_image.sh --create-fs btrfs 2G
```

### 0.4 一键初始化 (Makefile)

```bash
make setup    # = import-images + config (自动完成 0.3 + Step 2)
```

---

## Step 1: 构建内核

### 构建所有模块

```bash
./scripts/build_kernel.sh              # 构建 plain + 所有 13 个模块
```

### 只构建指定模块

```bash
./scripts/build_kernel.sh xfs btrfs    # 只构建 xfs 和 btrfs
```

### 常用选项

```bash
./scripts/build_kernel.sh --plain-only           # 仅构建无插桩 plain 内核
./scripts/build_kernel.sh --no-clean xfs         # 跳过 make clean, 增量编译
./scripts/build_kernel.sh --with-kcsan xfs       # 同时生成 KCSAN 版本
./scripts/build_kernel.sh --mode=isolated xfs    # 独立 build 目录 (首次慢, 但隔离更好)
./scripts/build_kernel.sh -j 32 xfs              # 指定并行任务数
```

### 输出

```
kernels/output/
  ├── plain/       vmlinux + bzImage  (无插桩基准)
  ├── xfs/         vmlinux + bzImage  (xfs 插桩)
  ├── btrfs/       vmlinux + bzImage  (btrfs 插桩)
  └── ...
```

---

## Step 2: 生成配置

```bash
python3 scripts/generate_config.py xfs           # 生成 xfs 的 fuzz + validate 配置
python3 scripts/generate_config.py --all          # 生成所有模块配置
python3 scripts/generate_config.py --all --force  # 强制覆盖已有配置
python3 scripts/generate_config.py --fuzz-only xfs       # 仅生成 fuzz 配置
python3 scripts/generate_config.py --validate-only xfs   # 仅生成 validate 配置
python3 scripts/generate_config.py --dry-run --force xfs  # 预览不写入
```

### 输出

```
exp/
  └── xfs/
      ├── fuzz.cfg          # fuzz 模式配置
      ├── validate.cfg      # validate 模式配置
      ├── overrides.json    # 模块特定参数
      └── syscalls/         # syscall 列表
```

---

## Step 3: 运行 Fuzz

### 启动

```bash
# ⚠️ 注意: 不要用 `sudo sh`, 要用 bash 或直接执行
./scripts/run_fuzz.sh start xfs                  # 启动 xfs fuzz (后台)
./scripts/run_fuzz.sh start xfs btrfs f2fs       # 同时启动多个
./scripts/run_fuzz.sh start --all                # 启动所有有 fuzz.cfg 的模块
./scripts/run_fuzz.sh start -t 2h xfs            # 2小时后自动停止
./scripts/run_fuzz.sh start --debug xfs          # 前台 debug 模式 (可看实时输出)
```

> **需要 sudo?** syzkaller 的 syz-manager 本身可以不用 sudo 运行,
> 但 QEMU 的 KVM 需要当前用户在 `kvm` 组中: `sudo usermod -aG kvm $USER`

### 查看状态

```bash
./scripts/run_fuzz.sh status                     # 查看所有模块运行状态

# 输出示例:
# MODULE          STATUS   PID      CONFIG
# ------          ------   ---      ------
# xfs             running  12345    exp/xfs/fuzz.cfg
# btrfs           stopped  —        exp/btrfs/fuzz.cfg
```

### 查看日志

```bash
./scripts/run_fuzz.sh log xfs                    # tail -f 最新日志
# 日志位置: exp/xfs/logs/fuzz-YYYYMMDD-HHMMSS.log
```

### 查看 Web UI

syzkaller 会启动 HTTP 服务, 端口在 fuzz.cfg 的 `http` 字段中:
- xfs: http://127.0.0.1:62001
- btrfs: http://127.0.0.1:62002
- 更多端口见 `exp/<slug>/fuzz.cfg`

### 停止

```bash
./scripts/run_fuzz.sh stop xfs                   # 停止指定模块
./scripts/run_fuzz.sh stop                       # 停止所有正在运行的
```

---

## Step 4: 运行 Validate (可选)

Validate 模式用于复现/验证 fuzz 阶段发现的 data race。

### 前置条件

Validate 需要 fuzz 阶段生成的 `uaf-corpus.db`:
```
exp/xfs/workdir/uaf-corpus.db   ← fuzz 阶段自动生成，validate 共享读取
```

### 启动

```bash
./scripts/run_validate.sh start xfs              # 启动 xfs validate
./scripts/run_validate.sh start --debug xfs      # 前台 debug 模式
./scripts/run_validate.sh start --all            # 启动所有
```

### 状态/日志/停止

```bash
./scripts/run_validate.sh status
./scripts/run_validate.sh log xfs
./scripts/run_validate.sh stop xfs
```

---

## Makefile 快捷命令

所有操作都可通过 Makefile 完成:

```bash
# 完整初始化
make setup                        # import-images + config

# 编译
make build-tools                  # DDRD 工具链
make build-syzkaller              # syzkaller
make build-kernel                 # 所有内核
make build-kernel MODULES=xfs     # 指定模块

# 运行
make fuzz MODULES=xfs             # 启动 fuzz
make fuzz-all                     # 启动所有 fuzz
make validate MODULES=xfs        # 启动 validate
make status                       # 查看状态
make stop                         # 停止所有

# 日志
make fuzz-log MODULES=xfs
make validate-log MODULES=xfs

# Corpus 管理
make corpus-stat                  # 查看 corpus 统计
make corpus-backup                # 备份 corpus
make corpus-import                # 导入 corpus
```

---

## 快速上手: 从零到 Fuzz

```bash
# 1. 编译工具链 + syzkaller
./scripts/build_ddrd_tools.sh
./scripts/build_syzkaller.sh

# 2. 准备镜像
./scripts/create_image.sh --import
sudo ./scripts/create_image.sh --fix-kccwf

# 3. 编译 xfs 插桩内核 (约 15 分钟)
./scripts/build_kernel.sh xfs

# 4. 生成配置
python3 scripts/generate_config.py --force xfs

# 5. 启动 fuzz
./scripts/run_fuzz.sh start xfs

# 6. 查看状态
./scripts/run_fuzz.sh status

# 7. 查看 Web UI
# 浏览器打开 http://127.0.0.1:62001

# 8. 查看日志
./scripts/run_fuzz.sh log xfs

# 9. 停止
./scripts/run_fuzz.sh stop xfs
```

---

## 目录结构

```
DDRD-syzkaller/
├── scripts/              # 所有工作流脚本
│   ├── envsetup.sh       # 环境变量 (被所有脚本 source)
│   ├── functions.sh      # 公共函数
│   ├── modules.conf      # 模块定义
│   ├── build_ddrd_tools.sh
│   ├── build_syzkaller.sh
│   ├── build_kernel.sh
│   ├── create_image.sh
│   ├── generate_config.py
│   ├── run_fuzz.sh
│   ├── run_validate.sh
│   ├── manage_corpus.sh
│   └── Makefile
├── ddrd-tools/            # DDRD 插桩工具链
│   ├── compiler/          # clang-wrapper + kernel_compiler
│   └── instrumenter/      # LLVM IR 插桩 pass
├── kernels/
│   ├── builds/            # 内核构建目录 (O= out-of-tree)
│   ├── output/            # 最终产物 (vmlinux + bzImage per module)
│   ├── configs/           # 内核 .config 模板
│   └── configs/           # 内核 .config 模板
├── exp/                   # 实验目录
│   └── <slug>/
│       ├── fuzz.cfg       # fuzz 配置
│       ├── validate.cfg   # validate 配置
│       ├── overrides.json # 模块参数
│       ├── workdir/       # fuzz/validate 共享工作目录 (corpus, crashes, uaf-corpus)
│       └── logs/          # 日志
└── bin/                   # 编译好的 syzkaller 二进制
    ├── syz-manager
    ├── syz-prog2c
    └── ...
```

---

## 常见问题

### Q: `sudo sh ./scripts/run_fuzz.sh` 报错 `Illegal option -o pipefail`

脚本使用 bash 语法，不要用 `sh` 执行:
```bash
# ✗ 错误
sudo sh ./scripts/run_fuzz.sh start xfs

# ✓ 正确
./scripts/run_fuzz.sh start xfs
sudo bash ./scripts/run_fuzz.sh start xfs
```

### Q: SSH key 权限错误 `Load key: Permission denied`

SSH key 必须是当前用户可读的:
```bash
# 重新导入 (会自动修权限)
./scripts/create_image.sh --import
```

### Q: networking.service 启动失败

镜像中的网络配置需要修复:
```bash
sudo ./scripts/create_image.sh --fix-kccwf
```

### Q: 编译内核时 "source tree is not clean"

内核源码树有 in-tree 编译残留, 脚本会自动运行 `make mrproper`。
如果仍失败:
```bash
cd /home/zzzccc/Linux-Kernel/DDRD-Kernel
make ARCH=x86 mrproper
```

### Q: 插桩后 vmlinux 和 plain 一样大

检查 clang-wrapper.sh 和 kernel_compiler 是否正确:
```bash
./scripts/build_ddrd_tools.sh check
```

### Q: 如何只跑文件系统相关模块?

```bash
./scripts/build_kernel.sh xfs btrfs f2fs jfs ext4
python3 scripts/generate_config.py --force xfs btrfs f2fs jfs ext4
./scripts/run_fuzz.sh start xfs btrfs f2fs jfs ext4
```
